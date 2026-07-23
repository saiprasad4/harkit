// HAR sanitizer, pure TypeScript. Parses a HAR (a browser network capture, JSON)
// and replaces sensitive values with [REDACTED] while keeping the structure and
// key names intact, so the cleaned file still validates as a HAR. Nothing here
// touches the network: it is a JSON parse plus in-memory redaction.

export const REDACTED = "[REDACTED]";

export interface RedactCounts {
  authHeaders: number;
  cookies: number;
  urlTokens: number;
  bodyTokens: number;
  pii: number;
}

export interface RedactResult {
  ok: boolean;
  error?: string;
  json: string;
  counts: RedactCounts;
  total: number;
  entries: number;
  entriesTouched: number;
}

// Header names that are sensitive by exact match (case-insensitive). "cookie" and
// "set-cookie" would not be caught by the substring list below, so they live here.
const HEADER_EXACT = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
]);

// A header is also sensitive if its name contains any of these substrings.
const HEADER_SUBSTR = ["token", "secret", "apikey", "api-key", "auth", "session", "password"];

// Query string params that are sensitive by exact name (case-insensitive).
const QUERY_NAMES = new Set([
  "access_token",
  "id_token",
  "refresh_token",
  "token",
  "code",
  "apikey",
  "api_key",
  "key",
  "password",
  "secret",
  "sig",
  "signature",
  "session",
  "sid",
]);

// Keys inside a JSON or form-encoded body that carry secrets. Reuses the exact
// query names plus the header substrings, so bodies and URLs stay consistent.
function isSensitiveBodyKey(name: string): boolean {
  const n = name.toLowerCase();
  if (QUERY_NAMES.has(n)) return true;
  return HEADER_SUBSTR.some((s) => n.includes(s));
}

function isSensitiveHeader(name: string): boolean {
  const n = name.toLowerCase();
  if (HEADER_EXACT.has(n)) return true;
  return HEADER_SUBSTR.some((s) => n.includes(s));
}

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

// Replace every regex match, returning the new string and how many were replaced.
function replaceCount(input: string, re: RegExp, to: string): { out: string; n: number } {
  let n = 0;
  const out = input.replace(re, () => {
    n++;
    return to;
  });
  return { out, n };
}

// Redact the same sensitive query params inside a full URL string, so request.url
// and request.queryString[] agree. Does not add to the count (queryString does).
function scrubUrl(url: string): string {
  const q = url.indexOf("?");
  if (q === -1) return url;
  const base = url.slice(0, q);
  const rest = url.slice(q + 1);
  const [query, hash] = splitHash(rest);
  const parts = query.split("&").map((pair) => {
    const eq = pair.indexOf("=");
    if (eq === -1) return pair;
    const name = pair.slice(0, eq);
    if (QUERY_NAMES.has(decodeURIComponent(name).toLowerCase())) {
      return name + "=" + REDACTED;
    }
    return pair;
  });
  return base + "?" + parts.join("&") + (hash ? "#" + hash : "");
}

function splitHash(rest: string): [string, string] {
  const h = rest.indexOf("#");
  if (h === -1) return [rest, ""];
  return [rest.slice(0, h), rest.slice(h + 1)];
}

// Redact sensitive values inside a parsed JSON body, recursively. Returns the
// number of values replaced.
function redactJsonValues(node: unknown): number {
  let n = 0;
  if (Array.isArray(node)) {
    for (const item of node) n += redactJsonValues(item);
  } else if (node && typeof node === "object") {
    const obj = node as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (isSensitiveBodyKey(key) && (typeof val === "string" || typeof val === "number" || typeof val === "boolean")) {
        obj[key] = REDACTED;
        n++;
      } else {
        n += redactJsonValues(val);
      }
    }
  }
  return n;
}

// Redact a request or response body string. Handles JSON, form-encoded, and raw
// text, then sweeps for JWTs and Bearer tokens. Returns new text and a count.
function redactBody(text: string): { out: string; n: number } {
  let n = 0;
  let out = text;

  // Structured pass: JSON first, then form-encoded.
  const trimmed = out.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(out);
      n += redactJsonValues(parsed);
      out = JSON.stringify(parsed);
    } catch {
      // not valid JSON, fall through to the token sweep
    }
  } else if (/^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(trimmed)) {
    out = trimmed
      .split("&")
      .map((pair) => {
        const eq = pair.indexOf("=");
        if (eq === -1) return pair;
        const name = pair.slice(0, eq);
        if (isSensitiveBodyKey(decodeURIComponent(name))) {
          n++;
          return name + "=" + REDACTED;
        }
        return pair;
      })
      .join("&");
  }

  // Token sweep on whatever text remains.
  const jwt = replaceCount(out, JWT_RE, REDACTED);
  out = jwt.out;
  n += jwt.n;
  const bearer = replaceCount(out, BEARER_RE, "Bearer " + REDACTED);
  out = bearer.out;
  n += bearer.n;

  return { out, n };
}

// Apply PII redaction (emails, IPv4) to a single value string.
function redactPii(value: string): { out: string; n: number } {
  let n = 0;
  let out = value;
  const em = replaceCount(out, EMAIL_RE, REDACTED);
  out = em.out;
  n += em.n;
  const ip = replaceCount(out, IPV4_RE, REDACTED);
  out = ip.out;
  n += ip.n;
  return { out, n };
}

function redactHeaderList(list: unknown, counts: RedactCounts, pii: boolean): boolean {
  if (!Array.isArray(list)) return false;
  let touched = false;
  for (const h of list) {
    if (!h || typeof h !== "object") continue;
    const header = h as Record<string, unknown>;
    if (typeof header.name !== "string" || typeof header.value !== "string") continue;
    if (isSensitiveHeader(header.name)) {
      header.value = REDACTED;
      counts.authHeaders++;
      touched = true;
    } else if (pii) {
      const r = redactPii(header.value);
      if (r.n) {
        header.value = r.out;
        counts.pii += r.n;
        touched = true;
      }
    }
  }
  return touched;
}

function redactCookieList(list: unknown, counts: RedactCounts): boolean {
  if (!Array.isArray(list)) return false;
  let touched = false;
  for (const c of list) {
    if (!c || typeof c !== "object") continue;
    const cookie = c as Record<string, unknown>;
    if (typeof cookie.value === "string" && cookie.value !== "") {
      cookie.value = REDACTED;
      counts.cookies++;
      touched = true;
    }
  }
  return touched;
}

function redactQueryList(list: unknown, counts: RedactCounts, pii: boolean): boolean {
  if (!Array.isArray(list)) return false;
  let touched = false;
  for (const q of list) {
    if (!q || typeof q !== "object") continue;
    const param = q as Record<string, unknown>;
    if (typeof param.name !== "string" || typeof param.value !== "string") continue;
    if (QUERY_NAMES.has(param.name.toLowerCase())) {
      param.value = REDACTED;
      counts.urlTokens++;
      touched = true;
    } else if (pii) {
      const r = redactPii(param.value);
      if (r.n) {
        param.value = r.out;
        counts.pii += r.n;
        touched = true;
      }
    }
  }
  return touched;
}

// Sanitize a HAR document string. `pii` toggles email and IPv4 redaction.
export function sanitizeHar(input: string, pii = false): RedactResult {
  const counts: RedactCounts = { authHeaders: 0, cookies: 0, urlTokens: 0, bodyTokens: 0, pii: 0 };
  const empty = (error: string): RedactResult => ({
    ok: false,
    error,
    json: "",
    counts,
    total: 0,
    entries: 0,
    entriesTouched: 0,
  });

  if (!input.trim()) return empty("paste a HAR file to sanitize");

  let har: unknown;
  try {
    har = JSON.parse(input);
  } catch (e) {
    return empty("not valid JSON: " + (e instanceof Error ? e.message : "parse error"));
  }

  const root = har as Record<string, unknown>;
  const log = root?.log as Record<string, unknown> | undefined;
  const rawEntries = log?.entries;
  if (!Array.isArray(rawEntries)) {
    return empty("not a HAR: missing log.entries array");
  }

  let entriesTouched = 0;

  for (const entry of rawEntries) {
    if (!entry || typeof entry !== "object") continue;
    let touched = false;
    const e = entry as Record<string, unknown>;
    const req = e.request as Record<string, unknown> | undefined;
    const res = e.response as Record<string, unknown> | undefined;

    if (req) {
      touched = redactHeaderList(req.headers, counts, pii) || touched;
      touched = redactCookieList(req.cookies, counts) || touched;
      touched = redactQueryList(req.queryString, counts, pii) || touched;

      if (typeof req.url === "string") req.url = scrubUrl(req.url);

      const postData = req.postData as Record<string, unknown> | undefined;
      if (postData && typeof postData.text === "string" && postData.text) {
        const r = redactBody(postData.text);
        counts.bodyTokens += r.n;
        let text = r.out;
        let piiN = 0;
        if (pii) {
          const p = redactPii(text);
          text = p.out;
          piiN = p.n;
          counts.pii += p.n;
        }
        postData.text = text;
        if (r.n || piiN) touched = true;
      }
    }

    if (res) {
      touched = redactHeaderList(res.headers, counts, pii) || touched;
      touched = redactCookieList(res.cookies, counts) || touched;

      const content = res.content as Record<string, unknown> | undefined;
      if (content && typeof content.text === "string" && content.text) {
        const r = redactBody(content.text);
        counts.bodyTokens += r.n;
        let text = r.out;
        let piiN = 0;
        if (pii) {
          const p = redactPii(text);
          text = p.out;
          piiN = p.n;
          counts.pii += p.n;
        }
        content.text = text;
        if (r.n || piiN) touched = true;
      }
    }

    if (touched) entriesTouched++;
  }

  const total =
    counts.authHeaders + counts.cookies + counts.urlTokens + counts.bodyTokens + counts.pii;

  return {
    ok: true,
    json: JSON.stringify(har, null, 2),
    counts,
    total,
    entries: rawEntries.length,
    entriesTouched,
  };
}
