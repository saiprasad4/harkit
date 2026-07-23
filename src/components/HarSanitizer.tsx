import { useMemo, useRef, useState } from "react";
import { sanitizeHar, type RedactResult } from "../lib/redact.ts";
import { SAMPLE_HAR } from "../lib/sample.ts";

const CATEGORIES: { key: keyof RedactResult["counts"]; label: string; note: string }[] = [
  { key: "authHeaders", label: "auth headers", note: "Authorization, Cookie, Set-Cookie, X-Api-Key, and any header named for a token, secret, or session." },
  { key: "cookies", label: "cookies", note: "The value of every request and response cookie, structure kept intact." },
  { key: "urlTokens", label: "url tokens", note: "Query params like access_token, code, sig, and key, in the queryString and the url." },
  { key: "bodyTokens", label: "body tokens", note: "JWTs, Bearer tokens, and sensitive keys inside JSON and form-encoded bodies." },
  { key: "pii", label: "pii", note: "Emails and IPv4 addresses. Off by default, since it is noisy." },
];

export default function HarSanitizer() {
  const [input, setInput] = useState("");
  const [pii, setPii] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [filename, setFilename] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const result = useMemo<RedactResult | null>(() => {
    if (!input.trim()) return null;
    return sanitizeHar(input, pii);
  }, [input, pii]);

  const state: "ok" | "bad" | "warn" = !result
    ? "warn"
    : !result.ok
      ? "bad"
      : result.total > 0
        ? "ok"
        : "warn";

  const verdict = !result
    ? "waiting for a HAR"
    : !result.ok
      ? `can't sanitize: ${result.error}`
      : result.total > 0
        ? `sanitized. removed ${result.total} ${result.total === 1 ? "secret" : "secrets"} across ${result.entriesTouched} of ${result.entries} ${result.entries === 1 ? "request" : "requests"}`
        : `parsed ${result.entries} ${result.entries === 1 ? "request" : "requests"}, found nothing sensitive`;

  function readFile(file: File) {
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = () => setInput(typeof reader.result === "string" ? reader.result : "");
    reader.readAsText(file);
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) readFile(file);
  }

  function download() {
    if (!result?.ok) return;
    const blob = new Blob([result.json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const base = filename ? filename.replace(/\.har$|\.json$/i, "") : "capture";
    a.href = url;
    a.download = `${base}.clean.har`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function clear() {
    setInput("");
    setFilename(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="dbg">
      <div className="dbg-tabs" role="tablist">
        <button type="button" onClick={() => { setInput(SAMPLE_HAR); setFilename("sample.har"); }}>Load sample</button>
        <button type="button" onClick={clear}>Clear</button>
      </div>
      <div className="dbg-meta">
        <span>HAR · JSON · sanitized in your browser</span>
        <span>zero egress</span>
      </div>

      <div className="dbg-grid">
        <div className="pane pane-in">
          <div className="pane-label">HAR: drop a file or paste it</div>

          <div
            className={`drop ${dragging ? "over" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => fileRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") fileRef.current?.click(); }}
          >
            <span>{filename ? `loaded: ${filename}` : "drop a .har here, or click to choose a file"}</span>
            <input
              ref={fileRef}
              type="file"
              accept=".har,application/json,.json"
              style={{ display: "none" }}
              onChange={(e) => { const f = e.target.files?.[0]; if (f) readFile(f); }}
            />
          </div>

          <label className="field">
            <span>HAR JSON <em>never uploaded</em></span>
            <textarea
              value={input}
              onChange={(e) => { setInput(e.target.value); setFilename(null); }}
              rows={16}
              spellCheck={false}
              placeholder='{ "log": { "entries": [ ... ] } }'
            />
          </label>

          <div className="in-actions">
            <button type="button" onClick={() => { setInput(SAMPLE_HAR); setFilename("sample.har"); }}>Load sample</button>
            <button type="button" onClick={clear}>Clear</button>
            <label className="toggle">
              <input type="checkbox" checked={pii} onChange={(e) => setPii(e.target.checked)} />
              <span>also redact PII (emails, IPs)</span>
            </label>
          </div>
        </div>

        <div className="pane pane-out">
          <div className={`verdict ${state}`}>{verdict}</div>

          {!result ? (
            <p className="why">
              Drop or paste a <code>.har</code> on the left, or press <code>Load sample</code>. The summary
              of what got stripped appears here.
            </p>
          ) : !result.ok ? (
            <p className="why">Nothing to show: <code>{result.error}</code>.</p>
          ) : (
            <>
              <div className="pane-label">Removed, by category</div>
              <ol className="ledger">
                {CATEGORIES.map((c) => {
                  const n = result.counts[c.key];
                  return (
                    <li key={c.key} className={n === 0 ? "zero" : ""}>
                      <b>{c.label} · {n}</b>
                      <em>{c.note}</em>
                    </li>
                  );
                })}
              </ol>

              <div className="in-actions">
                <button type="button" className="primary" onClick={download} disabled={!result.ok}>
                  Download clean HAR
                </button>
              </div>

              <p className="why">
                Every value above was replaced with <code>[REDACTED]</code> in place. Key names and the HAR
                structure are untouched, so the cleaned file still validates.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
