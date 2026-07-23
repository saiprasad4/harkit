# HAR sanitizer

Strip cookies, auth tokens, and PII out of a HAR file entirely in your browser. Part of [Sealed](https://sealedtools.pages.dev).

A HAR file is a full recording of your browser's network traffic. It leaks cookies, `Authorization` headers, session tokens, and request bodies. Sharing one for a bug report can hand over your session. This tool replaces every secret with `[REDACTED]` in your tab, shows a summary of what came out, and lets you download the cleaned HAR. Nothing is ever uploaded: zero egress.

## What it redacts

- **Auth headers**: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, and any header whose name contains token, secret, apikey, api-key, auth, session, or password.
- **Cookies**: the value of every `request.cookies[]` and `response.cookies[]` entry.
- **URL tokens**: query params named access_token, id_token, refresh_token, token, code, apikey, api_key, key, password, secret, sig, signature, session, or sid, in both `queryString[]` and the `url`.
- **Body tokens**: JWTs and `Bearer` tokens in `postData.text` and `content.text`, plus sensitive keys inside JSON and form-encoded bodies.
- **PII (optional, off by default)**: emails and IPv4 addresses in header, query, and body values.

Key names and the HAR structure are kept intact, so the cleaned file still validates as a HAR.

## Stack

A single lean Astro 5 app with one React island. The redaction engine (`src/lib/redact.ts`) is pure TypeScript: a JSON parse plus in-memory redaction. No backend, no network calls, ever. Fonts are self-hosted via `@fontsource`, so even a page load makes zero external requests.

## Develop

```
pnpm install
pnpm dev        # local dev server
pnpm build      # static dist/
pnpm preview    # serve the built site
pnpm verify:ui  # headless end-to-end check (set BASE to target a URL)
```
