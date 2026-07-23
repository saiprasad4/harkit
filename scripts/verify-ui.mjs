// End-to-end UI check: loads the page in a real headless browser, clicks
// "Load sample", confirms the verdict goes green and the summary reports secrets
// removed, confirms the rendered page contains [REDACTED], and records which
// hosts the browser contacted while sanitizing (should be only its own origin).
//
//   1. build + serve the site:  pnpm preview   (or point BASE at the live URL)
//   2. in another shell:        pnpm verify:ui
//
// Set BASE to point at a different origin (default http://localhost:4321).
import { chromium } from "playwright";

const BASE = process.env.BASE ?? "http://localhost:4321";

const browser = await chromium.launch();
const page = await browser.newPage();

const hosts = [];
page.on("request", (r) => hosts.push(new URL(r.url()).host));

await page.goto(BASE, { waitUntil: "networkidle" });

// Baseline: hosts touched on load. We only care about hosts touched while sanitizing.
const afterLoad = hosts.length;

await page.locator(".dbg-tabs button", { hasText: /^Load sample$/ }).click();

const verdict = page.locator(".verdict").first();
await page.waitForFunction(
  () => document.querySelector(".verdict")?.classList.contains("ok"),
  { timeout: 15000 },
);

const verdictText = (await verdict.textContent())?.trim();
const ledger = await page.locator(".ledger li").allTextContents();
const bodyText = await page.locator("body").textContent();
const hasRedacted = bodyText?.includes("[REDACTED]") ?? false;

// U+2014 em dash and U+2013 en dash must not appear anywhere in the rendered page.
const dashes = (bodyText?.match(/[\u2014\u2013]/g) ?? []).length;

const sanitizeHosts = [...new Set(hosts.slice(afterLoad))].filter(
  (h) => h && h !== new URL(BASE).host,
);

await browser.close();

console.log("verdict:", verdictText);
console.log("ledger:", ledger.map((l) => l.replace(/\s+/g, " ").trim()));
console.log("page contains [REDACTED]:", hasRedacted);
console.log("em/en dashes on page:", dashes);
console.log(
  "external hosts while sanitizing:",
  sanitizeHosts.length ? sanitizeHosts.join(", ") : "(none, only own origin)",
);

const ok = /sanitized\. removed/.test(verdictText ?? "") && hasRedacted && dashes === 0 && sanitizeHosts.length === 0;
console.log(ok ? "\nPASS" : "\nFAIL");
process.exit(ok ? 0 : 1);
