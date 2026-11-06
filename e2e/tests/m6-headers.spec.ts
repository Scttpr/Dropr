/**
 * Observatory-style checks that need a real browser (PLAN.md §7, PAGES.md
 * §9-10): no inline script or style, SRI present and correct on every script
 * and stylesheet, and no CSP violation reported by any browser on the real
 * pages. The exact headers per response type, cookie attributes and the 429
 * answer are covered by the Go tests (internal/server/headers_test.go).
 */

import { createHash } from "node:crypto";
import { anonymousPage, createRequest, expect, linkId, makeFile, shareFile, sqlRun, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let shareUrl = "";
let requestUrl = "";
let expiredUrl = "";

test("owner creates live, expired and request links", async ({ alice, filesDir, dropr }) => {
  const f = await makeFile(filesDir, "hdr.txt", 1000);
  shareUrl = await shareFile(alice, f);
  expiredUrl = await shareFile(alice, f);
  sqlRun(dropr, "UPDATE shares SET expires_at = unixepoch() - 5 WHERE id = ?", linkId(expiredUrl));
  requestUrl = await createRequest(alice);
});

test("pages: no inline script/style/handlers, SRI on every script and stylesheet, no CSP violations", async ({ browser, browserName, dropr, request, alice }) => {
  const { context, page } = await anonymousPage(browser, `observatory/${browserName}`);
  await context.addInitScript(() => {
    const w = window as unknown as { cspViolations: string[] };
    w.cspViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => w.cspViolations.push(`${e.violatedDirective} ${e.blockedURI} ${e.sourceFile}:${e.lineNumber}`));
  });
  const pages: [string, Promise<void> | null][] = [
    ["/", null],
    [new URL(shareUrl).pathname + new URL(shareUrl).hash, null],
    [new URL(requestUrl).pathname + new URL(requestUrl).hash, null],
    [new URL(expiredUrl).pathname, null],
    ["/s/AAAAAAAAAAAAAAAAAAAAAA", null],
    ["/nope", null],
  ];
  const audit = async (p: import("@playwright/test").Page, path: string, fetcher: typeof request): Promise<void> => {
    await p.goto("about:blank");
    await p.goto(dropr.origin + path);
    await p.waitForLoadState("networkidle");
    const facts = await p.evaluate(() => ({
      inlineScripts: [...document.querySelectorAll("script:not([src])")].length,
      scripts: [...document.querySelectorAll("script[src]")].map((s) => ({ src: s.getAttribute("src")!, integrity: s.getAttribute("integrity"), type: s.getAttribute("type") })),
      styles: [...document.querySelectorAll('link[rel="stylesheet"]')].map((s) => ({ src: s.getAttribute("href")!, integrity: s.getAttribute("integrity") })),
      inlineStyles: document.querySelectorAll("style").length,
      styleAttrs: document.querySelectorAll("[style]").length,
      handlers: [...document.querySelectorAll("*")].flatMap((e) => [...e.attributes].filter((a) => a.name.startsWith("on")).map((a) => `${e.tagName}.${a.name}`)),
      external: [...document.querySelectorAll("[src],[href]")].map((e) => e.getAttribute("src") ?? e.getAttribute("href")!).filter((u) => /^(https?:)?\/\//.test(u)),
      lang: document.documentElement.lang,
    }));
    expect(facts.inlineScripts, `${path}: inline scripts`).toBe(0);
    expect(facts.inlineStyles, `${path}: <style>`).toBe(0);
    expect(facts.styleAttrs, `${path}: style attributes`).toBe(0);
    expect(facts.handlers, `${path}: inline handlers`).toEqual([]);
    expect(facts.external, `${path}: third-party resources`).toEqual([]);
    expect(facts.lang).toBe("en");
    expect(facts.styles.length, `${path}: stylesheet`).toBe(1);
    for (const s of [...facts.scripts, ...facts.styles]) {
      expect(s.integrity, `${path}: SRI on ${s.src}`).toMatch(/^sha(256|384|512)-[A-Za-z0-9+/]+=*$/);
      const [alg, b64] = s.integrity!.split("-", 2) as [string, string];
      const body = await (await fetcher.get(dropr.origin + s.src)).body();
      expect(createHash(alg).update(body).digest("base64"), `${path}: SRI matches ${s.src}`).toBe(b64);
    }
    for (const s of facts.scripts) expect(s.type, `${path}: ${s.src} is a module`).toBe("module");
    const v = await p.evaluate(() => (window as unknown as { cspViolations?: string[] }).cspViolations ?? []);
    expect(v, `${path}: CSP violations`).toEqual([]);
  };
  for (const [path] of pages) await audit(page, path, request);
  await context.close();

  // Owner pages (Chromium).
  if (browserName === "chromium") {
    await alice.context.addInitScript(() => {
      const w = window as unknown as { cspViolations: string[] };
      w.cspViolations = [];
      document.addEventListener("securitypolicyviolation", (e) => w.cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`));
    });
    for (const path of ["/", "/inbox", "/links"]) await audit(alice.page, path, alice.context.request);
  }
});
