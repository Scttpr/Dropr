/**
 * Security headers on every response type (PLAN.md §7, ARCHITECTURE.md §3/§5,
 * PAGES.md §9-10) and an Observatory-style checklist: exact CSP/HSTS/…,
 * cache policy per type, cookie attributes, no inline script or style, SRI
 * present and correct on every script and stylesheet, and no CSP violation
 * reported by any browser on the real pages.
 */

import { createHash } from "node:crypto";
import type { APIResponse } from "@playwright/test";
import { KEYCLOAK } from "../fixtures.ts";
import { anonymousPage, createRequest, expect, linkId, makeFile, shareFile, sqlRun, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; " +
  `manifest-src 'self'; form-action 'self' ${KEYCLOAK}; frame-ancestors 'none'; base-uri 'none'; ` +
  "require-trusted-types-for 'script'; trusted-types dropr-sw";

const PERMISSIONS =
  "accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), " +
  "browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), " +
  "encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), " +
  "identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), " +
  "midi=(), otp-credentials=(), payment=(), picture-in-picture=(), " +
  "publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), " +
  "serial=(), storage-access=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()";

const COMMON: Record<string, string> = {
  "content-security-policy": CSP,
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": PERMISSIONS,
};

type Kind = "page" | "api" | "asset" | "sw" | "dl" | "other";

function checkHeaders(label: string, r: APIResponse, kind: Kind): void {
  const h = r.headers();
  for (const [k, v] of Object.entries(COMMON)) expect(h[k], `${label}: ${k}`).toBe(v);
  expect(h["x-powered-by"], `${label}: x-powered-by`).toBeUndefined();
  expect(h["server"], `${label}: server`).toBeUndefined();
  expect(h["access-control-allow-origin"], `${label}: CORS`).toBeUndefined();
  const cc = h["cache-control"] ?? "";
  switch (kind) {
    case "asset":
      expect(cc, `${label}: cache-control`).toMatch(/immutable/);
      expect(cc, `${label}: cache-control`).toMatch(/max-age=\d{7,}/);
      break;
    case "sw":
      expect(cc, `${label}: cache-control`).toBe("no-cache");
      expect(h["service-worker-allowed"], `${label}: service-worker-allowed`).toBe("/_dl/");
      expect(h["content-type"], `${label}: content-type`).toMatch(/^text\/javascript/);
      break;
    default:
      expect(cc, `${label}: cache-control`).toBe("no-store");
  }
  if (kind === "page") expect(h["content-type"], `${label}: content-type`).toBe("text/html; charset=utf-8");
  if (kind === "api") expect(h["content-type"], `${label}: content-type`).toMatch(/^application\/json/);
}

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

test("every response type carries the exact security headers", async ({ request, dropr, alice, browserName }) => {
  test.skip(browserName !== "chromium", "HTTP-level, browser-independent");
  const o = dropr.origin;
  const H = { origin: o };
  const login = await request.get(o + "/");
  const html = await login.text();
  const css = /href="(\/assets\/[^"]+\.css)"/.exec(html)?.[1];
  const icon = /href="(\/assets\/[^"]+\.svg)"/.exec(html)?.[1];
  expect(css).toBeDefined();
  expect(icon).toBeDefined();
  const sharePage = await (await request.get(o + new URL(shareUrl).pathname)).text();
  const js = /src="(\/assets\/[^"]+\.js)"/.exec(sharePage)?.[1];
  expect(js).toBeDefined();

  const cases: [string, Promise<APIResponse>, Kind, number][] = [
    ["login page", Promise.resolve(login), "page", 200],
    ["/login", request.get(o + "/login"), "page", 200],
    ["share page", request.get(o + new URL(shareUrl).pathname), "page", 200],
    ["request page", request.get(o + new URL(requestUrl).pathname), "page", 200],
    ["dead link 404", request.get(o + "/s/AAAAAAAAAAAAAAAAAAAAAA"), "page", 404],
    ["dead link 410", request.get(o + new URL(expiredUrl).pathname), "page", 410],
    ["malformed link id", request.get(o + "/r/not-an-id"), "page", 404],
    ["404 page", request.get(o + "/no/such/page"), "page", 404],
    ["/_dl fallback", request.get(o + "/_dl/AAAAAAAAAAAAAAAAAAAAAA"), "page", 404],
    ["owner page redirect", request.get(o + "/inbox", { maxRedirects: 0 }), "other", 303],
    ["dashboard (signed in)", alice.context.request.get(o + "/"), "page", 200],
    ["links (signed in)", alice.context.request.get(o + "/links"), "page", 200],
    ["API 401", request.get(o + "/api/shares"), "api", 401],
    ["API 200 (signed in)", alice.context.request.get(o + "/api/shares"), "api", 200],
    ["API 404", request.post(o + "/api/s/AAAAAAAAAAAAAAAAAAAAAA/download", { headers: H, data: {} }), "api", 404],
    ["API 410", request.post(o + `/api/s/${linkId(expiredUrl)}/download`, { headers: H, data: {} }), "api", 410],
    ["API 400", request.post(o + `/api/s/${linkId(shareUrl)}/download`, { headers: H, data: { nope: 1 } }), "api", 400],
    ["API 413", request.post(o + `/api/r/${linkId(requestUrl)}/files`, { headers: H, data: { meta: "A".repeat(40_000) } }), "api", 413],
    ["CSRF 403", request.post(o + "/api/shares", { headers: { "sec-fetch-site": "cross-site" }, data: {} }), "other", 403],
    ["upload 401", request.get(o + "/upload/AAAAAAAAAAAAAAAAAAAAAA"), "api", 401],
    ["download bad token", request.get(o + "/dl/" + "A".repeat(43)), "other", 404],
    ["stylesheet", request.get(o + css!), "asset", 200],
    ["icon", request.get(o + icon!), "asset", 200],
    ["module script", request.get(o + js!), "asset", 200],
    ["unknown asset", request.get(o + "/assets/nope-12345678.js"), "page", 404],
    ["service worker", request.get(o + "/sw.js"), "sw", 200],
    ["healthz", request.get(o + "/healthz"), "other", 200],
    ["auth login redirect", request.get(o + "/auth/login", { maxRedirects: 0 }), "other", 302],
    ["unlisted method (404 by contract)", request.put(o + "/login", { headers: H }), "page", 404],
  ];
  for (const [label, p, kind, status] of cases) {
    const r = await p;
    expect(r.status(), label).toBe(status);
    checkHeaders(label, r, kind);
  }
});

test("a real download response is an attachment with no validators", async ({ request, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "HTTP-level");
  const t = await request.post(`${dropr.origin}/api/s/${linkId(shareUrl)}/download`, { headers: { origin: dropr.origin }, data: {} });
  const { token } = (await t.json()) as { token: string };
  for (const [range, status] of [[undefined, 200], ["bytes=0-9", 206], ["bytes=0-1,4-5", 416]] as const) {
    const r = await request.get(`${dropr.origin}/dl/${token}`, range ? { headers: { range } } : {});
    expect(r.status()).toBe(status);
    checkHeaders(`dl ${range ?? "full"}`, r, "dl");
    const h = r.headers();
    if (status !== 416) {
      expect(h["content-type"]).toBe("application/octet-stream");
      expect(h["content-disposition"]).toBe('attachment; filename="dropr-download.bin"');
      expect(h["accept-ranges"]).toBe("bytes");
    }
    expect(h["etag"]).toBeUndefined();
    expect(h["last-modified"]).toBeUndefined();
  }
});

test("cookies: __Host- prefix, Secure, HttpOnly, SameSite, no Domain", async ({ request, dropr, alice, browserName }) => {
  test.skip(browserName !== "chromium", "HTTP-level");
  const r = await request.get(dropr.origin + "/auth/login", { maxRedirects: 0 });
  const sc = r.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);
  const oidc = sc.find((c) => c.startsWith("__Host-dropr_oidc="));
  expect(oidc, sc.join("\n")).toBeDefined();
  const attrs = oidc!.split(";").map((s) => s.trim().toLowerCase());
  expect(attrs).toContain("secure");
  expect(attrs).toContain("httponly");
  expect(attrs).toContain("samesite=lax");
  expect(attrs).toContain("path=/");
  expect(attrs.some((a) => a.startsWith("domain="))).toBe(false);
  const maxAge = Number(attrs.find((a) => a.startsWith("max-age="))?.slice(8) ?? "0");
  expect(maxAge).toBeGreaterThan(0);
  expect(maxAge).toBeLessThanOrEqual(600);
  const loc = new URL(r.headers()["location"]!);
  expect(loc.origin + loc.pathname).toBe(`${KEYCLOAK}/realms/dropr/protocol/openid-connect/auth`);
  expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
  for (const p of ["state", "nonce", "code_challenge"]) expect(loc.searchParams.get(p)?.length ?? 0).toBeGreaterThanOrEqual(22);

  const session = (await alice.context.cookies(dropr.origin)).find((c) => c.name === "__Host-dropr_session");
  expect(session).toBeDefined();
  expect(session).toMatchObject({ secure: true, httpOnly: true, sameSite: "Strict", path: "/", domain: "localhost" });
  // Session cookie is a browser-session cookie or short-lived (≤ 8 h absolute timeout).
  expect(session!.expires === -1 || session!.expires - Date.now() / 1000 <= 8 * 3600 + 60).toBe(true);
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

test("the per-IP rate limit answers 429 with the same headers", async ({ request, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "HTTP-level; last test (exhausts this worker's link limiter)");
  let limited: APIResponse | null = null;
  for (let i = 0; i < 80 && limited === null; i++) {
    const r = await request.get(dropr.origin + "/s/AAAAAAAAAAAAAAAAAAAAAA");
    if (r.status() === 429) limited = r;
  }
  expect(limited, "no 429 after 80 requests").not.toBeNull();
  checkHeaders("429", limited!, "other");
  expect(Number(limited!.headers()["retry-after"] ?? "1")).toBeGreaterThan(0);
});
