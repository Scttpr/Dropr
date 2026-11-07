/**
 * Cross-site request forgery (ARCHITECTURE.md §3 "State-changing request
 * protection"; DESIGN.md §7).
 *
 * An attacker page is served by a second local HTTP server:
 * - on http://127.0.0.1:<other> (cross-site: different host), and
 * - on http://localhost:<other>  (same-site but cross-origin: the
 *   SameSite=Strict session cookie IS sent, so only the Sec-Fetch-Site /
 *   Origin check protects the owner).
 * Auto-submitting forms and fetch() calls to state-changing endpoints must be
 * refused with 403 before any handler runs, in every browser. The header
 * policy itself is covered by the Go tests (internal/httpx TestCSRF).
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { anonymousPage, createRequest, expect, linkId, sqlGet, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let attacker: Server;
let attackerPort = 0;
let requestLink = "";

/** Attacker pages: /form?action=…&enctype=… auto-submits; /fetch?url=…&method=… calls fetch. */
function attackerPage(u: URL): string {
  const action = u.searchParams.get("action") ?? "";
  if (u.pathname === "/form") {
    const enctype = u.searchParams.get("enctype") ?? "text/plain";
    return `<!doctype html><title>evil</title><form id=f method=post action="${action}" enctype="${enctype}">
<input name='{"size":1016,"parts":1,"meta":"${"A".repeat(192)}","x":"' value='"}'></form>
<script>document.getElementById("f").submit()</script>`;
  }
  return `<!doctype html><title>evil</title><script>
window.result = fetch(${JSON.stringify(action)}, { method: ${JSON.stringify(u.searchParams.get("method") ?? "POST")}, mode: "no-cors", credentials: "include",
  headers: { "content-type": "text/plain" }, body: JSON.stringify({ size: 1016, parts: 1, meta: "${"A".repeat(192)}" }) })
  .then(r => r.type, e => "error:" + e);
</script>`;
}

test.beforeAll(async () => {
  attacker = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(attackerPage(u));
  });
  await new Promise<void>((ok) => attacker.listen(0, "127.0.0.1", ok));
  attackerPort = (attacker.address() as AddressInfo).port;
});

test.afterAll(async () => {
  attacker.closeAllConnections();
  await new Promise((ok) => attacker.close(ok));
});

test("owner creates a request link (target for anonymous endpoints)", async ({ alice }) => {
  requestLink = await createRequest(alice);
});

for (const site of ["cross-site", "same-site"] as const) {
  test(`a ${site} form post to an anonymous endpoint is refused`, async ({ browser, browserName, dropr }) => {
    const host = site === "cross-site" ? "127.0.0.1" : "localhost";
    const { context, page } = await anonymousPage(browser, `attacker/${browserName}`);
    const target = `${dropr.origin}/api/r/${linkId(requestLink)}/files`;
    const resp = page.waitForResponse((r) => r.url() === target);
    await page.goto(`http://${host}:${attackerPort}/form?action=${encodeURIComponent(target)}`);
    const r = await resp;
    expect(r.status()).toBe(403);
    expect(await r.request().headerValue("sec-fetch-site")).toBe(site);
    expect(sqlGet<{ n: number }>(dropr, "SELECT files_received AS n FROM requests WHERE id = ?", linkId(requestLink))?.n).toBe(0);
    await context.close();
  });
}

test("a same-site page cannot use the owner's session (SameSite=Strict cookie is sent)", async ({ alice, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "owner session lives in Chromium");
  const p = alice.page;
  const before = sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares")!.n;
  const reqBefore = sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests")!.n;
  const seen: { kind: string; url: string; status: number | null; cookie: boolean; sfs: string | null }[] = [];
  // fetch() in no-cors mode (only simple methods: POST): the response is
  // blocked by CORP same-origin so only the request is observable; form
  // navigations show the status.
  for (const [kind, path] of [
    ["fetch", "/api/shares"],
    ["fetch", "/api/requests"],
    ["form", "/api/shares"],
    ["form", "/api/requests"],
  ] as const) {
    const target = dropr.origin + path;
    const reqP = p.waitForRequest((r) => r.url() === target, { timeout: 15_000 });
    const respP = kind === "form" ? p.waitForResponse((r) => r.url() === target, { timeout: 15_000 }) : null;
    await p.goto(`http://localhost:${attackerPort}/${kind}?action=${encodeURIComponent(target)}&method=POST`);
    const req = await reqP;
    const resp = respP === null ? null : await respP;
    seen.push({
      kind,
      url: target,
      status: resp?.status() ?? null,
      cookie: ((await req.headerValue("cookie")) ?? "").includes("__Host-dropr_session"),
      sfs: await req.headerValue("sec-fetch-site"),
    });
  }
  await p.waitForTimeout(300);
  expect(seen).toHaveLength(4);
  for (const s of seen) {
    // Chromium does not report Sec-Fetch-* on no-cors requests whose response CORP blocked.
    if (s.kind === "form") {
      expect(s.sfs, `${s.kind} ${s.url}`).toBe("same-site");
      expect(s.status, `${s.kind} ${s.url}`).toBe(403);
    }
  }
  // The point of the test: the cookie travelled, the check still refused it.
  expect(seen.some((s) => s.cookie)).toBe(true);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares")!.n).toBe(before);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests")!.n).toBe(reqBefore);
  // The owner's own page still works (same-origin).
  await p.goto(dropr.origin + "/links");
  await expect(p.locator(`tr[data-request-id="${linkId(requestLink)}"]`)).toBeVisible();
});
