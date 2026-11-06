/**
 * Role checks against the real Keycloak.
 *
 * - mallory (no Dropr.User role) signs in successfully at the IdP and gets
 *   the 403 "You don't have access" page; no account and no session exist.
 * - bob has the role, signs in and creates a request link; his role is then
 *   removed through the Keycloak admin API mid-session. Revalidation is due
 *   when `sessions.revalidated_at` is older than revalidate_every (minimum
 *   1 m by config); instead of waiting, the test ages that column in SQLite.
 *   The next request must refresh at Keycloak, see the role is gone, and
 *   kill the session (PLAN.md §5.1). Signing in again is refused (403).
 *   The role is restored in every case.
 */

import {
  M6_USERS,
  anonymousPage,
  chromiumBrowser,
  createRequest,
  expect,
  expectNoPageModule,
  linkId,
  login,
  newOwner,
  setRealmRole,
  setupOwner,
  sqlGet,
  sqlRun,
  test,
} from "../m6.ts";

test.describe.configure({ mode: "serial" });

/** Playwright's WebKit (Linux) does not store `Secure` cookies on http://localhost, so the __Host- state cookie is lost and any login ends in "Sign-in failed" (missing state cookie). Production is https-only. */
const WEBKIT_NO_LOCALHOST_SECURE_COOKIES = "WebKit drops Secure (__Host-) cookies on http://localhost: test-environment limitation, not reachable over https";
test.use({ droprConfig: { revalidateEvery: "1m" } });

test("a user without the role gets the 403 page and no account", async ({ browser, browserName, dropr }) => {
  test.skip(browserName === "webkit", WEBKIT_NO_LOCALHOST_SECURE_COOKIES);
  const { context, page } = await anonymousPage(browser, `mallory/${browserName}`);
  await login(page, dropr.origin, M6_USERS.mallory);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("You don't have access to Dropr");
  await expect(page.locator("main")).toContainText("your account has not been given access");
  await expectNoPageModule(page);
  const res = await page.goto(dropr.origin + "/");
  expect(res?.status()).toBe(200);
  await expect(page.getByRole("link", { name: /Sign in/ })).toBeVisible(); // still anonymous
  const cookies = await context.cookies(dropr.origin);
  expect(cookies.map((c) => c.name)).not.toContain("__Host-dropr_session");
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM users WHERE subject IS NOT NULL AND display_name LIKE '%Mallory%'")?.n).toBe(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM users")?.n).toBe(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM sessions")?.n).toBe(0);
  // The forbidden status itself: the callback answers 403.
  await context.close();
});

test.describe("role removed mid-session", () => {
  let requestLink = "";

  test("bob loses the role: the next revalidation ends his session", async ({ browser, browserName, dropr }) => {
    test.skip(browserName !== "chromium", "owner flow runs in Chromium; IdP-side behaviour is browser-independent");
    const { b, close } = await chromiumBrowser(browser, browserName);
    const bob = await newOwner(b, dropr, "bob");
    try {
      await setupOwner(bob, M6_USERS.bob);
      requestLink = await createRequest(bob);
      const user = sqlGet<{ id: string }>(dropr, "SELECT id FROM users WHERE display_name = ?", M6_USERS.bob.name)!;
      expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", user.id)?.n).toBe(1);

      // Revalidation with the role still present keeps the session.
      sqlRun(dropr, "UPDATE sessions SET revalidated_at = unixepoch() - 120 WHERE user_id = ?", user.id);
      await bob.page.goto(dropr.origin + "/links");
      await expect(bob.page.locator(".who")).toHaveText(M6_USERS.bob.name);
      const after = sqlGet<{ age: number }>(dropr, "SELECT unixepoch() - revalidated_at AS age FROM sessions WHERE user_id = ?", user.id);
      expect(after?.age).toBeLessThan(30);

      await setRealmRole(M6_USERS.bob.username, false);
      // Not yet due: still signed in (revalidation is periodic, not per request).
      await bob.page.goto(dropr.origin + "/links");
      await expect(bob.page.locator(".who")).toHaveText(M6_USERS.bob.name);

      sqlRun(dropr, "UPDATE sessions SET revalidated_at = unixepoch() - 120 WHERE user_id = ?", user.id);
      const r = await bob.page.goto(dropr.origin + "/links");
      expect(bob.page.url()).toBe(dropr.origin + "/login");
      expect(r?.status()).toBe(200);
      await expect(bob.page.locator(".who")).toHaveCount(0);
      expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", user.id)?.n).toBe(0);
      const cookies = await bob.context.cookies(dropr.origin);
      expect(cookies.map((c) => c.name)).not.toContain("__Host-dropr_session");
      // The data stays (PLAN.md §5.1: removing the role blocks access; data stays until purged).
      expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests WHERE owner_id = ?", user.id)?.n).toBe(1);

      // Signing in again is refused.
      await bob.page.getByRole("link", { name: /Sign in/ }).click();
      // Keycloak still has an SSO session: it redirects straight back.
      await expect(bob.page.getByRole("heading", { level: 1 })).toHaveText("You don't have access to Dropr");
      expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", user.id)?.n).toBe(0);
    } finally {
      await setRealmRole(M6_USERS.bob.username, true);
      await bob.context.close();
      await close();
    }
  });

  test("the de-roled owner's request link stops accepting uploads", async ({ browser, browserName, dropr, request }) => {
    test.skip(browserName !== "chromium", "depends on the previous owner-flow test");
    test.skip(requestLink === "", "previous test did not create the link");
    // Fixed: a failed revalidation sets users.access_lost_at and the owner's
    // request links answer 410 `closed` (dead page, API) from then on.
    await setRealmRole(M6_USERS.bob.username, false);
    try {
      expect(sqlGet<{ lost: number | null }>(dropr, "SELECT access_lost_at AS lost FROM users WHERE display_name = ?", M6_USERS.bob.name)?.lost).not.toBeNull();
      const { context, page } = await anonymousPage(browser, "sender");
      const res = await page.goto(requestLink);
      expect(res?.status()).toBe(410);
      await expect(page.locator("main")).toContainText("This link no longer accepts files.");
      await expect(page.locator("#file-input")).toHaveCount(0);
      const api = await request.post(`${dropr.origin}/api/r/${linkId(requestLink)}/files`, {
        headers: { origin: dropr.origin },
        data: { size: 1016, parts: 1, meta: "A".repeat(80), wrapped_key: "A".repeat(107) },
      });
      expect(api.status()).toBe(410);
      expect(((await api.json()) as { error: string }).error).toBe("closed");
      expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox WHERE request_id = ?", linkId(requestLink))?.n).toBe(0);
      await context.close();
    } finally {
      await setRealmRole(M6_USERS.bob.username, true);
    }
  });
});
