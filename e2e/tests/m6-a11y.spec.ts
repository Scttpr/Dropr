/**
 * Accessibility smoke: axe-core (dev-only, pinned @axe-core/playwright) on
 * every page in each state a user meets, failing on serious or critical
 * violations (WCAG 2.x A/AA rules). Anonymous pages run in each project's
 * browser; owner pages in Chromium (see fixtures.ts `ownerBrowser`).
 */

import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import {
  M6_USERS,
  anonymousPage,
  createRequest,
  expect,
  gotoFresh,
  linkId,
  login,
  makeFile,
  newOwner,
  sendViaRequest,
  shareFile,
  sqlRun,
  test,
} from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

/** Known app bugs excluded from the general audit (none at the moment). */
const KNOWN: Record<string, string[]> = {};

async function axe(page: Page, label: string, known: string[] = []): Promise<void> {
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]).analyze();
  const bad = res.violations.filter((v) => (v.impact === "serious" || v.impact === "critical") && !known.includes(v.id));
  const minor = res.violations.filter((v) => !bad.includes(v));
  if (minor.length > 0) console.log(`[a11y ${label}] minor: ${minor.map((v) => `${v.id}(${v.impact})`).join(", ")}`);
  expect(
    bad.map((v) => `${v.id} (${v.impact}): ${v.help} — ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`),
    `${label}: serious/critical axe violations`,
  ).toEqual([]);
}

let shareUrl = "";
let requestUrl = "";
let expiredUrl = "";

test("owner pages: login, dashboard (idle, result, error), inbox, links", async ({ owner, dropr, filesDir, browserName }) => {
  test.skip(browserName !== "chromium", "owner pages run in Chromium");
  const p = owner.page;
  await p.goto(dropr.origin + "/");
  await axe(p, "login");
  await owner.login(M6_USERS.alice); // lands on the dashboard
  await axe(p, "dashboard");

  const f = await makeFile(filesDir, "a11y.txt", 2000);
  shareUrl = await shareFile(owner, f);
  await axe(p, "dashboard with share result (QR)");
  expiredUrl = await shareFile(owner, f);
  sqlRun(dropr, "UPDATE shares SET expires_at = unixepoch() - 5 WHERE id = ?", linkId(expiredUrl));
  requestUrl = await createRequest(owner);
  await axe(p, "dashboard with request result");

  await p.goto(dropr.origin + "/");
  await p.locator("#max-downloads").fill("0");
  await p.locator("#file-input").setInputFiles(f.path);
  await expect(p.locator("#share-error")).toBeVisible();
  await axe(p, "dashboard error state");

  await p.goto(dropr.origin + "/links");
  await expect(p.locator("#shares-table")).toBeVisible();
  await axe(p, "links", KNOWN["links"]);
  await p.goto(dropr.origin + "/inbox");
  await expect(p.locator("#inbox-empty")).toBeVisible();
  await axe(p, "inbox (empty)");
});

test("links page: 'Copy link' button's accessible name contains its visible text (WCAG 2.5.3)", async ({ owner, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "owner pages");
  const p = owner.page;
  await p.goto(dropr.origin + "/links");
  await expect(p.locator("#requests-table")).toBeVisible();
  const res = await new AxeBuilder({ page: p }).withRules(["label-content-name-mismatch"]).analyze();
  expect(res.violations.map((v) => v.id)).toEqual([]);
});

test("owner inbox with received files", async ({ owner, dropr, filesDir, browser, browserName }) => {
  test.skip(browserName !== "chromium", "owner pages");
  const g = await makeFile(filesDir, "for-inbox.txt", 3000);
  await sendViaRequest(browser, requestUrl, [g.path]);
  const p = owner.page;
  await p.goto(dropr.origin + "/inbox");
  await expect(p.locator("#inbox-list tr")).toHaveCount(1);
  await axe(p, "inbox with rows");
});

test("owner pages from another browser profile (foreign inbox row, 'Other browser' link)", async ({ dropr, browser, browserName }) => {
  test.skip(browserName !== "chromium", "owner pages");
  const other = await newOwner(browser, dropr, "a11y-other");
  try {
    await other.login(M6_USERS.alice);
    await other.page.goto(dropr.origin + "/inbox");
    await expect(other.page.locator("#inbox-list tr.foreign")).toHaveCount(1);
    await axe(other.page, "inbox with a foreign row");
    await other.page.goto(dropr.origin + "/links");
    await expect(other.page.locator("#requests-list").getByText("Other browser")).toHaveCount(1);
    await axe(other.page, "links from another browser");
  } finally {
    await other.context.close();
  }
});

test("anonymous pages in every browser", async ({ browser, browserName, dropr, filesDir, owner }) => {
  if (shareUrl === "") {
    // Non-Chromium projects run in a fresh worker: sign the owner in here.
    await owner.login(M6_USERS.alice);
    const f = await makeFile(filesDir, "a11y.txt", 2000);
    shareUrl = await shareFile(owner, f);
    expiredUrl = await shareFile(owner, f);
    sqlRun(dropr, "UPDATE shares SET expires_at = unixepoch() - 5 WHERE id = ?", linkId(expiredUrl));
    requestUrl = await createRequest(owner);
  }
  const { context, page } = await anonymousPage(browser, `a11y/${browserName}`);
  await page.goto(dropr.origin + "/");
  await axe(page, `login [${browserName}]`);
  await gotoFresh(page, shareUrl);
  await expect(page.locator("#download-button")).toBeEnabled();
  await axe(page, `share page [${browserName}]`);
  await gotoFresh(page, shareUrl.replace(/#.*/, ""));
  await expect(page.locator("#download-error")).toBeVisible();
  await axe(page, `share page, missing key [${browserName}]`);
  await gotoFresh(page, requestUrl);
  await expect(page.locator("#drop-zone")).toBeVisible();
  await axe(page, `request page [${browserName}]`);
  const f = await makeFile(filesDir, "sent.txt", 1000);
  await page.locator("#file-input").setInputFiles(f.path);
  await expect(page.locator("#upload-done")).toBeVisible({ timeout: 60_000 });
  await axe(page, `request page, sent [${browserName}]`);
  await gotoFresh(page, expiredUrl);
  await axe(page, `dead link 410 [${browserName}]`);
  await page.goto(dropr.origin + "/s/AAAAAAAAAAAAAAAAAAAAAA");
  await axe(page, `dead link 404 [${browserName}]`);
  await page.goto(dropr.origin + "/nope");
  await axe(page, `404 page [${browserName}]`);
  await page.goto(dropr.origin + "/_dl/AAAAAAAAAAAAAAAAAAAAAA");
  await axe(page, `/_dl fallback [${browserName}]`);
  await context.close();
});

test("forbidden page", async ({ browser, browserName, dropr }) => {
  // Playwright's WebKit drops Secure (__Host-) cookies on http://localhost, so login cannot complete there (https-only in production).
  test.skip(browserName === "webkit", "WebKit drops Secure cookies on http://localhost (test-environment limitation)");
  const { context, page } = await anonymousPage(browser, `a11y-mallory/${browserName}`);
  await login(page, dropr.origin, M6_USERS.mallory);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("You don't have access to Dropr");
  await axe(page, `forbidden [${browserName}]`);
  await context.close();
});
