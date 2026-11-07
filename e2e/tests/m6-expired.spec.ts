/**
 * Expired share and request links. Links are created with a 1 h expiry, then
 * moved into the past by editing `expires_at` in the worker's SQLite
 * database (no test backdoor exists in the server). Expected: the plain
 * "This link has expired." page (410, no script), API 410 `expired`, and a
 * download token issued before expiry stops working too.
 */

import { anonymousPage, createRequest, gotoFresh, expect, expectNoPageModule, linkId, makeFile, shareFile, sqlGet, sqlRun, test, type TestFile } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let file: TestFile;
let shareUrl = "";
let requestUrl = "";

test("owner creates a 1 h share link and a request link", async ({ alice, filesDir, dropr }) => {
  file = await makeFile(filesDir, "expiring.txt", 50_000);
  shareUrl = await shareFile(alice, file, { expiresIn: "1h" });
  await expect(alice.page.locator("#share-expiry")).toHaveText("Expires in 1 hour");
  requestUrl = await createRequest(alice);
  const row = sqlGet<{ left: number }>(dropr, "SELECT expires_at - unixepoch() AS left FROM shares WHERE id = ?", linkId(shareUrl));
  expect(row?.left).toBeGreaterThan(3500);
  expect(row?.left).toBeLessThanOrEqual(3600);
});

test("an expired share link shows the plain expired page and the API answers 410", async ({ browser, browserName, dropr, request }) => {
  const id = linkId(shareUrl);
  // A recipient who opened the page before expiry already holds a token.
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  await page.goto(shareUrl);
  await expect(page.locator("#download-button")).toBeEnabled();
  const tok = await request.post(`${dropr.origin}/api/s/${id}/download`, { headers: { origin: dropr.origin }, data: {} });
  expect(tok.status()).toBe(200);
  const { token } = (await tok.json()) as { token: string };

  expect(sqlRun(dropr, "UPDATE shares SET expires_at = unixepoch() - 5 WHERE id = ?", id)).toBe(1);

  // The open page: clicking Download now fails with a plain sentence.
  await page.locator("#download-button").click();
  await expect(page.locator("#download-error")).toBeVisible();
  await expect(page.locator("#download-error")).toContainText(/expired|does not exist|revoked/);

  // A fresh visit: server-rendered dead page without the script.
  const res = await gotoFresh(page, shareUrl);
  expect(res?.status()).toBe(410);
  await expect(page.locator("main")).toContainText("This link has expired.");
  await expectNoPageModule(page);
  await expect(page.locator("[data-share-id]")).toHaveCount(0);

  const api = await request.post(`${dropr.origin}/api/s/${id}/download`, { headers: { origin: dropr.origin }, data: {} });
  expect(api.status()).toBe(410);
  expect(await api.json()).toMatchObject({ error: "expired", message: "This link has expired." });

  // The token issued before expiry is dead too ("never past the share's expiry").
  const dl = await request.get(`${dropr.origin}/dl/${token}`);
  expect([404, 410]).toContain(dl.status());
  await context.close();

});

test("an expired request link shows the plain expired page and refuses uploads", async ({ browser, browserName, dropr, request, filesDir }) => {
  const id = linkId(requestUrl);
  const { context, page } = await anonymousPage(browser, `sender/${browserName}`);
  // Page opened while the link was alive...
  await page.goto(requestUrl);
  await expect(page.locator("#drop-zone")).toBeVisible();
  expect(sqlRun(dropr, "UPDATE requests SET expires_at = unixepoch() - 5 WHERE id = ?", id)).toBe(1);
  // ...then the upload is refused with the server's plain message.
  const f = await makeFile(filesDir, "late.txt", 1000);
  await page.locator("#file-input").setInputFiles(f.path);
  await expect(page.locator("#upload-error")).toContainText("This link has expired.");
  await expect(page.locator("#upload-done")).toBeHidden();

  const res = await gotoFresh(page, requestUrl);
  expect(res?.status()).toBe(410);
  await expect(page.locator("main")).toContainText("This link has expired.");
  await expectNoPageModule(page);

  const api = await request.post(`${dropr.origin}/api/r/${id}/files`, {
    headers: { origin: dropr.origin },
    data: { size: 1016, parts: 1, meta: "A".repeat(192), wrapped_key: "A".repeat(107) },
  });
  expect(api.status()).toBe(410);
  expect(((await api.json()) as { error: string }).error).toBe("expired");
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox WHERE request_id = ?", id)?.n).toBe(0);
  await context.close();
});
