/**
 * Revocation from the /links page: the recipient (or sender) then sees the
 * plain "does not exist or has been revoked" state, the API answers 404, an
 * already-issued download token stops working, and the blob directory is
 * removed from disk (PLAN.md §6, ARCHITECTURE.md §3 Link lifecycle).
 */

import {
  anonymousPage,
  blobDir,
  blobExists,
  createRequest,
  expect,
  gotoFresh,
  linkId,
  makeFile,
  sendViaRequest,
  shareFile,
  sqlAll,
  sqlGet,
  test,
} from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

const REVOKED = "This link does not exist or has been revoked.";

test("owner revokes a share link while a recipient has the page open", async ({ alice, browser, browserName, dropr, filesDir, request }) => {
  const file = await makeFile(filesDir, "to-revoke.bin", 300_000);
  const url = await shareFile(alice, file);
  const id = linkId(url);
  const blobId = sqlGet<{ blob_id: string }>(dropr, "SELECT blob_id FROM shares WHERE id = ?", id)!.blob_id;
  expect(blobExists(dropr, blobId)).toBe(true);

  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  await page.goto(url);
  await expect(page.locator("#file-name")).toHaveText(file.name);
  await expect(page.locator("#download-button")).toBeEnabled();
  const tok = await request.post(`${dropr.origin}/api/s/${id}/download`, { headers: { origin: dropr.origin }, data: {} });
  const { token } = (await tok.json()) as { token: string };

  // Revoke in the /links UI (confirm() accepted).
  const p = alice.page;
  await p.goto(dropr.origin + "/links");
  const row = p.locator(`tr[data-share-id="${id}"]`);
  await expect(row).toBeVisible();
  p.once("dialog", (d) => void d.accept());
  await row.getByRole("button", { name: /^Revoke/ }).click();
  await expect(p.locator("#links-status")).toHaveText("Share link revoked.");
  await expect(row).toHaveCount(0);

  // On disk and in the DB.
  expect(blobExists(dropr, blobId), blobDir(dropr, blobId)).toBe(false);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares WHERE id = ?", id)?.n).toBe(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM dl_tokens WHERE blob_id = ?", blobId)?.n).toBe(0);

  // The open page cannot download any more.
  await page.locator("#download-button").click();
  await expect(page.locator("#download-error")).toHaveText("This link does not exist or has been revoked by its owner.");
  expect((await request.get(`${dropr.origin}/dl/${token}`)).status()).toBe(404);

  const res = await gotoFresh(page, url);
  expect(res?.status()).toBe(404);
  await expect(page.locator("main")).toContainText(REVOKED);
  await expect(page.locator("script")).toHaveCount(0);
  const api = await request.post(`${dropr.origin}/api/s/${id}/download`, { headers: { origin: dropr.origin }, data: {} });
  expect(api.status()).toBe(404);
  await context.close();
});

test("owner revokes a request link: its received files are deleted with it", async ({ alice, browser, browserName, dropr, filesDir, request }) => {
  const link = await createRequest(alice);
  const id = linkId(link);
  const f = await makeFile(filesDir, "received.bin", 100_000);
  await sendViaRequest(browser, link, [f.path], `sender/${browserName}`);
  const blobs = sqlAll<{ blob_id: string }>(dropr, "SELECT blob_id FROM inbox WHERE request_id = ?", id).map((r) => r.blob_id);
  expect(blobs).toHaveLength(1);
  expect(blobExists(dropr, blobs[0]!)).toBe(true);

  // A sender has the page open when the link is revoked.
  const { context, page } = await anonymousPage(browser, `sender/${browserName}`);
  await page.goto(link);
  await expect(page.locator("#drop-zone")).toBeVisible();

  const p = alice.page;
  await p.goto(dropr.origin + "/links");
  const row = p.locator(`tr[data-request-id="${id}"]`);
  await expect(row).toContainText("1 of 10");
  p.once("dialog", (d) => void d.accept());
  await row.getByRole("button", { name: /^Revoke/ }).click();
  await expect(p.locator("#links-status")).toHaveText("Request link revoked.");

  expect(blobExists(dropr, blobs[0]!)).toBe(false);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox WHERE request_id = ?", id)?.n).toBe(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests WHERE id = ?", id)?.n).toBe(0);

  // The open uploader page now fails with a plain message.
  const g = await makeFile(filesDir, "too-late.bin", 1000);
  await page.locator("#file-input").setInputFiles(g.path);
  await expect(page.locator("#upload-error")).toBeVisible();
  await expect(page.locator("#upload-error")).toContainText(/does not exist|revoked/);
  await expect(page.locator("#upload-done")).toBeHidden();

  const res = await gotoFresh(page, link);
  expect(res?.status()).toBe(404);
  await expect(page.locator("main")).toContainText(REVOKED);
  await expect(page.locator("script")).toHaveCount(0);
  const api = await request.post(`${dropr.origin}/api/r/${id}/files`, {
    headers: { origin: dropr.origin },
    data: { size: 1016, parts: 1, meta: "A".repeat(80), wrapped_key: "A".repeat(107) },
  });
  expect(api.status()).toBe(404);

  // The inbox no longer lists the file.
  await p.goto(dropr.origin + "/");
  await expect(p.locator("a.tile[href=\"/inbox\"]")).toContainText("(0)");
  await context.close();
});

test("revoking a share while it is still uploading cancels the upload and removes its parts", async ({ alice, dropr, filesDir }) => {
  // Start a multi-part upload, hold part 1 back, revoke through the API, and
  // check nothing is left on disk.
  const big = await makeFile(filesDir, "half-uploaded.bin", 40 * 1024 * 1024);
  const p = alice.page;
  await p.goto(dropr.origin + "/");
  let release: () => void = () => undefined;
  const held = new Promise<void>((ok) => (release = ok));
  await p.route(/\/upload\/[^/]+\/part\/1$/, async (route) => {
    await held;
    await route.abort("connectionreset");
  });
  const created = p.waitForResponse((r) => r.url().endsWith("/api/shares") && r.request().method() === "POST");
  await p.locator("#file-input").setInputFiles(big.path);
  const { share_id, upload_id } = (await (await created).json()) as { share_id: string; upload_id: string };
  await p.waitForResponse((r) => /\/upload\/[^/]+\/part\/0$/.test(r.url()) && r.status() === 204, { timeout: 60_000 });
  expect(blobExists(dropr, upload_id)).toBe(true);
  await p.locator("#upload-cancel").click(); // the page deletes the unfinished share (DELETE /api/shares/{id})
  release();
  await expect.poll(() => sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares WHERE id = ?", share_id)?.n).toBe(0);
  await expect.poll(() => blobExists(dropr, upload_id)).toBe(false);
  await p.unroute(/\/upload\/[^/]+\/part\/1$/);
});
