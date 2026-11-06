/**
 * Upload resume. An anonymous sender (project browser) uploads a 3-part file
 * through a request link while every PUT of part 1 is aborted at the network
 * level. Parts 0 and 2 complete; part 1 exhausts its retries and the page
 * offers Retry ("The connection was lost…"). After the network "comes back"
 * (route removed) Retry resumes: the module asks GET /upload/{id} which
 * parts exist and sends only part 1. The owner then downloads the file from
 * the inbox and its SHA-256 equals the original. A one-off abort is also
 * retried transparently on the owner's share flow.
 *
 * Not covered: a connection cut *after* the server received part of a body
 * (Playwright can only abort before the request is sent); the Go tests cover
 * short bodies storing nothing (ARCHITECTURE.md §3 Uploads).
 */

import { MiB, anonymousPage, createRequest, downloadVia, expect, makeFile, shareFile, test, type TestFile } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let link = "";
let file: TestFile;

test("owner creates a request link", async ({ alice, filesDir }) => {
  link = await createRequest(alice);
  file = await makeFile(filesDir, "resumed.bin", 70 * MiB); // 3 parts
});

test("an upload interrupted on one part resumes with Retry and sends only the missing part", async ({ browser, browserName }) => {
  test.setTimeout(5 * 60_000);
  const { context, page } = await anonymousPage(browser, `sender/${browserName}`);
  const okParts: number[] = [];
  let aborted = 0;
  page.on("response", (r) => {
    const m = /\/upload\/[^/]+\/part\/(\d+)$/.exec(new URL(r.url()).pathname);
    if (m !== null && r.status() === 204) okParts.push(Number(m[1]));
  });
  const part1 = (u: URL): boolean => /\/upload\/[^/]+\/part\/1$/.test(u.pathname);
  await page.route(part1, async (route) => {
    aborted++;
    await route.abort("connectionreset");
  });
  await page.goto(link);
  await page.locator("#file-input").setInputFiles(file.path);
  const retry = page.locator("#upload-retry");
  // 1 attempt + 5 retries with exponential backoff.
  await expect(retry).toBeVisible({ timeout: 150_000 });
  await expect(retry).toBeFocused();
  await expect(page.locator("#upload-status")).toContainText("The connection was lost");
  expect(aborted).toBeGreaterThanOrEqual(6);
  expect([...okParts].sort()).toEqual([0, 2]);

  await page.unroute(part1);
  const status = page.waitForResponse((r) => /\/upload\/[^/]+$/.test(new URL(r.url()).pathname) && r.request().method() === "GET");
  await retry.click();
  expect((await (await status).json()) as unknown).toEqual({ parts_present: [0, 2], complete: false });
  await expect(page.locator("#upload-done")).toBeVisible({ timeout: 120_000 });
  // Parts 0 and 2 were never sent again.
  expect([...okParts].sort()).toEqual([0, 1, 2]);
  await context.close();
});

test("the owner downloads the resumed file intact", async ({ alice, dropr }) => {
  const p = alice.page;
  await p.goto(dropr.origin + "/inbox");
  await p.locator("#inbox-unlock").click();
  const row = p.locator("#inbox-list tr").filter({ has: p.locator("td.name", { hasText: file.name }) });
  await expect(row).toHaveCount(1);
  await p.evaluate(() => Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }));
  const got = await downloadVia(p, row.getByRole("button", { name: /^Download/ }));
  expect(got.sha256).toBe(file.sha256);
});

test("a single dropped part on the share flow is retried transparently", async ({ alice, filesDir, browserName, browser }) => {
  test.skip(browserName !== "chromium", "owner flow");
  const f = await makeFile(filesDir, "retried-share.bin", 40 * MiB);
  let dropped = false;
  await alice.page.route(/\/upload\/[^/]+\/part\/0$/, async (route) => {
    if (dropped) return route.continue();
    dropped = true;
    await route.abort("connectionreset");
  });
  const url = await shareFile(alice, f);
  await alice.page.unroute(/\/upload\/[^/]+\/part\/0$/);
  expect(dropped).toBe(true);
  const { context, page } = await anonymousPage(browser, "recipient");
  await page.goto(url);
  const got = await downloadVia(page, page.locator("#download-button"));
  expect(got.sha256).toBe(f.sha256);
  await context.close();
});
