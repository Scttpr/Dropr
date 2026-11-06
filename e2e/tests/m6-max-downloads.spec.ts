/**
 * max_downloads = 1. The first recipient's download is cut mid-stream once
 * (the first /dl response is replaced by a truncated body), so the browser
 * module resumes with `Range` on the same token, which must not count again;
 * the file arrives intact. A second recipient then sees "reached its
 * download limit" (dead page 410, API 410 `exhausted`), including one who
 * fetched a token before the limit was reached.
 */

import { anonymousPage, downloadVia, expect, gotoFresh, linkId, makeFile, shareFile, sqlGet, test, type TestFile } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let file: TestFile;
let url = "";

test("owner shares a file with a download limit of 1", async ({ alice, filesDir, dropr }) => {
  // > 1 part so the resume crosses a part boundary on the server side.
  file = await makeFile(filesDir, "once-only.bin", 34 * 1024 * 1024);
  url = await shareFile(alice, file, { maxDownloads: 1 });
  const row = sqlGet<{ max_downloads: number; download_count: number }>(dropr, "SELECT max_downloads, download_count FROM shares WHERE id = ?", linkId(url));
  expect(row).toEqual({ max_downloads: 1, download_count: 0 });
});

test("the only download survives a connection drop and resumes on the same token", async ({ browser, browserName, dropr }) => {
  const id = linkId(url);
  // Recipient B opens the page first and holds a token (issuing does not count).
  const b = await anonymousPage(browser, `late/${browserName}`);
  await b.page.goto(url);
  await expect(b.page.locator("#download-button")).toBeEnabled();

  const a = await anonymousPage(browser, `first/${browserName}`);
  const ranges: (string | null)[] = [];
  let cut = false;
  await a.page.route(
    (u) => u.pathname.startsWith("/dl/"),
    async (route) => {
      ranges.push(await route.request().headerValue("range"));
      if (cut) return route.continue();
      cut = true;
      // Fetch the real response (the server counts this first GET), deliver
      // only 1.5 segments of it: the stream ends early, mid-segment.
      const res = await route.fetch();
      const body = await res.body();
      const headers = { ...res.headers() };
      delete headers["content-length"];
      await route.fulfill({ status: res.status(), headers, body: body.subarray(0, 65552 + 30000) });
    },
  );
  const statuses: number[] = [];
  a.page.on("response", (r) => {
    if (new URL(r.url()).pathname.startsWith("/dl/")) statuses.push(r.status());
  });
  await a.page.goto(url);
  const got = await downloadVia(a.page, a.page.locator("#download-button"));
  expect(got.sha256).toBe(file.sha256);
  expect(got.name).toBe(file.name);
  await expect(a.page.locator("#download-status")).toHaveText(/^Download complete/, { timeout: 60_000 });
  expect(cut).toBe(true);
  // First request had no Range (200, cut short), the resume was a 206 for the
  // bytes after the last segment already released (at most the first one).
  expect(ranges[0]).toBeNull();
  expect(statuses[0]).toBe(200);
  expect(ranges.length).toBeGreaterThanOrEqual(2);
  // WebKit's interception neither exposes the Range header of fetch() nor
  // reports responses of continued requests; the intact hash proves the resume.
  if (browserName !== "webkit") {
    expect(statuses.slice(1)).toContain(206);
    expect(ranges.slice(1)).toEqual(expect.arrayContaining([expect.stringMatching(/^bytes=(0|65552)-$/)]));
  }
  expect(sqlGet<{ c: number }>(dropr, "SELECT download_count AS c FROM shares WHERE id = ?", id)?.c).toBe(1);
  await a.context.close();

  // B's token was issued before the limit was reached: refused now.
  await b.page.locator("#download-button").click();
  await expect(b.page.locator("#download-error")).toHaveText("This link has reached its download limit.");
  await b.context.close();
});

test("a second recipient sees that the download limit was reached", async ({ browser, browserName, dropr, request }) => {
  const { context, page } = await anonymousPage(browser, `second/${browserName}`);
  const res = await gotoFresh(page, url);
  expect(res?.status()).toBe(410);
  await expect(page.locator("main")).toContainText("This link has reached its download limit.");
  await expect(page.locator("script")).toHaveCount(0);
  const api = await request.post(`${dropr.origin}/api/s/${linkId(url)}/download`, { headers: { origin: dropr.origin }, data: {} });
  expect(api.status()).toBe(410);
  expect(((await api.json()) as { error: string }).error).toBe("exhausted");
  await context.close();
});
