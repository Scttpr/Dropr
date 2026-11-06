/**
 * Oversized files, against a server started with max_file_size = 1 MiB:
 * the dashboard and the request page refuse with a clear message before any
 * upload starts (no POST, no PUT). The API-side refusals (413 / 409, wrong
 * part sizes) are covered by the Go tests (internal/server/files_test.go).
 */

import type { Request } from "@playwright/test";
import { MiB, anonymousPage, createRequest, expect, makeFile, sqlGet, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: { maxFileSize: "1MB" } });


function watchUploads(page: import("@playwright/test").Page): Request[] {
  const seen: Request[] = [];
  page.on("request", (r) => {
    const path = new URL(r.url()).pathname;
    if (r.method() !== "GET" && (path === "/api/shares" || path.startsWith("/api/r/") || path.startsWith("/upload/"))) seen.push(r);
  });
  return seen;
}

let requestLink = "";

test("the dashboard refuses a file over the instance limit before uploading", async ({ alice, filesDir, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "owner-only (owner pages run in Chromium)");
  const p = alice.page;
  const big = await makeFile(filesDir, "too-big.bin", MiB + 1);
  await p.goto(dropr.origin + "/");
  await expect(p.locator("main")).toHaveAttribute("data-max-file-size", String(MiB));
  const seen = watchUploads(p);
  await p.locator("#file-input").setInputFiles(big.path);
  await expect(p.locator("#share-error")).toBeVisible();
  await expect(p.locator("#share-error")).toHaveText(/^This file is too large \(.+\)\. The limit is 1(\.0+)? MB\.$/);
  await expect(p.locator("#share-error")).toBeFocused();
  await expect(p.locator("#upload-panel")).toBeHidden();
  expect(seen).toHaveLength(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM blobs")?.n).toBe(0);

  // Exactly at the limit is accepted.
  const exact = await makeFile(filesDir, "exact.bin", MiB);
  await p.locator("#file-input").setInputFiles(exact.path);
  await expect(p.locator("#share-result")).toBeVisible({ timeout: 60_000 });
});


test("owner creates a request link", async ({ alice }) => {
  requestLink = await createRequest(alice, 5);
});

test("the request page refuses too-large files before uploading", async ({ browser, browserName, filesDir, dropr }) => {
  const { context, page } = await anonymousPage(browser, `sender/${browserName}`);
  await page.goto(requestLink);
  await expect(page.locator("main")).toHaveAttribute("data-max-bytes", String(MiB));
  const seen = watchUploads(page);
  const big = await makeFile(filesDir, "sender-too-big.bin", MiB + 1);
  await page.locator("#file-input").setInputFiles(big.path);
  await expect(page.locator("#upload-error")).toHaveText(/^These files are too large \(.+\)\. This link accepts up to 1(\.0+)? MB more\.$/);
  // Two files that fit one by one but not together.
  const a = await makeFile(filesDir, "half-a.bin", 600 * 1024);
  const b = await makeFile(filesDir, "half-b.bin", 600 * 1024);
  await page.locator("#file-input").setInputFiles([a.path, b.path]);
  await expect(page.locator("#upload-error")).toContainText("These files are too large");
  await expect(page.locator("#upload-panel")).toBeHidden();
  expect(seen).toHaveLength(0);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox")?.n).toBe(0);
  await context.close();
});
