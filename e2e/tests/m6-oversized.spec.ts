/**
 * Oversized files, against a server started with max_file_size = 1 MiB:
 * the dashboard and the request page refuse with a clear message before any
 * upload starts (no POST, no PUT), and the API refuses a declared size above
 * the instance limit or above a request link's max_bytes (413 / 409) even if
 * the browser checks are bypassed.
 */

import type { Request } from "@playwright/test";
import { MiB, anonymousPage, createRequest, expect, linkId, makeFile, pageFetch, sqlGet, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: { maxFileSize: "1MB" } });

/** Plaintext → ciphertext size (FORMAT.md §4.3). */
function cipherSize(p: number): number {
  return p + 16 * Math.max(1, Math.ceil(p / 65536));
}

function watchUploads(page: import("@playwright/test").Page): Request[] {
  const seen: Request[] = [];
  page.on("request", (r) => {
    const path = new URL(r.url()).pathname;
    if (r.method() !== "GET" && (path === "/api/shares" || path.startsWith("/api/r/") || path.startsWith("/upload/"))) seen.push(r);
  });
  return seen;
}

let requestLink = "";
let pending: { upload_id: string; upload_token: string } | null = null;

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

test("the share API refuses a declared size over the limit", async ({ alice, browserName }) => {
  test.skip(browserName !== "chromium", "owner-only");
  const over = cipherSize(MiB + 1);
  const r = await pageFetch(alice.page, "/api/shares", { method: "POST", body: { size: over, parts: 1, meta: "A".repeat(80) } });
  expect(r.status).toBe(413);
  expect(r.json).toMatchObject({ error: "too_large" });
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

test("the request API refuses sizes over the instance limit or the link's max_bytes", async ({ request, dropr }) => {
  const id = linkId(requestLink);
  const post = (size: number) =>
    request.post(`${dropr.origin}/api/r/${id}/files`, {
      headers: { origin: dropr.origin },
      data: { size, parts: 1, meta: "A".repeat(80), wrapped_key: "A".repeat(107) },
    });
  const over = await post(cipherSize(MiB + 1));
  expect(over.status()).toBe(413);
  expect(((await over.json()) as { error: string }).error).toBe("too_large");
  // A huge declared size (100 GiB geometry) is refused before anything is reserved.
  const huge = await post(cipherSize(100 * 1024 * MiB));
  expect([400, 413]).toContain(huge.status());
  // max_bytes = one maximal file: a first file of 600 KiB fits, a second one
  // of 600 KiB exceeds the link's byte budget (409 link_full).
  const first = await post(cipherSize(600 * 1024));
  expect(first.status(), await first.text()).toBe(201);
  pending = (await first.json()) as { upload_id: string; upload_token: string };
  const second = await post(cipherSize(600 * 1024));
  expect(second.status()).toBe(409);
  expect(((await second.json()) as { error: string }).error).toBe("link_full");
  const row = sqlGet<{ files_received: number; bytes_received: number }>(dropr, "SELECT files_received, bytes_received FROM requests WHERE id = ?", id);
  expect(row).toEqual({ files_received: 1, bytes_received: cipherSize(600 * 1024) });
});

test("a part body of the wrong size is refused and stores nothing", async ({ request, dropr }) => {
  expect(pending).not.toBeNull();
  const { upload_id, upload_token } = pending!;
  const put = (n: number) =>
    request.put(`${dropr.origin}/upload/${upload_id}/part/0`, {
      headers: { origin: dropr.origin, authorization: `Bearer ${upload_token}` },
      data: Buffer.alloc(n),
    });
  const declared = cipherSize(600 * 1024);
  for (const n of [declared + 1, declared - 1, 34 * 1024 * 1024]) {
    const r = await put(n);
    expect([400, 413], `part of ${n} bytes`).toContain(r.status());
  }
  const st = await request.get(`${dropr.origin}/upload/${upload_id}`, { headers: { authorization: `Bearer ${upload_token}` } });
  expect(await st.json()).toEqual({ parts_present: [], complete: false });
});
