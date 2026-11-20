/**
 * Several files in one share: the dashboard lists the selection (archive
 * names, sizes, remove buttons, duplicates skipped), builds one stored ZIP
 * in the browser and shares it like a single file. The server sees one
 * share and one blob; the recipient downloads one archive whose members
 * match the originals byte for byte.
 */

import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { MiB, anonymousPage, expect, linkId, makeFile, sqlGet, test, type TestFile } from "../m6.ts";
import { readStoredZip } from "../zip.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let notesA: TestFile;
let notesB: TestFile;
let report: TestFile;
let url = "";
let archiveName = "";

test("owner picks several files, edits the list and shares them as one archive", async ({ alice, filesDir, dropr, browserName }) => {
  test.skip(browserName !== "chromium", "owner-only (owner pages run in Chromium)");
  mkdirSync(join(filesDir, "a"), { recursive: true });
  mkdirSync(join(filesDir, "b"), { recursive: true });
  notesA = await makeFile(join(filesDir, "a"), "notes.txt", 4_321);
  notesB = await makeFile(join(filesDir, "b"), "notes.txt", 1_234);
  // Over one 32 MiB part, so the upload slices across headers and file data.
  report = await makeFile(filesDir, "Rapport été.bin", 40 * MiB);

  const p = alice.page;
  await p.goto(dropr.origin + "/");
  const rows = p.locator("#share-files li");
  const live = p.locator("#share-selection-status");
  await expect(p.locator("#share-selection")).toBeHidden();

  await p.locator("#file-input").setInputFiles([notesA.path, notesB.path, report.path]);
  await expect(rows).toHaveCount(3);
  await expect(p.locator("#share-files .file-row-name")).toHaveText(["notes.txt", "notes (2).txt", "Rapport été.bin"]);
  await expect(p.locator("#share-submit")).toHaveText("Share 3 files");
  await expect(p.locator("#share-summary")).toHaveText(/^3 files, .+ of .+\. They will be sent as one ZIP archive, files-\d{4}-\d{2}-\d{2}\.zip\.$/);
  await expect(live).toHaveText("3 files added. 3 files to share.");
  await expect(p.locator("#share-clear")).toBeVisible();
  // Nothing reaches the server before Share.
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares")?.n).toBe(0);

  // Removing keeps the keyboard in the list, on the next row.
  await p.getByRole("button", { name: "Remove notes (2).txt" }).click();
  await expect(rows).toHaveCount(2);
  await expect(p.getByRole("button", { name: "Remove Rapport été.bin" })).toBeFocused();
  await expect(live).toHaveText("notes (2).txt removed. 2 files to share.");

  // Picking again adds only what is new.
  await p.locator("#file-input").setInputFiles([notesA.path, notesB.path]);
  await expect(rows).toHaveCount(3);
  await expect(live).toHaveText("1 file added, 1 already in the list. 3 files to share.");

  const summary = (await p.locator("#share-summary").textContent()) ?? "";
  archiveName = /archive, (.+\.zip)\.$/.exec(summary)?.[1] ?? "";
  expect(archiveName).toMatch(/^files-\d{4}-\d{2}-\d{2}\.zip$/);

  await p.locator("#share-submit").click();
  await expect(p.locator("#share-result")).toBeVisible({ timeout: 120_000 });
  await expect(p.locator("#share-link")).toBeFocused();
  url = await p.locator("#share-link").inputValue();
  // The list is emptied for the next share.
  await expect(p.locator("#share-selection")).toBeHidden();

  // One share, one blob: the server never learns how many files there were.
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM shares")?.n).toBe(1);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM blobs WHERE complete = 1")?.n).toBe(1);
  expect(sqlGet<{ id: string }>(dropr, "SELECT id FROM shares")?.id).toBe(linkId(url));
});

test("the recipient downloads one archive holding every file intact", async ({ browser, browserName }) => {
  expect(url).not.toBe("");
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  await page.goto(url);
  await expect(page.locator("#file-name")).toHaveText(archiveName);
  const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 120_000 }), page.locator("#download-button").click()]);
  expect(await dl.failure()).toBeNull();
  expect(dl.suggestedFilename()).toBe(archiveName);
  const members = readStoredZip(readFileSync(await dl.path()));
  expect(members).toEqual([
    { name: "notes.txt", size: notesA.size, sha256: notesA.sha256 },
    { name: "Rapport été.bin", size: report.size, sha256: report.sha256 },
    { name: "notes (2).txt", size: notesB.size, sha256: notesB.sha256 },
  ]);
  await context.close();
});
