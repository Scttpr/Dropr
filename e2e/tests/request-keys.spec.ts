/**
 * Request link keys live in the browser that created the link
 * (ARCHITECTURE.md §2 "Request link key pair", §3 "Request link keys";
 * docs/PAGES.md §3, §4).
 *
 * - A second browser context signed in as the same user (another browser
 *   profile: own IndexedDB) sees the received file as `foreign` (no name, no
 *   Download, Delete works) and the request link as "Other browser" (no
 *   Copy link), while the creating context still has Copy link.
 * - Revoking a link deletes its IndexedDB record; a link revoked from another
 *   browser has its record pruned the next time the list loads (once older
 *   than the 60 s grace period).
 * - Records are scoped to the account (`ownerId` = `data-owner-id`): another
 *   account's record in the same browser profile survives /links and /inbox.
 * - The stored private key is a non-extractable X25519 CryptoKey: exportKey
 *   rejects in every format, and its public half matches the link fragment.
 *
 * Owner pages run in Chromium (fixtures.ts `ownerBrowser`), so the whole file
 * runs in the Chromium project only.
 */

import { randomBytes } from "node:crypto";
import {
  type Owner,
  type TestFile,
  createRequest,
  expect,
  injectRequestKey,
  M6_USERS,
  makeFile,
  newOwner,
  requestIdOf,
  requestKeyIds,
  sendViaRequest,
  setRequestKeyCreatedAt,
  sqlGet,
  test,
} from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });
test.skip(({ browserName }) => browserName !== "chromium", "owner pages run in Chromium");

const FOREIGN_NAME = "Sent through a link created in another browser";

let link = "";
let id = "";
let file: TestFile;
let other: Owner | undefined;

test.afterAll(async () => {
  await other?.context.close();
});

test("alice creates a request link and receives a file through it", async ({ alice, browser, filesDir }) => {
  link = await createRequest(alice);
  id = requestIdOf(link);
  expect(await requestKeyIds(alice.page)).toContain(id);
  file = await makeFile(filesDir, "only-in-the-first-browser.txt", 4096);
  await sendViaRequest(browser, link, [file.path], "sender");
});

test("another browser signed in as the same user sees the file as foreign and the link as 'Other browser'", async ({ alice, browser, dropr }) => {
  other = await newOwner(browser, dropr, "alice-other-browser");
  await other.login(M6_USERS.alice);
  const q = other.page;
  expect(await requestKeyIds(q)).toEqual([]);

  // Inbox: listed (size, date, Delete) but unreadable here.
  await q.goto(dropr.origin + "/inbox");
  await expect(q.locator("#inbox-device-note")).toBeVisible();
  const rows = q.locator("#inbox-list tr");
  await expect(rows).toHaveCount(1);
  const row = rows.first();
  await expect(row).toHaveClass(/(^|\s)foreign(\s|$)/);
  await expect(row.locator("td.name")).toHaveText(FOREIGN_NAME);
  await expect(row).not.toContainText(file.name);
  await expect(row.locator("td.size")).not.toBeEmpty();
  await expect(row.locator("td.date time")).toHaveCount(1);
  await expect(row.getByRole("button", { name: /^Download/ })).toHaveCount(0);
  await expect(row.getByRole("button", { name: /^Delete/ })).toHaveCount(1);

  // Links: no Copy link (the fragment exists only in the first browser).
  await q.goto(dropr.origin + "/links");
  await expect(q.locator("#requests-note")).toHaveText("A request link can be copied, and its files opened, only in the browser that created it.");
  const linkRow = q.locator(`tr[data-request-id="${id}"]`);
  await expect(linkRow).toHaveCount(1);
  await expect(linkRow.locator("span.muted", { hasText: "Other browser" })).toHaveCount(1);
  await expect(linkRow.getByRole("button", { name: /^Copy link/ })).toHaveCount(0);
  await expect(linkRow.getByRole("button", { name: /^Revoke/ })).toHaveCount(1);

  // The creating browser still has both.
  const p = alice.page;
  await p.goto(dropr.origin + "/links");
  const own = p.locator(`tr[data-request-id="${id}"]`);
  await expect(own.getByRole("button", { name: /^Copy link/ })).toHaveCount(1);
  await expect(own.getByText("Other browser")).toHaveCount(0);
  await p.goto(dropr.origin + "/inbox");
  const ownRow = p.locator("#inbox-list tr");
  await expect(ownRow).toHaveCount(1);
  await expect(ownRow.first()).not.toHaveClass(/(^|\s)foreign(\s|$)/);
  await expect(ownRow.locator("td.name")).toHaveText(file.name);
  await expect(ownRow.getByRole("button", { name: /^Download/ })).toHaveCount(1);
});

test("the foreign entry can be deleted from the other browser", async ({ dropr }) => {
  const q = other!.page;
  await q.goto(dropr.origin + "/inbox");
  const rows = q.locator("#inbox-list tr");
  await expect(rows).toHaveCount(1);
  q.once("dialog", (d) => void d.accept());
  await rows.first().getByRole("button", { name: /^Delete/ }).click();
  await expect(rows).toHaveCount(0);
  await expect(q.locator("#inbox-empty")).toBeVisible();
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox WHERE request_id = ?", id)?.n).toBe(0);
  // Deleting a file keeps the link and its key in the first browser.
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests WHERE id = ?", id)?.n).toBe(1);
});

test("the stored private key is a non-extractable X25519 key matching the link", async ({ alice, dropr }) => {
  const p = alice.page;
  await p.goto(dropr.origin + "/");
  const r = await p.evaluate(async (id) => {
    const db = await new Promise<IDBDatabase>((ok, fail) => {
      const req = indexedDB.open("dropr");
      req.onsuccess = () => ok(req.result);
      req.onerror = () => fail(req.error);
    });
    const rec = await new Promise<{ id: string; privateKey: CryptoKey; publicKey: Uint8Array; createdAt: number } | undefined>((ok, fail) => {
      const req = db.transaction("request-keys").objectStore("request-keys").get(id);
      req.onsuccess = () => ok(req.result as never);
      req.onerror = () => fail(req.error);
    });
    db.close();
    if (rec === undefined) return null;
    const k = rec.privateKey;
    const rejected: Record<string, boolean> = {};
    for (const format of ["pkcs8", "jwk", "raw"] as const) {
      try {
        await crypto.subtle.exportKey(format as "pkcs8", k);
        rejected[format] = false;
      } catch {
        rejected[format] = true;
      }
    }
    let b64 = btoa(String.fromCharCode(...rec.publicKey));
    b64 = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return {
      ownerId: (rec as { ownerId?: unknown }).ownerId,
      isCryptoKey: k instanceof CryptoKey,
      type: k.type,
      algorithm: k.algorithm.name,
      extractable: k.extractable,
      usages: [...k.usages],
      rejected,
      publicKey: b64,
      createdAt: rec.createdAt,
    };
  }, id);
  expect(r).not.toBeNull();
  // The record belongs to the signed-in account (data-owner-id on <main>).
  const ownerId = await p.locator("main").getAttribute("data-owner-id");
  expect(ownerId).toBeTruthy();
  expect(r!.ownerId).toBe(ownerId);
  expect(r!.isCryptoKey).toBe(true);
  expect(r!.type).toBe("private");
  expect(r!.algorithm).toBe("X25519");
  expect(r!.extractable).toBe(false);
  expect(r!.usages).toEqual(["deriveBits"]);
  expect(r!.rejected).toEqual({ pkcs8: true, jwk: true, raw: true });
  expect(link.endsWith("#" + r!.publicKey)).toBe(true);
  expect(Math.abs(r!.createdAt - Date.now() / 1000)).toBeLessThan(3600);
});

test("revoking a link deletes its key; a link revoked elsewhere is pruned", async ({ alice, dropr }) => {
  const p = alice.page;

  // Revoke from the creating browser: the record goes with the link.
  await p.goto(dropr.origin + "/links");
  const row = p.locator(`tr[data-request-id="${id}"]`);
  p.once("dialog", (d) => void d.accept());
  await row.getByRole("button", { name: /^Revoke/ }).click();
  await expect(p.locator("#links-status")).toHaveText("Request link revoked.");
  await expect(row).toHaveCount(0);
  await expect.poll(() => requestKeyIds(p)).not.toContain(id);

  // A second link, revoked from the other browser: the first browser keeps
  // the key until its list no longer contains the link, then prunes it.
  const link2 = await createRequest(alice);
  const id2 = requestIdOf(link2);
  expect(await requestKeyIds(p)).toContain(id2);
  const q = other!.page;
  await q.goto(dropr.origin + "/links");
  const otherRow = q.locator(`tr[data-request-id="${id2}"]`);
  await expect(otherRow.getByText("Other browser")).toHaveCount(1);
  q.once("dialog", (d) => void d.accept());
  await otherRow.getByRole("button", { name: /^Revoke/ }).click();
  await expect(q.locator("#links-status")).toHaveText("Request link revoked.");
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM requests WHERE id = ?", id2)?.n).toBe(0);
  expect(await requestKeyIds(p)).toContain(id2);
  // Records younger than 60 s are never pruned (another tab may have just
  // stored them); age this one, then load the list again.
  await setRequestKeyCreatedAt(p, id2, Math.floor(Date.now() / 1000) - 120);
  await p.goto(dropr.origin + "/links");
  await expect(p.locator("#requests-empty")).toBeVisible();
  await expect.poll(() => requestKeyIds(p)).not.toContain(id2);
});

test("another account's record in the same browser profile is never pruned", async ({ alice, dropr }) => {
  const p = alice.page;
  await p.goto(dropr.origin + "/links");
  const ownerId = await p.locator("main").getAttribute("data-owner-id");
  expect(ownerId).toBeTruthy();
  // Old enough to be pruned, and not in alice's list: only the owner scope keeps it.
  const foreignId = randomBytes(16).toString("base64url");
  await injectRequestKey(p, { id: foreignId, ownerId: "not-" + ownerId, createdAt: Math.floor(Date.now() / 1000) - 3600 });
  expect(await requestKeyIds(p)).toContain(foreignId);

  await p.goto(dropr.origin + "/links");
  await expect(p.locator("#requests-empty")).toBeVisible();
  await expect(p.locator(`tr[data-request-id="${foreignId}"]`)).toHaveCount(0);
  await p.goto(dropr.origin + "/inbox");
  await expect(p.locator("#inbox-empty")).toBeVisible();
  await p.goto(dropr.origin + "/links");
  await expect(p.locator("#requests-empty")).toBeVisible();
  // Prune runs after the list renders: give it time to (wrongly) delete.
  await p.waitForTimeout(1_000);
  expect(await requestKeyIds(p)).toContain(foreignId);
});
