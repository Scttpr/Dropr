/**
 * Request link with a tampered public key in the fragment.
 *
 * Expected behaviour (documented, by design): the uploader cannot detect
 * the substitution — any 32-byte X25519 key is a valid HPKE recipient, and
 * the server never vouches for the key (ARCHITECTURE.md §2: the owner's key
 * comes from the link, the server does not hold an authenticated copy for
 * uploaders). The upload succeeds, but the file key is sealed to the wrong
 * key, so the owner cannot open it: the inbox must show that one entry as
 * "Unreadable file" (Delete only) while the other entries still decrypt and
 * download, and the page must not crash. A malformed fragment is refused on
 * the uploader page.
 */

import { createRequest, expect, gotoFresh, linkId, makeFile, sendViaRequest, sqlGet, test, type TestFile, anonymousPage, downloadVia } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

let link = "";
let good: TestFile;
let bad: TestFile;

test("owner creates a request link", async ({ alice, filesDir }) => {
  link = await createRequest(alice);
  good = await makeFile(filesDir, "good.txt", 5000);
  bad = await makeFile(filesDir, "sent-to-wrong-key.txt", 6000);
});

test("an uploader with a substituted key cannot tell; a malformed key is refused", async ({ browser, browserName, dropr, filesDir }) => {
  const other = Buffer.alloc(32, 0x42).toString("base64url");
  const tampered = link.replace(/#.*/, "#" + other);
  await sendViaRequest(browser, link, [good.path], `sender-ok/${browserName}`);
  await sendViaRequest(browser, tampered, [bad.path], `sender-tampered/${browserName}`);
  expect(sqlGet<{ n: number }>(dropr, "SELECT count(*) AS n FROM inbox WHERE request_id = ?", linkId(link))?.n).toBe(2);

  const { context, page } = await anonymousPage(browser, `sender-bad/${browserName}`);
  for (const frag of ["#short", "#" + Buffer.alloc(33, 1).toString("base64url"), ""]) {
    await gotoFresh(page, link.replace(/#.*/, frag));
    await expect(page.locator("#upload-error")).toHaveText("This link is incomplete or damaged. Ask the person who sent it for the complete link.");
    await expect(page.locator("#drop-zone")).toBeHidden();
  }
  void filesDir;
  await context.close();
});

test("the owner sees the substituted-key file as unreadable, the other one still works", async ({ alice, dropr }) => {
  const p = alice.page;
  const errors: string[] = [];
  p.on("pageerror", (e) => errors.push(e.message));
  await p.goto(dropr.origin + "/inbox");
  await p.locator("#inbox-unlock").click();
  const rows = p.locator("#inbox-list tr");
  await expect(rows).toHaveCount(2);
  const unreadable = p.locator("#inbox-list td.name.unreadable");
  await expect(unreadable).toHaveCount(1);
  await expect(unreadable).toHaveText("Unreadable file");
  const badRow = rows.filter({ has: p.locator("td.name.unreadable") });
  await expect(badRow.getByRole("button", { name: /^Download/ })).toHaveCount(0);
  await expect(badRow.getByRole("button", { name: /^Delete/ })).toHaveCount(1);

  const goodRow = rows.filter({ has: p.locator("td.name", { hasText: good.name }) });
  await p.evaluate(() => Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }));
  const got = await downloadVia(p, goodRow.getByRole("button", { name: /^Download/ }));
  expect(got.sha256).toBe(good.sha256);

  // The unreadable entry can be deleted.
  p.once("dialog", (d) => void d.accept());
  await badRow.getByRole("button", { name: /^Delete/ }).click();
  await expect(rows).toHaveCount(1);
  expect(errors).toEqual([]);
});
