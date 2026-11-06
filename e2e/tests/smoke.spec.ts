/**
 * End-to-end smoke test: sign in through Keycloak, register two passkeys,
 * share files (single- and multi-part) and download them anonymously, then
 * create a request link, upload anonymously and decrypt in the owner's inbox.
 * Every transferred file is compared by SHA-256 with the original.
 *
 * The owner always runs in Chromium (virtual authenticators are CDP-only);
 * the anonymous recipient runs in the project's browser.
 */

import { type TestFile, USERS, anonymousPage, downloadVia, expect, makeFile, test } from "../fixtures.ts";

const MiB = 1024 * 1024;

test.describe.configure({ mode: "serial" });

let small: TestFile;
let large: TestFile;
const shareLinks = new Map<string, string>();

test("owner signs in and registers two passkeys", async ({ owner, filesDir }) => {
  small = await makeFile(filesDir, "Rapport été 2026 (final).txt", 12_345);
  large = await makeFile(filesDir, "big-archive.bin", 70 * MiB); // 3 upload parts

  const p = owner.page;
  // The first authenticator exists before /setup loads, so the page detects
  // that this device can hold a passkey and recommends it.
  const first = await owner.addAuthenticator();
  await owner.login(USERS.alice);
  await expect(p.locator("main")).toHaveAttribute("data-passkey-count", "0");

  const register = p.locator("#setup-register");
  await expect(register).toBeVisible();
  await expect(register).toHaveText("Create my first passkey");
  await expect(p.locator("#setup-step-title")).toHaveText("Step 1 of 2: your first passkey");
  await expect(p.locator("#setup-where-device")).toBeChecked();
  await expect(p.locator("#setup-choice-device .choice-badge")).toBeVisible();
  await register.click();
  // One prompt only when create() returns the PRF output; otherwise a
  // confirming get() runs on the same (virtual) authenticator.
  await expect(p.locator("#setup-done")).toBeFocused();
  await expect(p.locator("#setup-done-title")).toHaveText("Your first passkey is ready.");
  await expect(register).toHaveText("Create my spare passkey");
  await expect(p.locator("#setup-step-title")).toHaveText("Step 2 of 2: your spare passkey");
  await expect(p.locator("#setup-step-1")).toHaveAttribute("data-state", "done");
  // This device already holds the first passkey: no longer offered.
  await expect(p.locator("#setup-choice-device")).toBeHidden();
  expect(await owner.credentials(first)).toBe(1);

  // The second passkey must live on another authenticator (the server
  // excludes the first credential).
  const second = await owner.addAuthenticator("usb");
  await owner.only(second);
  await p.locator("#setup-where-security-key").check();
  await register.click();
  await expect(p.locator("#setup-done-title")).toHaveText("All done! Both of your passkeys are ready.");
  await p.waitForURL(owner.dropr.origin + "/");
  expect(await owner.credentials(second)).toBe(1);
  await expect(p.getByText("Drop a file here to share")).toBeVisible();
  await expect(p.getByRole("button", { name: "Ask someone to send me a file" })).toBeVisible();
});

for (const which of ["small", "large"] as const) {
  test(`owner shares the ${which} file`, async ({ owner }) => {
    const file = which === "small" ? small : large;
    const p = owner.page;
    await p.goto(owner.dropr.origin + "/");
    await expect(p.locator("#share-form")).toBeVisible();
    await p.locator("#file-input").setInputFiles(file.path);
    await expect(p.locator("#upload-panel")).toBeVisible();
    const link = p.locator("#share-link");
    await expect(p.locator("#share-result")).toBeVisible({ timeout: 120_000 });
    await expect(link).toBeFocused();
    const url = await link.inputValue();
    expect(url).toMatch(new RegExp(`^${owner.dropr.origin}/s/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]+$`));
    await expect(p.locator("#share-expiry")).toHaveText("Expires in 7 days");
    await expect(p.locator("#share-qr svg.qr")).toBeVisible();

    // Permissions-Policy denies clipboard-read (only writes are allowed), so
    // record what the Copy button writes instead of reading it back.
    await p.evaluate(() => {
      const w = window as unknown as { copied?: string };
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = (t: string) => ((w.copied = t), orig(t));
    });
    await p.locator("#share-copy").click();
    await expect(p.locator("#share-copy")).toHaveText("Copied");
    expect(await p.evaluate(() => (window as unknown as { copied?: string }).copied)).toBe(url);
    shareLinks.set(which, url);
  });
}

for (const which of ["small", "large"] as const) {
  test(`anonymous recipient downloads the ${which} file`, async ({ browser, browserName }) => {
    const file = which === "small" ? small : large;
    const url = shareLinks.get(which);
    expect(url).toBeDefined();
    const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
    await page.goto(url!);
    await expect(page.locator("#file-name")).toHaveText(file.name);
    await expect(page).toHaveTitle(`${file.name} – Dropr`);
    // Rounded up like the dashboard: a fresh 7-day link reads "Expires in 7 days".
    await expect(page.locator("#file-expiry")).toHaveText("Expires in 7 days");
    const button = page.locator("#download-button");
    await expect(button).toBeEnabled();
    const got = await downloadVia(page, button);
    expect(got.name).toBe(file.name);
    expect(got.sha256).toBe(file.sha256);
    // "Check your browser's downloads" is only said by the service-worker sink
    // (not the in-memory fallback), so this also proves the worker registered
    // under the Trusted Types CSP.
    await expect(page.locator("#download-status")).toHaveText("Download complete. Check your browser's downloads.", { timeout: 60_000 });
    await context.close();
  });
}

test("dead and broken share links are explained", async ({ browser, dropr }) => {
  const { context, page } = await anonymousPage(browser, "recipient");
  const url = shareLinks.get("small")!;
  await page.goto(url.replace(/#.*/, ""));
  await expect(page.locator("#download-error")).toContainText("missing its key");
  const res = await page.goto(dropr.origin + "/s/AAAAAAAAAAAAAAAAAAAAAA#x");
  expect(res?.status()).toBe(404);
  await expect(page.locator("main")).toContainText("This link does not exist or has been revoked.");
  await expect(page.locator("script")).toHaveCount(0);
  await context.close();
});

let requestLink = "";

test("owner creates a request link", async ({ owner }) => {
  const p = owner.page;
  await p.goto(owner.dropr.origin + "/");
  await expect(p.locator("#request-form")).toBeVisible();
  await p.locator("#request-max-files").fill("5");
  await p.locator("#request-create").click(); // prompts for the passkey ("Unlock")
  await expect(p.locator("#request-result")).toBeVisible();
  requestLink = await p.locator("#request-link").inputValue();
  expect(requestLink).toMatch(new RegExp(`^${owner.dropr.origin}/r/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]+$`));
});

test("anonymous sender uploads through the request link", async ({ browser, browserName }) => {
  const { context, page } = await anonymousPage(browser, `sender/${browserName}`);
  await page.goto(requestLink);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Send a file to ${USERS.alice.name}`);
  await expect(page.locator("#drop-zone")).toBeVisible();
  await page.locator("#file-input").setInputFiles([small.path, large.path]);
  const done = page.locator("#upload-done");
  await expect(done).toBeVisible({ timeout: 180_000 });
  await expect(done).toHaveText("✓ Sent. You can close this page.");
  await expect(done).toBeFocused();
  await expect(page.locator("#upload-list li")).toHaveCount(2);
  await context.close();
});

test("owner decrypts the inbox and downloads the received files", async ({ owner }) => {
  const p = owner.page;
  await p.goto(owner.dropr.origin + "/");
  await expect(p.getByRole("link", { name: "Received files (2)" })).toBeVisible();
  await p.goto(owner.dropr.origin + "/inbox");
  await p.locator("#inbox-unlock").click();
  const rows = p.locator("#inbox-list tr");
  await expect(rows).toHaveCount(2);
  // The owner's browser downloads through the File System Access picker by
  // default; shadow it so the service worker path is used and observable.
  await p.evaluate(() => Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }));
  for (const file of [small, large]) {
    const row = rows.filter({ has: p.locator("td.name", { hasText: file.name }) });
    await expect(row).toHaveCount(1);
    const got = await downloadVia(p, row.getByRole("button", { name: /^Download/ }));
    expect(got.name).toBe(file.name);
    expect(got.sha256).toBe(file.sha256);
    await expect(p.locator("#download-status")).toHaveText("Download complete. Check your browser's downloads.", { timeout: 60_000 });
  }
});
