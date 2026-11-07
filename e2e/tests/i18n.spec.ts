/**
 * Interface language and theme: French from Accept-Language, light theme by
 * default, the display settings popover (theme in place, language by reload
 * that keeps the link key in the fragment), the no-JavaScript form fallback,
 * and axe on the open popover.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, makeFile, shareFile, test } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

test("a French visitor gets the French interface and can switch theme and language", async ({ alice, browser, browserName, filesDir }) => {
  const file = await makeFile(filesDir, "rapport-annuel.bin", 200_000);
  const url = await shareFile(alice, file);

  const context = await browser.newContext({ locale: "fr-FR" });
  const page = await context.newPage();
  await page.goto(url);
  const html = page.locator("html");
  await expect(html).toHaveAttribute("lang", "fr");
  await expect(html).toHaveAttribute("data-theme", "light");
  await expect(page.locator("#file-name")).toHaveText(file.name);
  await expect(page.locator("#download-button")).toHaveText("Télécharger");
  await expect(page.locator("#file-expiry")).toHaveText(/^Expire dans \d+ jours?$/);

  // Theme: applied in place, remembered by the server.
  await page.getByRole("button", { name: "Affichage" }).click();
  const dark = page.getByRole("button", { name: "Sombre" });
  await dark.click();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await expect(dark).toHaveAttribute("aria-pressed", "true");
  // The rest needs the __Host- preference cookies to survive a reload, and
  // Playwright's WebKit drops Secure cookies on http://localhost
  // (test-environment limitation; production is https-only).
  if (browserName === "webkit") {
    await context.close();
    return;
  }
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute("content", "dark");

  // Language: the reload keeps the fragment, so the file name still decrypts.
  await page.getByRole("button", { name: "Affichage" }).click();
  await page.getByRole("button", { name: "English" }).click();
  await expect(html).toHaveAttribute("lang", "en");
  expect(page.url()).toBe(url);
  await expect(page.locator("#file-name")).toHaveText(file.name);
  await expect(page.locator("#download-button")).toHaveText("Download");
  await context.close();
});

test("display settings work without JavaScript", async ({ browser, browserName, dropr }) => {
  test.skip(browserName === "webkit", "WebKit drops Secure (__Host-) cookies on http://localhost (test-environment limitation)");
  const context = await browser.newContext({ javaScriptEnabled: false, locale: "en-US" });
  const page = await context.newPage();
  await page.goto(dropr.origin + "/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.getByRole("button", { name: "Display settings" }).click();
  await page.getByRole("button", { name: "Français" }).click();
  await expect(page).toHaveURL(dropr.origin + "/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "fr");
  await expect(page.locator("h1 + p")).toHaveText("Partagez des fichiers avec un chiffrement de bout en bout.");
  await page.getByRole("button", { name: "Affichage" }).click();
  await page.getByRole("button", { name: "Système" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "system");
  await context.close();
});

test("the French dashboard and the open settings popover pass axe", async ({ alice, browserName, dropr }) => {
  test.skip(browserName !== "chromium", "owner pages run in Chromium");
  const p = alice.page;
  // Switch through the popover: Playwright forces Secure=false on a cookie
  // added by http:// URL, and Chromium rejects that for a __Host- name.
  await p.goto(dropr.origin + "/");
  try {
    await p.getByRole("button", { name: "Display settings" }).click();
    await p.getByRole("button", { name: "Français" }).click();
    await expect(p.locator("#share-heading")).toHaveText("Partager un fichier");
    await p.getByRole("button", { name: "Affichage" }).click();
    await expect(p.locator("#prefs")).toBeVisible();
    const res = await new AxeBuilder({ page: p }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
    const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
  } finally {
    // alice is shared across the worker; later tests expect English.
    await alice.context.clearCookies({ name: "__Host-dropr_lang" });
  }
});
