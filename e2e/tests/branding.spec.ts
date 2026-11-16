/**
 * Instance branding ([branding] with the generic test logos of
 * dev/branding): the name and logos replace Dropr's on anonymous pages, the
 * dark logo follows the theme, the SVG logo is served sandboxed, and axe
 * still finds no serious violation. Rendering details are covered by the Go
 * tests (internal/web/brand_test.go, internal/server/branding_test.go).
 */

import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { BRAND_NAME, anonymousPage, expect, test } from "../m6.ts";

test.use({ droprConfig: { branding: true } });

/** Waits until no CSS transition or animation runs (theme switch, popover). */
async function settled(page: Page): Promise<void> {
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined))));
}

async function axe(page: Page, label: string): Promise<void> {
  // axe measures colors as rendered: a running transition gives false
  // contrast failures.
  await settled(page);
  const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]).analyze();
  const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(
    bad.map((v) => `${v.id} (${v.impact}): ${v.help} — ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`),
    `${label}: serious/critical axe violations`,
  ).toEqual([]);
}

test("anonymous pages show the configured name and logos", async ({ browser, browserName, dropr, request }) => {
  const { context, page } = await anonymousPage(browser, `branding/${browserName}`);
  await page.goto(dropr.origin + "/");
  await expect(page).toHaveTitle(new RegExp(`· ${BRAND_NAME}$`));
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(BRAND_NAME);
  const brand = page.getByRole("link", { name: BRAND_NAME, exact: true });
  await expect(brand).toBeVisible();
  const light = page.locator(".brand-logo-light");
  const dark = page.locator(".brand-logo-dark");
  await expect(light).toBeVisible();
  await expect(dark).toBeHidden();
  expect(await light.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
  await expect(page.locator(".powered a")).toHaveText("Dropr");
  await axe(page, `branded login, light [${browserName}]`);

  // The dark logo replaces the light one in the dark theme.
  await page.getByRole("button", { name: "Display settings" }).click();
  await page.getByRole("button", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(light).toBeHidden();
  await expect(dark).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#prefs")).toBeHidden();
  await axe(page, `branded login, dark [${browserName}]`);

  // Narrow screens keep the header usable.
  await page.setViewportSize({ width: 320, height: 640 });
  await expect(brand).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  // The SVG logo, opened directly, is an inert sandboxed document.
  const src = await light.getAttribute("src");
  expect(src).toMatch(/^\/assets\/brand\/logo-[0-9a-f]{8}\.svg$/);
  const res = await request.get(dropr.origin + src);
  expect(res.status()).toBe(200);
  expect(res.headers()["content-type"]).toBe("image/svg+xml");
  expect(res.headers()["content-security-policy"]).toBe("default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox");
  expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  const icon = await page.locator('link[rel="icon"]').getAttribute("href");
  expect(icon).toMatch(/^\/assets\/brand\/favicon-[0-9a-f]{8}\.svg$/);

  // Recipients see the brand on link pages too.
  await page.goto(dropr.origin + "/s/AAAAAAAAAAAAAAAAAAAAAA");
  await expect(page).toHaveTitle(new RegExp(`· ${BRAND_NAME}$`));
  await axe(page, `branded dead link [${browserName}]`);
  await context.close();
});
