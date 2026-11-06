import { defineConfig, devices } from "@playwright/test";

/**
 * Real-browser smoke tests. Browsers come from nixpkgs (PLAYWRIGHT_BROWSERS_PATH
 * in the dev shell); never run `playwright install`. Each worker starts its
 * own Dropr instance (fixtures.ts) against the dev Keycloak on :8180.
 *
 * The owner side always runs in Chromium (fixtures.ts: `ownerBrowser`); the
 * anonymous recipient and sender side runs in each project's browser. Request
 * link keys live in the owner's browser context (IndexedDB), so a test that
 * receives files must open the inbox in the context that created the link.
 */
export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  timeout: 5 * 60_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    acceptDownloads: true,
    // Pages follow Accept-Language; English keeps text assertions stable
    // (tests/i18n.spec.ts opts into French).
    locale: "en-US",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
