import { defineConfig, devices } from "@playwright/test";

/**
 * Real-browser smoke tests. Browsers come from nixpkgs (PLAYWRIGHT_BROWSERS_PATH
 * in the dev shell); never run `playwright install`. Each worker starts its
 * own Dropr instance (fixtures.ts) against the dev Keycloak on :8180.
 *
 * Owner flows need a WebAuthn virtual authenticator, which only Chromium
 * offers (CDP), so the owner side always runs in Chromium; the anonymous
 * recipient side runs in each project's browser.
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
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
