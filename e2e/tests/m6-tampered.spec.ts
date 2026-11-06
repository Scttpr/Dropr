/**
 * Integrity of downloads in the recipient's browser (each project).
 *
 * - A flipped ciphertext byte (first or last segment) → plain-language
 *   integrity error, nothing saved: either no download starts or the one
 *   the service worker started ends as *failed* (the browser discards it).
 * - A body truncated on every attempt → the module retries with Range, then
 *   gives up with "interrupted repeatedly"; nothing saved.
 * - A server lying about the size (one segment dropped from both the size
 *   and the body: a truncation attack) → caught by the authenticated
 *   metadata size before the download is offered.
 * - Wrong key, malformed key or missing key in the fragment → plain errors.
 */

import type { Download, Page, Route } from "@playwright/test";
import { anonymousPage, collectDownloads, expect, makeFile, shareFile, test, type TestFile } from "../m6.ts";

test.describe.configure({ mode: "serial" });
test.use({ droprConfig: {} });

const DAMAGED = "The file could not be decrypted: it has been damaged or altered, or the link is wrong.";
const SEG = 65552;

let file: TestFile;
let url = "";

test("owner shares a 4-segment file", async ({ alice, filesDir }) => {
  file = await makeFile(filesDir, "integrity.bin", 3 * 65536 + 1234);
  url = await shareFile(alice, file);
});

/** Replace /dl/ responses (only the page's own fetches; /_dl/ is the service worker's). */
async function tamper(page: Page, edit: (body: Buffer, route: Route) => Buffer | null): Promise<{ hits: number }> {
  const state = { hits: 0 };
  await page.route(
    (u) => u.pathname.startsWith("/dl/"),
    async (route) => {
      state.hits++;
      const res = await route.fetch();
      const body = edit(await res.body(), route);
      if (body === null) return route.fulfill({ response: res });
      const headers = { ...res.headers() };
      delete headers["content-length"];
      await route.fulfill({ status: res.status(), headers, body });
    },
  );
  return state;
}

async function expectNothingSaved(downloads: { list: Download[] }): Promise<void> {
  for (const d of downloads.list) {
    // Firefox may leave an errored service-worker download pending instead of
    // failing it; "not completed" is what matters (nothing committed to disk).
    const settled = await Promise.race([d.failure().then((f) => ({ f })), new Promise<null>((ok) => setTimeout(() => ok(null), 10_000))]);
    if (settled === null) {
      console.log(`[note] download ${d.suggestedFilename()} still pending after the error; cancelling`);
      await d.cancel();
      expect(await d.failure()).not.toBeNull();
      continue;
    }
    expect(settled.f, `download ${d.suggestedFilename()} should have failed`).not.toBeNull();
  }
}

for (const where of ["first", "last"] as const) {
  test(`a flipped byte in the ${where} segment fails with an integrity error and saves nothing`, async ({ browser, browserName }) => {
    const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
    const downloads = collectDownloads(page);
    await tamper(page, (b) => {
      const out = Buffer.from(b);
      const at = where === "first" ? 100 : out.length - 5;
      out[at] = out[at]! ^ 0x01;
      return out;
    });
    await page.goto(url);
    await expect(page.locator("#download-button")).toBeEnabled();
    await page.locator("#download-button").click();
    await expect(page.locator("#download-error")).toHaveText(DAMAGED);
    await expect(page.locator("#download-error")).toBeFocused();
    await expect(page.locator("#download-status")).not.toHaveText(/complete/);
    await page.waitForTimeout(1000);
    await expectNothingSaved(downloads);
    await context.close();
  });
}

test("a body that is truncated on every attempt ends with a plain error and saves nothing", async ({ browser, browserName }) => {
  test.setTimeout(3 * 60_000);
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  const downloads = collectDownloads(page);
  const state = await tamper(page, (b) => b.subarray(0, Math.max(0, b.length - SEG - 10)));
  await page.goto(url);
  await page.locator("#download-button").click();
  // 1 attempt + 5 retries with exponential backoff (1 s base, jitter).
  await expect(page.locator("#download-error")).toHaveText("The download was interrupted repeatedly. Check your connection and try again.", {
    timeout: 120_000,
  });
  expect(state.hits).toBeGreaterThanOrEqual(6);
  await expectNothingSaved(downloads);
  await context.close();
});

test("a server that drops the final segment from size and body is detected before download", async ({ browser, browserName }) => {
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  await page.route(
    (u) => /^\/api\/s\/[^/]+\/download$/.test(u.pathname),
    async (route) => {
      const res = await route.fetch();
      const j = (await res.json()) as { size: number };
      j.size -= 1234 + 16; // drop the last (short) segment
      await route.fulfill({ response: res, json: j });
    },
  );
  await page.goto(url);
  await expect(page.locator("#download-error")).toHaveText("The key in this link is wrong or the file is damaged. Ask the sender for the complete link.");
  await expect(page.locator("#download-button")).toBeHidden();
  await context.close();
});

test("a wrong key in the fragment is reported in plain language", async ({ browser, browserName }) => {
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  const wrong = Buffer.alloc(32, 7).toString("base64url");
  await page.goto(url.replace(/#.*/, "#" + wrong));
  await expect(page.locator("#download-error")).toHaveText("The key in this link is wrong or the file is damaged. Ask the sender for the complete link.");
  await expect(page.locator("#download-button")).toBeHidden();
  await expect(page.locator("#file-name")).not.toHaveText(file.name);
  await context.close();
});

test("a malformed or missing key is reported in plain language", async ({ browser, browserName }) => {
  const { context, page } = await anonymousPage(browser, `recipient/${browserName}`);
  const requests: string[] = [];
  page.on("request", (r) => requests.push(new URL(r.url()).pathname));
  for (const frag of ["#abc", "#" + "A".repeat(42) + "!", "#" + Buffer.alloc(31, 1).toString("base64url")]) {
    await page.goto("about:blank");
    await page.goto(url.replace(/#.*/, frag));
    await expect(page.locator("#download-error")).toHaveText("This link is incomplete or damaged. Ask the sender for the complete link.");
  }
  await page.goto("about:blank");
  await page.goto(url.replace(/#.*/, ""));
  await expect(page.locator("#download-error")).toHaveText("This link is missing its key (the part after #). Ask the sender for the complete link.");
  await page.goto("about:blank");
  await page.goto(url.replace(/#.*/, "#"));
  await expect(page.locator("#download-error")).toContainText("missing its key");
  // A bad fragment never even asks the server for a token.
  expect(requests.filter((p) => p.startsWith("/api/s/"))).toEqual([]);
  await context.close();
});
