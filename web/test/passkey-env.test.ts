/** Passkey capability detection and the setup page's "where to save it" plan. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { type PasskeyEnvironment, detectEnvironment, deviceKind, ignoresHints, planChoices } from "../src/lib/passkey-env.ts";

const CHROME_LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
const FIREFOX_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15";
const ANDROID_PHONE = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36";
const ANDROID_TABLET = "Mozilla/5.0 (Linux; Android 15; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const IPAD_DESKTOP_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

function fakePkc(caps: Record<string, boolean> | null, uvpaa: boolean | "throw" | null): unknown {
  const pkc = function PublicKeyCredential(): void {};
  if (caps !== null) Object.assign(pkc, { getClientCapabilities: async () => caps });
  if (uvpaa !== null) {
    Object.assign(pkc, {
      isUserVerifyingPlatformAuthenticatorAvailable: async () => {
        if (uvpaa === "throw") throw new Error("nope");
        return uvpaa;
      },
    });
  }
  return pkc;
}

const env = (over: Partial<PasskeyEnvironment> = {}): PasskeyEnvironment => ({
  platform: true,
  hybrid: true,
  prf: true,
  hints: true,
  device: "computer",
  ...over,
});

describe("passkey environment", () => {
  it("recognizes browsers that ignore hints, and the kind of device", () => {
    assert.ok(ignoresHints(FIREFOX_LINUX));
    assert.ok(!ignoresHints(CHROME_LINUX));
    assert.ok(!ignoresHints(FIREFOX_IOS), "Firefox on iOS is WebKit");
    assert.equal(deviceKind(CHROME_LINUX), "computer");
    assert.equal(deviceKind(ANDROID_PHONE), "phone");
    assert.equal(deviceKind(ANDROID_TABLET), "tablet");
    assert.equal(deviceKind(FIREFOX_IOS), "phone");
    assert.equal(deviceKind(IPAD_DESKTOP_UA, 5), "tablet");
    assert.equal(deviceKind(IPAD_DESKTOP_UA, 0), "computer");
  });

  it("detects capabilities, preferring getClientCapabilities and falling back to UVPAA", async () => {
    const chrome = await detectEnvironment(
      fakePkc({ passkeyPlatformAuthenticator: false, userVerifyingPlatformAuthenticator: false, hybridTransport: true, "extension:prf": true }, false),
      { userAgent: CHROME_LINUX },
    );
    assert.deepEqual(chrome, { platform: false, hybrid: true, prf: true, hints: true, device: "computer" });

    // Firefox on Linux: no platform storage, no phone, hints ignored.
    const firefox = await detectEnvironment(fakePkc({ hybridTransport: false, "extension:prf": true }, false), { userAgent: FIREFOX_LINUX });
    assert.deepEqual(firefox, { platform: false, hybrid: false, prf: true, hints: false, device: "computer" });

    // No getClientCapabilities: hints are assumed ignored, phone unknown.
    const old = await detectEnvironment(fakePkc(null, true), { userAgent: CHROME_LINUX });
    assert.deepEqual(old, { platform: true, hybrid: null, prf: null, hints: false, device: "computer" });

    const unknown = await detectEnvironment(fakePkc(null, "throw"), { userAgent: CHROME_LINUX });
    assert.equal(unknown.platform, null);
    const none = await detectEnvironment(undefined, { userAgent: CHROME_LINUX });
    assert.deepEqual(none, { platform: null, hybrid: null, prf: null, hints: false, device: "computer" });
  });
});

describe("where-to-save plan", () => {
  it("offers nothing when the browser ignores hints (it shows its own options)", () => {
    assert.deepEqual(planChoices(env({ hints: false }), 1, null), { show: false, offered: ["auto"], recommended: "auto" });
  });

  it("step 1 recommends this device, then a phone; only offers what can work", () => {
    assert.deepEqual(planChoices(env(), 1, null), { show: true, offered: ["device", "phone", "security-key", "auto"], recommended: "device" });
    assert.deepEqual(planChoices(env({ platform: false }), 1, null), { show: true, offered: ["phone", "security-key", "auto"], recommended: "phone" });
    assert.deepEqual(planChoices(env({ platform: false, hybrid: false }), 1, null), {
      show: true,
      offered: ["auto", "security-key"],
      recommended: "auto",
    });
    // Unknown: still offered, recommended only if nothing is known to work.
    assert.deepEqual(planChoices(env({ platform: null, hybrid: true }), 1, null).recommended, "phone");
    assert.deepEqual(planChoices(env({ platform: null, hybrid: null }), 1, null), {
      show: true,
      offered: ["device", "phone", "security-key", "auto"],
      recommended: "device",
    });
  });

  it("step 2 recommends somewhere other than step 1", () => {
    // This device can't hold a second Dropr passkey: hidden.
    assert.deepEqual(planChoices(env(), 2, "device"), { show: true, offered: ["phone", "security-key", "auto"], recommended: "phone" });
    assert.deepEqual(planChoices(env(), 2, "phone"), { show: true, offered: ["device", "phone", "security-key", "auto"], recommended: "device" });
    assert.deepEqual(planChoices(env({ hybrid: false }), 2, "device"), { show: true, offered: ["auto", "security-key"], recommended: "auto" });
    // Unknown first place (page reloaded without storage): a phone first.
    assert.equal(planChoices(env(), 2, null).recommended, "phone");
    assert.equal(planChoices(env({ hybrid: null }), 2, "device").recommended, "auto");
  });

  it("always keeps a way out", () => {
    for (const platform of [true, false, null]) {
      for (const hybrid of [true, false, null]) {
        for (const last of [null, "device", "phone", "security-key", "auto"] as const) {
          for (const step of [1, 2]) {
            const p = planChoices(env({ platform, hybrid }), step, last);
            assert.ok(p.offered.includes("auto"));
            assert.equal(p.offered[0], p.recommended);
            assert.equal(new Set(p.offered).size, p.offered.length);
          }
        }
      }
    }
  });
});
