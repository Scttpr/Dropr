/**
 * What this browser can really do with passkeys, and which "where to save
 * it" options the setup page should offer.
 *
 * Choices are applied through WebAuthn `hints`, which Chrome, Edge and
 * Safari follow and Firefox ignores; password manager extensions ignore
 * them everywhere. So the page only offers options that can work here, and
 * when the browser ignores hints it offers none and says the browser will
 * show its own options. Unknown capabilities keep an option (the ceremony
 * gives the definitive answer) without promising anything.
 *
 * Detection is best-effort: `getClientCapabilities()` (Chrome 133+,
 * Safari 18+, Firefox 135+) and `isUserVerifyingPlatformAuthenticatorAvailable()`.
 * {@link planChoices} is pure, so it is unit-tested in Node.
 *
 * @module
 */

import type { AuthenticatorChoice } from "./webauthn.ts";

/** What the browser and device can do. `null` = unknown. */
export interface PasskeyEnvironment {
  /** A passkey can be saved on this device (Windows Hello, Touch ID, Google Password Manager…). */
  readonly platform: boolean | null;
  /** A phone can be used through a QR code (needs Bluetooth). */
  readonly hybrid: boolean | null;
  /** The browser supports the PRF extension. */
  readonly prf: boolean | null;
  /** The browser follows WebAuthn `hints`, so the page's choice really changes the prompt. */
  readonly hints: boolean;
  /** What "this device" is, for the labels. */
  readonly device: "computer" | "phone" | "tablet";
}

type Caps = Record<string, boolean>;

interface PkcStatics {
  getClientCapabilities?: () => Promise<Caps>;
  isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
}

/** Firefox (desktop and Android) ignores WebAuthn hints. Firefox on iOS is WebKit ("FxiOS") and follows them. */
export function ignoresHints(userAgent: string): boolean {
  return /\bFirefox\//.test(userAgent);
}

export function deviceKind(userAgent: string, maxTouchPoints = 0): PasskeyEnvironment["device"] {
  if (/\biPad\b/.test(userAgent) || (/\bMacintosh\b/.test(userAgent) && maxTouchPoints > 1)) return "tablet";
  if (/\bAndroid\b/.test(userAgent)) return /\bMobile\b/.test(userAgent) ? "phone" : "tablet";
  if (/\b(iPhone|iPod)\b|\bMobile\b/.test(userAgent)) return "phone";
  return "computer";
}

function anyKnown(...vals: (boolean | null | undefined)[]): boolean | null {
  if (vals.includes(true)) return true;
  if (vals.includes(false)) return false;
  return null;
}

/** Detect the environment (never throws). */
export async function detectEnvironment(
  pkc: unknown = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential,
  nav: { userAgent: string; maxTouchPoints?: number } = navigator,
): Promise<PasskeyEnvironment> {
  const statics = (typeof pkc === "function" ? pkc : {}) as PkcStatics;
  let caps: Caps | null = null;
  if (typeof statics.getClientCapabilities === "function") {
    try {
      caps = await statics.getClientCapabilities();
    } catch {
      caps = null;
    }
  }
  let uvpaa: boolean | null = null;
  if (typeof statics.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    try {
      uvpaa = await statics.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      uvpaa = null;
    }
  }
  const cap = (k: string): boolean | null => (caps !== null && typeof caps[k] === "boolean" ? caps[k] : null);
  return {
    platform: anyKnown(cap("passkeyPlatformAuthenticator"), cap("userVerifyingPlatformAuthenticator"), uvpaa),
    hybrid: cap("hybridTransport"),
    prf: cap("extension:prf"),
    hints: caps !== null && !ignoresHints(nav.userAgent),
    device: deviceKind(nav.userAgent, nav.maxTouchPoints ?? 0),
  };
}

/** The options to show, recommended first. */
export interface ChoicePlan {
  /** Whether to show the choice at all (false: the browser shows its own options). */
  readonly show: boolean;
  /** Offered options, recommended first; `"auto"` (always offered) last unless recommended. */
  readonly offered: readonly AuthenticatorChoice[];
  readonly recommended: AuthenticatorChoice;
}

const ORDER: readonly AuthenticatorChoice[] = ["device", "phone", "security-key", "auto"];

/**
 * Which options to offer for setup step `step` (1 or 2), given where the
 * previous passkey was saved (`last`, if known on this page).
 *
 * - "This device" unless the device has no passkey storage, or step 1 just
 *   saved there (it cannot hold a second Dropr passkey).
 * - "Your phone" unless the browser cannot use a phone.
 * - "A security key" and "Another way" (`auto`, the browser's own chooser,
 *   which also reaches password managers) always: never a dead end.
 * - Recommended: for step 1, this device, else a phone; for step 2,
 *   somewhere other than step 1. Known-good options beat unknown ones;
 *   `auto` when nothing better is known.
 */
export function planChoices(env: PasskeyEnvironment, step: number, last: AuthenticatorChoice | null): ChoicePlan {
  if (!env.hints) return { show: false, offered: ["auto"], recommended: "auto" };
  const state: Record<AuthenticatorChoice, boolean | null | "hide"> = {
    device: env.platform === false || (step > 1 && last === "device") ? "hide" : env.platform,
    phone: env.hybrid === false ? "hide" : env.hybrid,
    "security-key": null,
    auto: null,
  };
  const prefs: AuthenticatorChoice[] =
    step <= 1 ? ["device", "phone"] : last === "phone" ? ["device"] : last === "device" ? ["phone"] : ["phone", "device"];
  const recommended =
    prefs.find((c) => state[c] === true) ?? (step <= 1 ? prefs.find((c) => state[c] === null) : undefined) ?? "auto";
  const offered = [recommended, ...ORDER.filter((c) => c !== recommended && state[c] !== "hide")];
  return { show: true, offered, recommended };
}
