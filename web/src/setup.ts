/**
 * First-login passkey setup (`/setup`): register two passkeys, guided.
 * DOM contract: docs/PAGES.md §3.
 *
 * Written for people who are not at ease with digital services: plain
 * words, one obvious next action, and no dead end (every error says what
 * happened and what to do, with a way to try another option).
 *
 * Step 1 generates the account key pair (extractable, in memory only) and
 * wraps it under the first passkey's PRF-derived KEK. Step 2 wraps the same
 * key under the second passkey. The extractable key is then dropped.
 *
 * "Where to save it" options come from {@link planChoices}: only what can
 * work in this browser, recommended first, a different place for step 2.
 * Browsers that ignore WebAuthn hints (Firefox) get no options, only a note
 * that the browser shows its own.
 *
 * The first registration leaves a 5-minute "add" grant for step 2, so step 2
 * normally prompts only for the new passkey. If the page is reloaded after
 * step 1 (`data-passkey-count="1"`, the key is gone) or step 2 is answered
 * `reauth_required` (the 5 minutes passed), the page first explains why,
 * then confirms with the existing passkey (hinted to where it was saved)
 * before creating the new one.
 *
 * @module
 */

import type { ExtractableOwnerKey } from "./crypto/index.ts";
import { ApiError } from "./lib/api.ts";
import { Notice, byId, dataInt, focusTo, maybeId, pageRoot, revealJsOnly } from "./lib/dom.ts";
import {
  BROWSER_NO_PRF_MESSAGE,
  NO_WEBAUTHN_MESSAGE,
  PasskeyError,
  registerPasskey,
  unlockExtractable,
  webauthnAvailable,
} from "./lib/passkey.ts";
import { type ChoicePlan, type PasskeyEnvironment, detectEnvironment, planChoices } from "./lib/passkey-env.ts";
import { type AuthenticatorChoice, choiceHints, isAuthenticatorChoice } from "./lib/webauthn.ts";

const REQUIRED = 2;
const LAST_KEY = "dropr:setup-last-choice";
const ALL: readonly AuthenticatorChoice[] = ["device", "phone", "security-key", "auto"];

function safeNext(raw: string | undefined): string {
  // Same-origin path only (no "//host", no scheme).
  return raw !== undefined && /^\/(?!\/)[A-Za-z0-9/_\-.?=&%]*$/.test(raw) ? raw : "/";
}

/** Where the previous passkey of this setup was saved (survives a reload; not sensitive). */
function loadLast(): AuthenticatorChoice | null {
  try {
    const v = sessionStorage.getItem(LAST_KEY);
    return isAuthenticatorChoice(v) ? v : null;
  } catch {
    return null;
  }
}

function saveLast(c: AuthenticatorChoice | null): void {
  try {
    if (c === null) sessionStorage.removeItem(LAST_KEY);
    else sessionStorage.setItem(LAST_KEY, c);
  } catch {
    // Storage unavailable: recommendations are just less precise.
  }
}

/** Short name of a place, for sentences ("…like your phone or a security key"). */
function placeName(c: AuthenticatorChoice, env: PasskeyEnvironment | null): string {
  const device = env?.device ?? "computer";
  switch (c) {
    case "device":
      return `this ${device}`;
    case "phone":
      return device === "computer" ? "your phone" : "another phone or tablet";
    case "security-key":
      return "a security key";
    case "auto":
      return "another way";
  }
}

/** What to do while the browser prompt is open. */
function duringText(c: AuthenticatorChoice, env: PasskeyEnvironment | null): string {
  switch (c) {
    case "device":
      return "Follow the steps on your screen. You may be asked for your fingerprint, your face or your PIN.";
    case "phone":
      return env !== null && env.device !== "computer"
        ? "Scan the QR code with the other device's camera, then follow the steps on it."
        : "Scan the QR code with your phone's camera, then follow the steps on your phone.";
    case "security-key":
      return "Plug in or tap your security key, then touch it if it blinks.";
    case "auto":
      return "Follow the steps your browser shows.";
  }
}

/** Said right before the second prompt (create() gave no PRF output). */
function againText(c: AuthenticatorChoice): string {
  switch (c) {
    case "device":
      return "Almost done. Please confirm one more time, the same way. That's normal.";
    case "phone":
      return "Almost done. Your phone will ask you one more time to confirm. That's normal.";
    case "security-key":
      return "Almost done. Touch your security key one more time. That's normal.";
    case "auto":
      return "Almost done. You'll be asked to confirm one more time. That's normal.";
  }
}

const PHONE_FAILED =
  "Your phone couldn't save the passkey. Please check the list under “Your phone”: Bluetooth on, on both devices; " +
  "internet on both; and on Android, Google Password Manager (Microsoft Authenticator can't be used). " +
  "Then try again, or try another way.";

const REAUTH_STATUS = "For your safety, please confirm with your first passkey before making the spare one.";

function init(main: HTMLElement): void {
  revealJsOnly();
  const button = byId("setup-register", HTMLButtonElement);
  const notice = new Notice(byId("setup-error"), byId("setup-status"));
  const where = maybeId("setup-where", HTMLFieldSetElement);
  const other = maybeId("setup-other", HTMLButtonElement);
  const done = maybeId("setup-done");
  const stepTitle = maybeId("setup-step-title");
  const reauthNote = maybeId("setup-reauth");
  const next = safeNext(main.dataset["next"]);

  let count = dataInt(main, "passkeyCount", 0);
  let key: ExtractableOwnerKey | null = null;
  let last = count >= 1 ? loadLast() : null;
  /** Step 2 must first confirm with the existing passkey (key gone, or grant expired). */
  let needConfirm = count >= 1;
  let failed = false;
  let finished = false;
  let env: PasskeyEnvironment | null = null;
  let plan: ChoicePlan | null = null;
  let plannedStep = 0;

  if (where !== null) where.hidden = true; // until we know what can work here

  const radio = (c: AuthenticatorChoice): HTMLInputElement | null => maybeId(`setup-where-${c}`, HTMLInputElement);
  const card = (c: AuthenticatorChoice): HTMLElement | null => maybeId(`setup-choice-${c}`);

  /** The checked "where to save it" option (default `"auto"`). */
  const choice = (): AuthenticatorChoice => {
    if (plan !== null && !plan.show) return "auto";
    const v = where?.querySelector<HTMLInputElement>("input[name=\"setup-where\"]:checked")?.value;
    return isAuthenticatorChoice(v) ? v : "auto";
  };

  /** Highlight the checked card; show the phone checklist when the phone is chosen. */
  const syncChecked = (): void => {
    const c = choice();
    for (const x of ALL) card(x)?.classList.toggle("is-checked", x === c && plan?.show !== false);
    const help = maybeId("setup-phone-help");
    if (help !== null && plan?.show !== false) help.hidden = c !== "phone";
  };

  /** Adapt labels to the device ("this phone", "another phone or tablet"). */
  const applyDevice = (e: PasskeyEnvironment): void => {
    for (const s of document.querySelectorAll<HTMLElement>("[data-device]")) s.textContent = e.device;
    if (e.device !== "computer") {
      const t = maybeId("setup-where-phone-title");
      if (t !== null) t.textContent = "Another phone or tablet";
      const d = maybeId("setup-where-phone-desc");
      if (d !== null) d.textContent = "You'll scan a QR code with the other device's camera.";
      const bt = maybeId("setup-phone-help-bluetooth");
      if (bt !== null) bt.textContent = "Turn on Bluetooth on both devices.";
    }
  };

  /** Show the options of the current plan, recommended first. */
  const applyPlan = (): void => {
    if (env === null || where === null || count >= REQUIRED) return;
    const step = count + 1;
    plan = planChoices(env, step, last);
    const note = maybeId("setup-browser-note");
    if (!plan.show) {
      where.hidden = true;
      if (note !== null) note.hidden = false;
      const tip = maybeId("setup-browser-tip");
      if (tip !== null) tip.hidden = !(env.platform === false && env.hybrid !== true);
      const tips = maybeId("setup-phone-tips");
      const help = maybeId("setup-phone-help");
      if (tips !== null && help !== null && env.hybrid !== false && env.device === "computer") {
        tips.append(help);
        help.hidden = false;
        tips.hidden = false;
      }
      return;
    }
    if (note !== null) note.hidden = true;
    where.hidden = false;
    for (const c of ALL) {
      const k = card(c);
      if (k === null) continue;
      k.hidden = !plan.offered.includes(c);
      const badge = k.querySelector<HTMLElement>(".choice-badge");
      if (badge !== null) badge.hidden = c !== plan.recommended;
    }
    for (const c of plan.offered) {
      const k = card(c);
      if (k !== null) where.append(k);
    }
    // Pre-select the recommendation once per step; keep the user's own pick otherwise.
    const current = choice();
    if (plannedStep !== step || !plan.offered.includes(current)) {
      const r = radio(plan.recommended);
      if (r !== null) r.checked = true;
    }
    plannedStep = step;
    syncChecked();
  };

  const render = (): void => {
    for (let i = 1; i <= REQUIRED; i++) {
      const step = maybeId(`setup-step-${i}`);
      if (step === null) continue;
      step.dataset["state"] = i <= count ? "done" : i === count + 1 ? "current" : "todo";
      if (i === count + 1) step.setAttribute("aria-current", "step");
      else step.removeAttribute("aria-current");
    }
    if (stepTitle !== null) {
      stepTitle.hidden = count >= REQUIRED;
      stepTitle.textContent = count === 0 ? "Step 1 of 2: your first passkey" : "Step 2 of 2: your spare passkey";
    }
    const confirming = count >= 1 && needConfirm;
    if (reauthNote !== null) reauthNote.hidden = !confirming || count >= REQUIRED;
    if (failed) button.textContent = "Try again";
    else if (count === 0) button.textContent = "Create my first passkey";
    else if (confirming) button.textContent = "Confirm with my first passkey";
    else button.textContent = "Create my spare passkey";
    applyPlan();
  };

  const showDone = (title: string, text: string): void => {
    if (done === null) return;
    byId("setup-done-title").textContent = title;
    byId("setup-done-next").textContent = text;
    done.hidden = false;
    focusTo(done);
  };

  /** "Now make a spare one … like your phone or a security key." */
  const spareAdvice = (): string => {
    const base = "Now make a spare one on a different device than the one you just used";
    if (env === null) return `${base}.`;
    const p = planChoices(env, 2, last);
    const ideas = p.offered.filter((c) => c !== "auto" && c !== last).slice(0, 2);
    if (!p.show || ideas.length === 0) return `${base}.`;
    return `${base}, for example ${ideas.map((c) => placeName(c, env)).join(" or ")}.`;
  };

  /** Offer "Try another way" when there is another option to pick. */
  const offerOther = (): void => {
    if (other === null || plan === null || !plan.show) return;
    other.hidden = plan.offered.length < 2;
  };

  if (!webauthnAvailable()) {
    button.disabled = true;
    notice.error(NO_WEBAUTHN_MESSAGE, false);
    return;
  }

  void detectEnvironment().then((e) => {
    env = e;
    applyDevice(e);
    if (e.prf === false) notice.error(BROWSER_NO_PRF_MESSAGE, false);
    if (!finished) render();
  });

  where?.addEventListener("change", () => {
    if (failed) {
      failed = false;
      render();
    }
    syncChecked();
  });

  if (other !== null) other.addEventListener("click", () => {
    if (plan === null) return;
    const offered = plan.offered;
    const at = offered.indexOf(choice());
    const pick = offered[(at + 1) % offered.length] ?? "auto";
    const r = radio(pick);
    if (r === null) return;
    r.checked = true;
    failed = false;
    notice.clear();
    notice.status("");
    other.hidden = true;
    render();
    syncChecked();
    r.focus();
  });

  button.addEventListener("click", async () => {
    const c = choice();
    button.disabled = true;
    if (where !== null) where.disabled = true;
    if (other !== null) other.hidden = true;
    if (done !== null) done.hidden = true;
    failed = false;
    notice.clear();
    /** The failing prompt was for the existing passkey, not the new one. */
    let confirmingFirst = false;
    try {
      if (count >= 1 && needConfirm) {
        confirmingFirst = true;
        notice.status("First, confirm with the passkey you already made…");
        const hints = last !== null ? choiceHints(last) : undefined;
        key = await unlockExtractable({}, hints);
        confirmingFirst = false;
        needConfirm = false;
        render();
        notice.status(`Thank you. Now create your spare passkey. ${duringText(c, env)}`);
      } else {
        notice.status(duringText(c, env));
      }
      try {
        key = await registerPasskey(key, {}, c, { onConfirmPrompt: () => notice.status(againText(c)) });
      } catch (e) {
        // The first registration authorizes the second for 5 minutes only:
        // explain, then let the user confirm with the first passkey.
        if (count >= 1 && e instanceof ApiError && e.code === "reauth_required") {
          needConfirm = true;
          render();
          notice.status(REAUTH_STATUS);
          focusTo(button);
          return;
        }
        throw e;
      }
      count++;
      last = c;
      if (count >= REQUIRED) {
        key = null; // drop the extractable private key
        finished = true;
        saveLast(null);
        render();
        if (where !== null) where.hidden = true;
        button.hidden = true;
        notice.status("");
        showDone("All done! Both of your passkeys are ready.", "Taking you to Dropr…");
        setTimeout(() => location.assign(next), 1500);
        return;
      }
      saveLast(c);
      render();
      notice.status("");
      showDone("Your first passkey is ready.", spareAdvice());
    } catch (e) {
      notice.status("");
      failed = true;
      render();
      if (c === "phone" && !confirmingFirst && e instanceof PasskeyError && e.reason === "NotAllowedError") notice.error(PHONE_FAILED);
      else notice.error(e);
      // Another place for the new passkey doesn't help confirm the first one.
      if (!confirmingFirst) offerOther();
    } finally {
      if (!finished) {
        button.disabled = false;
        if (where !== null) where.disabled = false;
      }
    }
  });

  render();
}

const main = pageRoot("setup");
if (main !== null) init(main);
