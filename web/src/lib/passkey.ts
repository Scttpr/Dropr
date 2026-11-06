/**
 * Passkeys with the WebAuthn PRF extension: registration (which wraps the
 * owner's X25519 private key under a PRF-derived KEK) and unlock (which
 * unwraps it into a non-extractable key held in memory).
 *
 * **Keyring.** The unlocked key pair lives in a module-level variable of the
 * current page only. It is never written to sessionStorage, localStorage or
 * IndexedDB, so it is gone after a navigation or reload: pages that need it
 * (inbox, "Ask someone to send me a file", copying a request link) call
 * {@link ensureUnlocked}, which prompts for the passkey when needed.
 *
 * **PRF at creation.** When `create()` returns the PRF output
 * (`prf.results.first`), registration wraps with it directly: one prompt,
 * no confirmation. Many authenticators only return it on `get()`
 * (`create()` reports `prf.enabled: true` without `results`); registration
 * then immediately runs one `get()` restricted to the new credential (with
 * the same hints as the creation, so the browser goes straight to the same
 * place), over the server's confirmation challenge when it sent one, and
 * sends that assertion back as `confirm` (optional for the server).
 * The server leaves the "add" grant for the second passkey of the setup
 * after the first registration either way (ARCHITECTURE.md §3 "Passkeys").
 *
 * **Passkey management.** Adding or deleting a passkey once the account has
 * one needs a fresh assertion by an existing passkey made for that action
 * ({@link unlockExtractable} for an addition, {@link deletePasskey}).
 *
 * **Messages.** Every error a user can meet here is a plain sentence that
 * says what happened and what to do next ({@link passkeyErrorMessage},
 * {@link PRF_UNSUPPORTED_MESSAGE}); the inbox, dashboard and links pages show
 * them as they are (messages.ts).
 *
 * The PRF output never leaves the browser: credentials sent to the server go
 * through `credentialToJSON`, which strips `prf.results`.
 *
 * @module
 */

import {
  type ExtractableOwnerKey,
  type OwnerKeyPair,
  b64urlEncode,
  deriveKek,
  generateOwnerKeyPair,
  prfSalt,
  unwrapExtractable,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "../crypto/index.ts";
import { Api, type UnlockPurpose, type UnlockResult } from "./api.ts";
import {
  type AuthenticatorChoice,
  type CredentialLike,
  b64uToBytes,
  choiceHints,
  creationOptionsFromJSON,
  credentialToJSON,
  hintsFromTransports,
  prfExtension,
  prfOutput,
  requestOptionsFromJSON,
  toBytes,
} from "./webauthn.ts";

/** A new passkey was saved somewhere that cannot evaluate PRF (registration). */
export const PRF_UNSUPPORTED_MESSAGE =
  "The place where you tried to save this passkey can't keep your files private. " +
  "Please choose another place: this computer, a security key, or your phone with " +
  "Google Password Manager (Android) or Passwords / iCloud Keychain (iPhone). " +
  "Microsoft Authenticator can't be used for Dropr.";

/** An existing passkey cannot evaluate PRF (unlock). */
export const PRF_UNSUPPORTED_UNLOCK_MESSAGE = "This passkey can't open your files. Please try again with another of your Dropr passkeys.";

/** The browser itself reports no PRF support (`getClientCapabilities`). */
export const BROWSER_NO_PRF_MESSAGE =
  "This browser can't keep your files private with a passkey. " +
  "Please open this page in another browser, such as a recent Chrome, Edge or Safari.";

/** The browser has no passkey support at all. */
export const NO_WEBAUTHN_MESSAGE =
  "This browser can't use passkeys. Please open this page in a recent Chrome, Edge, Safari or Firefox.";

/** The browser or authenticator cannot evaluate PRF. */
export class PrfUnsupportedError extends Error {
  constructor(during: "create" | "get" = "create") {
    super(during === "create" ? PRF_UNSUPPORTED_MESSAGE : PRF_UNSUPPORTED_UNLOCK_MESSAGE);
    this.name = "PrfUnsupportedError";
  }
}

/** A WebAuthn ceremony failed for a user-facing reason (cancelled, wrong domain, duplicate…). */
export class PasskeyError extends Error {
  override readonly cause: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "PasskeyError";
    this.cause = cause;
  }

  /** The DOMException name behind it (`"NotAllowedError"` for a cancel or a timeout), or `""`. */
  get reason(): string {
    return this.cause instanceof Error ? this.cause.name : "";
  }
}

/** Plain-language message for a WebAuthn DOMException: what happened, then what to do. */
export function passkeyErrorMessage(e: unknown, during: "create" | "get"): string {
  const name = e instanceof Error ? e.name : "";
  const create = during === "create";
  switch (name) {
    case "NotAllowedError":
      // Cancelled, timed out, or (phone) the connection did not work: browsers do not say which.
      return create
        ? "The passkey wasn't saved. The window may have been closed, or it took too long. Please try again, or choose another place to save it."
        : "Your passkey wasn't used. The window may have been closed, or it took too long. Please try again.";
    case "InvalidStateError":
      return create
        ? "You already have a Dropr passkey there. Please choose another place, such as your phone or a security key."
        : "This passkey can't be used here. Please try another of your passkeys.";
    case "SecurityError":
      return "Passkeys don't work on this web address. Please open Dropr from its usual link.";
    case "NotSupportedError":
      return create
        ? "This browser or device can't save this kind of passkey. Please choose another place, or try another browser such as Chrome, Edge or Safari."
        : "This browser or device can't use your passkey. Please try another browser such as Chrome, Edge or Safari.";
    case "AbortError":
      return "The passkey window closed before it finished. Please try again.";
    default:
      return create
        ? "Something went wrong while saving the passkey. Please try again, or choose another place to save it."
        : "Something went wrong with your passkey. Please try again.";
  }
}

/** Minimal view of `navigator.credentials` (injectable for tests). */
export interface CredentialsLike {
  create(o: CredentialCreationOptions): Promise<unknown>;
  get(o: CredentialRequestOptions): Promise<unknown>;
}

export interface PasskeyDeps {
  readonly api?: Api;
  readonly credentials?: CredentialsLike;
  /** Called to remove an orphan credential (PRF unsupported) from the authenticator, if supported. */
  readonly signalUnknown?: (rpId: string, credentialId: string) => Promise<void>;
}

/** Whether WebAuthn is available at all. */
export function webauthnAvailable(): boolean {
  return typeof globalThis.PublicKeyCredential === "function" && typeof navigator !== "undefined" && "credentials" in navigator;
}

/**
 * Best-effort early PRF detection (`getClientCapabilities`, Chrome 133+,
 * Safari 18+). `null` when unknown: the definitive answer comes from the
 * ceremony itself.
 */
export async function prfSupportHint(): Promise<boolean | null> {
  try {
    const pkc = globalThis.PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> };
    if (typeof pkc?.getClientCapabilities !== "function") return null;
    const caps = await pkc.getClientCapabilities();
    return typeof caps["extension:prf"] === "boolean" ? caps["extension:prf"] : null;
  } catch {
    return null;
  }
}

function defaultCredentials(): CredentialsLike {
  return navigator.credentials as unknown as CredentialsLike;
}

async function defaultSignalUnknown(rpId: string, credentialId: string): Promise<void> {
  const pkc = globalThis.PublicKeyCredential as unknown as {
    signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
  };
  if (typeof pkc?.signalUnknownCredential === "function") await pkc.signalUnknownCredential({ rpId, credentialId });
}

async function ceremony<T>(during: "create" | "get", fn: () => Promise<unknown>): Promise<T> {
  let cred: unknown;
  try {
    cred = await fn();
  } catch (e) {
    throw new PasskeyError(passkeyErrorMessage(e, during), e);
  }
  if (cred === null || typeof cred !== "object") throw new PasskeyError(passkeyErrorMessage(null, during));
  return cred as T;
}

function rpIdOf(opts: PublicKeyCredentialCreationOptions): string {
  return opts.rp.id ?? (typeof location !== "undefined" ? location.hostname : "");
}

/** Optional callbacks of {@link registerPasskey}. */
export interface RegisterEvents {
  /**
   * Called right before the confirming `get()` (only when `create()` did not
   * return the PRF output), so the page can say "you'll be asked once more".
   */
  readonly onConfirmPrompt?: () => void;
}

/**
 * Register a new passkey and wrap the owner private key under it.
 *
 * If `create()` returned the PRF output, that is all: one prompt. Otherwise
 * the new credential asserts once (`get()`, with the choice's hints and the
 * credential's transports) for the PRF output, over the server's
 * confirmation challenge when there is one, which is then sent back as
 * `confirm` (optional for the server).
 *
 * Adding a passkey to an account that already has one needs an "add" grant
 * on the session (the first registration leaves one; otherwise call
 * {@link unlockExtractable} first), or expect an {@link ApiError}
 * `reauth_required`.
 *
 * @param ownerKey - the extractable key to wrap (second passkey, or a key
 *   unlocked with {@link unlockExtractable}); `null` on the very first
 *   passkey, which generates the account key pair.
 * @param choice - where the user wants the passkey saved ({@link AuthenticatorChoice});
 *   `"auto"` lets the browser or a password manager extension decide.
 * @returns the extractable key that was wrapped, so the caller can wrap it
 *   for the next passkey. **Drop it** as soon as setup is done.
 * @throws {PrfUnsupportedError} if PRF output cannot be obtained.
 * @throws {PasskeyError} on cancel/duplicate/domain errors.
 * @throws {ApiError} if the server rejects the registration.
 */
export async function registerPasskey(
  ownerKey: ExtractableOwnerKey | null,
  deps: PasskeyDeps = {},
  choice: AuthenticatorChoice = "auto",
  events: RegisterEvents = {},
): Promise<ExtractableOwnerKey> {
  const api = deps.api ?? new Api();
  const credentials = deps.credentials ?? defaultCredentials();
  const salt = prfSalt();

  const begin = await api.registerBegin();
  const options = creationOptionsFromJSON(begin, salt, choice);
  const confirmChallenge = confirmChallengeOf(begin);
  const userHandle = toBytes(options.user.id);
  const cred = await ceremony<CredentialLike>("create", () => credentials.create({ publicKey: options }));

  const ext = cred.getClientExtensionResults();
  let prf = prfOutput(ext);
  let confirm: unknown;
  if (prf === null && ext.prf?.enabled !== true) {
    await (deps.signalUnknown ?? defaultSignalUnknown)(rpIdOf(options), cred.id).catch(() => undefined);
    throw new PrfUnsupportedError();
  }
  if (prf === null) {
    // create() did not evaluate PRF: ask the new credential once more, in
    // the same place (hints + transports), over the server's challenge.
    const allow: PublicKeyCredentialDescriptor = { type: "public-key", id: cred.rawId };
    const transports = cred.response.getTransports?.();
    if (transports && transports.length > 0) allow.transports = transports as AuthenticatorTransport[];
    const hints = choiceHints(choice) ?? hintsFromTransports(transports);
    const request: PublicKeyCredentialRequestOptions & { hints?: string[] } = {
      challenge: confirmChallenge ?? crypto.getRandomValues(new Uint8Array(32)),
      rpId: rpIdOf(options),
      allowCredentials: [allow],
      userVerification: "required",
      timeout: options.timeout ?? 120_000,
      extensions: prfExtension(salt),
    };
    if (hints !== undefined) request.hints = hints;
    events.onConfirmPrompt?.();
    const assertion = await ceremony<CredentialLike>("get", () => credentials.get({ publicKey: request }));
    prf = prfOutput(assertion.getClientExtensionResults());
    if (prf === null) throw new PrfUnsupportedError();
    if (confirmChallenge !== null) confirm = credentialToJSON(assertion);
  }

  const key = ownerKey ?? (await generateOwnerKeyPair());
  try {
    const kek = await deriveKek(prf, userHandle);
    const wrapped = await wrapPrivateKey(kek, key);
    await api.registerFinish({
      credential: credentialToJSON(cred),
      wrapped_privkey: b64urlEncode(wrapped),
      pubkey: b64urlEncode(key.publicKey),
      ...(confirm === undefined ? {} : { confirm }),
    });
  } finally {
    prf.fill(0);
  }
  return key;
}

/** The confirmation challenge of a register/begin body, if any. */
function confirmChallengeOf(begin: unknown): Uint8Array<ArrayBuffer> | null {
  if (begin === null || typeof begin !== "object") return null;
  const c = (begin as { confirm?: { challenge?: unknown } }).confirm?.challenge;
  if (typeof c !== "string" || c === "") return null;
  try {
    return b64uToBytes(c);
  } catch {
    return null;
  }
}

/**
 * Hints for an assertion: the caller's, else, when the server allows a
 * single credential, what its stored transports say (so confirming with the
 * one passkey of a half-done setup opens the right place, not a chooser).
 */
function assertionHints(options: PublicKeyCredentialRequestOptions, hints: readonly string[] | undefined): readonly string[] | undefined {
  if (hints !== undefined) return hints;
  const allow = options.allowCredentials;
  return allow?.length === 1 ? hintsFromTransports(allow[0]?.transports) : undefined;
}

/** Run one passkey assertion for `purpose` (begin, prompt, finish). */
async function assertFor(
  purpose: UnlockPurpose,
  deps: PasskeyDeps,
  hints?: readonly string[],
): Promise<{ cred: CredentialLike; res: UnlockResult }> {
  const api = deps.api ?? new Api();
  const credentials = deps.credentials ?? defaultCredentials();
  const options: PublicKeyCredentialRequestOptions & { hints?: string[] } = requestOptionsFromJSON(await api.unlockBegin({ purpose }), prfSalt());
  const chosen = assertionHints(options, hints);
  if (chosen !== undefined && chosen.length > 0) options.hints = [...chosen];
  const cred = await ceremony<CredentialLike>("get", () => credentials.get({ publicKey: options }));
  try {
    const res = await api.unlockFinish({ credential: credentialToJSON(cred) });
    return { cred, res };
  } catch (e) {
    const prf = prfOutput(cred.getClientExtensionResults());
    prf?.fill(0);
    throw e;
  }
}

async function unlockRaw<T>(
  unwrap: (kek: CryptoKey, wrapped: Uint8Array) => Promise<T>,
  deps: PasskeyDeps,
  purpose: UnlockPurpose = { kind: "unlock" },
  hints?: readonly string[],
): Promise<T> {
  const { cred, res } = await assertFor(purpose, deps, hints);
  const prf = prfOutput(cred.getClientExtensionResults());
  if (prf === null) throw new PrfUnsupportedError("get");
  try {
    const handle = cred.response.userHandle
      ? toBytes(cred.response.userHandle)
      : res.user_handle !== undefined
        ? b64uToBytes(res.user_handle)
        : null;
    if (handle === null || handle.length === 0) {
      throw new PasskeyError("This passkey didn't say which account it belongs to. Please try another of your Dropr passkeys.");
    }
    const kek = await deriveKek(prf, handle);
    try {
      return await unwrap(kek, b64uToBytes(res.wrapped_privkey));
    } catch (e) {
      throw new PasskeyError("This passkey could not unlock your files. Please try another of your Dropr passkeys.", e);
    }
  } finally {
    prf.fill(0);
  }
}

/**
 * Delete one of the account's passkeys: confirms with an existing passkey
 * (a fresh assertion for exactly this deletion), then deletes.
 * @throws {ApiError} `too_few_passkeys` if fewer than two would remain.
 */
export async function deletePasskey(passkeyId: string, deps: PasskeyDeps = {}): Promise<void> {
  const api = deps.api ?? new Api();
  const { cred } = await assertFor({ kind: "delete", passkeyId }, { ...deps, api });
  prfOutput(cred.getClientExtensionResults())?.fill(0);
  await api.deletePasskey(passkeyId);
}

// ---------------------------------------------------------------------------
// In-memory keyring
// ---------------------------------------------------------------------------

let current: OwnerKeyPair | null = null;
let inflight: Promise<OwnerKeyPair> | null = null;

/** The unlocked key pair of this page, or null. */
export function unlockedKey(): OwnerKeyPair | null {
  return current;
}

/** Forget the unlocked key (e.g. on logout or idle). */
export function lock(): void {
  current = null;
}

/** Unlock with a passkey (always prompts) and keep the non-extractable key pair in memory. */
export async function unlock(deps: PasskeyDeps = {}): Promise<OwnerKeyPair> {
  const key = await unlockRaw(unwrapPrivateKey, deps);
  current = key;
  return key;
}

/** The unlocked key, prompting for a passkey only if this page has none yet. Concurrent calls share one prompt. */
export function ensureUnlocked(deps: PasskeyDeps = {}): Promise<OwnerKeyPair> {
  if (current !== null) return Promise.resolve(current);
  inflight ??= unlock(deps).finally(() => {
    inflight = null;
  });
  return inflight;
}

/**
 * Unlock **extractable**, only to register an additional passkey. The
 * assertion also leaves the session's single-use, 5-minute "add" grant that
 * the registration needs. The result is not stored in the keyring; drop it
 * after {@link registerPasskey}.
 *
 * @param hints - WebAuthn hints for the prompt (e.g. where the setup page's
 *   first passkey was saved); by default derived from the stored transports
 *   when the account has a single passkey.
 */
export function unlockExtractable(deps: PasskeyDeps = {}, hints?: readonly string[]): Promise<ExtractableOwnerKey> {
  return unlockRaw(unwrapExtractable, deps, { kind: "add" }, hints);
}

/** For tests only. */
export function _resetKeyring(): void {
  current = null;
  inflight = null;
}
