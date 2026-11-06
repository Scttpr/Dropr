/**
 * WebAuthn JSON (de)serialization compatible with go-webauthn.
 *
 * go-webauthn's `protocol.CredentialCreation` / `CredentialAssertion` marshal
 * as `{"publicKey": {...}}` with binary members as unpadded base64url
 * (`URLEncodedBase64`). Its `ParseCredential{Creation,Request}ResponseBody`
 * accept the standard `RegistrationResponseJSON` / `AuthenticationResponseJSON`
 * shapes (WebAuthn L3 §5.1.8/§5.1.9).
 *
 * The browser's own `PublicKeyCredential.parse*OptionsFromJSON()` and
 * `toJSON()` are used when available; a manual implementation covers the
 * others.
 *
 * **Security**: `toJSON()` serializes `clientExtensionResults` *including*
 * `prf.results`, i.e. the PRF output from which the KEK is derived. Sending
 * that to the server would defeat the passkey protection of the inbox, so
 * {@link credentialToJSON} always rebuilds `clientExtensionResults` with
 * only `prf.enabled` (and `credProps`).
 *
 * Pure functions (no `navigator` access): unit-tested in Node.
 *
 * @module
 */

import { b64urlDecode, b64urlEncode } from "../crypto/index.ts";

type Json = Record<string, unknown>;

function isObject(x: unknown): x is Json {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Decode base64url as produced by Go (`RawURLEncoding`); tolerates `=` padding. */
export function b64uToBytes(s: unknown): Uint8Array<ArrayBuffer> {
  if (typeof s !== "string") throw new TypeError("expected a base64url string");
  return b64urlDecode(s.replace(/=+$/, ""));
}

export function bufToB64u(b: ArrayBuffer | ArrayBufferView): string {
  const u8 = b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  return b64urlEncode(u8);
}

/** Copy any BufferSource into a fresh Uint8Array. */
export function toBytes(b: BufferSource): Uint8Array<ArrayBuffer> {
  const u8 = b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  return new Uint8Array(u8);
}

/** Accept `{publicKey: {...}}` (go-webauthn) or the bare options object. */
function unwrapPublicKey(json: unknown): Json {
  if (isObject(json) && isObject(json["publicKey"])) return json["publicKey"];
  if (isObject(json) && typeof json["challenge"] === "string") return json;
  throw new TypeError("malformed WebAuthn options");
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.filter(isObject).map((d) => {
    const out: PublicKeyCredentialDescriptor = { type: "public-key", id: b64uToBytes(d["id"]) };
    if (Array.isArray(d["transports"])) out.transports = d["transports"].filter((t): t is AuthenticatorTransport => typeof t === "string");
    return out;
  });
}

type NativeStatics = {
  parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions;
};

function nativeStatics(): NativeStatics | null {
  const pkc = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  return typeof pkc === "function" ? (pkc as unknown as NativeStatics) : null;
}

/** Manual decoding of creation options JSON (no native helper). */
export function decodeCreationOptions(json: unknown): PublicKeyCredentialCreationOptions {
  const pk = unwrapPublicKey(json);
  const user = pk["user"];
  const rp = pk["rp"];
  if (!isObject(user) || !isObject(rp) || !Array.isArray(pk["pubKeyCredParams"])) throw new TypeError("malformed creation options");
  const out: PublicKeyCredentialCreationOptions = {
    rp: { name: String(rp["name"] ?? ""), ...(typeof rp["id"] === "string" ? { id: rp["id"] } : {}) },
    user: { id: b64uToBytes(user["id"]), name: String(user["name"] ?? ""), displayName: String(user["displayName"] ?? "") },
    challenge: b64uToBytes(pk["challenge"]),
    pubKeyCredParams: pk["pubKeyCredParams"].filter(isObject).map((p) => ({
      type: "public-key" as const,
      alg: Number(p["alg"]),
    })),
  };
  if (typeof pk["timeout"] === "number") out.timeout = pk["timeout"];
  const excl = descriptors(pk["excludeCredentials"]);
  if (excl) out.excludeCredentials = excl;
  if (isObject(pk["authenticatorSelection"])) out.authenticatorSelection = pk["authenticatorSelection"] as AuthenticatorSelectionCriteria;
  if (typeof pk["attestation"] === "string") out.attestation = pk["attestation"] as AttestationConveyancePreference;
  if (Array.isArray(pk["hints"])) (out as { hints?: unknown }).hints = pk["hints"];
  return out;
}

/** Manual decoding of request (assertion) options JSON. */
export function decodeRequestOptions(json: unknown): PublicKeyCredentialRequestOptions {
  const pk = unwrapPublicKey(json);
  const out: PublicKeyCredentialRequestOptions = { challenge: b64uToBytes(pk["challenge"]) };
  if (typeof pk["timeout"] === "number") out.timeout = pk["timeout"];
  if (typeof pk["rpId"] === "string") out.rpId = pk["rpId"];
  const allow = descriptors(pk["allowCredentials"]);
  if (allow) out.allowCredentials = allow;
  if (typeof pk["userVerification"] === "string") out.userVerification = pk["userVerification"] as UserVerificationRequirement;
  if (Array.isArray(pk["hints"])) (out as { hints?: unknown }).hints = pk["hints"];
  return out;
}

/** The PRF extension input Dropr always uses (never the server's). */
export function prfExtension(salt: Uint8Array<ArrayBuffer>): AuthenticationExtensionsClientInputs {
  return { prf: { eval: { first: salt } } };
}

/**
 * Where the user wants the new passkey saved. `"auto"` leaves the choice to
 * the browser, which also lets a password manager extension take the
 * ceremony; the others send WebAuthn `hints` (Chrome, Edge, Safari) and an
 * `authenticatorAttachment` so the browser opens the matching prompt
 * directly. Browsers that ignore hints (Firefox) are only ever given
 * `"auto"` by the setup page (see passkey-env.ts).
 */
export type AuthenticatorChoice = "auto" | "device" | "phone" | "security-key";

const CHOICES: Record<Exclude<AuthenticatorChoice, "auto">, { hint: string; attachment: AuthenticatorAttachment }> = {
  device: { hint: "client-device", attachment: "platform" },
  phone: { hint: "hybrid", attachment: "cross-platform" },
  "security-key": { hint: "security-key", attachment: "cross-platform" },
};

export function isAuthenticatorChoice(v: unknown): v is AuthenticatorChoice {
  return v === "auto" || (typeof v === "string" && Object.hasOwn(CHOICES, v));
}

/** The WebAuthn `hints` for a choice (`undefined` for `"auto"`). */
export function choiceHints(choice: AuthenticatorChoice): string[] | undefined {
  return choice === "auto" ? undefined : [CHOICES[choice].hint];
}

const EXTERNAL = new Set(["usb", "nfc", "ble", "smart-card"]);

/**
 * WebAuthn `hints` for an assertion by a credential with these stored
 * transports, when they say unambiguously where it lives: only `internal`
 * → this device; only `hybrid` → a phone; only external transports (`usb`,
 * `nfc`, `ble`, `smart-card`) → a security key. Anything else (e.g.
 * `["hybrid", "internal"]`, which synced passkeys report) → `undefined`:
 * the browser decides.
 */
export function hintsFromTransports(transports: readonly string[] | undefined): string[] | undefined {
  if (transports === undefined || transports.length === 0) return undefined;
  if (transports.every((t) => t === "internal")) return ["client-device"];
  if (transports.every((t) => t === "hybrid")) return ["hybrid"];
  if (transports.every((t) => EXTERNAL.has(t))) return ["security-key"];
  return undefined;
}

/**
 * Creation options from the server JSON, with Dropr's requirements forced:
 * resident key, user verification, and our PRF input (server extensions are
 * dropped). `choice` sets the hints and attachment (see
 * {@link AuthenticatorChoice}); `"auto"` removes any.
 */
export function creationOptionsFromJSON(
  json: unknown,
  prfSalt: Uint8Array<ArrayBuffer>,
  choice: AuthenticatorChoice = "auto",
): PublicKeyCredentialCreationOptions {
  const pk = unwrapPublicKey(json);
  const native = nativeStatics()?.parseCreationOptionsFromJSON;
  let opts: PublicKeyCredentialCreationOptions;
  try {
    opts = native ? native({ ...pk, extensions: {} }) : decodeCreationOptions(pk);
  } catch {
    opts = decodeCreationOptions(pk);
  }
  const { authenticatorAttachment: _, ...selection } = opts.authenticatorSelection ?? {};
  const out: PublicKeyCredentialCreationOptions & { hints?: string[] } = {
    ...opts,
    authenticatorSelection: {
      ...selection,
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    extensions: prfExtension(prfSalt),
  };
  delete out.hints;
  if (choice !== "auto") {
    out.hints = [CHOICES[choice].hint];
    out.authenticatorSelection = { ...out.authenticatorSelection, authenticatorAttachment: CHOICES[choice].attachment };
  }
  return out;
}

/**
 * Request options from the server JSON, with user verification and our PRF
 * input forced. `hints`, when given, replace the server's.
 */
export function requestOptionsFromJSON(
  json: unknown,
  prfSalt: Uint8Array<ArrayBuffer>,
  hints?: readonly string[],
): PublicKeyCredentialRequestOptions {
  const pk = unwrapPublicKey(json);
  const native = nativeStatics()?.parseRequestOptionsFromJSON;
  let opts: PublicKeyCredentialRequestOptions;
  try {
    opts = native ? native({ ...pk, extensions: {} }) : decodeRequestOptions(pk);
  } catch {
    opts = decodeRequestOptions(pk);
  }
  const out: PublicKeyCredentialRequestOptions & { hints?: string[] } = {
    ...opts,
    userVerification: "required",
    extensions: prfExtension(prfSalt),
  };
  if (hints !== undefined && hints.length > 0) out.hints = [...hints];
  return out;
}

/** Minimal structural view of a PublicKeyCredential (so tests can pass fakes). */
export interface CredentialLike {
  readonly id: string;
  readonly rawId: ArrayBuffer;
  readonly type: string;
  readonly authenticatorAttachment?: string | null;
  readonly response: {
    readonly clientDataJSON: ArrayBuffer;
    readonly attestationObject?: ArrayBuffer;
    readonly authenticatorData?: ArrayBuffer;
    readonly signature?: ArrayBuffer;
    readonly userHandle?: ArrayBuffer | null;
    getTransports?: () => string[];
  };
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
  toJSON?: () => unknown;
}

/** `clientExtensionResults` safe to send: never the PRF output itself. */
export function safeExtensionResults(ext: AuthenticationExtensionsClientOutputs): Json {
  const out: Json = {};
  if (ext.prf !== undefined && typeof ext.prf.enabled === "boolean") out["prf"] = { enabled: ext.prf.enabled };
  if (ext.credProps !== undefined && typeof ext.credProps.rk === "boolean") out["credProps"] = { rk: ext.credProps.rk };
  return out;
}

/**
 * Serialize a credential for `register/finish` or `unlock/finish`
 * (RegistrationResponseJSON / AuthenticationResponseJSON), with
 * `clientExtensionResults` scrubbed of PRF outputs.
 */
export function credentialToJSON(cred: CredentialLike): Json {
  let json: Json | null = null;
  if (typeof cred.toJSON === "function") {
    try {
      const j = cred.toJSON();
      if (isObject(j) && isObject(j["response"])) json = { ...j };
    } catch {
      json = null;
    }
  }
  if (json === null) {
    const r = cred.response;
    const response: Json = { clientDataJSON: bufToB64u(r.clientDataJSON) };
    if (r.attestationObject !== undefined) {
      response["attestationObject"] = bufToB64u(r.attestationObject);
      if (typeof r.getTransports === "function") response["transports"] = r.getTransports();
    } else {
      if (r.authenticatorData === undefined || r.signature === undefined) throw new TypeError("unknown credential response");
      response["authenticatorData"] = bufToB64u(r.authenticatorData);
      response["signature"] = bufToB64u(r.signature);
      response["userHandle"] = r.userHandle ? bufToB64u(r.userHandle) : null;
    }
    json = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response };
    if (cred.authenticatorAttachment) json["authenticatorAttachment"] = cred.authenticatorAttachment;
  }
  json["clientExtensionResults"] = safeExtensionResults(cred.getClientExtensionResults());
  return json;
}

/** `prf.results.first` as bytes (32), or null. */
export function prfOutput(ext: AuthenticationExtensionsClientOutputs): Uint8Array<ArrayBuffer> | null {
  const first = ext.prf?.results?.first;
  if (first === undefined) return null;
  const b = toBytes(first);
  return b.length === 32 ? b : null;
}
