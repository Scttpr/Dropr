/**
 * Owner X25519 key pair and its per-passkey wrapping (FORMAT.md §7).
 *
 * ```
 * prf  = WebAuthn PRF output for eval.first = SHA-256("dropr/v1 prf")   (32 bytes)
 * KEK  = HKDF-SHA256(ikm = prf, salt = userHandle, info = "dropr/v1 kek", 32)
 * blob = iv(12) ‖ AES-256-GCM(KEK, iv, aad = "dropr/v1 privkey",
 *                             JSON {"kty":"OKP","crv":"X25519","d":…,"x":…})
 * ```
 *
 * Security invariants:
 *
 * - The KEK is derived inside WebCrypto and is non-extractable.
 * - The public key returned by unwrap is the JWK `x` member, which is inside
 *   the authenticated plaintext, and it is additionally checked to be the
 *   public key of `d`. It never comes from the server.
 * - {@link unwrapPrivateKey} returns a **non-extractable** private key: once
 *   unlocked, script running later in the page cannot read the key bytes.
 *
 * @module
 */

import { b64urlDecode } from "./b64.ts";
import { assertLength, type Bytes, concat, constantTimeEqual, randomBytes, subtle, utf8 } from "./bytes.ts";
import { DecryptionError, FormatError } from "./errors.ts";
import { importX25519PrivateKey, X25519_KEY_SIZE, x25519PublicFromPrivate } from "./hpke.ts";
import { hkdfAesGcmKey } from "./kdf.ts";

/** WebAuthn PRF output length used by Dropr (the PRF extension yields 32 bytes). */
export const PRF_OUTPUT_SIZE = 32;
const IV_SIZE = 12;
const TAG_SIZE = 16;
/** Upper bound on a wrapped private key; a canonical blob is ~145 bytes. */
const MAX_WRAPPED_SIZE = 1024;
const PRIVKEY_AAD = utf8("dropr/v1 privkey");
const KEK_INFO = "dropr/v1 kek";

/** SHA-256("dropr/v1 prf"), checked against a live digest in the tests. */
const PRF_SALT_HEX = "87244d17699e2140d4fa99296c33555b7bc7a6b9758972c684d23ae3e5b31757";

/**
 * The PRF evaluation input `eval.first` = SHA-256("dropr/v1 prf") (32 bytes).
 * Returns a fresh copy on every call so callers cannot mutate a shared value.
 */
export function prfSalt(): Bytes {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(PRF_SALT_HEX.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The owner's key pair as used day to day: the private key is non-extractable. */
export interface OwnerKeyPair {
  /** X25519 private key, `extractable: false`, usage `deriveBits`. */
  readonly privateKey: CryptoKey;
  /** 32-byte X25519 public key (authenticated; see module docs). */
  readonly publicKey: Bytes;
}

/**
 * Key pair whose private key is **extractable**. Only exists while it must be
 * (re)wrapped: at first setup and when adding a passkey. Drop references to it
 * as soon as wrapping is done; use {@link toOwnerKeyPair} for everyday use.
 */
export interface ExtractableOwnerKey {
  /** X25519 private key, `extractable: true`, usage `deriveBits`. */
  readonly privateKey: CryptoKey;
  /** 32-byte X25519 public key. */
  readonly publicKey: Bytes;
}

/**
 * Derive the key-encryption key from a WebAuthn PRF output.
 *
 * @param prfOutput - `getClientExtensionResults().prf.results.first` (32 bytes).
 * @param userHandle - the WebAuthn user handle (`user.id`, 1..64 bytes); used
 *   as HKDF salt so a KEK is bound to the account.
 * @returns a non-extractable AES-256-GCM key.
 */
export function deriveKek(prfOutput: Uint8Array, userHandle: Uint8Array): Promise<CryptoKey> {
  assertLength(prfOutput, PRF_OUTPUT_SIZE, "PRF output");
  if (!(userHandle instanceof Uint8Array) || userHandle.length < 1 || userHandle.length > 64) {
    throw new FormatError("user handle must be 1..64 bytes");
  }
  return hkdfAesGcmKey(prfOutput, userHandle, KEK_INFO);
}

/** Generate a fresh owner X25519 key pair (extractable, for initial wrapping). */
export async function generateOwnerKeyPair(): Promise<ExtractableOwnerKey> {
  const kp = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

/** Re-import an extractable owner key as a non-extractable {@link OwnerKeyPair}. */
export async function toOwnerKeyPair(key: ExtractableOwnerKey): Promise<OwnerKeyPair> {
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", key.privateKey));
  try {
    const privateKey = await subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]);
    return { privateKey, publicKey: new Uint8Array(key.publicKey) };
  } finally {
    pkcs8.fill(0);
  }
}

/**
 * Wrap the owner private key under `kek` (one blob per passkey).
 *
 * @returns `iv(12) ‖ ciphertext ‖ tag(16)` with a fresh random IV.
 * @throws {FormatError} if `key.publicKey` is not the public key of `key.privateKey`.
 */
export async function wrapPrivateKey(kek: CryptoKey, key: ExtractableOwnerKey): Promise<Bytes> {
  const jwk = await subtle.exportKey("jwk", key.privateKey);
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || typeof jwk.d !== "string" || typeof jwk.x !== "string") {
    throw new FormatError("not an X25519 private key");
  }
  if (!constantTimeEqual(b64urlDecode(jwk.x), key.publicKey)) throw new FormatError("public key mismatch");
  // Canonical member order; only these four members.
  const plaintext = utf8(JSON.stringify({ kty: "OKP", crv: "X25519", d: jwk.d, x: jwk.x }));
  try {
    const iv = randomBytes(IV_SIZE);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: PRIVKEY_AAD }, kek, plaintext);
    return concat(iv, new Uint8Array(ct));
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Unwrap the owner private key for everyday use.
 *
 * @returns a **non-extractable** private key and the 32-byte public key taken
 *   from the authenticated JWK (and verified to match `d`).
 * @throws {DecryptionError} if the blob does not authenticate under `kek`
 *   (wrong passkey/PRF output, wrong user handle, tampered blob).
 * @throws {FormatError} if the authenticated contents are not a valid JWK.
 */
export function unwrapPrivateKey(kek: CryptoKey, wrapped: Uint8Array): Promise<OwnerKeyPair> {
  return unwrap(kek, wrapped, false);
}

/**
 * Unwrap the owner private key as **extractable**.
 *
 * Use only when registering an additional passkey: the new passkey's KEK must
 * wrap the same private key, and wrapping needs the key bytes. A
 * non-extractable CryptoKey cannot be exported, so the key is unwrapped with
 * an existing passkey into an extractable form, re-wrapped with
 * {@link wrapPrivateKey}, and then dropped. Never keep the result around.
 */
export function unwrapExtractable(kek: CryptoKey, wrapped: Uint8Array): Promise<ExtractableOwnerKey> {
  return unwrap(kek, wrapped, true);
}

async function unwrap(kek: CryptoKey, wrapped: Uint8Array, extractable: boolean): Promise<OwnerKeyPair> {
  if (!(wrapped instanceof Uint8Array) || wrapped.length < IV_SIZE + TAG_SIZE + 1 || wrapped.length > MAX_WRAPPED_SIZE) {
    throw new DecryptionError();
  }
  let plaintext: Bytes;
  try {
    const iv = wrapped.slice(0, IV_SIZE);
    const ct = wrapped.slice(IV_SIZE);
    plaintext = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: PRIVKEY_AAD }, kek, ct));
  } catch {
    throw new DecryptionError();
  }
  let d: Bytes | undefined;
  try {
    const parsed = parseJwk(plaintext);
    d = parsed.d;
    // The JWK is authentic, but still verify x = X25519(d, 9) so a buggy
    // writer can never make us publish a public key we cannot decrypt for.
    const check = await importX25519PrivateKey(d, true);
    if (!constantTimeEqual(await x25519PublicFromPrivate(check), parsed.x)) {
      throw new FormatError("wrapped key: x does not match d");
    }
    const privateKey = await importX25519PrivateKey(d, extractable);
    return { privateKey, publicKey: parsed.x };
  } finally {
    plaintext.fill(0);
    d?.fill(0);
  }
}

/** Strictly parse `{"kty":"OKP","crv":"X25519","d":<b64url 32>,"x":<b64url 32>}`. */
function parseJwk(bytes: Uint8Array): { d: Bytes; x: Bytes } {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new FormatError("wrapped key: invalid JSON");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new FormatError("wrapped key: not an object");
  const keys = Object.keys(v).sort();
  if (keys.length !== 4 || keys.join(",") !== "crv,d,kty,x") throw new FormatError("wrapped key: unexpected members");
  const o = v as Record<string, unknown>;
  if (o["kty"] !== "OKP" || o["crv"] !== "X25519") throw new FormatError("wrapped key: not X25519");
  const d = o["d"];
  const x = o["x"];
  if (typeof d !== "string" || typeof x !== "string") throw new FormatError("wrapped key: bad members");
  const dBytes = b64urlDecode(d);
  const xBytes = b64urlDecode(x);
  if (dBytes.length !== X25519_KEY_SIZE || xBytes.length !== X25519_KEY_SIZE) {
    throw new FormatError("wrapped key: bad key length");
  }
  return { d: dBytes, x: xBytes };
}
