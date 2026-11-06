/**
 * HKDF-SHA256 (RFC 5869) and the HPKE labeled variants (RFC 9180 §4).
 *
 * Two implementations of the same function, both on WebCrypto:
 *
 * - {@link hkdf} / {@link hkdfAesGcmKey} use the native `HKDF` algorithm. Used
 *   for all Dropr subkeys (CK, MK, KEK). `hkdfAesGcmKey` never materialises
 *   the derived key as bytes: it is returned as a non-extractable CryptoKey.
 * - {@link hkdfExtract} / {@link hkdfExpand} are built from `HMAC-SHA256`,
 *   because HPKE needs Extract and Expand separately (WebCrypto only offers
 *   the combined function). RFC 5869 test vectors check both paths agree.
 *
 * @module
 */

import { type Bytes, concat, copyBytes, i2osp, subtle, utf8 } from "./bytes.ts";
import { FormatError } from "./errors.ts";

/** SHA-256 output length in bytes (HKDF `HashLen`). */
export const HASH_LEN = 32;

/**
 * HKDF-SHA256(ikm, salt, info) → `length` bytes, via WebCrypto.
 *
 * An empty salt is equivalent to `HashLen` zero bytes (RFC 5869 §2.2).
 */
export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Bytes> {
  checkLength(length);
  const key = await subtle.importKey("raw", copyBytes(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: copyBytes(salt), info: copyBytes(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-SHA256 straight into a **non-extractable** AES-256-GCM key usable for
 * `encrypt` and `decrypt`. The derived bytes never reach JavaScript.
 */
export async function hkdfAesGcmKey(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const key = await subtle.importKey("raw", copyBytes(ikm), "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: copyBytes(salt), info: utf8(info) },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Bytes> {
  // WebCrypto rejects zero-length HMAC keys. HMAC zero-pads keys shorter than
  // the block size, so an empty key is identical to HashLen zero bytes.
  const k = key.length === 0 ? new Uint8Array(HASH_LEN) : copyBytes(key);
  const ck = await subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", ck, copyBytes(data)));
}

/** HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm) → PRK (32 bytes). */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Bytes> {
  return hmac(salt, ikm);
}

/** HKDF-Expand(prk, info, length) per RFC 5869 §2.3. */
export async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Bytes> {
  checkLength(length);
  if (prk.length < HASH_LEN) throw new FormatError("PRK too short");
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  for (let i = 1, off = 0; off < length; i++) {
    t = await hmac(prk, concat(t, info, Uint8Array.of(i)));
    out.set(t.subarray(0, Math.min(HASH_LEN, length - off)), off);
    off += HASH_LEN;
  }
  return out;
}

function checkLength(length: number): void {
  if (!Number.isInteger(length) || length <= 0 || length > 255 * HASH_LEN) {
    throw new FormatError("invalid HKDF output length");
  }
}

const HPKE_V1 = utf8("HPKE-v1");

/**
 * RFC 9180 LabeledExtract(salt, label, ikm) =
 * Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm).
 */
export function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Promise<Bytes> {
  return hkdfExtract(salt, concat(HPKE_V1, suiteId, utf8(label), ikm));
}

/**
 * RFC 9180 LabeledExpand(prk, label, info, L) =
 * Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L).
 */
export function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Promise<Bytes> {
  return hkdfExpand(prk, concat(i2osp(length, 2), HPKE_V1, suiteId, utf8(label), info), length);
}
