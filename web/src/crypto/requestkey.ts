/**
 * Request-link key pair and request label (ARCHITECTURE.md §2 "Request link
 * key pair" and "Request label").
 *
 * ```
 * key pair     = X25519, one per request link, generateKey(extractable = false)
 * request link = https://host/r/<requestId>#<b64url(publicKey)>
 * label_meta   = enc(32) ‖ ct = HPKE.Seal(publicKey, info = "dropr/v1 label " ‖ requestId, aad = "", pad(label))
 * ```
 *
 * `pad` (pad.ts) zero-fills the label to 128 or 256 bytes, so `label_meta`
 * is 176 or 304 bytes whatever the label's exact length (audit 2026-11b L-8).
 *
 * Security invariants:
 *
 * - The private key is generated **non-extractable**: no script, Dropr's own
 *   included, can ever read its bytes. The owner's browser keeps the
 *   `CryptoKey` itself (structured-cloned into IndexedDB, see
 *   lib/request-keys.ts); it never leaves that browser.
 * - The server never sees either half, so it cannot substitute the key a
 *   link encrypts to: the public key travels only in the link fragment.
 *
 * @module
 */

import { type Bytes, concat, subtle, utf8 } from "./bytes.ts";
import { DecryptionError, FormatError } from "./errors.ts";
import { requestInfo } from "./filekey.ts";
import { HPKE_ENC_SIZE, HPKE_TAG_SIZE, type HpkeRecipient, open, seal } from "./hpke.ts";
import { PAD_MIN, pad, unpad } from "./pad.ts";

/** Maximum request label length, in UTF-8 bytes (also the largest padded length). */
export const MAX_LABEL_BYTES = 256;

const LABEL_INFO = "dropr/v1 label ";
const EMPTY = new Uint8Array(0);

/** A request link's key pair: the HPKE recipient of every file sent through it. */
export interface RequestKeyPair extends HpkeRecipient {
  /** X25519 private key, `extractable: false`, usage `deriveBits`. */
  readonly privateKey: CryptoKey;
  /** 32-byte raw X25519 public key: the link fragment. */
  readonly publicKey: Bytes;
}

/** Generate a fresh key pair for a new request link (private half non-extractable). */
export async function generateRequestKeyPair(): Promise<RequestKeyPair> {
  const kp = (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

/**
 * Seal an owner-only label to the link's public key. The label binds the
 * request ID, so it can only be set once the link exists.
 *
 * @returns `label_meta` = `enc ‖ ct` (176 or 304 bytes).
 * @throws {FormatError} if `label` is empty, longer than
 *   {@link MAX_LABEL_BYTES} in UTF-8 or contains U+0000 (the padding byte),
 *   or `requestId` is malformed.
 */
export async function sealRequestLabel(publicKey: Uint8Array, requestId: string, label: string): Promise<Bytes> {
  const raw = utf8(label);
  if (raw.length === 0 || raw.length > MAX_LABEL_BYTES) throw new FormatError(`label must be 1..${MAX_LABEL_BYTES} UTF-8 bytes`);
  const pt = pad(raw, MAX_LABEL_BYTES);
  const { enc, ct } = await seal(publicKey, requestInfo(LABEL_INFO, requestId), EMPTY, pt);
  return concat(enc, ct);
}

/**
 * Open a `label_meta` with the link's key pair. Show the result with
 * `textContent` only.
 *
 * @throws {FormatError} if `requestId` is malformed, or the padding is not
 *   canonical or leaves an empty label.
 * @throws {DecryptionError} if it does not open (wrong key pair or request
 *   ID, tampering, bad length) or is not valid UTF-8.
 */
export async function openRequestLabel(link: HpkeRecipient, requestId: string, labelMeta: Uint8Array): Promise<string> {
  const info = requestInfo(LABEL_INFO, requestId);
  const min = HPKE_ENC_SIZE + PAD_MIN + HPKE_TAG_SIZE;
  const max = HPKE_ENC_SIZE + MAX_LABEL_BYTES + HPKE_TAG_SIZE;
  if (!(labelMeta instanceof Uint8Array) || labelMeta.length < min || labelMeta.length > max) {
    throw new DecryptionError();
  }
  const pt = await open(link, labelMeta.subarray(0, HPKE_ENC_SIZE), info, EMPTY, labelMeta.subarray(HPKE_ENC_SIZE));
  const raw = unpad(pt, MAX_LABEL_BYTES);
  if (raw.length === 0) throw new FormatError("empty label");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    throw new DecryptionError();
  }
}
