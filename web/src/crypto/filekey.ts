/**
 * File keys, subkeys and how they travel (FORMAT.md §2, §3, §6).
 *
 * ```
 * FK  = 32 random bytes, fresh per file
 * CK  = HKDF-SHA256(ikm = FK, salt = "", info = "dropr/v1 content", 32)
 * MK  = HKDF-SHA256(ikm = FK, salt = "", info = "dropr/v1 metadata", 32)
 * share link   : https://host/s/<shareId>#<b64url(FK)>
 * request link : https://host/r/<requestId>#<b64url(ownerPublicKey)>
 * wrapped_key  = enc(32) ‖ ct(48) = HPKE.Seal(pkOwner, info = "dropr/v1 request " ‖ requestId, aad = "", FK)
 * ```
 *
 * @module
 */

import { b64urlDecode, b64urlEncode } from "./b64.ts";
import { assertLength, type Bytes, concat, randomBytes, utf8 } from "./bytes.ts";
import { DecryptionError, FormatError } from "./errors.ts";
import { HPKE_ENC_SIZE, HPKE_TAG_SIZE, type HpkeRecipient, open, seal, X25519_KEY_SIZE } from "./hpke.ts";
import { hkdfAesGcmKey } from "./kdf.ts";

/** File key length in bytes. */
export const FILE_KEY_SIZE = 32;
/** Length of a request-flow `wrapped_key`: enc(32) ‖ ct(32 + 16). */
export const WRAPPED_FILE_KEY_SIZE = HPKE_ENC_SIZE + FILE_KEY_SIZE + HPKE_TAG_SIZE; // 80

const EMPTY = new Uint8Array(0);

/** Per-file subkeys. Both are non-extractable AES-256-GCM keys. */
export interface FileKeys {
  /** CK: STREAM content key. */
  readonly content: CryptoKey;
  /** MK: metadata key (single message). */
  readonly metadata: CryptoKey;
}

/**
 * Generate a fresh file key. A new FK **must** be generated for every file:
 * nonce uniqueness of both STREAM and metadata encryption relies on it.
 */
export function generateFileKey(): Bytes {
  return randomBytes(FILE_KEY_SIZE);
}

/** Derive CK and MK from FK (domain-separated HKDF; derived bytes never leave WebCrypto). */
export async function deriveFileKeys(fk: Uint8Array): Promise<FileKeys> {
  assertLength(fk, FILE_KEY_SIZE, "file key");
  const [content, metadata] = await Promise.all([
    hkdfAesGcmKey(fk, EMPTY, "dropr/v1 content"),
    hkdfAesGcmKey(fk, EMPTY, "dropr/v1 metadata"),
  ]);
  return { content, metadata };
}

function stripHash(fragment: string): string {
  return fragment.startsWith("#") ? fragment.slice(1) : fragment;
}

/** Share-link fragment for FK: unpadded base64url (43 chars, no `#`). */
export function encodeShareFragment(fk: Uint8Array): string {
  assertLength(fk, FILE_KEY_SIZE, "file key");
  return b64urlEncode(fk);
}

/**
 * Parse a share-link fragment (with or without the leading `#`, e.g.
 * `location.hash`) into FK.
 *
 * @throws {FormatError} unless it is the canonical encoding of 32 bytes.
 */
export function decodeShareFragment(fragment: string): Bytes {
  const fk = b64urlDecode(stripHash(fragment));
  assertLength(fk, FILE_KEY_SIZE, "file key");
  return fk;
}

/** Request-link fragment for the owner's 32-byte X25519 public key. */
export function encodeRequestFragment(publicKey: Uint8Array): string {
  assertLength(publicKey, X25519_KEY_SIZE, "public key");
  return b64urlEncode(publicKey);
}

/**
 * Parse a request-link fragment into the owner's public key.
 *
 * @throws {FormatError} unless it is the canonical encoding of 32 bytes.
 */
export function decodeRequestFragment(fragment: string): Bytes {
  const pk = b64urlDecode(stripHash(fragment));
  assertLength(pk, X25519_KEY_SIZE, "public key");
  return pk;
}

/**
 * HPKE `info` for a request: `"dropr/v1 request " ‖ requestId` (ASCII).
 * `requestId` must be a canonical 22-character base64url 128-bit ID.
 */
function requestInfo(requestId: string): Bytes {
  if (typeof requestId !== "string" || requestId.length !== 22 || b64urlDecode(requestId).length !== 16) {
    throw new FormatError("invalid request id");
  }
  return concat(utf8("dropr/v1 request "), utf8(requestId));
}

/**
 * Seal FK to the request owner's public key (uploader side).
 *
 * Binding `requestId` into HPKE `info` means a wrapped key only opens in the
 * context of the request it was uploaded to: the server cannot move an inbox
 * entry to another request link unnoticed.
 *
 * @param ownerPublicKey - from {@link decodeRequestFragment} (never from the server).
 * @returns `wrapped_key`, exactly {@link WRAPPED_FILE_KEY_SIZE} (80) bytes.
 */
export async function wrapFileKeyForRequest(ownerPublicKey: Uint8Array, requestId: string, fk: Uint8Array): Promise<Bytes> {
  assertLength(fk, FILE_KEY_SIZE, "file key");
  const { enc, ct } = await seal(ownerPublicKey, requestInfo(requestId), EMPTY, fk);
  return concat(enc, ct);
}

/**
 * Open a request-flow `wrapped_key` with the owner's unlocked key pair.
 *
 * @throws {FormatError} if `requestId` is malformed.
 * @throws {DecryptionError} if `wrapped` is not 80 bytes or does not open
 *   (wrong owner key, wrong request id, tampering).
 */
export async function unwrapFileKeyFromRequest(owner: HpkeRecipient, requestId: string, wrapped: Uint8Array): Promise<Bytes> {
  const info = requestInfo(requestId);
  if (!(wrapped instanceof Uint8Array) || wrapped.length !== WRAPPED_FILE_KEY_SIZE) throw new DecryptionError();
  const fk = await open(owner, wrapped.subarray(0, HPKE_ENC_SIZE), info, EMPTY, wrapped.subarray(HPKE_ENC_SIZE));
  if (fk.length !== FILE_KEY_SIZE) throw new DecryptionError();
  return fk;
}
