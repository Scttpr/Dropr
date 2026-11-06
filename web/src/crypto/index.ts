/**
 * Dropr crypto core — public API.
 *
 * Pure modules on WebCrypto only (`globalThis.crypto.subtle`): no third-party
 * crypto, no custom primitives. Byte formats are specified normatively in
 * `docs/FORMAT.md`.
 *
 * Typical flows:
 *
 * - **Share (flow A)**: `generateFileKey` → `deriveFileKeys` → `sealMeta` +
 *   `encryptPart` per part → link `…/s/<id>#` + `encodeShareFragment(fk)`.
 *   Recipient: `decodeShareFragment` → `deriveFileKeys` → `openMeta` →
 *   `createDecryptStream`.
 * - **Request (flow B)**: owner `generateRequestKeyPair` → link `…/r/<id>#` +
 *   `encodeRequestFragment(publicKey)` (optional label: `sealRequestLabel`).
 *   Uploader: `decodeRequestFragment` → `generateFileKey` →
 *   `wrapFileKeyForRequest` + as above. Owner, with the link's stored key
 *   pair: `unwrapFileKeyFromRequest` → as above.
 *
 * Errors: {@link DecryptionError} (authentication failed, no detail) and
 * {@link FormatError} (malformed public input).
 *
 * @module
 */

export { DecryptionError, FormatError } from "./errors.ts";
export type { Bytes } from "./bytes.ts";
export { b64urlDecode, b64urlEncode } from "./b64.ts";
export { hkdf } from "./kdf.ts";
export {
  CIPHER_PART_SIZE,
  CIPHER_SEGMENT_SIZE,
  MAX_FILE_SIZE,
  MAX_PARTS,
  MAX_PLAINTEXT_SIZE,
  MAX_SEGMENTS,
  PART_SIZE,
  SEGMENT_SIZE,
  SEGMENTS_PER_PART,
  TAG_SIZE,
  ciphertextSize,
  createDecryptStream,
  createEncryptStream,
  decryptSegment,
  encryptPart,
  encryptSegment,
  partCipherRange,
  partCount,
  partPlainRange,
  plaintextSize,
  segmentCipherOffset,
  segmentCount,
} from "./stream.ts";
export type { ByteRange, DecryptStreamOptions } from "./stream.ts";
export { HPKE_ENC_SIZE, HPKE_TAG_SIZE, X25519_KEY_SIZE, open as hpkeOpen, seal as hpkeSeal } from "./hpke.ts";
export type { HpkeRecipient, HpkeSealed } from "./hpke.ts";
export { MAX_LABEL_BYTES, generateRequestKeyPair, openRequestLabel, sealRequestLabel } from "./requestkey.ts";
export type { RequestKeyPair } from "./requestkey.ts";
export {
  FALLBACK_NAME,
  FALLBACK_TYPE,
  MAX_META_SIZE,
  MAX_NAME_BYTES,
  openMeta,
  sanitizeFileName,
  sanitizeMediaType,
  sealMeta,
} from "./meta.ts";
export type { FileMeta } from "./meta.ts";
export {
  FILE_KEY_SIZE,
  WRAPPED_FILE_KEY_SIZE,
  decodeRequestFragment,
  decodeShareFragment,
  deriveFileKeys,
  encodeRequestFragment,
  encodeShareFragment,
  generateFileKey,
  unwrapFileKeyFromRequest,
  wrapFileKeyForRequest,
} from "./filekey.ts";
export type { FileKeys } from "./filekey.ts";
