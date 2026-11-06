/**
 * Encrypted file metadata (FORMAT.md §5).
 *
 * ```
 * meta = AES-256-GCM(MK, nonce = 0x00{12}, aad = "dropr/v1 meta",
 *                    UTF-8 JSON {"name": string, "type": string, "size": number})
 * ```
 *
 * The all-zero nonce is safe because MK is derived from a fresh random file
 * key and encrypts exactly one message (see FORMAT.md §8.1).
 *
 * Metadata is authenticated but **not trusted**: on the request flow it is
 * written by an anonymous uploader. {@link openMeta} therefore sanitizes the
 * name (no path separators, control or bidi characters, bounded length) and
 * reduces `type` to a syntactically valid bare media type or
 * `application/octet-stream`. The type is informational only; downloads must
 * always be served as `application/octet-stream` with
 * `Content-Disposition: attachment`.
 *
 * @module
 */

import { type Bytes, subtle, utf8 } from "./bytes.ts";
import { DecryptionError, FormatError } from "./errors.ts";
import { MAX_PLAINTEXT_SIZE } from "./stream.ts";

/** Maximum sealed metadata size in bytes (ciphertext ‖ tag), as stored by the server. */
export const MAX_META_SIZE = 4096;
/** Maximum file name length, in UTF-8 bytes (common filesystem limit). */
export const MAX_NAME_BYTES = 255;
/** Name used when sanitization leaves nothing. */
export const FALLBACK_NAME = "file";
/** Media type used when the declared one is absent or invalid. */
export const FALLBACK_TYPE = "application/octet-stream";

const TAG_SIZE = 16;
const META_AAD = utf8("dropr/v1 meta");

/** Decrypted, sanitized file metadata. */
export interface FileMeta {
  /** Display/save name, sanitized by {@link sanitizeFileName}. */
  readonly name: string;
  /** Bare media type, sanitized by {@link sanitizeMediaType}. Informational only. */
  readonly type: string;
  /** Plaintext size in bytes. */
  readonly size: number;
}

/** Zero nonce: MK is single-use (one message per key). */
function zeroNonce(): Bytes {
  return new Uint8Array(12);
}

// Lone UTF-16 surrogates (possible via JSON "\ud800" escapes).
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
// Controls (C0, DEL, C1) and every default-ignorable code point: bidi
// marks, embeddings, overrides and isolates, zero-width and invisible
// separators, BOM, soft hyphen, Hangul fillers (U+115F, U+1160, U+3164,
// U+FFA0), Mongolian vowel separator…, plus the Arabic letter mark, line and
// paragraph separators and the Braille blank (U+2800), which render as
// nothing. Kept: ZWJ/ZWNJ (U+200C/D, needed by several scripts and emoji
// sequences), variation selectors (emoji presentation) and emoji tag
// characters (subdivision flags). Audit I-4.
const STRIP = /(?![\u200C\u200D\uFE00-\uFE0F\u{E0020}-\u{E007F}])[\p{Cc}\p{Default_Ignorable_Code_Point}\u061C\u2028\u2029\u2800]/gu;
// Runs of spaces of any width (U+00A0, U+2000–U+200A, U+3000…) collapse to
// one ASCII space, so padding cannot push a fake extension out of view.
const SPACES = /\p{Zs}+/gu;
// Path separators and characters invalid in Windows file names.
const REPLACE = /[/\\:*?"<>|]/g;

function utf8Length(cp: number): number {
  return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
}

function truncateUtf8(s: string, maxBytes: number): string {
  let bytes = 0;
  let out = "";
  for (const ch of s) {
    const n = utf8Length(ch.codePointAt(0) ?? 0);
    if (bytes + n > maxBytes) break;
    bytes += n;
    out += ch;
  }
  return out;
}

function trimName(s: string): string {
  return s.trim().replace(/[. ]+$/u, "");
}

/**
 * Make an untrusted file name safe to display and to offer as a download name.
 *
 * Replaces lone surrogates, applies NFC, removes control, bidi and other
 * invisible (default-ignorable) characters, collapses runs of spaces of any
 * width to one space, replaces `/ \ : * ? " < > |` with `_`, trims surrounding
 * whitespace and trailing dots, and truncates to {@link MAX_NAME_BYTES} UTF-8
 * bytes (keeping a short extension). Never returns an empty string, `.` or `..`.
 */
export function sanitizeFileName(name: string): string {
  let s = String(name).replace(LONE_SURROGATE, "\uFFFD").normalize("NFC").replace(STRIP, "").replace(SPACES, " ").replace(REPLACE, "_");
  s = trimName(s); // also turns "." and ".." into ""
  if (utf8(s).length > MAX_NAME_BYTES) {
    const ext = /\.[^.\s]{1,16}$/u.exec(s)?.[0] ?? "";
    s = trimName(truncateUtf8(s.slice(0, s.length - ext.length), MAX_NAME_BYTES - utf8(ext).length)) + ext;
  }
  return s === "" ? FALLBACK_NAME : s;
}

const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/;

/**
 * Reduce an untrusted media type to a bare RFC 6838 `type/subtype` (lower
 * case, no parameters, ≤ 127 chars) or {@link FALLBACK_TYPE}.
 */
export function sanitizeMediaType(type: string): string {
  const t = String(type).trim().toLowerCase();
  return MEDIA_TYPE.test(t) ? t : FALLBACK_TYPE;
}

function checkSize(size: unknown): size is number {
  return typeof size === "number" && Number.isSafeInteger(size) && size >= 0 && size <= MAX_PLAINTEXT_SIZE;
}

/**
 * Seal metadata under MK. Name and type are sanitized before sealing, so
 * what the recipient sees is what the sender's browser stored.
 *
 * @param mk - metadata key from {@link deriveFileKeys}. Must be used for one
 *   message only: never call this twice with the same MK.
 * @throws {FormatError} if `size` is invalid or the result exceeds {@link MAX_META_SIZE}.
 */
export async function sealMeta(mk: CryptoKey, meta: FileMeta): Promise<Bytes> {
  if (!checkSize(meta.size)) throw new FormatError("invalid size");
  const json = JSON.stringify({ name: sanitizeFileName(meta.name), type: sanitizeMediaType(meta.type), size: meta.size });
  const pt = utf8(json);
  if (pt.length + TAG_SIZE > MAX_META_SIZE) throw new FormatError("metadata too large");
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: zeroNonce(), additionalData: META_AAD }, mk, pt);
  return new Uint8Array(ct);
}

/**
 * Open and validate sealed metadata.
 *
 * @param mk - metadata key.
 * @param sealed - the server's `meta` value, base64url-decoded.
 * @param expectedSize - if given, the plaintext size implied by the blob's
 *   ciphertext size ({@link plaintextSize}); a mismatch is rejected so the
 *   displayed size cannot lie about the actual content.
 * @throws {FormatError} if `sealed` exceeds {@link MAX_META_SIZE}, or the
 *   authenticated JSON is malformed or inconsistent with `expectedSize`.
 * @throws {DecryptionError} if authentication fails.
 */
export async function openMeta(mk: CryptoKey, sealed: Uint8Array, expectedSize?: number): Promise<FileMeta> {
  if (sealed.length > MAX_META_SIZE) throw new FormatError("metadata too large");
  if (sealed.length < TAG_SIZE) throw new DecryptionError();
  let pt: Bytes;
  try {
    const buf = await subtle.decrypt({ name: "AES-GCM", iv: zeroNonce(), additionalData: META_AAD }, mk, new Uint8Array(sealed));
    pt = new Uint8Array(buf);
  } catch {
    throw new DecryptionError();
  }
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(pt));
  } catch {
    throw new FormatError("invalid metadata");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new FormatError("invalid metadata");
  const keys = Object.keys(v).sort().join(",");
  const o = v as Record<string, unknown>;
  const name = o["name"];
  const type = o["type"];
  const size = o["size"];
  if (keys !== "name,size,type" || typeof name !== "string" || typeof type !== "string" || !checkSize(size)) {
    throw new FormatError("invalid metadata");
  }
  if (expectedSize !== undefined && size !== expectedSize) throw new FormatError("metadata size mismatch");
  return { name: sanitizeFileName(name), type: sanitizeMediaType(type), size };
}
