/**
 * Length-hiding padding for sealed metadata and request labels (FORMAT.md §5.1,
 * audit 2026-11b L-8).
 *
 * ```
 * padded = content ‖ 0x00{L − |content|}
 * L      = the smallest power of two ≥ max(PAD_MIN, |content|)
 * ```
 *
 * `content` never contains a 0x00 byte (JSON text escapes U+0000; labels
 * reject it), so the first 0x00 ends it and the padding is unambiguous.
 * {@link unpad} accepts only the canonical encoding: a bucket length, no
 * byte after the first 0x00 other than 0x00, and the smallest bucket that
 * fits the content.
 *
 * @module
 */

import type { Bytes } from "./bytes.ts";
import { FormatError } from "./errors.ts";

/** Smallest padded length (bytes). */
export const PAD_MIN = 128;

/** The padded length of `n` content bytes: the smallest power of two ≥ max(PAD_MIN, n). */
export function paddedLength(n: number): number {
  let l = PAD_MIN;
  while (l < n) l *= 2;
  return l;
}

/** Whether `n` is a padded length no greater than `max`. */
export function isPaddedLength(n: number, max: number): boolean {
  return n >= PAD_MIN && n <= max && (n & (n - 1)) === 0;
}

/**
 * Pad `content` to its bucket.
 *
 * @param max - largest allowed padded length (a power of two ≥ PAD_MIN).
 * @throws {FormatError} if `content` contains 0x00 or does not fit in `max`.
 */
export function pad(content: Uint8Array, max: number): Bytes {
  if (content.includes(0)) throw new FormatError("content contains a NUL byte");
  const l = paddedLength(content.length);
  if (l > max) throw new FormatError("content too large");
  const out = new Uint8Array(l);
  out.set(content);
  return out;
}

/**
 * Strip canonical padding.
 *
 * @param max - largest allowed padded length.
 * @throws {FormatError} if the length is not a bucket ≤ `max`, a byte after
 *   the first 0x00 is not 0x00, or a smaller bucket would have fit.
 */
export function unpad(padded: Uint8Array, max: number): Uint8Array {
  if (!isPaddedLength(padded.length, max)) throw new FormatError("invalid padding");
  let end = padded.indexOf(0);
  if (end < 0) end = padded.length;
  for (let i = end; i < padded.length; i++) {
    if (padded[i] !== 0) throw new FormatError("invalid padding");
  }
  if (paddedLength(end) !== padded.length) throw new FormatError("invalid padding");
  return padded.subarray(0, end);
}
