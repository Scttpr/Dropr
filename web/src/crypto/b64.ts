/**
 * Strict base64url (RFC 4648 §5) without padding.
 *
 * Decoding is strict so that every byte string has exactly one accepted
 * encoding: padding (`=`), whitespace, the standard alphabet (`+`, `/`), a
 * length ≡ 1 (mod 4) and non-zero unused trailing bits are all rejected.
 *
 * The character mapping is branch-free and table-free (after libsodium's
 * `sodium_base642bin`), because this codec handles secret key material (file
 * keys in URL fragments, private-key JWK fields). Only the *validity* of the
 * input, a public fact, influences control flow.
 *
 * @module
 */

import type { Bytes } from "./bytes.ts";
import { FormatError } from "./errors.ts";

// 0xFF if x == y else 0 (x, y < 2^16).
const eq = (x: number, y: number): number => (((0 - (x ^ y)) >>> 8) & 0xff) ^ 0xff;
// 0xFF if x > y else 0 (x, y < 2^16).
const gt = (x: number, y: number): number => ((y - x) >>> 8) & 0xff;
const ge = (x: number, y: number): number => gt(y, x) ^ 0xff;
const lt = (x: number, y: number): number => gt(y, x);
const le = (x: number, y: number): number => ge(y, x);

function byteToChar(x: number): number {
  return (
    (lt(x, 26) & (x + 65)) |
    (ge(x, 26) & lt(x, 52) & (x + 71)) |
    (ge(x, 52) & lt(x, 62) & (x - 4)) |
    (eq(x, 62) & 45) |
    (eq(x, 63) & 95)
  );
}

/** Sextet value of `c`, or 0xFF if `c` is not in the base64url alphabet. */
function charToByte(c: number): number {
  const x =
    (ge(c, 65) & le(c, 90) & (c - 65)) |
    (ge(c, 97) & le(c, 122) & (c - 71)) |
    (ge(c, 48) & le(c, 57) & (c + 4)) |
    (eq(c, 45) & 62) |
    (eq(c, 95) & 63);
  return x | (eq(x, 0) & (eq(c, 65) ^ 0xff));
}

/** Encode bytes as unpadded base64url. */
export function b64urlEncode(bytes: Uint8Array): string {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    acc = ((acc << 8) | (bytes[i] ?? 0)) & 0xffff;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push(byteToChar((acc >>> bits) & 0x3f));
    }
  }
  if (bits > 0) out.push(byteToChar((acc << (6 - bits)) & 0x3f));
  return String.fromCharCode(...out);
}

/**
 * Decode unpadded base64url, strictly.
 *
 * @throws {FormatError} if `s` is not the canonical unpadded base64url
 *   encoding of some byte string.
 */
export function b64urlDecode(s: string): Bytes {
  if (typeof s !== "string" || s.length % 4 === 1) throw new FormatError("invalid base64url");
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let invalid = 0;
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = charToByte(c & 0xff);
    invalid |= eq(v, 0xff) | gt(c, 0xff); // outside alphabet, or not even Latin-1
    acc = ((acc << 6) | (v & 0x3f)) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // Canonical form: the unused low bits of the last character must be zero.
  invalid |= acc & ((1 << bits) - 1);
  if (invalid !== 0) throw new FormatError("invalid base64url");
  return out;
}
