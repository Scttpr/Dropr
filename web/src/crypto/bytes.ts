/**
 * Small byte helpers shared by the crypto modules. Internal; not re-exported.
 *
 * @module
 */

import { FormatError } from "./errors.ts";

/**
 * Byte array backed by a plain (non-shared) `ArrayBuffer`. This is what
 * WebCrypto's `BufferSource` accepts, and what every function here returns.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

/** The WebCrypto `SubtleCrypto` instance (browser main thread, worker, or Node ≥ 24). */
export const subtle: SubtleCrypto = globalThis.crypto.subtle;

const utf8Encoder = new TextEncoder();

/** UTF-8 encode a string. */
export function utf8(s: string): Bytes {
  return utf8Encoder.encode(s);
}

/** Concatenate byte arrays into a fresh buffer. */
export function concat(...parts: readonly Uint8Array[]): Bytes {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** `n` cryptographically secure random bytes. */
export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** True iff every byte is zero, evaluated in constant time. */
export function isAllZero(a: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i] ?? 0;
  return acc === 0;
}

/** Big-endian unsigned integer of `len` bytes (RFC 8017 I2OSP). `n` must be a safe integer. */
export function i2osp(n: number, len: number): Bytes {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("i2osp: invalid integer");
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = v % 256;
    v = Math.floor(v / 256);
  }
  if (v !== 0) throw new RangeError("i2osp: integer too large");
  return out;
}

/**
 * Copy `src` into a fresh `ArrayBuffer`-backed array. Used to accept any
 * `Uint8Array` (including views over `SharedArrayBuffer` or larger buffers)
 * at API boundaries while handing WebCrypto an exact, private copy.
 */
export function copyBytes(src: Uint8Array): Bytes {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/**
 * View `src` as {@link Bytes} without copying when it is already backed by a
 * plain `ArrayBuffer`; copy otherwise (e.g. `SharedArrayBuffer` views, which
 * WebCrypto does not accept). Callers must not mutate `src` until the
 * WebCrypto promise it is passed to has settled.
 */
export function asBytes(src: Uint8Array): Bytes {
  return src.buffer instanceof ArrayBuffer ? (src as Bytes) : copyBytes(src);
}

/** Throw a {@link FormatError} unless `b` is a `Uint8Array` of exactly `len` bytes. */
export function assertLength(b: Uint8Array, len: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length !== len) {
    throw new FormatError(`${what} must be ${len} bytes`);
  }
}
