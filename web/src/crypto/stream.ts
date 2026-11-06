/**
 * STREAM online authenticated encryption of file contents
 * (Hoang–Reyhanitabar–Rogaway–Vizár 2015, as used by age and Tink), exactly as
 * specified in docs/FORMAT.md §4 and ARCHITECTURE.md §2:
 *
 * - plaintext is cut into 64 KiB segments; only the last may be shorter, and
 *   it is empty only when the whole file is empty (one empty final segment);
 * - segment `i` is `AES-256-GCM(CK, nonce = 0x00{7} ‖ u32be(i) ‖ last, aad = "")`;
 * - the blob is the concatenation of the ciphertext segments, no header.
 *
 * Security invariants enforced here:
 *
 * - **Order**: each segment is decrypted with the counter it must have, so
 *   reordering, duplication or dropping of segments fails authentication.
 * - **Truncation**: the final segment is authenticated with `last = 1` and
 *   every other with `last = 0`. A stream that ends without a valid final
 *   segment, or that continues after one, is rejected.
 * - **Splicing between files**: CK is unique per file, so segments from
 *   another file never authenticate.
 * - **Counter bound**: at most 2^32 segments; indexes are range-checked
 *   before every operation, never wrapped.
 * - **Bounded memory**: the streaming transforms buffer at most one segment
 *   plus the current input chunk and the segments derived from it; memory is
 *   independent of file size. Feed chunks of a few MiB at most.
 *
 * Streaming decryption releases each segment as soon as it authenticates.
 * Output is only *complete* once the stream closes without error: on error,
 * consumers must discard what they wrote (see FORMAT.md §8.3).
 *
 * @module
 */

import { asBytes, type Bytes, subtle } from "./bytes.ts";
import { DecryptionError, FormatError } from "./errors.ts";

/** Plaintext bytes per segment (64 KiB). */
export const SEGMENT_SIZE = 65_536;
/** AES-GCM tag bytes appended to every segment. */
export const TAG_SIZE = 16;
/** Ciphertext bytes per full segment. */
export const CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + TAG_SIZE; // 65 552
/** Segments per upload part. */
export const SEGMENTS_PER_PART = 512;
/** Plaintext bytes per full part (32 MiB). */
export const PART_SIZE = SEGMENT_SIZE * SEGMENTS_PER_PART; // 33 554 432
/** Ciphertext bytes per full part. */
export const CIPHER_PART_SIZE = CIPHER_SEGMENT_SIZE * SEGMENTS_PER_PART; // 33 562 624
/** Format limit: the segment counter is 32 bits, so at most 2^32 segments. */
export const MAX_SEGMENTS = 2 ** 32;
/** Format limit on plaintext size (2^48 bytes = 256 TiB). */
export const MAX_PLAINTEXT_SIZE = MAX_SEGMENTS * SEGMENT_SIZE;
/** Deployment cap from ARCHITECTURE.md: 100 GiB, i.e. 3200 parts. Enforced by callers, not the format. */
export const MAX_FILE_SIZE = 100 * 2 ** 30;
/** Parts in a {@link MAX_FILE_SIZE} file. */
export const MAX_PARTS = MAX_FILE_SIZE / PART_SIZE; // 3200

// ---------------------------------------------------------------------------
// Geometry (public sizes only; all functions are pure and validate inputs)
// ---------------------------------------------------------------------------

function checkSize(n: number, max: number, what: string): void {
  if (!Number.isSafeInteger(n) || n < 0 || n > max) throw new FormatError(`invalid ${what}`);
}

/** Number of segments for a plaintext of `plainSize` bytes: `max(1, ceil(P / 65536))`. */
export function segmentCount(plainSize: number): number {
  checkSize(plainSize, MAX_PLAINTEXT_SIZE, "plaintext size");
  return Math.max(1, Math.ceil(plainSize / SEGMENT_SIZE));
}

/** Ciphertext size for a plaintext of `plainSize` bytes: `P + 16 · segmentCount(P)`. */
export function ciphertextSize(plainSize: number): number {
  return plainSize + TAG_SIZE * segmentCount(plainSize);
}

/**
 * Inverse of {@link ciphertextSize}.
 *
 * @throws {FormatError} if no plaintext size maps to `cipherSize` (e.g. 0..15,
 *   or a 16-byte remainder after full segments, which would be an empty
 *   non-initial final segment).
 */
export function plaintextSize(cipherSize: number): number {
  checkSize(cipherSize, ciphertextSize(MAX_PLAINTEXT_SIZE), "ciphertext size");
  const full = Math.floor(cipherSize / CIPHER_SEGMENT_SIZE);
  const rem = cipherSize % CIPHER_SEGMENT_SIZE;
  let segments: number;
  if (rem === 0) segments = full;
  else if (rem > TAG_SIZE || (rem === TAG_SIZE && full === 0)) segments = full + 1;
  else segments = 0;
  if (segments === 0) throw new FormatError("invalid ciphertext size");
  return cipherSize - TAG_SIZE * segments;
}

/** Number of upload parts for a ciphertext of `cipherSize` bytes (≥ 1). */
export function partCount(cipherSize: number): number {
  return Math.ceil(segmentCount(plaintextSize(cipherSize)) / SEGMENTS_PER_PART);
}

/** A half-open byte range `[start, end)`. */
export interface ByteRange {
  readonly start: number;
  readonly end: number;
}

function checkPartIndex(n: number, parts: number): void {
  if (!Number.isSafeInteger(n) || n < 0 || n >= parts) throw new FormatError("invalid part index");
}

/** Ciphertext byte range of part `n` (0-based) in a blob of `cipherSize` bytes. */
export function partCipherRange(n: number, cipherSize: number): ByteRange {
  checkPartIndex(n, partCount(cipherSize));
  const start = n * CIPHER_PART_SIZE;
  return { start, end: Math.min(start + CIPHER_PART_SIZE, cipherSize) };
}

/** Plaintext byte range of part `n` (0-based) in a file of `plainSize` bytes (for `File.slice`). */
export function partPlainRange(n: number, plainSize: number): ByteRange {
  checkPartIndex(n, Math.ceil(segmentCount(plainSize) / SEGMENTS_PER_PART));
  const start = n * PART_SIZE;
  return { start, end: Math.min(start + PART_SIZE, plainSize) };
}

/** Ciphertext offset of segment `i`: `i · 65552`. Use with {@link createDecryptStream}'s `startSegment` to resume. */
export function segmentCipherOffset(i: number): number {
  checkSegmentIndex(i);
  return i * CIPHER_SEGMENT_SIZE;
}

// ---------------------------------------------------------------------------
// Segment level
// ---------------------------------------------------------------------------

function checkSegmentIndex(i: number): void {
  if (!Number.isSafeInteger(i) || i < 0 || i >= MAX_SEGMENTS) throw new FormatError("invalid segment index");
}

/** `0x00{7} ‖ u32be(index) ‖ (last ? 0x01 : 0x00)`. */
function segmentNonce(index: number, last: boolean): Bytes {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(7, index, false);
  nonce[11] = last ? 1 : 0;
  return nonce;
}

/** Plaintext length rule for segment `index`; `len` is the plaintext length. */
function validSegmentLength(index: number, len: number, last: boolean): boolean {
  if (!last) return len === SEGMENT_SIZE;
  return len <= SEGMENT_SIZE && (len > 0 || index === 0);
}

/**
 * Encrypt one segment.
 *
 * @param ck - content key from {@link deriveFileKeys} (AES-256-GCM).
 * @param index - segment counter, `0 ≤ index < 2^32`.
 * @param plaintext - exactly 64 KiB unless `last`; if `last`, 0..64 KiB and
 *   non-empty unless `index === 0`.
 * @param last - whether this is the final segment of the file.
 * @throws {FormatError} on an invalid index or length.
 */
export async function encryptSegment(ck: CryptoKey, index: number, plaintext: Uint8Array, last: boolean): Promise<Bytes> {
  checkSegmentIndex(index);
  if (!validSegmentLength(index, plaintext.length, last)) throw new FormatError("invalid segment length");
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: segmentNonce(index, last) }, ck, asBytes(plaintext));
  return new Uint8Array(ct);
}

/**
 * Decrypt and authenticate one segment.
 *
 * @throws {FormatError} on an invalid index.
 * @throws {DecryptionError} if the length is impossible for this position or
 *   authentication fails (wrong key, wrong index, wrong `last` flag, tampering).
 */
export async function decryptSegment(ck: CryptoKey, index: number, ciphertext: Uint8Array, last: boolean): Promise<Bytes> {
  checkSegmentIndex(index);
  if (ciphertext.length < TAG_SIZE || !validSegmentLength(index, ciphertext.length - TAG_SIZE, last)) {
    throw new DecryptionError();
  }
  try {
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: segmentNonce(index, last) }, ck, asBytes(ciphertext));
    return new Uint8Array(pt);
  } catch {
    throw new DecryptionError();
  }
}

// ---------------------------------------------------------------------------
// Part level (upload path)
// ---------------------------------------------------------------------------

/** Segments encrypted concurrently inside {@link encryptPart}; bounds transient memory. */
const PART_CONCURRENCY = 8;

/**
 * Encrypt upload part `partIndex` (segments `512·partIndex … 512·partIndex+511`).
 * The result is byte-identical to the corresponding range of the streaming
 * encryption of the whole file.
 *
 * @param ck - content key.
 * @param partIndex - 0-based part number.
 * @param plaintext - exactly {@link PART_SIZE} bytes unless `isLastPart`; the
 *   last part holds 1..PART_SIZE bytes (0 only for an empty file, part 0).
 * @param isLastPart - marks the final segment of this part as the file's last.
 * @returns the ciphertext part, `plaintext.length + 16 · segments` bytes.
 * @throws {FormatError} on an invalid index/length or counter overflow.
 */
export async function encryptPart(ck: CryptoKey, partIndex: number, plaintext: Uint8Array, isLastPart: boolean): Promise<Bytes> {
  if (!Number.isSafeInteger(partIndex) || partIndex < 0 || partIndex >= MAX_SEGMENTS / SEGMENTS_PER_PART) {
    throw new FormatError("invalid part index");
  }
  const len = plaintext.length;
  const ok = isLastPart ? len <= PART_SIZE && (len > 0 || partIndex === 0) : len === PART_SIZE;
  if (!ok) throw new FormatError("invalid part length");

  const segments = Math.max(1, Math.ceil(len / SEGMENT_SIZE));
  const first = partIndex * SEGMENTS_PER_PART;
  const out = new Uint8Array(len + TAG_SIZE * segments);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < segments) {
      const s = next++;
      const pt = plaintext.subarray(s * SEGMENT_SIZE, Math.min((s + 1) * SEGMENT_SIZE, len));
      const ct = await encryptSegment(ck, first + s, pt, isLastPart && s === segments - 1);
      out.set(ct, s * CIPHER_SEGMENT_SIZE);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PART_CONCURRENCY, segments) }, worker));
  return out;
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/**
 * Re-segment an arbitrary chunked byte stream into blocks of `blockSize`,
 * holding back the most recent full block until it is known whether more
 * data follows. `emit(block, index, last)` is called for every block in
 * order; at end of stream the held block (possibly short or empty) is emitted
 * with `last = true`.
 */
function segmenter(
  blockSize: number,
  startIndex: number,
  emit: (block: Uint8Array, index: number, last: boolean) => Promise<Bytes>,
  onEnd: (held: number) => void,
): Transformer<Uint8Array, Bytes> {
  const buf = new Uint8Array(blockSize);
  let fill = 0;
  let index = startIndex;
  return {
    async transform(chunk, controller) {
      if (!(chunk instanceof Uint8Array)) throw new TypeError("chunks must be Uint8Array");
      let off = 0;
      while (off < chunk.length) {
        if (fill === blockSize) {
          controller.enqueue(await emit(buf, index, false));
          index++;
          fill = 0;
        }
        const n = Math.min(blockSize - fill, chunk.length - off);
        buf.set(chunk.subarray(off, off + n), fill);
        fill += n;
        off += n;
      }
    },
    async flush(controller) {
      onEnd(fill);
      controller.enqueue(await emit(buf.subarray(0, fill), index, true));
    },
  };
}

/**
 * A `TransformStream` that STREAM-encrypts a whole file: plaintext chunks of
 * any size in, ciphertext segments (one chunk per segment) out. An empty
 * input produces the single 16-byte empty final segment.
 *
 * @throws (errors the stream) {FormatError} past 2^32 segments.
 */
export function createEncryptStream(ck: CryptoKey): TransformStream<Uint8Array, Bytes> {
  return new TransformStream(
    segmenter(SEGMENT_SIZE, 0, (block, i, last) => encryptSegment(ck, i, block, last), () => {}),
  );
}

/** Options for {@link createDecryptStream}. */
export interface DecryptStreamOptions {
  /**
   * Index of the first segment in the input, for resuming a download with an
   * HTTP Range request starting at {@link segmentCipherOffset}(startSegment).
   * Default 0.
   */
  readonly startSegment?: number;
}

/**
 * A `TransformStream` that STREAM-decrypts ciphertext (chunks of any size)
 * into plaintext, one chunk per authenticated segment.
 *
 * The stream errors with {@link DecryptionError} on any tampering, reordering,
 * splicing, wrong key, truncation (input ends without a valid final segment,
 * including empty input) or trailing data after the final segment. Plaintext
 * already emitted before the error is authentic but incomplete; discard it.
 */
export function createDecryptStream(ck: CryptoKey, options: DecryptStreamOptions = {}): TransformStream<Uint8Array, Bytes> {
  const start = options.startSegment ?? 0;
  checkSegmentIndex(start);
  return new TransformStream(
    segmenter(
      CIPHER_SEGMENT_SIZE,
      start,
      (block, i, last) => decryptSegment(ck, i, block, last),
      (held) => {
        if (held === 0) throw new DecryptionError(); // truncated: no final segment
      },
    ),
  );
}
