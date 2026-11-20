/**
 * Stored (uncompressed) ZIP archives built as a `Blob`, so several files can
 * travel as one share without changing the encrypted format: the archive is
 * encrypted and uploaded like any other file.
 *
 * The archive is a composite `Blob` of small header buffers and the original
 * `File` objects: nothing is read into memory, and `Blob.slice()` keeps the
 * uploader's part-by-part reads (and resume) working unchanged. Sizes are
 * known up front, so headers carry the real sizes and CRC-32 (no data
 * descriptors). ZIP64 records are added only where a size, an offset or the
 * entry count needs them (APPNOTE 6.3.10 §4.3, §4.5.3). Names are UTF-8
 * (flag bit 11), with an Info-ZIP Unicode Path field when not ASCII.
 *
 * The CRC-32 of each file needs one read pass before the archive can be
 * built: {@link withChecksums}.
 *
 * @module
 */

/** One archive member. `crc32` is required by {@link buildZip}'s output to be valid. */
export interface ZipInput {
  /** Name inside the archive (already sanitized: see {@link zipInputs}). */
  readonly name: string;
  readonly data: Blob;
  /** Modification time, ms since the epoch. */
  readonly lastModified: number;
  /** CRC-32 of `data`; 0 until {@link withChecksums} computed it. */
  readonly crc32: number;
}

export interface ZipOptions {
  /** Write ZIP64 records even when nothing needs them (tests). */
  readonly forceZip64?: boolean;
}

const U32_MAX = 0xffff_ffff;
const U16_MAX = 0xffff;
const FLAG_UTF8 = 0x0800;
const VERSION_DEFAULT = 20;
const VERSION_ZIP64 = 45;
const encoder = new TextEncoder();

// ---- CRC-32 (IEEE 802.3, reflected 0xEDB88320), slicing-by-8 -------------

const CRC_TABLES: readonly Uint32Array[] = (() => {
  const t: Uint32Array[] = Array.from({ length: 8 }, () => new Uint32Array(256));
  const t0 = t[0] as Uint32Array;
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t0[n] = c >>> 0;
  }
  for (let n = 0; n < 256; n++) {
    let c = t0[n] as number;
    for (let k = 1; k < 8; k++) {
      c = (t0[c & 0xff] as number) ^ (c >>> 8);
      (t[k] as Uint32Array)[n] = c >>> 0;
    }
  }
  return t;
})();

/**
 * CRC-32 of `bytes`, continuing from `previous` (the CRC of the bytes that
 * came before, 0 to start).
 */
export function crc32(bytes: Uint8Array, previous = 0): number {
  const [t0, t1, t2, t3, t4, t5, t6, t7] = CRC_TABLES as [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array,
  ];
  let c = ~previous >>> 0;
  let i = 0;
  const n = bytes.length;
  for (; i + 8 <= n; i += 8) {
    const lo = (c ^ ((bytes[i] as number) | ((bytes[i + 1] as number) << 8) | ((bytes[i + 2] as number) << 16) | ((bytes[i + 3] as number) << 24))) >>> 0;
    c =
      (t7[lo & 0xff] as number) ^
      (t6[(lo >>> 8) & 0xff] as number) ^
      (t5[(lo >>> 16) & 0xff] as number) ^
      (t4[lo >>> 24] as number) ^
      (t3[bytes[i + 4] as number] as number) ^
      (t2[bytes[i + 5] as number] as number) ^
      (t1[bytes[i + 6] as number] as number) ^
      (t0[bytes[i + 7] as number] as number);
  }
  for (; i < n; i++) c = (t0[(c ^ (bytes[i] as number)) & 0xff] as number) ^ (c >>> 8);
  return ~c >>> 0;
}

export interface ChecksumOptions {
  readonly signal?: AbortSignal;
  /** Called after each chunk with the bytes read so far over all inputs. */
  readonly onProgress?: (done: number, total: number) => void;
  /** Read size (default 16 MiB). */
  readonly chunkSize?: number;
}

/** A member could not be read (moved, deleted or changed since it was picked). */
export class FileReadError extends Error {
  override readonly name = "FileReadError";
  readonly entry: string;
  constructor(entry: string, options?: ErrorOptions) {
    super(`could not read ${entry}`, options);
    this.entry = entry;
  }
}

/**
 * Read every input once and return copies carrying their CRC-32. Rejects
 * with an `AbortError` when `signal` aborts, or {@link FileReadError}.
 */
export async function withChecksums(inputs: readonly ZipInput[], opts: ChecksumOptions = {}): Promise<ZipInput[]> {
  const chunk = opts.chunkSize ?? 16 * 1024 * 1024;
  const total = inputs.reduce((s, e) => s + e.data.size, 0);
  let done = 0;
  const out: ZipInput[] = [];
  for (const e of inputs) {
    let c = 0;
    for (let off = 0; off < e.data.size; off += chunk) {
      opts.signal?.throwIfAborted();
      const end = Math.min(off + chunk, e.data.size);
      let bytes: ArrayBuffer;
      try {
        bytes = await e.data.slice(off, end).arrayBuffer();
      } catch (cause) {
        throw new FileReadError(e.name, { cause });
      }
      c = crc32(new Uint8Array(bytes), c);
      done += end - off;
      opts.onProgress?.(done, total);
    }
    opts.signal?.throwIfAborted();
    out.push({ ...e, crc32: c });
  }
  return out;
}

// ---- Names ------------------------------------------------------------------

/** Characters that are path separators, reserved on Windows, or control codes. */
const UNSAFE = /[\u0000-\u001f\u007f/\\:*?"<>|]/g;

/**
 * One path component, safe to extract on Windows, macOS and Linux: no
 * separators, no reserved or control characters, no trailing dot or space,
 * never empty, `.` or `..`.
 */
export function safeEntryName(name: string): string {
  const cleaned = name.normalize("NFC").replace(UNSAFE, "_").replace(/[. ]+$/u, "").trim();
  return cleaned === "" || cleaned === "." || cleaned === ".." ? "file" : cleaned;
}

/**
 * A relative path (`/`-separated, as from a dropped folder) made of safe
 * components: never absolute, never climbing out with `..`, so extracting
 * the archive cannot write outside the folder it is extracted into.
 */
export function safeEntryPath(path: string): string {
  const parts = path.split(/[/\\]+/u).filter((c) => c !== "" && c !== ".");
  return parts.length === 0 ? "file" : parts.map(safeEntryName).join("/");
}

function withSuffix(path: string, n: number): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  return dot > slash + 1 ? `${path.slice(0, dot)} (${n})${path.slice(dot)}` : `${path} (${n})`;
}

/** A picked file and its path relative to what was dropped (its name if picked directly). */
export interface PickedFile {
  readonly file: File;
  readonly path: string;
}

/**
 * Archive members for the picked files, in order: safe paths, made unique
 * case-insensitively ("a.txt", "A.txt" → "a.txt", "A (2).txt") since most
 * desktop file systems would otherwise overwrite one with the other.
 */
export function zipInputs(picked: readonly PickedFile[]): ZipInput[] {
  const taken = new Set<string>();
  return picked.map(({ file, path }) => {
    const base = safeEntryPath(path);
    let name = base;
    for (let n = 2; taken.has(name.toLowerCase()); n++) name = withSuffix(base, n);
    taken.add(name.toLowerCase());
    return { name, data: file, lastModified: file.lastModified, crc32: 0 };
  });
}

// ---- Layout -----------------------------------------------------------------

/** MS-DOS date and time (local time, 2 s resolution), clamped to 1980–2107. */
export function dosDateTime(ms: number): { date: number; time: number } {
  const d = new Date(Number.isFinite(ms) ? ms : 0);
  const y = d.getFullYear();
  if (y < 1980) return { date: (1 << 5) | 1, time: 0 };
  if (y > 2107) return { date: (127 << 9) | (12 << 5) | 31, time: (23 << 11) | (59 << 5) | 29 };
  return {
    date: ((y - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
  };
}

function setU64(v: DataView, at: number, n: number): void {
  v.setUint32(at, n % 0x1_0000_0000, true);
  v.setUint32(at + 4, Math.floor(n / 0x1_0000_0000), true);
}

const EMPTY = new Uint8Array(0);

function concatBytes(a: Uint8Array<ArrayBuffer>, b: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** ZIP64 extended information extra field (0x0001) with these 8-byte values. */
function zip64Extra(values: readonly number[]): Uint8Array<ArrayBuffer> {
  const x = new Uint8Array(4 + 8 * values.length);
  const v = new DataView(x.buffer);
  v.setUint16(0, 0x0001, true);
  v.setUint16(2, 8 * values.length, true);
  values.forEach((n, i) => setU64(v, 4 + 8 * i, n));
  return x;
}

/** Info-ZIP Unicode Path extra field (0x7075, APPNOTE §4.6.9), version 1. */
function unicodePathExtra(name: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const x = new Uint8Array(9 + name.length);
  const v = new DataView(x.buffer);
  v.setUint16(0, 0x7075, true);
  v.setUint16(2, 5 + name.length, true);
  x[4] = 1;
  v.setUint32(5, crc32(name), true); // CRC of the header's name field
  x.set(name, 9);
  return x;
}

/**
 * Build the archive. The result's `size` is exact and does not depend on the
 * CRCs, so a size check can run on unchecksummed inputs before the read pass.
 */
export function buildZip(inputs: readonly ZipInput[], opts: ZipOptions = {}): Blob {
  const force = opts.forceZip64 === true;
  const parts: BlobPart[] = [];
  const central: Uint8Array<ArrayBuffer>[] = [];
  let offset = 0;

  for (const e of inputs) {
    const name = encoder.encode(e.name);
    if (name.length > U16_MAX) throw new RangeError("file name too long for a ZIP archive");
    const size = e.data.size;
    const { date, time } = dosDateTime(e.lastModified);
    const bigSize = force || size >= U32_MAX;
    const bigOffset = force || offset >= U32_MAX;
    const version = bigSize || bigOffset ? VERSION_ZIP64 : VERSION_DEFAULT;
    // Extractors that ignore the UTF-8 flag (unpatched Info-ZIP unzip 6.0)
    // still read the Info-ZIP Unicode Path field: add it to non-ASCII names.
    const unicode = name.some((b) => b >= 0x80) ? unicodePathExtra(name) : EMPTY;
    // ZIP64 extra (§4.5.3): the local one holds both sizes; the central one
    // only the fields set to 0xFFFFFFFF, in order.
    const localExtra = concatBytes(bigSize ? zip64Extra([size, size]) : EMPTY, unicode);
    const centralExtra = concatBytes(
      bigSize || bigOffset ? zip64Extra([...(bigSize ? [size, size] : []), ...(bigOffset ? [offset] : [])]) : EMPTY,
      unicode,
    );

    // Local file header (§4.3.7).
    const local = new Uint8Array(30 + name.length + localExtra.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, version, true);
    lv.setUint16(6, FLAG_UTF8, true);
    lv.setUint16(8, 0, true); // stored
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint32(14, e.crc32, true);
    lv.setUint32(18, bigSize ? U32_MAX : size, true);
    lv.setUint32(22, bigSize ? U32_MAX : size, true);
    lv.setUint16(26, name.length, true);
    lv.setUint16(28, localExtra.length, true);
    local.set(name, 30);
    local.set(localExtra, 30 + name.length);

    // Central directory header (§4.3.12).
    const cd = new Uint8Array(46 + name.length + centralExtra.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, VERSION_ZIP64, true); // made by: MS-DOS attributes, spec 4.5
    cv.setUint16(6, version, true);
    cv.setUint16(8, FLAG_UTF8, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, time, true);
    cv.setUint16(14, date, true);
    cv.setUint32(16, e.crc32, true);
    cv.setUint32(20, bigSize ? U32_MAX : size, true);
    cv.setUint32(24, bigSize ? U32_MAX : size, true);
    cv.setUint16(28, name.length, true);
    cv.setUint16(30, centralExtra.length, true);
    // comment length, disk number, internal and external attributes: 0
    cv.setUint32(42, bigOffset ? U32_MAX : offset, true);
    cd.set(name, 46);
    cd.set(centralExtra, 46 + name.length);

    parts.push(local, e.data);
    central.push(cd);
    offset += local.length + size;
  }

  const cdOffset = offset;
  const cdSize = central.reduce((s, c) => s + c.length, 0);
  parts.push(...central);
  const count = inputs.length;
  const zip64End = force || count >= U16_MAX || cdSize >= U32_MAX || cdOffset >= U32_MAX;

  if (zip64End) {
    // ZIP64 end of central directory record (§4.3.14) and locator (§4.3.15).
    const rec = new Uint8Array(56 + 20);
    const rv = new DataView(rec.buffer);
    rv.setUint32(0, 0x06064b50, true);
    setU64(rv, 4, 44);
    rv.setUint16(12, VERSION_ZIP64, true);
    rv.setUint16(14, VERSION_ZIP64, true);
    // disk numbers: 0
    setU64(rv, 24, count);
    setU64(rv, 32, count);
    setU64(rv, 40, cdSize);
    setU64(rv, 48, cdOffset);
    rv.setUint32(56, 0x07064b50, true);
    // disk with the ZIP64 record: 0
    setU64(rv, 64, cdOffset + cdSize);
    rv.setUint32(72, 1, true);
    parts.push(rec);
  }

  // End of central directory record (§4.3.16).
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, zip64End ? U16_MAX : count, true);
  ev.setUint16(10, zip64End ? U16_MAX : count, true);
  ev.setUint32(12, zip64End ? U32_MAX : cdSize, true);
  ev.setUint32(16, zip64End ? U32_MAX : cdOffset, true);
  parts.push(end);

  return new Blob(parts, { type: "application/zip" });
}
