/**
 * Minimal QR Code encoder (ISO/IEC 18004): byte mode, error correction
 * level M, versions 1–10 (up to 213 bytes, plenty for a ~100-character
 * link), automatic mask selection. Rendered as SVG built with
 * `createElementNS` (no markup strings, Trusted Types–safe).
 *
 * Structure follows the reference algorithm of Project Nayuki's QR Code
 * generator (MIT), reduced to what Dropr needs.
 *
 * @module
 */

/** Data codewords capacity (bytes) per version for level M, from the block table below. */
const ECC_PER_BLOCK_M = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26] as const;
const BLOCKS_M = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5] as const;
const ALIGNMENT: readonly (readonly number[])[] = [
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
];

export const MAX_VERSION = 10;

/** A QR symbol: `size × size` modules, `true` = dark. */
export interface QrCode {
  readonly version: number;
  readonly size: number;
  readonly mask: number;
  readonly modules: readonly (readonly boolean[])[];
}

// ---------------------------------------------------------------------------
// GF(256) and Reed–Solomon
// ---------------------------------------------------------------------------

/** Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D). */
export function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/** Generator polynomial of degree `d` (coefficients after the leading 1, highest power first). */
export function rsGenerator(degree: number): Uint8Array {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j] ?? 0, root);
      if (j + 1 < degree) result[j] = (result[j] ?? 0) ^ (result[j + 1] ?? 0);
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

/** Reed–Solomon error-correction codewords for `data`. */
export function rsEncode(data: ArrayLike<number>, degree: number): Uint8Array {
  const gen = rsGenerator(degree);
  const rem = new Uint8Array(degree);
  for (let k = 0; k < data.length; k++) {
    const factor = (data[k] ?? 0) ^ (rem[0] ?? 0);
    rem.copyWithin(0, 1);
    rem[degree - 1] = 0;
    for (let i = 0; i < degree; i++) rem[i] = (rem[i] ?? 0) ^ gfMul(gen[i] ?? 0, factor);
  }
  return rem;
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

function rawDataModules(ver: number): number {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

/** Total data codewords (excluding EC) for version `ver`, level M. */
export function dataCodewords(ver: number): number {
  return Math.floor(rawDataModules(ver) / 8) - (ECC_PER_BLOCK_M[ver] ?? 0) * (BLOCKS_M[ver] ?? 0);
}

/** Maximum byte-mode payload for version `ver`, level M. */
export function byteCapacity(ver: number): number {
  const ccBits = ver <= 9 ? 8 : 16;
  return Math.floor((dataCodewords(ver) * 8 - 4 - ccBits) / 8);
}

// ---------------------------------------------------------------------------
// Format / version information
// ---------------------------------------------------------------------------

/** 15-bit format information for level M (bits 00) and `mask`, BCH-coded and masked with 0x5412. */
export function formatBits(mask: number): number {
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

/** 18-bit version information (versions ≥ 7). */
export function versionBits(ver: number): number {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

const bit = (x: number, i: number): boolean => ((x >>> i) & 1) !== 0;

class Matrix {
  readonly size: number;
  readonly m: boolean[][];
  readonly fn: boolean[][];
  constructor(size: number) {
    this.size = size;
    this.m = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  /** Set a function module at column x, row y. */
  set(x: number, y: number, dark: boolean): void {
    (this.m[y] as boolean[])[x] = dark;
    (this.fn[y] as boolean[])[x] = true;
  }
  get(x: number, y: number): boolean {
    return (this.m[y] as boolean[])[x] as boolean;
  }
  isFn(x: number, y: number): boolean {
    return (this.fn[y] as boolean[])[x] as boolean;
  }
}

function drawFunctionPatterns(q: Matrix, ver: number): void {
  const n = q.size;
  for (let i = 0; i < n; i++) {
    q.set(6, i, i % 2 === 0);
    q.set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [
    [3, 3],
    [n - 4, 3],
    [3, n - 4],
  ] as const) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= n || y >= n) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        q.set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  const pos = ALIGNMENT[ver] ?? [];
  const last = pos.length - 1;
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      const cx = pos[i] as number;
      const cy = pos[j] as number;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) q.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  drawFormat(q, 0); // reserve; real bits drawn after masking
  if (ver >= 7) {
    const v = versionBits(ver);
    for (let i = 0; i < 18; i++) {
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      q.set(a, b, bit(v, i));
      q.set(b, a, bit(v, i));
    }
  }
}

function drawFormat(q: Matrix, mask: number): void {
  const f = formatBits(mask);
  const n = q.size;
  for (let i = 0; i <= 5; i++) q.set(8, i, bit(f, i));
  q.set(8, 7, bit(f, 6));
  q.set(8, 8, bit(f, 7));
  q.set(7, 8, bit(f, 8));
  for (let i = 9; i < 15; i++) q.set(14 - i, 8, bit(f, i));
  for (let i = 0; i < 8; i++) q.set(n - 1 - i, 8, bit(f, i));
  for (let i = 8; i < 15; i++) q.set(8, n - 15 + i, bit(f, i));
  q.set(8, n - 8, true); // dark module
}

/** Split into blocks, append RS codewords, interleave. */
function addEccAndInterleave(data: Uint8Array, ver: number): Uint8Array {
  const numBlocks = BLOCKS_M[ver] as number;
  const ecLen = ECC_PER_BLOCK_M[ver] as number;
  const raw = Math.floor(rawDataModules(ver) / 8);
  const numShort = numBlocks - (raw % numBlocks);
  const shortLen = Math.floor(raw / numBlocks); // data + ec of a short block
  const blocks: Uint8Array[] = [];
  const eccs: Uint8Array[] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const len = shortLen - ecLen + (i < numShort ? 0 : 1);
    const d = data.subarray(k, k + len);
    k += len;
    blocks.push(d);
    eccs.push(rsEncode(d, ecLen));
  }
  const out: number[] = [];
  const maxLen = shortLen - ecLen + 1;
  for (let i = 0; i < maxLen; i++) for (const b of blocks) if (i < b.length) out.push(b[i] as number);
  for (let i = 0; i < ecLen; i++) for (const e of eccs) out.push(e[i] as number);
  return Uint8Array.from(out);
}

function drawCodewords(q: Matrix, cw: Uint8Array): void {
  const n = q.size;
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? n - 1 - vert : vert;
        if (!q.isFn(x, y) && i < cw.length * 8) {
          (q.m[y] as boolean[])[x] = bit(cw[i >>> 3] as number, 7 - (i & 7));
          i++;
        }
        // Remainder bits (if any) stay light.
      }
    }
  }
}

/** Mask predicate for column x, row y. */
export function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

function applyMask(q: Matrix, mask: number): void {
  for (let y = 0; y < q.size; y++) {
    for (let x = 0; x < q.size; x++) {
      if (!q.isFn(x, y) && maskBit(mask, x, y)) (q.m[y] as boolean[])[x] = !q.get(x, y);
    }
  }
}

/** Penalty score (ISO 18004 §7.8.3: N1=3, N2=3, N3=40, N4=10). */
export function penalty(m: readonly (readonly boolean[])[]): number {
  const n = m.length;
  const at = (x: number, y: number): boolean => (m[y] as readonly boolean[])[x] as boolean;
  let score = 0;
  const line = (get: (i: number) => boolean): void => {
    // Rule 1: runs of ≥ 5 same-colour modules.
    let run = 1;
    for (let i = 1; i <= n; i++) {
      if (i < n && get(i) === get(i - 1)) run++;
      else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    // Rule 3: 1:1:3:1:1 finder-like pattern with 4 light modules on one side.
    for (let i = 0; i + 11 <= n; i++) {
      const p = [1, 0, 1, 1, 1, 0, 1];
      const coreAt = (o: number): boolean => p.every((v, k) => get(o + k) === (v === 1));
      const lightAt = (o: number): boolean => [0, 1, 2, 3].every((k) => !get(o + k));
      if ((coreAt(i) && lightAt(i + 7)) || (lightAt(i) && coreAt(i + 4))) score += 40;
    }
  };
  for (let y = 0; y < n; y++) line((i) => at(i, y));
  for (let x = 0; x < n; x++) line((i) => at(x, i));
  // Rule 2: 2×2 blocks.
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = at(x, y);
      if (c === at(x + 1, y) && c === at(x, y + 1) && c === at(x + 1, y + 1)) score += 3;
    }
  }
  // Rule 4: dark proportion.
  let dark = 0;
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (at(x, y)) dark++;
  const total = n * n;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  score += Math.max(0, k) * 10;
  return score;
}

/** Build the data codeword sequence (mode, count, payload, terminator, padding) for byte mode. */
export function dataCodewordsFor(payload: Uint8Array, ver: number): Uint8Array {
  const cap = dataCodewords(ver);
  const bits: number[] = [];
  const push = (val: number, len: number): void => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  push(0b0100, 4);
  push(payload.length, ver <= 9 ? 8 : 16);
  for (const b of payload) push(b, 8);
  push(0, Math.min(4, cap * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const out = new Uint8Array(cap);
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let k = 0; k < 8; k++) v = (v << 1) | (bits[i + k] as number);
    out[i / 8] = v;
  }
  for (let i = bits.length / 8, pad = 0xec; i < cap; i++, pad ^= 0xec ^ 0x11) out[i] = pad;
  return out;
}

/**
 * Encode `text` (UTF-8, byte mode, level M) in the smallest version that
 * fits. `forceMask` (0–7) is for tests.
 *
 * @throws RangeError if the text needs more than version 10.
 */
export function encodeQr(text: string | Uint8Array, forceMask?: number): QrCode {
  const payload = typeof text === "string" ? new TextEncoder().encode(text) : text;
  let ver = 1;
  while (ver <= MAX_VERSION && byteCapacity(ver) < payload.length) ver++;
  if (ver > MAX_VERSION) throw new RangeError("text too long for a version 1–10 QR code");
  const size = ver * 4 + 17;
  const cw = addEccAndInterleave(dataCodewordsFor(payload, ver), ver);

  let best: Matrix | null = null;
  let bestMask = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    if (forceMask !== undefined && mask !== forceMask) continue;
    const q = new Matrix(size);
    drawFunctionPatterns(q, ver);
    drawCodewords(q, cw);
    applyMask(q, mask);
    drawFormat(q, mask);
    const s = penalty(q.m);
    if (s < bestScore) {
      best = q;
      bestMask = mask;
      bestScore = s;
    }
  }
  const q = best as Matrix;
  return { version: ver, size, mask: bestMask, modules: q.m };
}

const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * Render as an SVG element (one `<path>` of unit squares, 4-module quiet
 * zone). `label` becomes the accessible name.
 */
export function qrToSvg(qr: QrCode, doc: Document, label: string, quiet = 4): SVGSVGElement {
  const dim = qr.size + 2 * quiet;
  const svg = doc.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${dim} ${dim}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("class", "qr");
  const title = doc.createElementNS(SVG_NS, "title");
  title.textContent = label;
  svg.append(title);
  const bg = doc.createElementNS(SVG_NS, "rect");
  bg.setAttribute("width", String(dim));
  bg.setAttribute("height", String(dim));
  bg.setAttribute("fill", "#fff");
  svg.append(bg);
  const path = doc.createElementNS(SVG_NS, "path");
  path.setAttribute("d", qrPathData(qr, quiet));
  path.setAttribute("fill", "#000");
  svg.append(path);
  return svg;
}

/** SVG path data: one `M x y h1 v1 h-1 z` square per dark module (runs merged horizontally). */
export function qrPathData(qr: QrCode, quiet = 4): string {
  const parts: string[] = [];
  for (let y = 0; y < qr.size; y++) {
    const row = qr.modules[y] as readonly boolean[];
    for (let x = 0; x < qr.size; x++) {
      if (!row[x]) continue;
      let w = 1;
      while (x + w < qr.size && row[x + w]) w++;
      parts.push(`M${x + quiet} ${y + quiet}h${w}v1h-${w}z`);
      x += w - 1;
    }
  }
  return parts.join("");
}
