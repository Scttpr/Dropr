/**
 * QR encoder: GF(256)/Reed–Solomon against published vectors, format and
 * version information against the ISO 18004 tables, capacities, and full
 * decodability through an independent decoder written from the spec (its own
 * block table, function-pattern map, GF tables and syndrome check).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  byteCapacity,
  dataCodewordsFor,
  encodeQr,
  formatBits,
  gfMul,
  penalty,
  qrPathData,
  rsEncode,
  versionBits,
  type QrCode,
} from "../src/lib/qr.ts";

// ---------------------------------------------------------------------------
// Independent reference data (ISO/IEC 18004:2015 tables)
// ---------------------------------------------------------------------------

/** Format information strings for level M, masks 0–7 (Table C.1). */
const FORMAT_M = [
  "101010000010010",
  "101000100100101",
  "101111001111100",
  "101101101001011",
  "100010111111001",
  "100000011001110",
  "100111110010111",
  "100101010100000",
].map((s) => parseInt(s, 2));

/** Version information for versions 7–10 (Table D.1). */
const VERSION_INFO: Record<number, number> = {
  7: 0x07c94,
  8: 0x085bc,
  9: 0x09a99,
  10: 0x0a4d3,
};

/** Level M blocks: [ec codewords per block, [count, data codewords]...] (Table 9). */
const BLOCKS: Record<number, [number, ...[number, number][]]> = {
  1: [10, [1, 16]],
  2: [16, [1, 28]],
  3: [26, [1, 44]],
  4: [18, [2, 32]],
  5: [24, [2, 43]],
  6: [16, [4, 27]],
  7: [18, [4, 31]],
  8: [22, [2, 38], [2, 39]],
  9: [22, [3, 36], [2, 37]],
  10: [26, [4, 43], [1, 44]],
};

/** Byte-mode capacity, level M (Table 7). */
const BYTE_CAPACITY_M = [0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213];

const ALIGN: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

// GF(256) exp/log tables built from the primitive polynomial (independent of gfMul).
const EXP = new Array<number>(512);
const LOG = new Array<number>(256).fill(0);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255] as number;
}
const mulT = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : (EXP[(LOG[a] as number) + (LOG[b] as number)] as number));

// ---------------------------------------------------------------------------
// Independent decoder
// ---------------------------------------------------------------------------

function isFunctionModule(size: number, ver: number, r: number, c: number): boolean {
  if (r <= 8 && c <= 8) return true; // top-left finder + separator + format
  if (r <= 8 && c >= size - 8) return true; // top-right
  if (r >= size - 8 && c <= 8) return true; // bottom-left (+ dark module)
  if (r === 6 || c === 6) return true; // timing
  if (ver >= 7 && ((r <= 5 && c >= size - 11 && c <= size - 9) || (c <= 5 && r >= size - 11 && r <= size - 9))) return true;
  const a = ALIGN[ver] as number[];
  for (const ar of a) {
    for (const ac of a) {
      const nearFinder = (ar === 6 && ac === 6) || (ar === 6 && ac === a.at(-1)) || (ar === a.at(-1) && ac === 6);
      if (!nearFinder && Math.abs(r - ar) <= 2 && Math.abs(c - ac) <= 2) return true;
    }
  }
  return false;
}

function maskSpec(mask: number, i: number, j: number): boolean {
  // i = row, j = column (ISO 18004 Table 10).
  return [
    (i + j) % 2 === 0,
    i % 2 === 0,
    j % 3 === 0,
    (i + j) % 3 === 0,
    (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
    ((i * j) % 2) + ((i * j) % 3) === 0,
    (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
    (((i * j) % 3) + ((i + j) % 2)) % 2 === 0,
  ][mask] as boolean;
}

function decode(qr: QrCode): { text: Uint8Array; mask: number; version: number } {
  const m = qr.modules;
  const size = m.length;
  const at = (r: number, c: number): boolean => (m[r] as readonly boolean[])[c] as boolean;
  assert.equal((size - 17) % 4, 0, "size");
  const ver = (size - 17) / 4;

  // Finder patterns.
  for (const [r0, c0] of [
    [0, 0],
    [0, size - 7],
    [size - 7, 0],
  ] as const) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
        assert.equal(at(r0 + r, c0 + c), ring !== 2, `finder at ${r0},${c0}`);
      }
    }
  }
  // Timing patterns.
  for (let k = 8; k < size - 8; k++) {
    assert.equal(at(6, k), k % 2 === 0, "horizontal timing");
    assert.equal(at(k, 6), k % 2 === 0, "vertical timing");
  }
  assert.equal(at(size - 8, 8), true, "dark module");

  // Format information, both copies.
  let f1 = 0;
  let f2 = 0;
  const f1pos: [number, number][] = [];
  for (let i = 0; i <= 5; i++) f1pos.push([i, 8]);
  f1pos.push([7, 8], [8, 8], [8, 7]);
  for (let i = 9; i < 15; i++) f1pos.push([8, 14 - i]);
  const f2pos: [number, number][] = [];
  for (let i = 0; i < 8; i++) f2pos.push([8, size - 1 - i]);
  for (let i = 8; i < 15; i++) f2pos.push([size - 15 + i, 8]);
  f1pos.forEach(([r, c], i) => (f1 |= (at(r, c) ? 1 : 0) << i));
  f2pos.forEach(([r, c], i) => (f2 |= (at(r, c) ? 1 : 0) << i));
  assert.equal(f1, f2, "format copies agree");
  const mask = FORMAT_M.indexOf(f1);
  assert.ok(mask >= 0, `format bits ${f1.toString(2)} are a level-M format string`);

  if (ver >= 7) {
    let v1 = 0;
    let v2 = 0;
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      v1 |= (at(b, a) ? 1 : 0) << i; // top-right block: row b, column a
      v2 |= (at(a, b) ? 1 : 0) << i; // bottom-left block
    }
    assert.equal(v1, VERSION_INFO[ver]);
    assert.equal(v2, VERSION_INFO[ver]);
  }

  // Read codewords in the zigzag order, unmasking.
  const bits: number[] = [];
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col = 5;
    for (let k = 0; k < size; k++) {
      const r = upward ? size - 1 - k : k;
      for (const c of [col, col - 1]) {
        if (isFunctionModule(size, ver, r, c)) continue;
        bits.push((at(r, c) !== maskSpec(mask, r, c) ? 1 : 0));
      }
    }
    upward = !upward;
  }
  const [ec, ...groups] = BLOCKS[ver] as [number, ...[number, number][]];
  const lens: number[] = groups.flatMap(([count, len]) => new Array<number>(count).fill(len));
  const total = lens.reduce((a, b) => a + b, 0) + ec * lens.length;
  assert.ok(bits.length >= total * 8 && bits.length - total * 8 < 8, "remainder bits < 8");
  const cw: number[] = [];
  for (let i = 0; i < total; i++) cw.push(parseInt(bits.slice(i * 8, i * 8 + 8).join(""), 2));

  // De-interleave.
  const blocks = lens.map(() => [] as number[]);
  let p = 0;
  for (let i = 0; i < Math.max(...lens); i++) for (let b = 0; b < lens.length; b++) if (i < (lens[b] as number)) (blocks[b] as number[]).push(cw[p++] as number);
  for (let i = 0; i < ec; i++) for (const b of blocks) b.push(cw[p++] as number);

  // Syndromes must be zero: block(α^i) = 0 for i < ec.
  for (const b of blocks) {
    for (let i = 0; i < ec; i++) {
      let s = 0;
      for (const c of b) s = mulT(s, EXP[i] as number) ^ c;
      assert.equal(s, 0, "Reed–Solomon syndrome");
    }
  }

  // Parse the data stream.
  const data = blocks.flatMap((b, i) => b.slice(0, lens[i]));
  const dbits = data.flatMap((byte) => Array.from({ length: 8 }, (_, k) => (byte >> (7 - k)) & 1));
  let q = 0;
  const take = (n: number): number => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | (dbits[q++] as number);
    return v;
  };
  assert.equal(take(4), 0b0100, "byte mode");
  const count = take(ver <= 9 ? 8 : 16);
  const text = new Uint8Array(count);
  for (let i = 0; i < count; i++) text[i] = take(8);
  const term = Math.min(4, dbits.length - q);
  assert.equal(take(term), 0, "terminator");
  while (q % 8 !== 0) assert.equal(take(1), 0, "bit padding");
  for (let pad = 0xec; q < dbits.length; pad ^= 0xec ^ 0x11) assert.equal(take(8), pad, "pad codewords");
  return { text, mask, version: ver };
}

// ---------------------------------------------------------------------------

describe("QR: arithmetic", () => {
  it("multiplies in GF(256) like the log tables", () => {
    for (let a = 0; a < 256; a += 7) for (let b = 0; b < 256; b += 5) assert.equal(gfMul(a, b), mulT(a, b));
    assert.equal(gfMul(0x80, 2), 0x1d);
  });

  it("matches the published Reed–Solomon vector for HELLO WORLD 1-M", () => {
    // Data and EC codewords from the well-known worked example (thonky.com / ISO 18004 Annex I style).
    const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
    assert.deepEqual([...rsEncode(data, 10)], [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
  });

  it("produces format information equal to ISO Table C.1 (level M)", () => {
    for (let mask = 0; mask < 8; mask++) assert.equal(formatBits(mask), FORMAT_M[mask]);
  });

  it("produces version information equal to ISO Table D.1", () => {
    for (const v of [7, 8, 9, 10]) assert.equal(versionBits(v), VERSION_INFO[v]);
  });

  it("has the ISO byte-mode capacities for level M", () => {
    for (let v = 1; v <= 10; v++) assert.equal(byteCapacity(v), BYTE_CAPACITY_M[v], `version ${v}`);
  });

  it("pads data codewords with 0xEC 0x11", () => {
    const cw = dataCodewordsFor(new TextEncoder().encode("A"), 1);
    assert.equal(cw.length, 16);
    assert.deepEqual([...cw.subarray(0, 3)], [0x40, 0x14, 0x10]);
    assert.deepEqual([...cw.subarray(3, 7)], [0xec, 0x11, 0xec, 0x11]);
  });
});

describe("QR: encoding is decodable", () => {
  it("round-trips a typical share link and picks the smallest version", () => {
    const url = "https://drop.example.com/s/AAAAAAAAAAAAAAAAAAAAAA#BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const qr = encodeQr(url);
    const d = decode(qr);
    assert.equal(new TextDecoder().decode(d.text), url);
    assert.equal(qr.version, 6); // 92 bytes: v5 holds 84, v6 holds 106
    assert.equal(d.mask, qr.mask);
  });

  it("round-trips every length at every version boundary, all eight masks", () => {
    const lengths = new Set<number>([0, 1]);
    for (let v = 1; v <= 10; v++) {
      lengths.add(BYTE_CAPACITY_M[v] as number);
      if (v > 1) lengths.add((BYTE_CAPACITY_M[v - 1] as number) + 1);
    }
    for (const len of lengths) {
      const payload = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len) & 0xff);
      for (let mask = 0; mask < 8; mask++) {
        const qr = encodeQr(payload, mask);
        const d = decode(qr);
        assert.deepEqual([...d.text], [...payload], `len ${len} mask ${mask}`);
        assert.equal(d.mask, mask);
        const expectV = BYTE_CAPACITY_M.findIndex((c, v) => v > 0 && c >= len);
        assert.equal(qr.version, expectV, `len ${len}`);
      }
    }
  });

  it("round-trips UTF-8 text", () => {
    const s = "https://dröp.example/r/x#ü€😀";
    assert.equal(new TextDecoder().decode(decode(encodeQr(s)).text), s);
  });

  it("chooses the mask with the lowest penalty", () => {
    const url = "https://drop.example.com/r/abcdefghijklmnopqrstuv#0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
    const auto = encodeQr(url);
    const scores = Array.from({ length: 8 }, (_, m) => penalty(encodeQr(url, m).modules));
    assert.equal(penalty(auto.modules), Math.min(...scores));
  });

  it("rejects text beyond version 10", () => {
    assert.throws(() => encodeQr(new Uint8Array(214)), RangeError);
  });
});

describe("QR: SVG path", () => {
  it("emits one merged rectangle per horizontal run, offset by the quiet zone", () => {
    const qr: QrCode = { version: 1, size: 3, mask: 0, modules: [[true, true, false], [false, false, false], [false, true, true]] };
    assert.equal(qrPathData(qr, 4), "M4 4h2v1h-2zM5 6h2v1h-2z");
  });
});
