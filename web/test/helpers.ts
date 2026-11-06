/**
 * Test helpers: hex, a seeded PRNG, a tiny property-test harness and stream
 * plumbing. No dependencies.
 *
 * Property runs are reproducible: set PROP_SEED=<n> to replay a failure (the
 * failing seed and case are printed in the assertion message).
 */

import assert from "node:assert/strict";

export function hex(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("hex");
}

export function unhex(s: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})*$/i.test(s)) throw new Error(`bad hex: ${s}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concatAll(parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** sfc32: small, fast, good-quality 32-bit PRNG (not cryptographic; tests only). */
export class Rng {
  private a: number;
  private b: number;
  private c: number;
  private d: number;
  constructor(seed: number) {
    this.a = 0x9e3779b9;
    this.b = 0x243f6a88;
    this.c = 0xb7e15162;
    this.d = seed >>> 0;
    for (let i = 0; i < 16; i++) this.u32();
  }
  u32(): number {
    const t = (((this.a + this.b) | 0) + this.d) | 0;
    this.d = (this.d + 1) | 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) | 0;
    this.c = (this.c << 21) | (this.c >>> 11);
    this.c = (this.c + t) | 0;
    return t >>> 0;
  }
  /** Uniform integer in [lo, hi] (inclusive), hi - lo < 2^32. */
  int(lo: number, hi: number): number {
    return lo + (this.u32() % (hi - lo + 1));
  }
  pick<T>(xs: readonly T[]): T {
    const x = xs[this.int(0, xs.length - 1)];
    if (x === undefined) throw new Error("pick from empty array");
    return x;
  }
  bytes(n: number): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(n);
    const words = new Uint32Array(out.buffer, 0, n >>> 2);
    for (let i = 0; i < words.length; i++) words[i] = this.u32();
    for (let i = words.length * 4; i < n; i++) out[i] = this.u32() & 0xff;
    return out;
  }
}

export const BASE_SEED = process.env["PROP_SEED"] !== undefined ? Number(process.env["PROP_SEED"]) : 0xd5017;

/**
 * Run `check` on `runs` generated cases. Each case gets its own seed derived
 * from BASE_SEED so a single failing case can be replayed.
 */
export async function property<T>(
  runs: number,
  gen: (rng: Rng) => T,
  check: (value: T, rng: Rng) => Promise<void> | void,
  describe: (value: T) => string = (v) => JSON.stringify(v),
): Promise<void> {
  for (let i = 0; i < runs; i++) {
    const seed = (BASE_SEED + i * 0x9e3779b1) >>> 0;
    const rng = new Rng(seed);
    const value = gen(rng);
    try {
      await check(value, rng);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      assert.fail(`property failed (PROP_SEED=${BASE_SEED}, case ${i}, seed ${seed}, input ${describe(value)}): ${msg}`);
    }
  }
}

/** Feed `chunks` through `ts` and collect the output. Rejects if the stream errors. */
export async function runStream(
  ts: TransformStream<Uint8Array, Uint8Array>,
  chunks: readonly Uint8Array[],
): Promise<Uint8Array<ArrayBuffer>> {
  const src = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      controller.close();
    },
  });
  const out: Uint8Array[] = [];
  const reader = src.pipeThrough(ts).getReader();
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    out.push(r.value);
  }
  return concatAll(out);
}

/** Split `data` into chunks of random sizes (including empty chunks). */
export function randomChunks(data: Uint8Array, rng: Rng, maxChunk = 200_000): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  let off = 0;
  while (off < data.length) {
    const n = rng.int(0, 7) === 0 ? 0 : rng.int(1, maxChunk);
    chunks.push(data.subarray(off, Math.min(off + n, data.length)));
    off += n;
  }
  if (rng.int(0, 1) === 0) chunks.push(new Uint8Array(0));
  return chunks;
}
