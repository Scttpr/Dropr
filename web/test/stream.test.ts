/**
 * STREAM: geometry, round trips (streaming vs part-level must be identical),
 * and rejection of truncation, reordering, splicing, tampering, trailing data,
 * misplaced final flags and counter overflow.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import { deriveFileKeys, generateFileKey } from "../src/crypto/filekey.ts";
import {
  CIPHER_PART_SIZE,
  CIPHER_SEGMENT_SIZE,
  MAX_FILE_SIZE,
  MAX_PARTS,
  MAX_PLAINTEXT_SIZE,
  MAX_SEGMENTS,
  PART_SIZE,
  SEGMENT_SIZE,
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
} from "../src/crypto/stream.ts";
import { concatAll, property, randomChunks, Rng, runStream } from "./helpers.ts";

const S = SEGMENT_SIZE;
const CS = CIPHER_SEGMENT_SIZE;

async function newCk(): Promise<CryptoKey> {
  return (await deriveFileKeys(generateFileKey())).content;
}

async function encryptStreaming(ck: CryptoKey, pt: Uint8Array, rng: Rng): Promise<Uint8Array<ArrayBuffer>> {
  return runStream(createEncryptStream(ck), randomChunks(pt, rng));
}

async function encryptByParts(ck: CryptoKey, pt: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const c = ciphertextSize(pt.length);
  const n = partCount(c);
  const parts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const { start, end } = partPlainRange(i, pt.length);
    const part = await encryptPart(ck, i, pt.subarray(start, end), i === n - 1);
    const range = partCipherRange(i, c);
    assert.equal(part.length, range.end - range.start, `part ${i} size`);
    parts.push(part);
  }
  return concatAll(parts);
}

function decrypt(ck: CryptoKey, ct: Uint8Array, rng: Rng, startSegment = 0): Promise<Uint8Array> {
  return runStream(createDecryptStream(ck, { startSegment }), randomChunks(ct, rng));
}

function segments(ct: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let off = 0; off < ct.length; off += CS) out.push(ct.subarray(off, Math.min(off + CS, ct.length)));
  return out;
}

describe("geometry", () => {
  it("matches ARCHITECTURE.md constants", () => {
    assert.equal(CS, 65_552);
    assert.equal(PART_SIZE, 33_554_432);
    assert.equal(CIPHER_PART_SIZE, 33_562_624);
    assert.equal(MAX_PARTS, 3200);
    assert.equal(segmentCipherOffset(7), 7 * 65_552);
  });

  it("known sizes", () => {
    const table: [number, number, number][] = [
      // plaintext, ciphertext, parts
      [0, 16, 1],
      [1, 17, 1],
      [S - 1, S + 15, 1],
      [S, S + 16, 1],
      [S + 1, S + 1 + 32, 1],
      [PART_SIZE - 1, PART_SIZE - 1 + 16 * 512, 1],
      [PART_SIZE, CIPHER_PART_SIZE, 1],
      [PART_SIZE + 1, CIPHER_PART_SIZE + 17, 2],
      [MAX_FILE_SIZE, MAX_PARTS * CIPHER_PART_SIZE, 3200],
    ];
    for (const [p, c, parts] of table) {
      assert.equal(ciphertextSize(p), c, `ciphertextSize(${p})`);
      assert.equal(plaintextSize(c), p, `plaintextSize(${c})`);
      assert.equal(partCount(c), parts, `partCount(${c})`);
    }
  });

  it("ciphertextSize and plaintextSize are mutual inverses", async () => {
    await property(
      2000,
      (rng) => {
        const k = rng.int(0, 3);
        if (k === 0) return rng.int(0, 4 * S);
        if (k === 1) return rng.int(0, 3000) * S + rng.int(-2, 2);
        if (k === 2) return rng.int(0, 4000) * PART_SIZE + rng.int(-2, 2);
        return rng.u32() * 2 ** 16 + rng.int(0, 2 ** 16 - 1); // up to 2^48
      },
      (p) => {
        if (p < 0 || p > MAX_PLAINTEXT_SIZE) {
          assert.throws(() => ciphertextSize(p), FormatError);
          return;
        }
        assert.equal(plaintextSize(ciphertextSize(p)), p);
      },
    );
    await property(
      5000,
      (rng) => (rng.int(0, 1) === 0 ? rng.int(0, 5 * CS) : rng.int(0, 100_000) * CS + rng.int(-20, 20)),
      (c) => {
        let p: number;
        try {
          p = plaintextSize(c);
        } catch (e) {
          assert.ok(e instanceof FormatError);
          // Impossible sizes: negative, < 16, or a remainder of 1..16 bytes after full segments.
          const rem = c % CS;
          assert.ok(c < 16 || (c > CS && rem >= 1 && rem <= 16), `rejected ${c}`);
          return;
        }
        assert.equal(ciphertextSize(p), c);
      },
    );
  });

  it("rejects impossible sizes", () => {
    for (const c of [-1, 0, 1, 15, CS + 1, CS + 16, 3 * CS + 16, 0.5, NaN, Infinity, 2 ** 53, ciphertextSize(MAX_PLAINTEXT_SIZE) + 1]) {
      assert.throws(() => plaintextSize(c), FormatError, String(c));
    }
    for (const p of [-1, 1.5, NaN, MAX_PLAINTEXT_SIZE + 1]) assert.throws(() => ciphertextSize(p), FormatError, String(p));
    assert.equal(segmentCount(MAX_PLAINTEXT_SIZE), MAX_SEGMENTS);
  });

  it("part ranges tile the blob exactly and reject out-of-range indexes", async () => {
    await property(
      300,
      (rng) => rng.int(0, 1) === 0 ? rng.int(0, 5 * PART_SIZE) : rng.int(0, 3200) * PART_SIZE + rng.int(-1, 1),
      (p) => {
        if (p < 0) return;
        const c = ciphertextSize(p);
        const n = partCount(c);
        let cOff = 0;
        let pOff = 0;
        for (let i = 0; i < n; i++) {
          const cr = partCipherRange(i, c);
          const pr = partPlainRange(i, p);
          assert.equal(cr.start, cOff);
          assert.equal(pr.start, pOff);
          assert.equal(cr.end - cr.start, ciphertextSize(pr.end - pr.start), `part ${i}`);
          if (i < n - 1) assert.equal(cr.end - cr.start, CIPHER_PART_SIZE);
          cOff = cr.end;
          pOff = pr.end;
        }
        assert.equal(cOff, c);
        assert.equal(pOff, p);
        assert.throws(() => partCipherRange(n, c), FormatError);
        assert.throws(() => partCipherRange(-1, c), FormatError);
        assert.throws(() => partPlainRange(n, p), FormatError);
      },
    );
  });
});

describe("round trip", () => {
  const sizes = [
    0, 1, 2, 15, 16, 17, S - 1, S, S + 1, 2 * S - 1, 2 * S, 2 * S + 1, 5 * S + 12_345,
    PART_SIZE - 1, PART_SIZE, PART_SIZE + 1, PART_SIZE + S, 2 * PART_SIZE, 2 * PART_SIZE + 3 * S + 5,
  ];

  for (const size of sizes) {
    it(`size ${size}: streaming == part-level, decrypts to input`, async () => {
      const rng = new Rng(size);
      const ck = await newCk();
      const pt = rng.bytes(size);
      const viaStream = await encryptStreaming(ck, pt, rng);
      assert.equal(viaStream.length, ciphertextSize(size));
      const viaParts = await encryptByParts(ck, pt);
      assert.ok(Buffer.from(viaStream).equals(viaParts), "streaming and part-level ciphertext differ");
      assert.ok(Buffer.from(await decrypt(ck, viaStream, rng)).equals(pt));
    });
  }

  it("random sizes and chunkings", async () => {
    const ck = await newCk();
    await property(
      40,
      (rng) => rng.int(0, 1) === 0 ? rng.int(0, 3 * S) : rng.int(0, 40) * S + rng.int(-3, 3),
      async (size, rng) => {
        if (size < 0) return;
        const pt = rng.bytes(size);
        const ct = await encryptStreaming(ck, pt, rng);
        assert.ok(Buffer.from(ct).equals(await encryptByParts(ck, pt)));
        assert.ok(Buffer.from(await decrypt(ck, ct, rng)).equals(pt));
      },
    );
  });

  it("is deterministic for a key and distinct across keys", async () => {
    const pt = new Rng(1).bytes(3 * S);
    const ck1 = await newCk();
    const ck2 = await newCk();
    const a = await encryptByParts(ck1, pt);
    assert.deepEqual(await encryptByParts(ck1, pt), a);
    assert.notDeepEqual(await encryptByParts(ck2, pt), a);
  });
});

describe("resume from an arbitrary segment", () => {
  it("decrypting from segment k yields the plaintext suffix, for every k", async () => {
    const rng = new Rng(42);
    const ck = await newCk();
    const pt = rng.bytes(9 * S + 777);
    const ct = await encryptByParts(ck, pt);
    const n = segmentCount(pt.length);
    for (let k = 0; k < n; k++) {
      const out = await decrypt(ck, ct.subarray(segmentCipherOffset(k)), rng, k);
      assert.ok(Buffer.from(out).equals(pt.subarray(k * S)), `k = ${k}`);
    }
    // Wrong start index for an offset fails.
    await assert.rejects(decrypt(ck, ct.subarray(segmentCipherOffset(3)), rng, 4), DecryptionError);
    await assert.rejects(decrypt(ck, ct.subarray(segmentCipherOffset(3)), rng, 2), DecryptionError);
    // Resuming exactly at the end (no data) is truncation.
    await assert.rejects(decrypt(ck, new Uint8Array(0), rng, n), DecryptionError);
  });

  it("resume across a part boundary", async () => {
    const rng = new Rng(7);
    const ck = await newCk();
    const pt = rng.bytes(PART_SIZE + 3 * S + 1);
    const ct = await encryptByParts(ck, pt);
    for (const k of [510, 511, 512, 513, 515]) {
      const out = await decrypt(ck, ct.subarray(segmentCipherOffset(k)), rng, k);
      assert.ok(Buffer.from(out).equals(pt.subarray(k * S)), `k = ${k}`);
    }
  });

  it("validates startSegment", async () => {
    const ck = await newCk();
    for (const bad of [-1, 1.5, MAX_SEGMENTS, NaN]) {
      assert.throws(() => createDecryptStream(ck, { startSegment: bad }), FormatError, String(bad));
    }
  });
});

describe("rejection", () => {
  async function fixture(size: number, seed: number) {
    const rng = new Rng(seed);
    const ck = await newCk();
    const pt = rng.bytes(size);
    const ct = await encryptByParts(ck, pt);
    return { rng, ck, pt, ct };
  }

  it("truncation at every segment boundary and at random points", async () => {
    for (const size of [0, 1, S, S + 1, 7 * S, 7 * S + 100]) {
      const { rng, ck, ct } = await fixture(size, size + 1);
      for (let cut = 0; cut < ct.length; cut += CS) {
        await assert.rejects(decrypt(ck, ct.subarray(0, cut), rng), DecryptionError, `size ${size} cut ${cut}`);
      }
      for (let i = 0; i < 20 && ct.length > 1; i++) {
        const cut = rng.int(0, ct.length - 1);
        await assert.rejects(decrypt(ck, ct.subarray(0, cut), rng), DecryptionError, `size ${size} cut ${cut}`);
      }
    }
  });

  it("truncation at a part boundary (dropping whole trailing parts)", async () => {
    const { rng, ck, ct } = await fixture(2 * PART_SIZE + 10, 99);
    await assert.rejects(decrypt(ck, ct.subarray(0, CIPHER_PART_SIZE), rng), DecryptionError);
    await assert.rejects(decrypt(ck, ct.subarray(0, 2 * CIPHER_PART_SIZE), rng), DecryptionError);
  });

  it("swapping, duplicating or dropping segments", async () => {
    const { rng, ck, ct } = await fixture(6 * S + 9, 3);
    const segs = segments(ct);
    const n = segs.length;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const s = segs.slice();
        [s[i], s[j]] = [s[j] as Uint8Array, s[i] as Uint8Array];
        await assert.rejects(decrypt(ck, concatAll(s), rng), DecryptionError, `swap ${i},${j}`);
      }
      const dup = [...segs.slice(0, i + 1), ...segs.slice(i)];
      await assert.rejects(decrypt(ck, concatAll(dup), rng), DecryptionError, `dup ${i}`);
      if (i < n - 1) {
        const drop = [...segs.slice(0, i), ...segs.slice(i + 1)];
        await assert.rejects(decrypt(ck, concatAll(drop), rng), DecryptionError, `drop ${i}`);
      }
    }
  });

  it("flipping any bit in sampled positions (every segment's first/last byte, tags, random)", async () => {
    const { rng, ck, ct } = await fixture(4 * S + 50, 5);
    const positions = new Set<number>([0, ct.length - 1]);
    for (let off = 0; off < ct.length; off += CS) {
      const end = Math.min(off + CS, ct.length);
      for (const p of [off, off + 1, end - 17, end - 16, end - 1]) positions.add(p);
    }
    for (let i = 0; i < 60; i++) positions.add(rng.int(0, ct.length - 1));
    for (const p of positions) {
      const bad = ct.slice();
      bad[p] = (bad[p] ?? 0) ^ (1 << rng.int(0, 7));
      await assert.rejects(decrypt(ck, bad, rng), DecryptionError, `byte ${p}`);
    }
  });

  it("splicing segments from another file (same size, different key)", async () => {
    const a = await fixture(5 * S + 3, 11);
    const b = await fixture(5 * S + 3, 12);
    const sa = segments(a.ct);
    const sb = segments(b.ct);
    for (let i = 0; i < sa.length; i++) {
      const s = sa.slice();
      s[i] = sb[i] as Uint8Array;
      await assert.rejects(decrypt(a.ck, concatAll(s), a.rng), DecryptionError, `splice ${i}`);
    }
    // Appending another file's tail, or prefixing with its head, also fails.
    await assert.rejects(decrypt(a.ck, concatAll([...sa.slice(0, 2), ...sb.slice(2)]), a.rng), DecryptionError);
  });

  it("trailing data after the final segment", async () => {
    for (const size of [0, 10, S, 3 * S, 3 * S + 5]) {
      const { rng, ck, ct } = await fixture(size, 20 + size);
      const segs = segments(ct);
      const last = segs[segs.length - 1] as Uint8Array;
      for (const extra of [Uint8Array.of(0), new Uint8Array(16), new Uint8Array(CS), last, rng.bytes(1000)]) {
        await assert.rejects(decrypt(ck, concatAll([ct, extra]), rng), DecryptionError, `size ${size} +${extra.length}`);
      }
      // A valid extra segment with the right key at the next index, still fails:
      // the previous one carried the final flag.
      const next = await encryptSegment(ck, segs.length, rng.bytes(5), true);
      await assert.rejects(decrypt(ck, concatAll([ct, next]), rng), DecryptionError, `size ${size} + forged next`);
    }
  });

  it("final flag must be on the last segment and only there", async () => {
    const ck = await newCk();
    const rng = new Rng(9);
    const full = (): Uint8Array => rng.bytes(S);
    // Middle segment flagged as final.
    const s0 = await encryptSegment(ck, 0, full(), false);
    const s1 = await encryptSegment(ck, 1, full(), true);
    const s2 = await encryptSegment(ck, 2, rng.bytes(10), true);
    await assert.rejects(decrypt(ck, concatAll([s0, s1, s2]), rng), DecryptionError);
    // Last segment not flagged as final (truncation forgery).
    const s2nf = await encryptSegment(ck, 2, full(), false);
    await assert.rejects(decrypt(ck, concatAll([s0, await encryptSegment(ck, 1, full(), false), s2nf]), rng), DecryptionError);
    // Correct one passes.
    const ok = await decrypt(ck, concatAll([s0, await encryptSegment(ck, 1, full(), false), s2]), rng);
    assert.equal(ok.length, 2 * S + 10);
  });

  it("wrong key and empty input", async () => {
    const { rng, ct } = await fixture(3 * S, 30);
    await assert.rejects(decrypt(await newCk(), ct, rng), DecryptionError);
    await assert.rejects(decrypt(await newCk(), new Uint8Array(0), rng), DecryptionError);
  });

  it("an empty final segment is only valid as the whole (empty) file", async () => {
    const ck = await newCk();
    const rng = new Rng(31);
    await assert.rejects(encryptSegment(ck, 1, new Uint8Array(0), true), FormatError);
    // Even with a valid tag, a 16-byte segment at index > 0 is refused structurally.
    const s0 = await encryptSegment(ck, 0, rng.bytes(S), false);
    await assert.rejects(decrypt(ck, concatAll([s0, new Uint8Array(16)]), rng), DecryptionError);
    assert.equal((await decrypt(ck, await encryptSegment(ck, 0, new Uint8Array(0), true), rng)).length, 0);
  });

  it("non-Uint8Array chunks error the stream", async () => {
    const ck = await newCk();
    const ts = createEncryptStream(ck);
    const w = ts.writable.getWriter();
    const r = ts.readable.getReader();
    void r.read().catch(() => {});
    await assert.rejects(w.write("nope" as unknown as Uint8Array), TypeError);
  });
});

describe("segment and part validation, counter bounds", () => {
  it("segment lengths", async () => {
    const ck = await newCk();
    await assert.rejects(encryptSegment(ck, 0, new Uint8Array(S - 1), false), FormatError);
    await assert.rejects(encryptSegment(ck, 0, new Uint8Array(S + 1), true), FormatError);
    await assert.rejects(decryptSegment(ck, 0, new Uint8Array(15), true), DecryptionError);
    await assert.rejects(decryptSegment(ck, 0, new Uint8Array(CS + 1), true), DecryptionError);
    await assert.rejects(decryptSegment(ck, 0, new Uint8Array(CS - 1), false), DecryptionError);
  });

  it("counter overflow is refused, never wrapped", async () => {
    const ck = await newCk();
    const max = MAX_SEGMENTS - 1;
    const last = await encryptSegment(ck, max, Uint8Array.of(1), true);
    assert.deepEqual(await decryptSegment(ck, max, last, true), Uint8Array.of(1));
    await assert.rejects(encryptSegment(ck, MAX_SEGMENTS, Uint8Array.of(1), true), FormatError);
    await assert.rejects(decryptSegment(ck, MAX_SEGMENTS, last, true), FormatError);
    // The nonce of 2^32 would equal the nonce of 0 if wrapped: make sure index 0 does not open it.
    await assert.rejects(decryptSegment(ck, 0, last, true), DecryptionError);
    // Streaming from the last index: a full non-final segment followed by more data must fail on the counter.
    const s = await encryptSegment(ck, max, new Uint8Array(S), false);
    const rng = new Rng(1);
    await assert.rejects(decrypt(ck, concatAll([s, new Uint8Array(17)]), rng, max), FormatError);
    assert.deepEqual(await decrypt(ck, last, rng, max), Uint8Array.of(1));
  });

  it("part lengths and indexes", async () => {
    const ck = await newCk();
    await assert.rejects(encryptPart(ck, 0, new Uint8Array(PART_SIZE - 1), false), FormatError);
    await assert.rejects(encryptPart(ck, 0, new Uint8Array(PART_SIZE + 1), true), FormatError);
    await assert.rejects(encryptPart(ck, 1, new Uint8Array(0), true), FormatError);
    await assert.rejects(encryptPart(ck, -1, new Uint8Array(1), true), FormatError);
    await assert.rejects(encryptPart(ck, MAX_SEGMENTS / 512, new Uint8Array(1), true), FormatError);
    assert.equal((await encryptPart(ck, 0, new Uint8Array(0), true)).length, 16);
    assert.equal((await encryptPart(ck, MAX_SEGMENTS / 512 - 1, new Uint8Array(1), true)).length, 17);
  });
});
