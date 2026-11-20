/**
 * Stored ZIP archives (lib/zip.ts): CRC-32, member names, layout. Archives
 * are checked with an independent reader written here from APPNOTE, not
 * with the writer's own code.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  FileReadError,
  type ZipInput,
  buildZip,
  crc32,
  dosDateTime,
  safeEntryName,
  safeEntryPath,
  withChecksums,
  zipInputs,
} from "../src/lib/zip.ts";

const utf8 = new TextEncoder();

/** Bitwise reference CRC-32. */
function crcRef(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  return ~c >>> 0;
}

function u64(v: DataView, at: number): number {
  return v.getUint32(at, true) + v.getUint32(at + 4, true) * 2 ** 32;
}

interface Read {
  readonly name: string;
  readonly data: Uint8Array;
  readonly crc: number;
  readonly flags: number;
  readonly zip64: boolean;
  /** Name from the Info-ZIP Unicode Path field, if any (checked against the header name). */
  readonly unicodePath: string | null;
}

/** Minimal reader: EOCD (and ZIP64 EOCD), central directory, local headers. */
function readZip(buf: Uint8Array): Read[] {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const eocd = buf.length - 22;
  assert.equal(v.getUint32(eocd, true), 0x06054b50, "EOCD signature");
  let count = v.getUint16(eocd + 10, true);
  let cdSize = v.getUint32(eocd + 12, true);
  let cdOffset = v.getUint32(eocd + 16, true);
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    assert.equal(v.getUint32(loc, true), 0x07064b50, "ZIP64 locator signature");
    const rec = u64(v, loc + 8);
    assert.equal(v.getUint32(rec, true), 0x06064b50, "ZIP64 EOCD signature");
    count = u64(v, rec + 32);
    cdSize = u64(v, rec + 40);
    cdOffset = u64(v, rec + 48);
    assert.equal(rec, cdOffset + cdSize, "ZIP64 record follows the central directory");
  } else {
    assert.equal(eocd, cdOffset + cdSize, "EOCD follows the central directory");
  }
  const out: Read[] = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    assert.equal(v.getUint32(p, true), 0x02014b50, "central header signature");
    const flags = v.getUint16(p + 8, true);
    assert.equal(v.getUint16(p + 10, true), 0, "stored");
    const crc = v.getUint32(p + 16, true);
    let size = v.getUint32(p + 24, true);
    let csize = v.getUint32(p + 20, true);
    const nameLen = v.getUint16(p + 28, true);
    const extraLen = v.getUint16(p + 30, true);
    const commentLen = v.getUint16(p + 32, true);
    let offset = v.getUint32(p + 42, true);
    const name = new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(p + 46, p + 46 + nameLen));
    let zip64 = false;
    let unicodePath: string | null = null;
    let x = p + 46 + nameLen;
    const xEnd = x + extraLen;
    while (x < xEnd) {
      const id = v.getUint16(x, true);
      const len = v.getUint16(x + 2, true);
      if (id === 1) {
        zip64 = true;
        let q = x + 4;
        if (size === 0xffffffff) (size = u64(v, q)), (q += 8);
        if (csize === 0xffffffff) (csize = u64(v, q)), (q += 8);
        if (offset === 0xffffffff) offset = u64(v, q);
      }
      if (id === 0x7075) {
        assert.equal(buf[x + 4], 1, "Unicode Path version");
        assert.equal(v.getUint32(x + 5, true), crcRef(buf.subarray(p + 46, p + 46 + nameLen)), "Unicode Path name CRC");
        unicodePath = new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(x + 9, x + 4 + len));
      }
      x += 4 + len;
    }
    assert.equal(csize, size, "stored: sizes agree");
    // Local header must agree with the central one.
    assert.equal(v.getUint32(offset, true), 0x04034b50, "local header signature");
    assert.equal(v.getUint32(offset + 14, true), crc, "local CRC");
    const lNameLen = v.getUint16(offset + 26, true);
    const lExtraLen = v.getUint16(offset + 28, true);
    assert.equal(lNameLen, nameLen);
    if (v.getUint32(offset + 22, true) === 0xffffffff) {
      const lx = offset + 30 + lNameLen;
      assert.equal(v.getUint16(lx, true), 1, "local ZIP64 extra");
      assert.equal(u64(v, lx + 4), size, "local ZIP64 size");
      assert.equal(u64(v, lx + 12), size, "local ZIP64 compressed size");
    } else {
      assert.equal(v.getUint32(offset + 22, true), size, "local size");
    }
    const start = offset + 30 + lNameLen + lExtraLen;
    out.push({ name, data: buf.slice(start, start + size), crc, flags, zip64, unicodePath });
    p += 46 + nameLen + extraLen + commentLen;
  }
  assert.equal(p, cdOffset + cdSize, "central directory size");
  return out;
}

function file(name: string, content: string | Uint8Array<ArrayBuffer>, lastModified = Date.UTC(2026, 10, 20, 10, 30, 12)): File {
  return new File([typeof content === "string" ? utf8.encode(content) : content], name, { lastModified });
}

async function archive(inputs: ZipInput[], force = false): Promise<Uint8Array> {
  const blob = buildZip(await withChecksums(inputs), { forceZip64: force });
  return new Uint8Array(await blob.arrayBuffer());
}

describe("crc32", () => {
  it("matches the standard check values", () => {
    assert.equal(crc32(new Uint8Array(0)), 0);
    assert.equal(crc32(utf8.encode("123456789")), 0xcbf43926);
    assert.equal(crc32(utf8.encode("The quick brown fox jumps over the lazy dog")), 0x414fa339);
  });

  it("agrees with the bitwise reference at every length and chains", () => {
    const data = new Uint8Array(1000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 131 + 7) & 0xff;
    for (const n of [1, 3, 7, 8, 9, 15, 16, 17, 255, 1000]) {
      assert.equal(crc32(data.subarray(0, n)), crcRef(data.subarray(0, n)), `length ${n}`);
    }
    for (const cut of [0, 1, 5, 8, 333, 1000]) {
      assert.equal(crc32(data.subarray(cut), crc32(data.subarray(0, cut))), crcRef(data), `split at ${cut}`);
    }
  });
});

describe("member names", () => {
  it("makes one safe path component", () => {
    assert.equal(safeEntryName("report.pdf"), "report.pdf");
    assert.equal(safeEntryName("a/b\\c:d*e?f\"g<h>i|j"), "a_b_c_d_e_f_g_h_i_j");
    assert.equal(safeEntryName("tab\there\u0000\u007f"), "tab_here__");
    assert.equal(safeEntryName("trailing. . "), "trailing");
    for (const bad of ["", ".", "..", " ", "..."]) assert.equal(safeEntryName(bad), "file", JSON.stringify(bad));
    assert.equal(safeEntryName("e\u0301te\u0301.txt"), "\u00e9t\u00e9.txt", "NFC");
  });

  it("keeps relative folders and never climbs out", () => {
    assert.equal(safeEntryPath("dossier/sous/a.txt"), "dossier/sous/a.txt");
    assert.equal(safeEntryPath("/etc/passwd"), "etc/passwd");
    assert.equal(safeEntryPath("../../x"), "file/file/x");
    assert.equal(safeEntryPath("a\\..\\b"), "a/file/b");
    assert.equal(safeEntryPath("./a//b/"), "a/b");
    assert.equal(safeEntryPath(""), "file");
    for (const p of ["../../x", "/etc/passwd", "a\\..\\b", "C:/x"]) {
      const out = safeEntryPath(p);
      assert.ok(!out.startsWith("/") && !out.split("/").includes(".."), out);
    }
  });

  it("de-duplicates case-insensitively, before the extension", () => {
    const names = zipInputs([
      { file: file("a.txt", "1"), path: "a.txt" },
      { file: file("A.txt", "2"), path: "A.txt" },
      { file: file("a.txt", "3"), path: "a.txt" },
      { file: file("notes", "4"), path: "notes" },
      { file: file("notes", "5"), path: "notes" },
      { file: file(".env", "6"), path: ".env" },
      { file: file(".env", "7"), path: ".env" },
      { file: file("x.tar.gz", "8"), path: "d.v1/x.tar.gz" },
      { file: file("x.tar.gz", "9"), path: "d.v1/x.tar.gz" },
      { file: file("y", "10"), path: "d.v1/y" },
      { file: file("y", "11"), path: "d.v1/y" },
    ]).map((m) => m.name);
    assert.deepEqual(names, [
      "a.txt",
      "A (2).txt",
      "a (3).txt",
      "notes",
      "notes (2)",
      ".env",
      ".env (2)",
      "d.v1/x.tar.gz",
      "d.v1/x.tar (2).gz",
      "d.v1/y",
      "d.v1/y (2)",
    ]);
  });
});

describe("dosDateTime", () => {
  it("encodes local time at 2 s resolution", () => {
    const ms = new Date(2026, 10, 20, 14, 5, 59).getTime();
    assert.deepEqual(dosDateTime(ms), { date: (46 << 9) | (11 << 5) | 20, time: (14 << 11) | (5 << 5) | 29 });
  });

  it("clamps to the representable range", () => {
    assert.deepEqual(dosDateTime(new Date(1970, 0, 1).getTime()), { date: (1 << 5) | 1, time: 0 });
    assert.deepEqual(dosDateTime(Number.NaN), { date: (1 << 5) | 1, time: 0 });
    assert.equal(dosDateTime(new Date(2200, 0, 1).getTime()).date >> 9, 127);
  });
});

describe("buildZip", () => {
  const picked = [
    { file: file("hello.txt", "hello, world\n"), path: "hello.txt" },
    { file: file("empty", ""), path: "empty" },
    { file: file("été €.md", "# Ünïcödé\n"), path: "dossier/été €.md" },
  ];

  it("writes a valid stored archive with UTF-8 names and correct CRCs", async () => {
    const entries = readZip(await archive(zipInputs(picked)));
    assert.deepEqual(
      entries.map((e) => e.name),
      ["hello.txt", "empty", "dossier/été €.md"],
    );
    for (const [i, e] of entries.entries()) {
      const want = new Uint8Array(await (picked[i] as { file: File }).file.arrayBuffer());
      assert.deepEqual(e.data, want, e.name);
      assert.equal(e.crc, crcRef(want), `${e.name} CRC`);
      assert.equal(e.flags & 0x0800, 0x0800, "UTF-8 flag");
      assert.equal(e.zip64, false);
      assert.equal(e.unicodePath, /^[\x00-\x7f]*$/.test(e.name) ? null : e.name, `${e.name} Unicode Path`);
    }
  });

  it("writes ZIP64 records that a reader follows", async () => {
    const entries = readZip(await archive(zipInputs(picked), true));
    assert.equal(entries.length, 3);
    assert.ok(entries.every((e) => e.zip64));
    assert.equal(entries[2]?.unicodePath, "dossier/été €.md", "Unicode Path next to the ZIP64 field");
    assert.equal(new TextDecoder().decode((entries[0] as Read).data), "hello, world\n");
  });

  it("has a size that does not depend on the checksums", async () => {
    const plain = zipInputs(picked);
    const summed = await withChecksums(plain);
    assert.equal(buildZip(plain).size, buildZip(summed).size);
    assert.equal(buildZip(plain, { forceZip64: true }).size, buildZip(summed, { forceZip64: true }).size);
    assert.equal((await archive(plain)).length, buildZip(plain).size);
  });

  it("writes an empty archive for no members", async () => {
    const bytes = await archive([]);
    assert.equal(bytes.length, 22);
    assert.deepEqual(readZip(bytes), []);
  });

  it("keeps the members as Blob references (no copy of the data)", () => {
    const big = new Blob([new Uint8Array(1 << 20)]);
    const z = buildZip([{ name: "big", data: big, lastModified: 0, crc32: 0 }]);
    assert.equal(z.type, "application/zip");
    assert.equal(z.size, (1 << 20) + 30 + 3 + 46 + 3 + 22);
  });
});

describe("withChecksums", () => {
  it("reads in chunks and reports progress over all members", async () => {
    const data = new Uint8Array(100);
    for (let i = 0; i < data.length; i++) data[i] = i;
    const seen: number[] = [];
    const out = await withChecksums(
      [
        { name: "a", data: new Blob([data]), lastModified: 0, crc32: 0 },
        { name: "b", data: new Blob([data.subarray(0, 30)]), lastModified: 0, crc32: 0 },
      ],
      { chunkSize: 32, onProgress: (done, total) => seen.push(done, total) },
    );
    assert.equal(out[0]?.crc32, crcRef(data));
    assert.equal(out[1]?.crc32, crcRef(data.subarray(0, 30)));
    assert.deepEqual(seen.filter((_, i) => i % 2 === 0), [32, 64, 96, 100, 130]);
    assert.ok(seen.filter((_, i) => i % 2 === 1).every((t) => t === 130));
  });

  it("stops on abort", async () => {
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(
      withChecksums([{ name: "a", data: new Blob(["x"]), lastModified: 0, crc32: 0 }], { signal: ctl.signal }),
      (e: unknown) => e instanceof DOMException && e.name === "AbortError",
    );
  });

  it("names the member that could not be read", async () => {
    const unreadable = {
      size: 10,
      slice: () => ({ arrayBuffer: () => Promise.reject(new DOMException("gone", "NotReadableError")) }),
    } as unknown as Blob;
    await assert.rejects(
      withChecksums([{ name: "dossier/x.bin", data: unreadable, lastModified: 0, crc32: 0 }]),
      (e: unknown) => e instanceof FileReadError && e.entry === "dossier/x.bin",
    );
  });
});
