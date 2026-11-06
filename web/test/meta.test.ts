/** Metadata sealing, size cap, strict parsing and sanitization. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import { deriveFileKeys, generateFileKey } from "../src/crypto/filekey.ts";
import { MAX_META_SIZE, MAX_NAME_BYTES, openMeta, sanitizeFileName, sanitizeMediaType, sealMeta } from "../src/crypto/meta.ts";
import { property } from "./helpers.ts";

const subtle = globalThis.crypto.subtle;
const utf8Len = (s: string): number => new TextEncoder().encode(s).length;

async function mk(): Promise<CryptoKey> {
  return (await deriveFileKeys(generateFileKey())).metadata;
}

/** Seal arbitrary JSON text exactly like sealMeta (MK is usable for encrypt). */
async function craft(key: CryptoKey, json: string): Promise<Uint8Array> {
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(12), additionalData: new TextEncoder().encode("dropr/v1 meta") },
    key,
    new TextEncoder().encode(json),
  );
  return new Uint8Array(ct);
}

describe("metadata", () => {
  it("round trip, canonical JSON, expected size check", async () => {
    const key = await mk();
    const meta = { name: "Report Q3.pdf", type: "application/pdf", size: 123_456 };
    const sealed = await sealMeta(key, meta);
    assert.equal(sealed.length, utf8Len(JSON.stringify(meta)) + 16);
    assert.deepEqual(await openMeta(key, sealed), meta);
    assert.deepEqual(await openMeta(key, sealed, 123_456), meta);
    await assert.rejects(openMeta(key, sealed, 123_457), FormatError);
  });

  it("is bound to its key and AAD, and detects tampering", async () => {
    const key = await mk();
    const sealed = await sealMeta(key, { name: "a", type: "", size: 0 });
    await assert.rejects(openMeta(await mk(), sealed), DecryptionError);
    const files = await deriveFileKeys(generateFileKey());
    await assert.rejects(openMeta(files.content, await sealMeta(files.metadata, { name: "a", type: "", size: 0 })), DecryptionError);
    for (let i = 0; i < sealed.length; i++) {
      const bad = sealed.slice();
      bad[i] = (bad[i] ?? 0) ^ 0x10;
      await assert.rejects(openMeta(key, bad), DecryptionError, `byte ${i}`);
    }
    await assert.rejects(openMeta(key, sealed.subarray(0, 15)), DecryptionError);
    const wrongAad = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, key, new TextEncoder().encode('{"name":"a","type":"","size":0}')),
    );
    await assert.rejects(openMeta(key, wrongAad), DecryptionError);
  });

  it("enforces the 4 KiB cap", async () => {
    const key = await mk();
    const pad = (n: number): string => JSON.stringify({ name: "x".repeat(n), type: "text/plain", size: 1 });
    const base = utf8Len(pad(0));
    const atCap = await craft(key, pad(MAX_META_SIZE - 16 - base));
    assert.equal(atCap.length, MAX_META_SIZE);
    const opened = await openMeta(key, atCap);
    assert.ok(utf8Len(opened.name) <= MAX_NAME_BYTES, "oversized name truncated on open");
    const over = await craft(key, pad(MAX_META_SIZE - 16 - base + 1));
    assert.equal(over.length, MAX_META_SIZE + 1);
    await assert.rejects(openMeta(key, over), FormatError);
  });

  it("strictly validates the authenticated JSON", async () => {
    const key = await mk();
    const bad = [
      "not json",
      "[]",
      "null",
      '"str"',
      '{"name":"a","type":"x/y"}',
      '{"name":"a","type":"x/y","size":1,"extra":1}',
      '{"name":1,"type":"x/y","size":1}',
      '{"name":"a","type":null,"size":1}',
      '{"name":"a","type":"x/y","size":-1}',
      '{"name":"a","type":"x/y","size":1.5}',
      '{"name":"a","type":"x/y","size":"1"}',
      '{"name":"a","type":"x/y","size":1e300}',
    ];
    for (const json of bad) await assert.rejects(openMeta(key, await craft(key, json)), FormatError, json);
    const ct = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12), additionalData: new TextEncoder().encode("dropr/v1 meta") }, key, Uint8Array.of(0xc3, 0x28)),
    );
    await assert.rejects(openMeta(key, ct), FormatError, "invalid UTF-8");
    await assert.rejects(sealMeta(key, { name: "a", type: "", size: -1 }), FormatError);
  });

  it("sanitizes untrusted names and types on open", async () => {
    const key = await mk();
    const sealed = await craft(key, JSON.stringify({ name: "../../etc/passwd\u0000", type: "text/html; charset=utf-8", size: 3 }));
    assert.deepEqual(await openMeta(key, sealed), { name: ".._.._etc_passwd", type: "application/octet-stream", size: 3 });
  });
});

describe("sanitizeFileName", () => {
  const cases: [string, string][] = [
    ["report.pdf", "report.pdf"],
    ["../../etc/passwd", ".._.._etc_passwd"],
    ["C:\\Windows\\evil.exe", "C__Windows_evil.exe"],
    ["a/b\\c:d*e?f\"g<h>i|j", "a_b_c_d_e_f_g_h_i_j"],
    ["invoice\u202Efdp.exe", "invoicefdp.exe"],
    ["\u2066x\u2069\u200E\u200F\u061C.txt", "x.txt"],
    ["line\nbreak\r\ttab\u0085", "linebreaktab"],
    ["zero\u200Bwidth\uFEFF", "zerowidth"],
    ["  spaced.txt  ", "spaced.txt"],
    ["trailing.txt...", "trailing.txt"],
    ["", "file"],
    [".", "file"],
    ["..", "file"],
    ["   ", "file"],
    ["\u0000\u0001", "file"],
    [".bashrc", ".bashrc"],
    ["e\u0301te\u0301.txt", "\u00e9t\u00e9.txt"],
    ["lone\uD800surrogate", "lone\uFFFDsurrogate"],
    ["emoji 👩\u200D💻.png", "emoji 👩\u200D💻.png"],
    // Audit I-4: whitespace runs collapse; invisible fillers are removed.
    ["invoice.pdf" + "\u2003".repeat(40) + ".exe", "invoice.pdf .exe"],
    ["invoice.pdf" + " ".repeat(60) + "x.exe", "invoice.pdf x.exe"],
    ["a\u00A0\u00A0\u3000b", "a b"],
    ["invoice.pdf\u3164\u3164\u3164.exe", "invoice.pdf.exe"],
    ["x\u115F\u1160\uFFA0\u2800\u00AD\u180E\u034F\u2064y", "xy"],
    ["\u3164 \u3164.pdf", ".pdf"],
    ["flag 🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}.png", "flag 🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}.png"],
    ["heart \u2764\uFE0F.txt", "heart \u2764\uFE0F.txt"],
  ];
  for (const [input, want] of cases) {
    it(JSON.stringify(input), () => assert.equal(sanitizeFileName(input), want));
  }

  it("truncates to 255 UTF-8 bytes on a code point boundary, keeping the extension", () => {
    const long = sanitizeFileName("a".repeat(300) + ".pdf");
    assert.equal(utf8Len(long), MAX_NAME_BYTES);
    assert.ok(long.endsWith(".pdf"));
    const multi = sanitizeFileName("é".repeat(200) + ".tar.gz");
    assert.ok(utf8Len(multi) <= MAX_NAME_BYTES);
    assert.ok(multi.endsWith(".gz"));
    assert.ok(!multi.includes("\uFFFD"));
    const astral = sanitizeFileName("😀".repeat(100));
    assert.ok(utf8Len(astral) <= MAX_NAME_BYTES && utf8Len(astral) > MAX_NAME_BYTES - 4);
    assert.equal(astral.length % 2, 0, "no split surrogate pair");
  });

  it("property: output is non-empty, bounded, has no separators/controls, and is idempotent", async () => {
    const alphabet = ["a", "Z", "0", ".", " ", "/", "\\", ":", "\u0000", "\u001F", "\u007F", "\u0085", "\u202E", "é", "😀", "\uD800", "\uDC00", "\u200D"];
    await property(
      2000,
      (rng) => Array.from({ length: rng.int(0, 400) }, () => rng.pick(alphabet)).join(""),
      (input) => {
        const out = sanitizeFileName(input);
        assert.ok(out.length > 0);
        assert.ok(utf8Len(out) <= MAX_NAME_BYTES);
        assert.ok(!/[/\\:*?"<>|\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/.test(out), out);
        assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(out), "lone surrogate");
        assert.ok(out !== "." && out !== "..");
        assert.equal(sanitizeFileName(out), out, "idempotent");
      },
    );
  });
});

describe("sanitizeMediaType", () => {
  const cases: [string, string][] = [
    ["application/pdf", "application/pdf"],
    ["IMAGE/PNG", "image/png"],
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ["", "application/octet-stream"],
    ["text/html; charset=utf-8", "application/octet-stream"],
    ["<script>", "application/octet-stream"],
    ["text/", "application/octet-stream"],
    ["/plain", "application/octet-stream"],
    ["a/b/c", "application/octet-stream"],
    ["text/plain\r\nX-Evil: 1", "application/octet-stream"],
    ["x/" + "y".repeat(100), "application/octet-stream"],
  ];
  for (const [input, want] of cases) {
    it(JSON.stringify(input), () => assert.equal(sanitizeMediaType(input), want));
  }
});
