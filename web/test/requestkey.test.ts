/** Request-link key pair (non-extractable, HPKE recipient) and request labels. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import { open, seal } from "../src/crypto/hpke.ts";
import { MAX_LABEL_BYTES, generateRequestKeyPair, openRequestLabel, sealRequestLabel } from "../src/crypto/requestkey.ts";

const subtle = globalThis.crypto.subtle;
const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);
const EMPTY = new Uint8Array(0);
const REQUEST_ID = "q83vEjRWeJq8Ad7tEjRWeA";
const OTHER_ID = "q83vEjRWeJq8Ad7tEjRWeQ";

/** HPKE-seal raw label plaintext exactly like sealRequestLabel, minus the padding. */
async function craft(publicKey: Uint8Array, pt: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const { enc, ct } = await seal(publicKey, utf8("dropr/v1 label " + REQUEST_ID), EMPTY, pt);
  return new Uint8Array([...enc, ...ct]);
}

/** `content` followed by zeros up to `len` bytes. */
function zeroPadded(content: Uint8Array, len: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(len);
  out.set(content);
  return out;
}

describe("request key pair", () => {
  it("is a fresh X25519 pair whose private key cannot be exported", async () => {
    const kp = await generateRequestKeyPair();
    assert.equal(kp.publicKey.length, 32);
    assert.equal(kp.privateKey.type, "private");
    assert.equal(kp.privateKey.extractable, false);
    assert.deepEqual(kp.privateKey.algorithm, { name: "X25519" });
    assert.deepEqual(kp.privateKey.usages, ["deriveBits"]);
    for (const format of ["pkcs8", "jwk", "raw"] as const) {
      await assert.rejects(subtle.exportKey(format, kp.privateKey), format);
    }
    assert.notDeepEqual((await generateRequestKeyPair()).publicKey, kp.publicKey);
  });

  it("opens what is HPKE-sealed to its public key, and only that", async () => {
    const kp = await generateRequestKeyPair();
    const other = await generateRequestKeyPair();
    const info = utf8("dropr/v1 request " + REQUEST_ID);
    const s = await seal(kp.publicKey, info, EMPTY, utf8("file key"));
    assert.equal(new TextDecoder().decode(await open(kp, s.enc, info, EMPTY, s.ct)), "file key");
    await assert.rejects(open(other, s.enc, info, EMPTY, s.ct), DecryptionError);
  });
});

describe("request label", () => {
  it("round-trips, bound to info \"dropr/v1 label \" ‖ requestId", async () => {
    const kp = await generateRequestKeyPair();
    const sealed = await sealRequestLabel(kp.publicKey, REQUEST_ID, "Invoices – Q3 ✓");
    assert.equal(sealed.length, 32 + 128 + 16, "padded to the smallest bucket");
    assert.equal(await openRequestLabel(kp, REQUEST_ID, sealed), "Invoices – Q3 ✓");
    // Byte layout cross-check against raw HPKE.
    const raw = await open(kp, sealed.subarray(0, 32), utf8("dropr/v1 label " + REQUEST_ID), EMPTY, sealed.subarray(32));
    assert.deepEqual(raw, zeroPadded(utf8("Invoices – Q3 ✓"), 128));
  });

  it("is domain-separated from file keys and bound to its request and key pair", async () => {
    const kp = await generateRequestKeyPair();
    const other = await generateRequestKeyPair();
    const sealed = await sealRequestLabel(kp.publicKey, REQUEST_ID, "label");
    await assert.rejects(openRequestLabel(kp, OTHER_ID, sealed), DecryptionError);
    await assert.rejects(openRequestLabel(other, REQUEST_ID, sealed), DecryptionError);
    await assert.rejects(open(kp, sealed.subarray(0, 32), utf8("dropr/v1 request " + REQUEST_ID), EMPTY, sealed.subarray(32)), DecryptionError);
    const bad = sealed.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, bad), DecryptionError);
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, sealed.subarray(0, 48)), DecryptionError);
  });

  it("limits labels to 1..256 UTF-8 bytes and checks the request id", async () => {
    const kp = await generateRequestKeyPair();
    const max = "é".repeat(MAX_LABEL_BYTES / 2);
    const sealedMax = await sealRequestLabel(kp.publicKey, REQUEST_ID, max);
    assert.equal(sealedMax.length, 32 + 256 + 16);
    assert.equal(await openRequestLabel(kp, REQUEST_ID, sealedMax), max);
    await assert.rejects(sealRequestLabel(kp.publicKey, REQUEST_ID, max + "a"), FormatError);
    await assert.rejects(sealRequestLabel(kp.publicKey, REQUEST_ID, ""), FormatError);
    await assert.rejects(sealRequestLabel(kp.publicKey, "short", "label"), FormatError);
    await assert.rejects(sealRequestLabel(kp.publicKey, REQUEST_ID, "a\u0000b"), FormatError, "NUL is the padding byte");
  });

  it("pads to 128 or 256 bytes, so label_meta is 176 or 304 bytes (audit 2026-11b L-8)", async () => {
    const kp = await generateRequestKeyPair();
    for (let n = 1; n <= MAX_LABEL_BYTES; n++) {
      const sealed = await sealRequestLabel(kp.publicKey, REQUEST_ID, "x".repeat(n));
      assert.equal(sealed.length, n <= 128 ? 176 : 304, `label ${n}`);
    }
  });

  it("rejects non-canonical padding", async () => {
    const kp = await generateRequestKeyPair();
    const label = utf8("label");
    assert.equal(await openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, zeroPadded(label, 128))), "label");
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, zeroPadded(label, 200))), FormatError, "not a bucket");
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, zeroPadded(label, 256))), FormatError, "larger bucket than needed");
    const nonZero = zeroPadded(label, 128);
    nonZero[127] = 0x61;
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, nonZero)), FormatError, "non-zero pad byte");
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, new Uint8Array(128))), FormatError, "empty label");
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, await craft(kp.publicKey, label)), DecryptionError, "unpadded: bad length");
  });

  it("rejects a label that is not valid UTF-8", async () => {
    const kp = await generateRequestKeyPair();
    const sealed = await craft(kp.publicKey, zeroPadded(Uint8Array.of(0xff, 0xfe), 128));
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, sealed), DecryptionError);
  });
});
