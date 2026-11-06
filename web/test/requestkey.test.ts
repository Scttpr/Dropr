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
    assert.equal(sealed.length, 32 + utf8("Invoices – Q3 ✓").length + 16);
    assert.equal(await openRequestLabel(kp, REQUEST_ID, sealed), "Invoices – Q3 ✓");
    // Byte layout cross-check against raw HPKE.
    const raw = await open(kp, sealed.subarray(0, 32), utf8("dropr/v1 label " + REQUEST_ID), EMPTY, sealed.subarray(32));
    assert.equal(new TextDecoder().decode(raw), "Invoices – Q3 ✓");
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
    assert.equal(await openRequestLabel(kp, REQUEST_ID, await sealRequestLabel(kp.publicKey, REQUEST_ID, max)), max);
    await assert.rejects(sealRequestLabel(kp.publicKey, REQUEST_ID, max + "a"), FormatError);
    await assert.rejects(sealRequestLabel(kp.publicKey, REQUEST_ID, ""), FormatError);
    await assert.rejects(sealRequestLabel(kp.publicKey, "short", "label"), FormatError);
  });

  it("rejects a label that is not valid UTF-8", async () => {
    const kp = await generateRequestKeyPair();
    const { enc, ct } = await seal(kp.publicKey, utf8("dropr/v1 label " + REQUEST_ID), EMPTY, Uint8Array.of(0xff, 0xfe));
    await assert.rejects(openRequestLabel(kp, REQUEST_ID, new Uint8Array([...enc, ...ct])), DecryptionError);
  });
});
