/** Owner key generation and PRF-based private-key wrapping. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { b64urlEncode } from "../src/crypto/b64.ts";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import { open, seal } from "../src/crypto/hpke.ts";
import {
  deriveKek,
  generateOwnerKeyPair,
  prfSalt,
  toOwnerKeyPair,
  unwrapExtractable,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "../src/crypto/keywrap.ts";
import { hex, Rng } from "./helpers.ts";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const rng = new Rng(77);
const prf = rng.bytes(32);
const userHandle = rng.bytes(16);

/** Encrypt arbitrary plaintext exactly like wrapPrivateKey does (KEK is usable, just not extractable). */
async function craftBlob(kek: CryptoKey, plaintext: string): Promise<Uint8Array> {
  const iv = rng.bytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("dropr/v1 privkey") }, kek, enc.encode(plaintext));
  return new Uint8Array([...iv, ...new Uint8Array(ct)]);
}

describe("keywrap", () => {
  it("PRF salt is SHA-256(\"dropr/v1 prf\") and is returned as a fresh copy", () => {
    assert.equal(hex(prfSalt()), createHash("sha256").update("dropr/v1 prf").digest("hex"));
    const a = prfSalt();
    a[0] = 0;
    assert.notEqual(prfSalt()[0], 0);
  });

  it("KEK is a non-extractable AES-256-GCM key and validates inputs", async () => {
    const kek = await deriveKek(prf, userHandle);
    assert.equal(kek.extractable, false);
    assert.deepEqual(kek.algorithm, { name: "AES-GCM", length: 256 });
    assert.throws(() => deriveKek(prf.subarray(1), userHandle), FormatError);
    assert.throws(() => deriveKek(prf, new Uint8Array(0)), FormatError);
    assert.throws(() => deriveKek(prf, new Uint8Array(65)), FormatError);
  });

  it("round trip: non-extractable private key, authenticated public key, functional", async () => {
    const owner = await generateOwnerKeyPair();
    assert.equal(owner.privateKey.extractable, true);
    const kek = await deriveKek(prf, userHandle);
    const blob = await wrapPrivateKey(kek, owner);
    assert.ok(blob.length > 12 + 16 && blob.length < 200, `blob ${blob.length} bytes`);

    const unlocked = await unwrapPrivateKey(kek, blob);
    assert.equal(unlocked.privateKey.extractable, false);
    assert.equal(unlocked.privateKey.type, "private");
    assert.deepEqual(unlocked.privateKey.algorithm, { name: "X25519" });
    assert.deepEqual(unlocked.privateKey.usages, ["deriveBits"]);
    assert.deepEqual(unlocked.publicKey, owner.publicKey);
    await assert.rejects(subtle.exportKey("jwk", unlocked.privateKey));
    await assert.rejects(subtle.exportKey("pkcs8", unlocked.privateKey));

    const s = await seal(owner.publicKey, enc.encode("x"), new Uint8Array(0), enc.encode("hello"));
    assert.equal(new TextDecoder().decode(await open(unlocked, s.enc, enc.encode("x"), new Uint8Array(0), s.ct)), "hello");
  });

  it("wrapping uses a fresh IV each time", async () => {
    const owner = await generateOwnerKeyPair();
    const kek = await deriveKek(prf, userHandle);
    const a = await wrapPrivateKey(kek, owner);
    const b = await wrapPrivateKey(kek, owner);
    assert.notDeepEqual(a.subarray(0, 12), b.subarray(0, 12));
  });

  it("adding a passkey: unwrapExtractable then re-wrap under a second KEK", async () => {
    const owner = await generateOwnerKeyPair();
    const kek1 = await deriveKek(prf, userHandle);
    const kek2 = await deriveKek(rng.bytes(32), userHandle);
    const blob1 = await wrapPrivateKey(kek1, owner);
    const ext = await unwrapExtractable(kek1, blob1);
    assert.equal(ext.privateKey.extractable, true);
    const blob2 = await wrapPrivateKey(kek2, ext);
    const k2 = await unwrapPrivateKey(kek2, blob2);
    assert.deepEqual(k2.publicKey, owner.publicKey);
    await assert.rejects(unwrapPrivateKey(kek1, blob2), DecryptionError);
    const ne = await toOwnerKeyPair(ext);
    assert.equal(ne.privateKey.extractable, false);
    assert.deepEqual(ne.publicKey, owner.publicKey);
  });

  it("wrong PRF output, wrong user handle, tampered or resized blob → DecryptionError", async () => {
    const owner = await generateOwnerKeyPair();
    const kek = await deriveKek(prf, userHandle);
    const blob = await wrapPrivateKey(kek, owner);
    const wrongPrf = prf.slice();
    wrongPrf[0] = (wrongPrf[0] ?? 0) ^ 1;
    await assert.rejects(unwrapPrivateKey(await deriveKek(wrongPrf, userHandle), blob), DecryptionError);
    const wrongUh = userHandle.slice();
    wrongUh[15] = (wrongUh[15] ?? 0) ^ 1;
    await assert.rejects(unwrapPrivateKey(await deriveKek(prf, wrongUh), blob), DecryptionError);
    for (let i = 0; i < blob.length; i++) {
      const bad = blob.slice();
      bad[i] = (bad[i] ?? 0) ^ 0x01;
      await assert.rejects(unwrapPrivateKey(kek, bad), DecryptionError, `byte ${i}`);
    }
    await assert.rejects(unwrapPrivateKey(kek, blob.subarray(0, blob.length - 1)), DecryptionError);
    await assert.rejects(unwrapPrivateKey(kek, new Uint8Array([...blob, 0])), DecryptionError);
    await assert.rejects(unwrapPrivateKey(kek, new Uint8Array(28)), DecryptionError);
    await assert.rejects(unwrapPrivateKey(kek, new Uint8Array(2000)), DecryptionError);
  });

  it("wrap refuses a public key that does not belong to the private key", async () => {
    const a = await generateOwnerKeyPair();
    const b = await generateOwnerKeyPair();
    const kek = await deriveKek(prf, userHandle);
    await assert.rejects(wrapPrivateKey(kek, { privateKey: a.privateKey, publicKey: b.publicKey }), FormatError);
  });

  it("strict JWK validation of the authenticated contents", async () => {
    const kek = await deriveKek(prf, userHandle);
    const a = await subtle.exportKey("jwk", (await generateOwnerKeyPair()).privateKey);
    const b = await subtle.exportKey("jwk", (await generateOwnerKeyPair()).privateKey);
    const d = a.d ?? "";
    const x = a.x ?? "";
    const good = JSON.stringify({ kty: "OKP", crv: "X25519", d, x });
    assert.equal(b64urlEncode((await unwrapPrivateKey(kek, await craftBlob(kek, good))).publicKey), x);

    const bad: Record<string, string> = {
      "not JSON": "{",
      array: "[]",
      null: "null",
      "extra member": JSON.stringify({ kty: "OKP", crv: "X25519", d, x, ext: true }),
      "missing x": JSON.stringify({ kty: "OKP", crv: "X25519", d }),
      "wrong kty": JSON.stringify({ kty: "EC", crv: "X25519", d, x }),
      "wrong crv": JSON.stringify({ kty: "OKP", crv: "Ed25519", d, x }),
      "padded d": JSON.stringify({ kty: "OKP", crv: "X25519", d: d + "=", x }),
      "short d": JSON.stringify({ kty: "OKP", crv: "X25519", d: d.slice(0, 42), x }),
      "d not string": JSON.stringify({ kty: "OKP", crv: "X25519", d: 1, x }),
      "x of another key": JSON.stringify({ kty: "OKP", crv: "X25519", d, x: b.x }),
    };
    for (const [name, pt] of Object.entries(bad)) {
      await assert.rejects(unwrapPrivateKey(kek, await craftBlob(kek, pt)), FormatError, name);
    }
    // Invalid UTF-8 inside an authentic blob.
    const iv = rng.bytes(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("dropr/v1 privkey") }, kek, Uint8Array.of(0xff, 0xfe));
    await assert.rejects(unwrapPrivateKey(kek, new Uint8Array([...iv, ...new Uint8Array(ct)])), FormatError);
  });
});
