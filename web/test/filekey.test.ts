/** File keys, link fragments, request-flow key wrapping and both end-to-end flows. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import {
  decodeRequestFragment,
  decodeShareFragment,
  deriveFileKeys,
  encodeRequestFragment,
  encodeShareFragment,
  generateFileKey,
  unwrapFileKeyFromRequest,
  WRAPPED_FILE_KEY_SIZE,
  wrapFileKeyForRequest,
} from "../src/crypto/filekey.ts";
import { open } from "../src/crypto/hpke.ts";
import { hkdf } from "../src/crypto/kdf.ts";
import { deriveKek, generateOwnerKeyPair, toOwnerKeyPair, unwrapPrivateKey, wrapPrivateKey } from "../src/crypto/keywrap.ts";
import { openMeta, sealMeta } from "../src/crypto/meta.ts";
import { ciphertextSize, createDecryptStream, encryptPart, partCount, partPlainRange, plaintextSize, SEGMENT_SIZE } from "../src/crypto/stream.ts";
import { concatAll, randomChunks, Rng, runStream } from "./helpers.ts";

const subtle = globalThis.crypto.subtle;
const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);
const REQUEST_ID = "q83vEjRWeJq8Ad7tEjRWeA"; // 22-char base64url of 16 bytes
const OTHER_ID = "q83vEjRWeJq8Ad7tEjRWeQ";

describe("file keys", () => {
  it("are 32 fresh random bytes", () => {
    const a = generateFileKey();
    assert.equal(a.length, 32);
    assert.notDeepEqual(generateFileKey(), a);
  });

  it("CK and MK are HKDF(FK, \"\", \"dropr/v1 content|metadata\") and differ", async () => {
    const fk = generateFileKey();
    const { content, metadata } = await deriveFileKeys(fk);
    assert.equal(content.extractable, false);
    assert.equal(metadata.extractable, false);
    const iv = new Uint8Array(12);
    for (const [key, label] of [[content, "dropr/v1 content"], [metadata, "dropr/v1 metadata"]] as const) {
      const raw = await hkdf(fk, new Uint8Array(0), utf8(label), 32);
      const ref = await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
      assert.deepEqual(
        new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, new Uint8Array(1))),
        new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, ref, new Uint8Array(1))),
        label,
      );
    }
    const c = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, content, new Uint8Array(1)));
    const m = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, metadata, new Uint8Array(1)));
    assert.notDeepEqual(c, m);
    await assert.rejects(deriveFileKeys(new Uint8Array(31)), FormatError);
  });
});

describe("link fragments", () => {
  it("share fragment round-trips FK, with or without '#'", () => {
    const fk = generateFileKey();
    const f = encodeShareFragment(fk);
    assert.match(f, /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(decodeShareFragment(f), fk);
    assert.deepEqual(decodeShareFragment("#" + f), fk);
  });

  it("request fragment round-trips a public key", () => {
    const pk = new Rng(3).bytes(32);
    const f = encodeRequestFragment(pk);
    assert.deepEqual(decodeRequestFragment("#" + f), pk);
  });

  it("rejects malformed fragments", () => {
    const f = encodeShareFragment(generateFileKey());
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const nonCanonical = f.slice(0, 42) + alphabet[alphabet.indexOf(f.slice(42)) | 1]; // unused low bits set
    for (const bad of ["", "#", f + "=", f.slice(1), f + "A", f.slice(0, 42) + "/", nonCanonical, " " + f, "##" + f]) {
      assert.throws(() => decodeShareFragment(bad), FormatError, JSON.stringify(bad));
      assert.throws(() => decodeRequestFragment(bad), FormatError, JSON.stringify(bad));
    }
    assert.throws(() => encodeShareFragment(new Uint8Array(16)), FormatError);
    assert.throws(() => encodeRequestFragment(new Uint8Array(33)), FormatError);
  });
});

describe("request-flow key wrapping", () => {
  it("wraps FK into 80 bytes that open with info \"dropr/v1 request \" ‖ id", async () => {
    const owner = await toOwnerKeyPair(await generateOwnerKeyPair());
    const fk = generateFileKey();
    const wrapped = await wrapFileKeyForRequest(owner.publicKey, REQUEST_ID, fk);
    assert.equal(wrapped.length, WRAPPED_FILE_KEY_SIZE);
    assert.equal(WRAPPED_FILE_KEY_SIZE, 80);
    assert.deepEqual(await unwrapFileKeyFromRequest(owner, REQUEST_ID, wrapped), fk);
    // Byte layout cross-check against raw HPKE.
    const raw = await open(owner, wrapped.subarray(0, 32), utf8("dropr/v1 request " + REQUEST_ID), new Uint8Array(0), wrapped.subarray(32));
    assert.deepEqual(raw, fk);
  });

  it("rejects wrong request id, wrong owner, tampering and bad lengths", async () => {
    const owner = await toOwnerKeyPair(await generateOwnerKeyPair());
    const other = await toOwnerKeyPair(await generateOwnerKeyPair());
    const wrapped = await wrapFileKeyForRequest(owner.publicKey, REQUEST_ID, generateFileKey());
    await assert.rejects(unwrapFileKeyFromRequest(owner, OTHER_ID, wrapped), DecryptionError);
    await assert.rejects(unwrapFileKeyFromRequest(other, REQUEST_ID, wrapped), DecryptionError);
    for (let i = 0; i < wrapped.length; i++) {
      const bad = wrapped.slice();
      bad[i] = (bad[i] ?? 0) ^ (i === 31 ? 0x40 : 0x01);
      await assert.rejects(unwrapFileKeyFromRequest(owner, REQUEST_ID, bad), DecryptionError, `byte ${i}`);
    }
    await assert.rejects(unwrapFileKeyFromRequest(owner, REQUEST_ID, wrapped.subarray(0, 79)), DecryptionError);
    await assert.rejects(unwrapFileKeyFromRequest(owner, REQUEST_ID, new Uint8Array([...wrapped, 0])), DecryptionError);
  });

  it("validates request ids and FK length", async () => {
    const owner = await toOwnerKeyPair(await generateOwnerKeyPair());
    for (const id of ["", "short", REQUEST_ID + "A", REQUEST_ID.slice(0, 21) + "B", REQUEST_ID.slice(0, 21) + "+", "q83vEjRWeJq8Ad7tEjRWe=="]) {
      await assert.rejects(wrapFileKeyForRequest(owner.publicKey, id, generateFileKey()), FormatError, id);
    }
    await assert.rejects(wrapFileKeyForRequest(owner.publicKey, REQUEST_ID, new Uint8Array(16)), FormatError);
  });
});

describe("end-to-end flows", () => {
  async function upload(fk: Uint8Array, pt: Uint8Array, name: string) {
    const keys = await deriveFileKeys(fk);
    const meta = await sealMeta(keys.metadata, { name, type: "application/zip", size: pt.length });
    const size = ciphertextSize(pt.length);
    const parts: Uint8Array[] = [];
    for (let i = 0, n = partCount(size); i < n; i++) {
      const r = partPlainRange(i, pt.length);
      parts.push(await encryptPart(keys.content, i, pt.subarray(r.start, r.end), i === n - 1));
    }
    return { size, meta, blob: concatAll(parts) };
  }

  async function download(fk: Uint8Array, stored: { size: number; meta: Uint8Array; blob: Uint8Array }, rng: Rng) {
    const keys = await deriveFileKeys(fk);
    const meta = await openMeta(keys.metadata, stored.meta, plaintextSize(stored.size));
    const data = await runStream(createDecryptStream(keys.content), randomChunks(stored.blob, rng));
    return { meta, data };
  }

  it("flow A: share link", async () => {
    const rng = new Rng(100);
    const pt = rng.bytes(3 * SEGMENT_SIZE + 1);
    const fk = generateFileKey();
    const stored = await upload(fk, pt, "photos.zip");
    const link = `https://drop.example/s/AAAAAAAAAAAAAAAAAAAAAA#${encodeShareFragment(fk)}`;
    const got = await download(decodeShareFragment(new URL(link).hash), stored, rng);
    assert.equal(got.meta.name, "photos.zip");
    assert.ok(Buffer.from(got.data).equals(pt));
  });

  it("flow B: request link with passkey-unlocked owner key", async () => {
    const rng = new Rng(200);
    // Setup: owner key wrapped by a passkey's PRF output.
    const owner = await generateOwnerKeyPair();
    const prf = rng.bytes(32);
    const userHandle = rng.bytes(32);
    const blob = await wrapPrivateKey(await deriveKek(prf, userHandle), owner);
    // Owner creates a request link from the *unwrapped* public key.
    const unlocked = await unwrapPrivateKey(await deriveKek(prf, userHandle), blob);
    const link = `https://drop.example/r/${REQUEST_ID}#${encodeRequestFragment(unlocked.publicKey)}`;
    // Uploader.
    const pk = decodeRequestFragment(new URL(link).hash);
    const fk = generateFileKey();
    const pt = rng.bytes(SEGMENT_SIZE);
    const stored = await upload(fk, pt, "scan.zip");
    const wrapped = await wrapFileKeyForRequest(pk, REQUEST_ID, fk);
    // Owner reads the inbox.
    const fk2 = await unwrapFileKeyFromRequest(unlocked, REQUEST_ID, wrapped);
    const got = await download(fk2, stored, rng);
    assert.equal(got.meta.name, "scan.zip");
    assert.ok(Buffer.from(got.data).equals(pt));
  });
});
