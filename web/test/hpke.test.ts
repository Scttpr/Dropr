/**
 * HPKE: the official RFC 9180 / CFRG test vector for
 * DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, base mode
 * (every intermediate and all 257 sequence numbers), plus negative tests.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { DecryptionError, FormatError } from "../src/crypto/errors.ts";
import { _internals, importX25519PrivateKey, open, seal, type HpkeRecipient } from "../src/crypto/hpke.ts";
import { generateRequestKeyPair } from "../src/crypto/requestkey.ts";
import { hex, property, unhex } from "./helpers.ts";

interface Vector {
  mode: number;
  kem_id: number;
  kdf_id: number;
  aead_id: number;
  info: string;
  ikmR: string;
  ikmE: string;
  skRm: string;
  skEm: string;
  pkRm: string;
  pkEm: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: { aad: string; ct: string; nonce: string; pt: string }[];
}

const fixture = JSON.parse(
  readFileSync(new URL("./vectors/hpke-x25519-sha256-aes256gcm-base.json", import.meta.url), "utf8"),
) as { vector: Vector };
const v = fixture.vector;

async function recipientFromVector(): Promise<HpkeRecipient> {
  return { privateKey: await importX25519PrivateKey(unhex(v.skRm), false), publicKey: unhex(v.pkRm) };
}

describe("HPKE RFC 9180 test vector (0x0020/0x0001/0x0002, mode_base)", () => {
  it("is the right suite", () => {
    assert.deepEqual([v.mode, v.kem_id, v.kdf_id, v.aead_id], [0, 0x20, 0x01, 0x02]);
    assert.equal(hex(_internals.KEM_SUITE_ID), "4b454d0020");
    assert.equal(hex(_internals.HPKE_SUITE_ID), "48504b45002000010002");
    assert.equal(v.encryptions.length, 257);
  });

  it("DeriveKeyPair(ikmE), DeriveKeyPair(ikmR)", async () => {
    const e = await _internals.deriveKeyPair(unhex(v.ikmE));
    assert.equal(hex(e.sk), v.skEm);
    assert.equal(hex(e.pk), v.pkEm);
    const r = await _internals.deriveKeyPair(unhex(v.ikmR));
    assert.equal(hex(r.sk), v.skRm);
    assert.equal(hex(r.pk), v.pkRm);
  });

  it("Encap/Decap shared_secret and enc", async () => {
    const first = v.encryptions[0];
    assert.ok(first);
    const sealed = await _internals.sealDeterministic(
      unhex(v.pkRm), unhex(v.info), unhex(first.aad), unhex(first.pt), unhex(v.skEm), unhex(v.pkEm),
    );
    assert.equal(hex(sealed.enc), v.enc);
    assert.equal(hex(sealed.ct), first.ct, "single-shot seal, seq 0");
    assert.equal(hex(await _internals.decap(unhex(v.enc), await recipientFromVector())), v.shared_secret);
  });

  it("KeySchedule: key_schedule_context, secret, key, base_nonce, exporter_secret", async () => {
    const ks = await _internals.keySchedule(unhex(v.shared_secret), unhex(v.info));
    assert.equal(hex(ks.keyScheduleContext), v.key_schedule_context);
    assert.equal(hex(ks.secret), v.secret);
    assert.equal(hex(ks.key), v.key);
    assert.equal(hex(ks.baseNonce), v.base_nonce);
    assert.equal(hex(ks.exporterSecret), v.exporter_secret);
  });

  it("every sequence number: nonce, Seal, Open", async () => {
    const ctx = await _internals.contextFromSchedule(await _internals.keySchedule(unhex(v.shared_secret), unhex(v.info)));
    for (const [seq, e] of v.encryptions.entries()) {
      assert.equal(hex(_internals.computeNonce(unhex(v.base_nonce), seq)), e.nonce, `nonce ${seq}`);
      assert.equal(hex(await _internals.contextSeal(ctx, seq, unhex(e.aad), unhex(e.pt))), e.ct, `seal ${seq}`);
      assert.equal(hex(await _internals.contextOpen(ctx, seq, unhex(e.aad), unhex(e.ct))), e.pt, `open ${seq}`);
    }
  });

  it("public single-shot open() of the vector's seq-0 ciphertext", async () => {
    const first = v.encryptions[0];
    assert.ok(first);
    const pt = await open(await recipientFromVector(), unhex(v.enc), unhex(v.info), unhex(first.aad), unhex(first.ct));
    assert.equal(hex(pt), first.pt);
  });
});

describe("HPKE seal/open", () => {
  const enc = new TextEncoder();

  it("round-trips random messages to a fresh key", async () => {
    const r = await generateRequestKeyPair();
    await property(
      40,
      (rng) => ({ info: rng.bytes(rng.int(0, 64)), aad: rng.bytes(rng.int(0, 64)), pt: rng.bytes(rng.int(0, 300)) }),
      async ({ info, aad, pt }) => {
        const s = await seal(r.publicKey, info, aad, pt);
        assert.equal(s.enc.length, 32);
        assert.equal(s.ct.length, pt.length + 16);
        assert.deepEqual(await open(r, s.enc, info, aad, s.ct), pt);
      },
      (x) => `pt ${x.pt.length}B`,
    );
  });

  it("uses a fresh ephemeral key every time", async () => {
    const r = await generateRequestKeyPair();
    const a = await seal(r.publicKey, new Uint8Array(0), new Uint8Array(0), new Uint8Array(32));
    const b = await seal(r.publicKey, new Uint8Array(0), new Uint8Array(0), new Uint8Array(32));
    assert.notDeepEqual(a.enc, b.enc);
    assert.notDeepEqual(a.ct, b.ct);
  });

  it("rejects wrong key, wrong info, wrong aad, tampered enc and ct", async () => {
    const r = await generateRequestKeyPair();
    const other = await generateRequestKeyPair();
    const info = enc.encode("dropr/v1 request AAAAAAAAAAAAAAAAAAAAAA");
    const aad = new Uint8Array(0);
    const pt = new Uint8Array(32).fill(7);
    const s = await seal(r.publicKey, info, aad, pt);

    await assert.rejects(open(other, s.enc, info, aad, s.ct), DecryptionError, "wrong private key");
    await assert.rejects(open({ privateKey: r.privateKey, publicKey: other.publicKey }, s.enc, info, aad, s.ct), DecryptionError, "wrong pkR in kem_context");
    await assert.rejects(open(r, s.enc, enc.encode("dropr/v1 request BAAAAAAAAAAAAAAAAAAAAA"), aad, s.ct), DecryptionError, "wrong info");
    await assert.rejects(open(r, s.enc, info, Uint8Array.of(0), s.ct), DecryptionError, "wrong aad");
    for (let i = 0; i < s.enc.length; i++) {
      const bad = s.enc.slice();
      bad[i] = (bad[i] ?? 0) ^ (i === 31 ? 0x40 : 0x01); // bit 255 is masked by X25519; flip bit 254 instead
      await assert.rejects(open(r, bad, info, aad, s.ct), DecryptionError, `enc byte ${i}`);
    }
    for (let i = 0; i < s.ct.length; i++) {
      const bad = s.ct.slice();
      bad[i] = (bad[i] ?? 0) ^ 0x80;
      await assert.rejects(open(r, s.enc, info, aad, bad), DecryptionError, `ct byte ${i}`);
    }
    await assert.rejects(open(r, s.enc, info, aad, s.ct.subarray(0, 15)), DecryptionError, "short ct");
    await assert.rejects(open(r, s.enc.subarray(1), info, aad, s.ct), DecryptionError, "short enc");
  });

  // Low-order points: X25519 with any of them yields the all-zero output.
  const lowOrder = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ];

  it("seal refuses low-order recipient keys (all-zero DH)", async () => {
    for (const p of lowOrder) {
      await assert.rejects(seal(unhex(p), new Uint8Array(0), new Uint8Array(0), new Uint8Array(1)), FormatError, p);
    }
  });

  it("open refuses low-order enc (all-zero DH)", async () => {
    const r = await generateRequestKeyPair();
    for (const p of lowOrder) {
      await assert.rejects(open(r, unhex(p), new Uint8Array(0), new Uint8Array(0), new Uint8Array(16)), DecryptionError, p);
    }
  });

  it("seal validates the public key length", async () => {
    await assert.rejects(seal(new Uint8Array(31), new Uint8Array(0), new Uint8Array(0), new Uint8Array(1)), FormatError);
  });
});

describe("X25519 key generation retry (WebKitGTK/WPE OperationError)", () => {
  const { retryOperationError } = _internals;
  const flaky = (failures: number, error: () => unknown) => {
    let calls = 0;
    const generate = () => (++calls <= failures ? Promise.reject(error()) : Promise.resolve(calls));
    return { generate, calls: () => calls };
  };

  it("retries OperationError until an attempt succeeds", async () => {
    const f = flaky(3, () => new DOMException("failed", "OperationError"));
    assert.equal(await retryOperationError(f.generate, 8), 4);
  });

  it("gives up after the last attempt", async () => {
    const f = flaky(Infinity, () => new DOMException("failed", "OperationError"));
    await assert.rejects(retryOperationError(f.generate, 8), { name: "OperationError" });
    assert.equal(f.calls(), 8);
  });

  it("does not retry other errors", async () => {
    const f = flaky(Infinity, () => new DOMException("nope", "NotSupportedError"));
    await assert.rejects(retryOperationError(f.generate, 8), { name: "NotSupportedError" });
    assert.equal(f.calls(), 1);
  });
});
