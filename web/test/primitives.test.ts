/**
 * Known-answer tests for the primitives we rely on, through the exact code
 * paths Dropr uses: base64url (RFC 4648), HKDF-SHA256 (RFC 5869 §A.1–A.3),
 * AES-256-GCM (McGrew–Viega GCM spec test cases 13, 14, 16), X25519 (RFC 7748 §6.1).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { b64urlDecode, b64urlEncode } from "../src/crypto/b64.ts";
import { FormatError } from "../src/crypto/errors.ts";
import { hkdf, hkdfAesGcmKey, hkdfExpand, hkdfExtract } from "../src/crypto/kdf.ts";
import { importX25519PrivateKey, importX25519PublicKey, x25519PublicFromPrivate } from "../src/crypto/hpke.ts";
import { hex, property, unhex } from "./helpers.ts";

const subtle = globalThis.crypto.subtle;
const range = (from: number, to: number): Uint8Array =>
  Uint8Array.from({ length: to - from + 1 }, (_, i) => from + i);

describe("base64url", () => {
  it("RFC 4648 §10 vectors (unpadded)", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [plain, enc] of vectors) {
      assert.equal(b64urlEncode(new TextEncoder().encode(plain)), enc);
      assert.equal(new TextDecoder().decode(b64urlDecode(enc)), plain);
    }
  });

  it("uses the URL-safe alphabet", () => {
    assert.equal(b64urlEncode(Uint8Array.of(0xfb, 0xff, 0xbf)), "-_-_");
    assert.equal(b64urlEncode(Uint8Array.of(0xfb, 0xff)), "-_8");
    assert.equal(hex(b64urlDecode("-_-_")), "fbffbf");
  });

  it("rejects padding, standard alphabet, whitespace, bad length, non-canonical bits, non-ASCII", () => {
    for (const bad of ["Zg==", "Zm8=", "+/+/", "Zm9 v", "Zm9v\n", "Z", "Zm9vY", "Zh", "Zm9vYmF", "Zé", "ZĀ", "Zg\u0000", "Zm9v=="]) {
      assert.throws(() => b64urlDecode(bad), FormatError, JSON.stringify(bad));
    }
  });

  it("accepts exactly the canonical encodings (exhaustive over 2- and 3-char strings)", () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const extra = ["=", "+", "/", ".", " ", "ÿ"];
    const chars = [...alphabet, ...extra];
    let accepted = 0;
    for (const a of chars) {
      for (const b of chars) {
        for (const c of ["", ...chars]) {
          const s = a + b + c;
          const ref = /^[A-Za-z0-9_-]+$/.test(s) ? Buffer.from(s, "base64url") : null;
          const canonical = ref !== null && ref.toString("base64url") === s;
          let ok = true;
          try {
            const out = b64urlDecode(s);
            assert.ok(ref !== null && Buffer.from(out).equals(ref), s);
          } catch (e) {
            if (!(e instanceof FormatError)) throw e;
            ok = false;
          }
          assert.equal(ok, canonical, JSON.stringify(s));
          if (ok) accepted++;
        }
      }
    }
    assert.equal(accepted, 2 ** 8 + 2 ** 16); // one canonical string per 1- and 2-byte value
  });

  it("round-trips random bytes and matches Node's encoder", async () => {
    await property(
      300,
      (rng) => rng.bytes(rng.int(0, 100)),
      (bytes) => {
        const enc = b64urlEncode(bytes);
        assert.equal(enc, Buffer.from(bytes).toString("base64url"));
        assert.deepEqual(b64urlDecode(enc), bytes);
      },
      hex,
    );
  });
});

describe("HKDF-SHA256 (RFC 5869 Appendix A)", () => {
  const cases = [
    {
      name: "A.1 basic",
      ikm: unhex("0b".repeat(22)),
      salt: unhex("000102030405060708090a0b0c"),
      info: unhex("f0f1f2f3f4f5f6f7f8f9"),
      prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
      okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    {
      name: "A.2 long inputs",
      ikm: range(0x00, 0x4f),
      salt: range(0x60, 0xaf),
      info: range(0xb0, 0xff),
      prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
      okm:
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    {
      name: "A.3 empty salt and info",
      ikm: unhex("0b".repeat(22)),
      salt: new Uint8Array(0),
      info: new Uint8Array(0),
      prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
      okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
  ];
  for (const c of cases) {
    it(c.name, async () => {
      const len = c.okm.length / 2;
      assert.equal(hex(await hkdf(c.ikm, c.salt, c.info, len)), c.okm, "WebCrypto HKDF");
      const prk = await hkdfExtract(c.salt, c.ikm);
      assert.equal(hex(prk), c.prk, "HMAC Extract");
      assert.equal(hex(await hkdfExpand(prk, c.info, len)), c.okm, "HMAC Expand");
    });
  }

  it("rejects invalid output lengths and short PRKs", async () => {
    await assert.rejects(hkdf(new Uint8Array(32), new Uint8Array(0), new Uint8Array(0), 0), FormatError);
    await assert.rejects(hkdfExpand(new Uint8Array(32), new Uint8Array(0), 255 * 32 + 1), FormatError);
    await assert.rejects(hkdfExpand(new Uint8Array(31), new Uint8Array(0), 32), FormatError);
  });

  it("hkdfAesGcmKey yields a non-extractable AES-256-GCM key equal to HKDF output", async () => {
    const ikm = unhex("0b".repeat(22));
    const key = await hkdfAesGcmKey(ikm, new Uint8Array(0), "dropr/v1 content");
    assert.equal(key.extractable, false);
    assert.deepEqual(key.algorithm, { name: "AES-GCM", length: 256 });
    const raw = await hkdf(ikm, new Uint8Array(0), new TextEncoder().encode("dropr/v1 content"), 32);
    const ref = await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
    const iv = new Uint8Array(12);
    const a = await subtle.encrypt({ name: "AES-GCM", iv }, key, new Uint8Array(5));
    const b = await subtle.encrypt({ name: "AES-GCM", iv }, ref, new Uint8Array(5));
    assert.deepEqual(new Uint8Array(a), new Uint8Array(b));
  });
});

describe("AES-256-GCM (McGrew–Viega test cases 13, 14, 16)", () => {
  const K16 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
  const P =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
  const cases = [
    { name: "TC13 empty, zero key/IV", key: "00".repeat(32), iv: "00".repeat(12), pt: "", aad: "", out: "530f8afbc74536b9a963b4f1c4cb738b" },
    {
      name: "TC14 one zero block, zero key/IV",
      key: "00".repeat(32),
      iv: "00".repeat(12),
      pt: "00".repeat(16),
      aad: "",
      out: "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919",
    },
    {
      name: "TC16 with AAD",
      key: K16,
      iv: "cafebabefacedbaddecaf888",
      pt: P,
      aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
      out:
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
        "76fc6ece0f4e1768cddf8853bb2d551b",
    },
  ];
  for (const c of cases) {
    it(c.name, async () => {
      const key = await subtle.importKey("raw", unhex(c.key), "AES-GCM", false, ["encrypt", "decrypt"]);
      const params = { name: "AES-GCM", iv: unhex(c.iv), additionalData: unhex(c.aad) };
      assert.equal(hex(new Uint8Array(await subtle.encrypt(params, key, unhex(c.pt)))), c.out);
      assert.equal(hex(new Uint8Array(await subtle.decrypt(params, key, unhex(c.out)))), c.pt);
    });
  }
});

describe("X25519 (RFC 7748 §6.1)", () => {
  const aliceSk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  const alicePk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const bobSk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
  const bobPk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
  const shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  it("public keys and shared secret", async () => {
    const a = await importX25519PrivateKey(unhex(aliceSk), true);
    const b = await importX25519PrivateKey(unhex(bobSk), true);
    assert.equal(hex(await x25519PublicFromPrivate(a)), alicePk);
    assert.equal(hex(await x25519PublicFromPrivate(b)), bobPk);
    const ab = await subtle.deriveBits({ name: "X25519", public: await importX25519PublicKey(unhex(bobPk)) }, a, 256);
    const ba = await subtle.deriveBits({ name: "X25519", public: await importX25519PublicKey(unhex(alicePk)) }, b, 256);
    assert.equal(hex(new Uint8Array(ab)), shared);
    assert.equal(hex(new Uint8Array(ba)), shared);
  });

  it("rejects wrong-length keys", async () => {
    assert.throws(() => importX25519PublicKey(new Uint8Array(31)), FormatError);
    assert.throws(() => importX25519PrivateKey(new Uint8Array(33), false), FormatError);
  });
});
