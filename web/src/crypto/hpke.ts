/**
 * HPKE (RFC 9180), base mode, single-shot, for exactly one suite:
 * DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
 * (kem_id 0x0020, kdf_id 0x0001, aead_id 0x0002).
 *
 * Built only from WebCrypto primitives (X25519 `deriveBits`, HMAC-SHA256,
 * AES-GCM). The full key schedule is implemented (suite ids, labeled
 * extract/expand, `psk_id_hash` and `info_hash` with the empty PSK), and the
 * DH output is checked against the all-zero value (RFC 9180 §7.1.4) in
 * addition to WebCrypto's own check.
 *
 * Single-shot means one message per context: sequence number 0. The
 * multi-message context functions in {@link _internals} exist only to
 * verify every sequence number of the official test vectors.
 *
 * @module
 */

import { assertLength, type Bytes, concat, copyBytes, i2osp, isAllZero, subtle, utf8 } from "./bytes.ts";
import { b64urlDecode } from "./b64.ts";
import { DecryptionError, FormatError } from "./errors.ts";
import { labeledExpand, labeledExtract } from "./kdf.ts";

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0002;
const MODE_BASE = 0x00;

/** X25519 public key / encapsulated key length. */
export const X25519_KEY_SIZE = 32;
/** Length of `enc` for this suite (Nenc). */
export const HPKE_ENC_SIZE = 32;
/** AEAD tag length (Nt). */
export const HPKE_TAG_SIZE = 16;

const N_SECRET = 32;
const N_K = 32;
const N_N = 12;
const N_H = 32;

const KEM_SUITE_ID = concat(utf8("KEM"), i2osp(KEM_ID, 2));
const HPKE_SUITE_ID = concat(utf8("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
const EMPTY = new Uint8Array(0);

/** An X25519 recipient: private key (may be non-extractable) and its 32-byte public key. */
export interface HpkeRecipient {
  readonly privateKey: CryptoKey;
  readonly publicKey: Uint8Array;
}

/** Output of {@link seal}: encapsulated key and AEAD ciphertext (plaintext ‖ 16-byte tag). */
export interface HpkeSealed {
  readonly enc: Bytes;
  readonly ct: Bytes;
}

// ---------------------------------------------------------------------------
// X25519 via WebCrypto
// ---------------------------------------------------------------------------

/** DER prefix of a PKCS#8 X25519 private key (RFC 8410); followed by the 32-byte scalar. */
const PKCS8_X25519_PREFIX = Uint8Array.of(
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
);

/** Import a raw 32-byte X25519 private scalar. */
export function importX25519PrivateKey(sk: Uint8Array, extractable: boolean): Promise<CryptoKey> {
  assertLength(sk, X25519_KEY_SIZE, "X25519 private key");
  return subtle.importKey("pkcs8", concat(PKCS8_X25519_PREFIX, sk), { name: "X25519" }, extractable, ["deriveBits"]);
}

/** Import a raw 32-byte X25519 public key. */
export function importX25519PublicKey(pk: Uint8Array): Promise<CryptoKey> {
  assertLength(pk, X25519_KEY_SIZE, "X25519 public key");
  return subtle.importKey("raw", copyBytes(pk), { name: "X25519" }, true, []);
}

/** Attempts at X25519 key generation; see {@link generateX25519KeyPair}. */
const KEYGEN_ATTEMPTS = 8;

/**
 * Retry `generate` while it rejects with an `OperationError`. Every attempt
 * draws a fresh random key, so retrying loses nothing.
 */
async function retryOperationError<T>(generate: () => Promise<T>, attempts: number): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await generate();
    } catch (e) {
      if (i >= attempts || !(e instanceof DOMException && e.name === "OperationError")) throw e;
    }
  }
}

/**
 * Generate an X25519 key pair: private half non-extractable, raw 32-byte
 * public half.
 *
 * WebKitGTK/WPE (libgcrypt backend) rejects about 1 in 130 X25519
 * `generateKey` calls with an `OperationError`; importing, exporting and
 * `deriveBits` are unaffected. Retrying makes a failure vanishingly rare
 * (about 1e-17 after {@link KEYGEN_ATTEMPTS} attempts).
 */
export async function generateX25519KeyPair(): Promise<{ privateKey: CryptoKey; publicKey: Bytes }> {
  const kp = await retryOperationError(
    async () => (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair,
    KEYGEN_ATTEMPTS,
  );
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

/** Public key of an **extractable** X25519 private key. */
export async function x25519PublicFromPrivate(sk: CryptoKey): Promise<Bytes> {
  const jwk = await subtle.exportKey("jwk", sk);
  if (typeof jwk.x !== "string") throw new FormatError("not an X25519 private key");
  return b64urlDecode(jwk.x);
}

/**
 * DH(sk, pk) with the RFC 9180 §7.1.4 all-zero check. Returns `null` instead
 * of throwing so each caller picks its own error class.
 */
async function dh(sk: CryptoKey, pk: CryptoKey): Promise<Bytes | null> {
  let z: Bytes;
  try {
    z = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pk }, sk, 256));
  } catch {
    return null; // WebCrypto itself rejects the all-zero output
  }
  return isAllZero(z) ? null : z;
}

// ---------------------------------------------------------------------------
// DHKEM(X25519, HKDF-SHA256)
// ---------------------------------------------------------------------------

async function extractAndExpand(dhOut: Uint8Array, kemContext: Uint8Array): Promise<Bytes> {
  const eaePrk = await labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dhOut);
  return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, N_SECRET);
}

/** RFC 9180 §7.1.3 DeriveKeyPair for X25519. Returns raw scalars; test use only. */
async function deriveKeyPair(ikm: Uint8Array): Promise<{ sk: Bytes; pk: Bytes }> {
  const dkpPrk = await labeledExtract(KEM_SUITE_ID, EMPTY, "dkp_prk", ikm);
  const sk = await labeledExpand(KEM_SUITE_ID, dkpPrk, "sk", EMPTY, X25519_KEY_SIZE);
  const pk = await x25519PublicFromPrivate(await importX25519PrivateKey(sk, true));
  return { sk, pk };
}

interface EphemeralKeyPair {
  readonly privateKey: CryptoKey;
  readonly publicKey: Bytes;
}

function generateEphemeral(): Promise<EphemeralKeyPair> {
  return generateX25519KeyPair();
}

async function encap(pkR: Uint8Array, eph: EphemeralKeyPair): Promise<{ sharedSecret: Bytes; enc: Bytes }> {
  const z = await dh(eph.privateKey, await importX25519PublicKey(pkR));
  if (z === null) throw new FormatError("invalid recipient public key");
  const enc = eph.publicKey;
  return { sharedSecret: await extractAndExpand(z, concat(enc, pkR)), enc };
}

async function decap(enc: Uint8Array, recipient: HpkeRecipient): Promise<Bytes> {
  const z = await dh(recipient.privateKey, await importX25519PublicKey(enc));
  if (z === null) throw new DecryptionError();
  return extractAndExpand(z, concat(enc, recipient.publicKey));
}

// ---------------------------------------------------------------------------
// Key schedule and AEAD context
// ---------------------------------------------------------------------------

interface KeyScheduleOutput {
  readonly keyScheduleContext: Bytes;
  readonly secret: Bytes;
  readonly key: Bytes;
  readonly baseNonce: Bytes;
  readonly exporterSecret: Bytes;
}

/** RFC 9180 §5.1 KeySchedule for mode_base (psk = psk_id = ""). */
async function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): Promise<KeyScheduleOutput> {
  const pskIdHash = await labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = await labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
  const keyScheduleContext = concat(Uint8Array.of(MODE_BASE), pskIdHash, infoHash);
  const secret = await labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
  const [key, baseNonce, exporterSecret] = await Promise.all([
    labeledExpand(HPKE_SUITE_ID, secret, "key", keyScheduleContext, N_K),
    labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", keyScheduleContext, N_N),
    labeledExpand(HPKE_SUITE_ID, secret, "exp", keyScheduleContext, N_H),
  ]);
  return { keyScheduleContext, secret, key, baseNonce, exporterSecret };
}

interface AeadContext {
  readonly key: CryptoKey;
  readonly baseNonce: Bytes;
}

async function contextFromSchedule(ks: KeyScheduleOutput): Promise<AeadContext> {
  const key = await subtle.importKey("raw", ks.key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { key, baseNonce: ks.baseNonce };
}

/** RFC 9180 §5.2 ComputeNonce: base_nonce XOR I2OSP(seq, Nn). */
function computeNonce(baseNonce: Uint8Array, seq: number): Bytes {
  const s = i2osp(seq, N_N);
  for (let i = 0; i < N_N; i++) s[i] = (s[i] ?? 0) ^ (baseNonce[i] ?? 0);
  return s;
}

async function contextSeal(ctx: AeadContext, seq: number, aad: Uint8Array, pt: Uint8Array): Promise<Bytes> {
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: computeNonce(ctx.baseNonce, seq), additionalData: copyBytes(aad) },
    ctx.key,
    copyBytes(pt),
  );
  return new Uint8Array(ct);
}

async function contextOpen(ctx: AeadContext, seq: number, aad: Uint8Array, ct: Uint8Array): Promise<Bytes> {
  try {
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: computeNonce(ctx.baseNonce, seq), additionalData: copyBytes(aad) },
      ctx.key,
      copyBytes(ct),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptionError();
  }
}

// ---------------------------------------------------------------------------
// Public single-shot API
// ---------------------------------------------------------------------------

/**
 * HPKE base-mode single-shot Seal (RFC 9180 §6.1) to recipient public key
 * `pkR`, with a fresh ephemeral X25519 key pair.
 *
 * @param pkR - recipient's 32-byte X25519 public key. Must come from an
 *   authenticated source (for Dropr: the request-link fragment, which the
 *   owner's browser took from the link's own key pair).
 * @param info - application context; binds the ciphertext to its purpose.
 * @param aad - additional authenticated data.
 * @param pt - plaintext.
 * @returns `enc` (32 bytes) and `ct` (`pt.length + 16` bytes).
 * @throws {FormatError} if `pkR` is not 32 bytes or is a low-order point.
 */
export async function seal(pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<HpkeSealed> {
  return sealWithEphemeral(pkR, info, aad, pt, await generateEphemeral());
}

async function sealWithEphemeral(
  pkR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
  eph: EphemeralKeyPair,
): Promise<HpkeSealed> {
  assertLength(pkR, X25519_KEY_SIZE, "recipient public key");
  const { sharedSecret, enc } = await encap(pkR, eph);
  const ctx = await contextFromSchedule(await keySchedule(sharedSecret, info));
  return { enc, ct: await contextSeal(ctx, 0, aad, pt) };
}

/**
 * HPKE base-mode single-shot Open (RFC 9180 §6.1).
 *
 * The recipient's public key is required because DHKEM binds it into the
 * shared secret (`kem_context = enc ‖ pkR`) and it cannot be recomputed from
 * a non-extractable private key.
 *
 * @throws {DecryptionError} on any failure (malformed `enc`, low-order `enc`,
 *   wrong key, wrong `info`/`aad`, tampered ciphertext). No detail is given.
 */
export async function open(
  recipient: HpkeRecipient,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Promise<Bytes> {
  if (enc.length !== HPKE_ENC_SIZE || ct.length < HPKE_TAG_SIZE || recipient.publicKey.length !== X25519_KEY_SIZE) {
    throw new DecryptionError();
  }
  const sharedSecret = await decap(enc, recipient);
  const ctx = await contextFromSchedule(await keySchedule(sharedSecret, info));
  return contextOpen(ctx, 0, aad, ct);
}

/**
 * Test-only internals: deterministic key derivation and context-level access
 * so the RFC 9180 vectors can check every intermediate value. Not part of the
 * public API (not re-exported from the package index). Never use the
 * deterministic-ephemeral path in production: reusing an ephemeral key for
 * the same recipient and info yields the same AES-GCM key and nonce for
 * different messages, which breaks both confidentiality and integrity.
 *
 * @internal
 */
export const _internals = {
  KEM_SUITE_ID,
  HPKE_SUITE_ID,
  deriveKeyPair,
  extractAndExpand,
  keySchedule,
  contextFromSchedule,
  contextSeal,
  contextOpen,
  computeNonce,
  decap,
  retryOperationError,
  /** Seal with a caller-supplied ephemeral key pair (raw scalars). */
  async sealDeterministic(
    pkR: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
    skE: Uint8Array,
    pkE: Uint8Array,
  ): Promise<HpkeSealed> {
    const eph = { privateKey: await importX25519PrivateKey(skE, false), publicKey: copyBytes(pkE) };
    return sealWithEphemeral(pkR, info, aad, pt, eph);
  },
} as const;
