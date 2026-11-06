# Dropr — Encrypted Formats (v1)

Normative specification of every byte format produced or consumed by the Dropr
browser code. `docs/ARCHITECTURE.md` §2 is the summary; this document is the
full contract. The reference implementation is `web/src/crypto/`, tested
against published vectors in `web/test/`.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

| Notation | Meaning |
|---|---|
| `a ‖ b` | byte concatenation |
| `0x00{n}` | `n` zero bytes |
| `u32be(i)` | 4-byte big-endian unsigned integer |
| `"text"` | the ASCII/UTF-8 bytes of the string, no terminator |
| `HKDF(ikm, salt, info, L)` | HKDF-SHA256 (RFC 5869), `L` output bytes. Empty salt ≡ 32 zero bytes. |
| `GCM(K, N, A, P)` | AES-256-GCM (NIST SP 800-38D) encryption, 96-bit nonce `N`, AAD `A`, 128-bit tag appended: output `C ‖ T`, `|C| = |P|`, `|T| = 16` |
| `b64url(x)` | base64url (RFC 4648 §5) **without padding** |

**base64url decoding is strict.** Decoders MUST reject: padding (`=`),
characters outside `A–Z a–z 0–9 - _` (including whitespace and `+ /`), a length
≡ 1 (mod 4), and non-zero unused bits in the final character. Every byte string
therefore has exactly one accepted encoding. Where a fixed length is expected
(keys, IDs), the decoded length MUST be checked.

All primitives are WebCrypto: AES-GCM, HKDF, HMAC-SHA256, X25519, SHA-256.
Nothing else is used.

## 2. Key hierarchy

```
                       FK (32 random bytes, one per file)
              ┌─────────────┼───────────────────────────┐
     HKDF "dropr/v1 content"      HKDF "dropr/v1 metadata"   transported as:
              │                          │                  • share link fragment b64url(FK)
              CK                         MK                 • or HPKE-sealed to the link key (wrapped_key)
       STREAM (file body)       metadata (name/type/size)

  request link X25519 key pair (skR, pkR), one per link, generated in the owner's browser
        pkR in the request-link fragment; skR non-extractable in that browser's IndexedDB
```

### 2.1 Labels

Every key derivation and every AAD carries a distinct, versioned label.

| Label (ASCII) | Used as | Section |
|---|---|---|
| `dropr/v1 content` | HKDF info → CK | §3 |
| `dropr/v1 metadata` | HKDF info → MK | §3 |
| `dropr/v1 meta` | GCM AAD for metadata | §5 |
| `dropr/v1 request ` (trailing space) ‖ requestId | HPKE info (file key) | §6 |
| `dropr/v1 label ` (trailing space) ‖ requestId | HPKE info (request label) | §7 |

## 3. File key, subkeys and links

- `FK` = 32 bytes from a CSPRNG (`crypto.getRandomValues`). A new FK MUST be
  generated for **every** file, including re-uploads of the same file.
- `CK = HKDF(ikm = FK, salt = "", info = "dropr/v1 content", 32)`
- `MK = HKDF(ikm = FK, salt = "", info = "dropr/v1 metadata", 32)`

CK and MK SHOULD be derived directly into non-extractable WebCrypto keys.

**Share link** (flow A): `https://<host>/s/<shareId>#<b64url(FK)>`. The fragment
is exactly 43 characters. Decoders MAY accept a leading `#` (as in
`location.hash`) and MUST reject anything that does not decode to 32 bytes.

**Request link** (flow B): `https://<host>/r/<requestId>#<b64url(pkR)>`, where
`pkR` is the link's own 32-byte X25519 public key (43 characters, §7).

IDs (`shareId`, `requestId`) are 16 random bytes encoded as 22-character
canonical base64url.

## 4. Content: STREAM

### 4.1 Segmentation

Let `P` be the plaintext length in bytes.

- Segment size `S = 65 536` (64 KiB). Tag size 16. Ciphertext segment size
  `CS = 65 552`.
- `segments(P) = max(1, ceil(P / S))`.
- Segment `i` (0-based) is plaintext bytes `[i·S, min((i+1)·S, P))`.
- Every segment except the last is exactly `S` bytes. The last is 1..S bytes,
  except for an **empty file**, which is exactly one empty segment (`P = 0`,
  one segment of 0 bytes). A non-initial empty segment MUST NOT exist; in
  particular a file whose size is a multiple of `S` ends with a full final
  segment, not an extra empty one.
- At most `2^32` segments (the counter is 32 bits): `P ≤ 2^48`.

### 4.2 Segment encryption

```
nonce_i = 0x00{7} ‖ u32be(i) ‖ (i is last ? 0x01 : 0x00)        (12 bytes)
C_i     = GCM(CK, nonce_i, A = "" (empty), segment_i)            (|segment_i| + 16 bytes)
blob    = C_0 ‖ C_1 ‖ … ‖ C_{n-1}
```

There is no header, version byte, or length field in the blob. The "last" flag
MUST be 1 on segment `n-1` and 0 on all others.

### 4.3 Geometry

- `ciphertextSize(P) = P + 16 · segments(P)`.
- Offset of segment `i` in the blob: `i · 65 552`.
- **Inverse**: given a ciphertext size `C`, let `f = floor(C / CS)`,
  `r = C mod CS`. Then `segments = f` if `r = 0`; `segments = f + 1` if
  `r > 16`, or if `r = 16` and `f = 0`; otherwise `C` is **invalid**
  (`C < 16`, or `r ∈ [1, 16]` after at least one full segment). `P = C − 16 · segments`.
- Examples: `P = 0 → C = 16`; `P = 1 → 17`; `P = 65 536 → 65 552`;
  `P = 65 537 → 65 569`; `C = 65 568` is invalid.

### 4.4 Upload parts

- One part = 512 segments = `33 554 432` plaintext bytes (32 MiB) =
  `33 562 624` ciphertext bytes. Part `n` holds segments `[512n, 512n + 511]`
  and ciphertext bytes `[n · 33 562 624, min((n+1) · 33 562 624, C))`.
- Only the last part is shorter. `parts(C) = ceil(segments / 512)`.
- Parts are independent byte ranges of the same blob: encrypting each part
  separately (with the absolute segment indexes, the final flag only on the
  file's last segment) yields byte-identical output to encrypting the whole
  stream.
- Deployment cap: 100 GiB plaintext = 3200 parts (ARCHITECTURE.md §2).
  The format limit (2^32 segments) is far above it.

### 4.5 Decryption (normative)

A decryptor that starts at segment `k` (0 for a full download; `k > 0` when
resuming at byte offset `k · 65 552` with an HTTP Range request) MUST:

1. Cut the input into consecutive blocks of `CS` bytes; the final block may be
   shorter.
2. Decrypt block `j` (index `i = k + j`) with `nonce_i` and last-flag 0 if more
   input follows it, or last-flag 1 if it is the final block.
3. Reject (and stop) if: GCM authentication fails; a block is shorter than 16
   bytes; the final block is exactly 16 bytes and `i > 0`; the input is empty
   (no final segment ⇒ truncation); or `i ≥ 2^32` (the counter MUST NOT wrap).
4. Release segment plaintext only after that segment authenticates.

This rejects truncation (the remaining last block was sealed with flag 0),
extension or trailing data (the real final block is now decrypted with flag 0),
reordering/duplication/omission (counter mismatch), and splicing from another
file (different CK). A decryptor learns that the file is complete **only when
the final segment authenticates**; see §8.3.

## 5. Metadata

```
json = UTF-8 of {"name": <string>, "type": <string>, "size": <integer>}
meta = GCM(MK, nonce = 0x00{12}, A = "dropr/v1 meta", json)
```

- Writers MUST emit exactly the three members `name`, `type`, `size`, in that
  order, with `JSON.stringify` serialization.
- `size` is the plaintext size `P` (a non-negative integer ≤ 2^48).
- `name` is sanitized by the writer (see below). `type` is a bare media type
  (`type/subtype`, lower case, no parameters) or `application/octet-stream`.
- The server stores `meta` opaque, as base64url; its decoded length MUST be
  ≤ 4096 bytes (so `|json| ≤ 4080`).

Readers MUST:

1. Reject `meta` longer than 4096 bytes before decrypting.
2. Reject if GCM authentication fails.
3. Reject unless the plaintext is valid UTF-8 JSON, an object with **exactly**
   the members `name` (string), `type` (string), `size` (safe integer, 0 ≤ size ≤ 2^48).
4. Reject if `size ≠ plaintextSize(C)` for the blob's ciphertext size `C`.
5. Sanitize, regardless of what the writer did (on the request flow the writer
   is an anonymous uploader):
   - `name`: replace lone UTF-16 surrogates with U+FFFD; NFC-normalize; remove
     C0/C1 controls and DEL, every Default_Ignorable_Code_Point (bidi
     controls, zero-width characters, U+FEFF, U+00AD, Hangul fillers U+115F,
     U+1160, U+3164, U+FFA0, …) except ZWNJ/ZWJ (U+200C/D), variation
     selectors (U+FE00–U+FE0F) and emoji tags (U+E0020–U+E007F), plus
     U+061C, U+2028/9 and U+2800; collapse runs of `\p{Zs}` to one U+0020;
     replace `/ \ : * ? " < > |` with `_`; trim whitespace and trailing dots; truncate
     to 255 UTF-8 bytes on a code-point boundary keeping a short extension;
     use `file` if nothing remains.
   - `type`: keep only if it matches
     `^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`
     after trim + lower-casing, else `application/octet-stream`.
     The type is informational: downloads MUST be served as
     `application/octet-stream` with `Content-Disposition: attachment`.

## 6. Request flow: wrapped file key

The uploader seals FK to the link's public key `pkR` (taken from the
request-link fragment) with HPKE (RFC 9180):

- Mode: `mode_base` (0x00), single-shot (sequence number 0 only).
- Suite: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`,
  AES-256-GCM `0x0002`.
- `info = "dropr/v1 request " ‖ requestId` where `requestId` is the
  22-character ASCII ID from the link path. `aad = ""`.
- `enc, ct = SealBase(pkR, info, aad, FK)`; `|enc| = 32`, `|ct| = 48`.
- `wrapped_key = enc ‖ ct` (exactly **80 bytes**), stored by the server.

The full RFC 9180 key schedule applies: `suite_id = "HPKE" ‖ 0x0020 ‖ 0x0001 ‖ 0x0002`,
KEM `suite_id = "KEM" ‖ 0x0020`, `psk = psk_id = ""`,
`key_schedule_context = 0x00 ‖ LabeledExtract("", "psk_id_hash", "") ‖ LabeledExtract("", "info_hash", info)`,
`secret = LabeledExtract(shared_secret, "secret", "")`, `key`/`base_nonce` via
LabeledExpand; `kem_context = enc ‖ pkR`.

Openers MUST reject a `wrapped_key` that is not 80 bytes, and MUST treat an
all-zero X25519 output as failure (RFC 9180 §7.1.4); senders MUST likewise
refuse a `pkR` that yields an all-zero DH output. The recipient's public key is
an input to Open (`kem_context`); the owner uses the `pkR` stored with `skR`
(§7), never a server-supplied value.

## 7. Request link key pair and label

**Key pair.** Every request link has its own X25519 key pair `(skR, pkR)`,
generated by the owner's browser when the link is created:

- `generateKey({name: "X25519"}, extractable = false, ["deriveBits"])`.
  `skR` MUST be non-extractable: neither `exportKey` nor `wrapKey` can ever
  reveal its bytes, not even to Dropr's own scripts.
- `pkR` = the 32-byte raw public key (`exportKey("raw", publicKey)`).
- `skR` is stored as the `CryptoKey` object itself (structured clone) in that
  browser's IndexedDB, under the request ID, in the record
  `{id, privateKey: skR, publicKey: pkR, ownerId, createdAt}` (`ownerId` = the
  creating account's `users.id`, `createdAt` in Unix seconds; ARCHITECTURE.md §3
  "Request link keys"). It is never serialized to bytes and never sent anywhere.
- Neither half is sent to the server: `pkR` travels only in the link fragment.
  A link is built only from the stored `pkR`, never from a server value.
- A key pair serves exactly one request link; it is deleted when the link is
  revoked or no longer listed by the server.

**Label.** An optional owner-only note on a request link, sealed to the link's
own public key with the HPKE suite and mode of §6:

- `label` = 1..256 bytes of UTF-8.
- `info = "dropr/v1 label " ‖ requestId`, `aad = ""`.
- `enc, ct = SealBase(pkR, info, aad, label)`;
  `label_meta = enc ‖ ct` (49..304 bytes), stored by the server opaque. Because
  `info` binds the request ID, the label is set after the link is created.

Openers MUST reject a `label_meta` of 48 bytes or less or longer than 304
bytes, reject on authentication failure and on invalid UTF-8, and display the
result as text only.

## 8. Security considerations

### 8.1 Nonce uniqueness

AES-GCM loses confidentiality and integrity if a (key, nonce) pair is reused.

- **STREAM**: CK is derived from a fresh 256-bit FK per file, so each CK is
  used for exactly one blob. Within the blob, nonces differ by the counter
  (and the last flag). Since there are at most `2^32` segments and the counter
  never wraps, no nonce repeats under one CK. Re-encrypting the same part
  (upload retry) produces byte-identical output — same key, same nonce, **same
  plaintext** — which leaks nothing; a client MUST NOT re-encrypt a part with
  *different* plaintext under the same FK (it MUST start a new upload with a
  new FK if the source file changed).
- **Metadata**: MK encrypts exactly one message, so a fixed nonce is unique.
- **HPKE**: a fresh ephemeral key per Seal gives a fresh key and base nonce.
- The probability that two files get the same FK (2^-256 per pair) is negligible.

### 8.2 Why zero and counter nonces are safe

Deterministic nonces are safe whenever a key is single-purpose and its nonces
are unique, which §8.1 establishes. Domain separation keeps CK and MK
independent (distinct HKDF info), so the metadata's zero nonce never collides
with segment 0's nonce under the same key: they are different keys. The 7-byte
zero prefix in the STREAM nonce is a constant for the same reason; a random
prefix would add nothing when the key itself is unique.

### 8.3 Streaming release and truncation

Each segment is authenticated before release, but a truncated download is only
detected at its end. Consumers (File System Access writer, service-worker
response) MUST treat output as provisional until the stream closes without
error, and MUST abort/delete the partial file on error. Resumed downloads MUST
use the decryptor's `startSegment` matching the Range offset; a mismatched
index fails authentication.

### 8.4 Key commitment

AES-GCM is not key-committing: one can construct a ciphertext that
authenticates under two different keys chosen by the attacker ("invisible
salamanders"). This matters when a decryptor might try several keys or when a
third party relies on a ciphertext determining a unique plaintext (abuse
reporting, message franking). Neither applies:

- Every decryption uses exactly one candidate key (FK from the link fragment,
  or FK from one HPKE open), so there is no partitioning oracle.
- Keys are 256-bit random values, not passwords.
- Whoever can produce a two-key ciphertext must know both keys; in Dropr that
  is the sender, who already controls the content. A sender giving different
  recipients different fragments for one share could show them different
  content, but could equally create two shares; no Dropr property depends on a
  blob having a unique plaintext.
- The HPKE ciphertext is bound to `pkR`, `enc` and `requestId` by the key
  schedule.

If Dropr ever adds a feature that needs commitment (e.g. reporting a file to an
admin), add a commitment such as `HKDF(FK, "", "dropr/v2 commit", 32)` stored
alongside the blob and checked before decryption.

### 8.5 Empty files

An empty file is one empty final segment (16 bytes: the tag alone, nonce
`0x00{11} ‖ 0x01`). It is authenticated, so an attacker cannot turn a
non-empty file into an empty one (that would require a valid tag under CK).
An empty segment at any index other than 0 is structurally invalid; this keeps
the plaintext↔ciphertext size map a bijection.

### 8.6 Size limits

- Format: ≤ 2^32 segments (2^48 bytes); the implementation range-checks every
  index and size (all are exact JavaScript safe integers).
- Deployment: ≤ 100 GiB (3200 parts); the server validates declared sizes with
  §4.3 before accepting parts.
- AES-GCM per-key usage: one CK performs ≤ 2^32 invocations (unique
  deterministic nonces, so the 2^32 random-IV limit of NIST SP 800-38D does not
  apply) of ≤ 2^16 bytes each (limit: 2^36 − 32 bytes). The PRP/PRF-switching
  term of the confidentiality bound is ≈ σ²/2^129 for σ AES blocks: about
  2^-63 for a 100 GiB file (σ ≈ 2^33) and 2^-41 at the 2^48-byte format limit.
- Metadata ≤ 4096 bytes; wrapped key = 80 bytes; request label ≤ 304 bytes.

### 8.7 What the server learns

Ciphertext size (hence plaintext size exactly, by §4.3), timing, part count,
and which request link an upload belongs to. It never sees request link
public keys (they travel only in the fragment) nor private keys. Names and
types are encrypted. Padding is not used: sizes are considered metadata the
server legitimately needs for quotas and Range requests.

### 8.8 Public-key trust

The request-link public key is generated by the owner's browser and kept with
its private key; the link is built from that stored value only. A compromised
server cannot substitute its own key in links created by an honest client. It *can*
always inject inbox entries (anyone holding a request link can), so inbox
content is untrusted input: never rendered, metadata sanitized (§5).

`requestId` in the HPKE info stops the server from moving an uploaded file to
another request of the same owner without detection.

### 8.9 Non-extractable keys

Non-extractable CryptoKeys prevent any script from reading key bytes; they do
not prevent malicious script (e.g. served by a compromised server, or XSS) from
*using* the key while it runs in the page. This is the residual risk of
browser E2E noted in PLAN.md §12. `skR` is never extractable, at any point of
its life. Anyone controlling the browser profile can likewise use the stored
keys (THREAT_MODEL.md R16).

### 8.10 Error handling and side channels

Decryption failures are reported as a single generic error with no detail
(which segment, why). Base64url coding of key material uses table-free,
branch-free character mapping; byte comparisons of keys use constant-time
equality. Lengths are treated as public.

### 8.11 Versioning

All labels contain `v1`. The blob has no header; a future format MUST use new
labels (`dropr/v2 …`) and the server MUST record the format version per blob
so that clients pick the right decoder. Decoders MUST NOT try several versions
on the same input.

## 9. Test vectors

- HPKE: `web/test/vectors/hpke-x25519-sha256-aes256gcm-base.json`, the
  official CFRG vector for this exact suite (all intermediates and 257
  sequence numbers are checked).
- HKDF: RFC 5869 A.1–A.3. AES-256-GCM: McGrew–Viega test cases 13, 14, 16.
  X25519: RFC 7748 §6.1. base64url: RFC 4648 §10 plus exhaustive canonicality.
- STREAM, metadata, request labels: property tests in `web/test/` (round trip
  through streaming and part-level APIs, truncation at every boundary,
  reordering, splicing, tampering, trailing data, resume, counter overflow).
