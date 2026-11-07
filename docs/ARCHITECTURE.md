# Dropr — Architecture & Contracts

This document is the **binding contract** between the Go server, the browser
modules and the tests. [DESIGN.md](DESIGN.md) is the product spec; this file pins the
details the design leaves open. Change it only deliberately, and update every
side at once. "Audit X-n" cites a finding of the
[2026-11 internal audit](security-audit-2026-11.md).

## 0. Environment

- Everything runs inside `nix develop` (see `flake.nix`). Never assume global
  `go`, `node`, `npm`. Use `nix develop -c <cmd>` from non-interactive shells.
- `CGO_ENABLED=0` everywhere (pure-Go SQLite: `modernc.org/sqlite`).
- Playwright: browsers come from nixpkgs (`PLAYWRIGHT_BROWSERS_PATH`). The npm
  `@playwright/test` version **must equal** `$PLAYWRIGHT_VERSION` (1.64.1). Never
  run `npx playwright install`.
- The dev Keycloak runs with `podman-compose` (`dev/compose.yaml`).

## 1. Repository layout

```
flake.nix                 dev shell, packages (dropr, web-assets), checks
nix/                      hashes.nix: vendorHash and npmDepsHash (`make hashes`, scripts/update-hashes.sh)
Makefile                  developer tasks (CONTRIBUTING.md)
.github/workflows/ci.yml  CI and the tagged release (binaries, signed checksums, asset hashes)
dropr.example.toml        commented production configuration
go.mod                    module github.com/scttpr/dropr
cmd/dropr/                main: `dropr serve | user list|revoke|disable|enable|purge|migrate | gc | backup | healthcheck | version`
internal/config/          TOML config (BurntSushi/toml), validation, binary sizes, secrets from files
internal/db/              SQLite open (WAL, foreign_keys, busy_timeout), embedded migrations, online backup
internal/store/           typed queries per table (no ORM); storetest/ fixtures
internal/auth/oidc/       discovery, PKCE, private_key_jwt assertions, token verification, revalidation;
  oidctest/               fake OIDC provider for negative tests
internal/auth/session/    server-side sessions, cookie handling, rotation, idle/absolute timeouts
internal/blob/            sharded part storage, part geometry, multi-part ReadSeeker, Range serving, disk-space checks
internal/httpx/           middleware: security headers, CSP, CSRF, body limits, deadlines, rate and transfer
                          limits, real client IP, JSON problems, request logging
internal/server/          router (net/http ServeMux patterns), API, transfer and page handlers
internal/web/             html/template pages (templates/), display settings (prefs.go), asset manifest,
                          go:embed of internal/web/static (esbuild output, gitignored)
internal/i18n/            language negotiation, gettext-style Go catalogs (English = msgid, fr.go)
internal/seal/            AES-GCM sealing of server secrets, HKDF subkeys of the refresh key
internal/ids/             random IDs (128-bit) and bearer secrets (256-bit), validation
internal/keyed/           per-key mutex (per-blob part commit / finalize lock)
internal/jobs/            cleanup ticker (5 min) and its tasks
web/                      TypeScript browser modules (esbuild), zero runtime dependencies
  src/crypto/             stream, hpke, kdf, meta, pad, filekey, requestkey, b64 (pure, WebCrypto only)
  src/lib/                api, uploader, downloader, swproto, request-keys (IndexedDB), i18n + locales/,
                          dropzone, progress, format, …
  src/*.ts                page entry points: dashboard, links, inbox, share, request, prefs; sw (service worker)
  scripts/                build.ts (hashed bundles + manifest.json), bench.ts
  test/                   node --test unit and property tests, vectors/ (FORMAT.md test vectors)
e2e/                      Playwright specs (tests/), fixtures
dev/                      compose.yaml (dev Keycloak), dropr.toml (dev config), client_secret,
                          keycloak/ (dev realm, TEST-ONLY private_key_jwt key)
docs/                     design, contracts, format, pages, threat model, OIDC providers, 2026-11 audit
```

Go: stdlib-first. Direct dependencies: `coreos/go-oidc/v3`, `golang.org/x/oauth2`,
`golang.org/x/crypto` (autocert), `golang.org/x/time/rate`, `modernc.org/sqlite`,
`BurntSushi/toml`. Logging with `log/slog`. Browser: zero runtime
dependencies; dev dependencies are only `typescript`, `esbuild` and
`@types/node`, plus
`@playwright/test` in `e2e/`.

## 2. Encrypted format (normative summary; full spec in docs/FORMAT.md)

Notation: `||` concat, integers big-endian, `HKDF = HKDF-SHA256`.

- **File key** `FK`: 32 random bytes, fresh per file.
  - Share link: `FK` is placed in the URL fragment, base64url (no padding):
    `https://host/s/<shareId>#<b64url(FK)>`.
  - Request link: `FK` is sealed to the link's X25519 public key with HPKE
    base mode, suite DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM
    (kem 0x0020, kdf 0x0001, aead 0x0002),
    `info = "dropr/v1 request " || requestId`, `aad = ""`.
    Stored as `wrapped_key = enc(32) || ct(48)` (80 bytes).
- **Subkeys**: `CK = HKDF(ikm=FK, salt="", info="dropr/v1 content", 32)`,
  `MK = HKDF(ikm=FK, salt="", info="dropr/v1 metadata", 32)`.
- **Content (STREAM)**: plaintext split in 64 KiB segments (last may be
  shorter, possibly 0 bytes only if the file is empty — an empty file is one
  empty final segment). Segment `i` →
  `AES-256-GCM(CK, nonce = 0x00{7} || u32(i) || u8(last?1:0), aad="")`.
  Ciphertext segment = plaintext segment + 16-byte tag. No header in the blob.
- **Parts**: 1 part = 512 segments = 32 MiB plaintext =
  `512 * (65536+16) = 33 562 624` ciphertext bytes. Only the last part is
  shorter. Part `n` (0-based) holds segments `[512n, 512n+511]`.
  Ciphertext offset of segment `i` = `i * 65552`.
  Max parts = 3200 (100 GiB / 32 MiB).
- **Metadata**: JSON `{"name": string, "type": string, "size": number}` (UTF-8),
  zero-padded to 128, 256 or 512 bytes (FORMAT.md §5.1, audit 2026-11b L-8),
  sealed as `AES-256-GCM(MK, nonce = 0x00{12}, aad = "dropr/v1 meta")`,
  stored by the server as opaque base64url `meta` (144, 272 or 528 bytes
  decoded; the API rejects any other length).
- **Request label** (optional, owner-only note on a request link): UTF-8 ≤ 256 B,
  zero-padded to 128 or 256 bytes, HPKE-sealed to the link's own public key with
  `info = "dropr/v1 label " || requestId`, stored as `label_meta = enc || ct`
  (set after creation with `PUT /api/requests/{id}/label`, since it binds the id).
  Sealed labels are 176 or 304 bytes and the API accepts only those lengths
  (the database CHECK still allows 49..512).
  The API and crypto exist; the pages do not offer a label field yet.
- **HPKE open** needs the recipient public key (`kem_context = enc || pkR`), so
  the API is `hpkeOpen({privateKey, publicKey}, enc, info, aad, ct)`.
- **Request link key pair**: X25519, one per request link, generated in the
  owner's browser when the link is created (`generateKey({name: "X25519"},
  extractable = false, ["deriveBits"])`, so the private key can never be
  exported, not even by Dropr's own scripts). The private key never leaves
  that browser: it is stored as a `CryptoKey` in IndexedDB (§3 "Request link
  keys"). The public key is the link fragment, `/r/<id>#<b64url(pub)>`. The
  server never sees or stores either half, so it cannot substitute a key, and
  nobody holding only the owner's OIDC login can read received files.
  Consequence (accepted): files received through a link open only in the
  browser profile that created it; clearing that site's data makes them
  unreadable.

## 3. HTTP surface

All JSON APIs: `Content-Type: application/json`, bodies ≤ 16 KiB, errors are
`{"error": "<code>", "message": "<plain language>"}`. IDs are 128-bit random
base64url (22 chars). Anything not listed returns 404.

### Pages (server-rendered, `html/template`, no inline JS/CSS)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/` | session → dashboard, else login page | |
| GET | `/login` | – | "Sign in" button → `/auth/login` |
| GET | `/inbox` | session | list received files (encrypted names, decrypted client-side) |
| GET | `/links` | session | active share + request links |
| GET | `/s/{id}` | – | share recipient page; dead links render a plain 404/410 page without the script |
| GET | `/r/{id}` | – | request uploader page; dead, closed or full links render a plain 404/410 page |
| GET | `/assets/{hash-name}` | – | immutable, long cache |
| GET | `/sw.js` | – | service worker (registered with scope `/_dl/`), `Cache-Control: no-cache` |
| GET | `/_dl/{…}` | – | always 404 ("The download could not start"): only the service worker answers there |
| GET | `/healthz` | – | `200 ok` when the database answers within 2 s, else 503 (load balancers, `dropr healthcheck`) |
| POST | `/prefs` | – | display settings without JavaScript: `lang` (`en`, `fr`) and/or `theme` (`light`, `dark`, `system`) → cookies, 303 to `next` (same-origin path only, else `/`) |

### Auth
| Method | Path | Notes |
|---|---|---|
| GET | `/auth/login` | sets `__Host-dropr_oidc` (Lax, 10 min) with state/nonce/PKCE verifier and the hash of the browser's current session, if any (sealed AES-GCM), redirects to IdP |
| GET | `/auth/callback` | verifies, creates session, rotates ID, deletes the previous session named in the state cookie, responds 200 with landing page that navigates to `/` (a refused or cancelled sign-in keeps the previous session) |
| POST | `/auth/logout` | kills session, revokes its refresh token at the `revocation_endpoint` if discovery advertises one (background, best effort), redirects to `end_session_endpoint` if any |
| GET | `/auth/frontchannel-logout` | `iss` + `sid` → kill matching sessions |

Session cookie: `__Host-dropr_session`, `Secure; HttpOnly; SameSite=Strict; Path=/`.

Display settings: `__Host-dropr_lang` (`en`, `fr`) and `__Host-dropr_theme` (`light`, `dark`, `system`; default `light`), `Secure; SameSite=Lax; Path=/; Max-Age=1 year`. Not HttpOnly: `prefs.js` sets them so a change keeps the URL fragment. They carry no secret.

### Request link keys (browser only, no endpoint)

There is no key endpoint and no setup step: the first sign-in lands on the
dashboard.

- **Store**: IndexedDB database `dropr`, version 1, object store
  `request-keys`, key path `id` (the request ID). Record:
  `{id: string, privateKey: CryptoKey /*X25519, non-extractable*/,
  publicKey: Uint8Array(32), ownerId: string /*users.id*/, createdAt: number
  /*Unix s*/}`. Owner pages (`/`, `/inbox`, `/links`) carry the signed-in
  account's ID as `data-owner-id` on `<main>`.
- **Create** (dashboard): generate the pair → `POST /api/requests` → `add`
  the record under the returned ID (never overwriting an existing record) →
  show `/r/<id>#<b64url(pub)>`. If storing fails, the browser deletes the new
  request (`DELETE /api/requests/{id}`) and reports the error: a link is never
  handed out without its key. If it failed because a record with that ID
  already exists, the request is *not* deleted (the ID names an existing link)
  and only the error is shown (audit 2026-11b L-7). The browser also asks for persistent storage
  (`navigator.storage.persist()`, best effort) so the keys are not evicted.
- **Use**: `/inbox` opens each entry with the key of its `request_id`;
  entries without a local key are listed as "received through a link
  created in another browser" (size, date, Delete; no name, no Download).
  `/links` offers "Copy link" only for requests with a local key (the
  fragment is the stored public key, never a server value).
- **Prune**: after a successful `GET /api/requests`, records whose ID is not
  in the list (expired, revoked, deleted elsewhere) are deleted: their files
  are gone from the server with the link. Records created less than 60 s
  before the list was requested are kept, so a tab listing links never
  deletes a key another tab has just stored for a new link. Revoking a link
  deletes its record after the `DELETE` succeeds. The list is trusted: a server
  that wrongly omits a live link makes the browser delete its key for good
  (THREAT_MODEL R17).
- Several accounts may share one browser profile: listing, Copy link and
  pruning only ever consider records whose `ownerId` is the signed-in
  account, so one account never touches another's keys (the server lists
  only the signed-in owner's requests, so a foreign record would otherwise
  look like a deleted link).

### Shares (flow A)
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/shares` | session | `{size, parts, meta (144, 272 or 528 bytes), expires_in?: "1h"|"1d"|"7d"|"30d", max_downloads?: 1..999999}` → 201 `{share_id, upload_id, upload_token}`. `expires_in` defaults to `limits.default_expiry`; 429 `rate_limited` at 5000 live shares per owner |
| DELETE | `/api/shares/{id}` | session (owner) | revoke, complete or still uploading (upload cancelled): delete row + blob → 204 |
| GET | `/api/shares` | session | → `{"shares": [{id, size, parts, expires_at, max_downloads|null, download_count, created_at}]}` (complete, unexpired) |
| POST | `/api/s/{id}/download` | – (rate-limited) | body empty or `{}` → `{token, size, parts, meta}`; 410 `expired` / `exhausted` (count ≥ `max_downloads`); issuing does not count |
| GET | `/dl/{token}` | token | ciphertext, see "Downloads" |

### Requests (flow B)
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/requests` | session | `{expires_in?, max_files: 1..1000, max_bytes, single_use}` → 201 `{request_id}`; client builds link `/r/<id>#<b64url(pubkey)>` from the link's own key pair (§2). `16 ≤ max_bytes ≤ max_files × C(limits.max_file_size)`; 429 `rate_limited` at 5000 live request links per owner; 507 `disk_full` below the disk headroom |
| PUT | `/api/requests/{id}/label` | session (owner) | `{label_meta}` (b64url, 176 or 304 bytes, HPKE-sealed to the link's public key with `info = "dropr/v1 label " ‖ requestId`, so set after creation) → 204 |
| DELETE | `/api/requests/{id}` | session (owner) | revoke: row + every inbox file and blob it received → 204 |
| GET | `/api/requests` | session | → `{"requests": [{id, expires_at, max_files, max_bytes, single_use, files_received, bytes_received, closed, label_meta|null, created_at}]}` (unexpired) |
| POST | `/api/r/{id}/files` | – (rate-limited) | `{size, parts, meta, wrapped_key}` → 201 `{upload_id, upload_token}`; 404 unknown, 410 `expired` / `closed`, 409 `link_full`, 413 `too_large` / `quota_exceeded`, 429 `rate_limited` (100 open incomplete uploads per request link, 500 per owner), 507 `disk_full`. The space check runs only after the link is validated (audit 2026-11b M-2) |
| GET | `/api/inbox` | session | → `{"inbox": [{id, request_id, size, parts, created_at, meta, wrapped_key}]}` (complete files of unexpired requests) |
| POST | `/api/inbox/{id}/download` | session (owner) | → `{token, size, parts}`; 404 once its request expired (the link takes its files with it). Using the token without the owner's session answers 404 before any byte budget is spent |
| DELETE | `/api/inbox/{id}` | session (owner) | delete row + blob → 204 (link counters unchanged) |

The owner's display name for the uploader page ("Send a file to Alice") is
rendered server-side on `/r/{id}`. It is cleaned at login: controls (C0, DEL,
C1), bidi controls and other default-ignorable characters removed (same class
as the file-name sanitizer, FORMAT §5), runs of `\p{Zs}` collapsed to one
space, 200 bytes max; no NFC normalization.

**Request caps** (enforced atomically in the write transaction of
`POST /api/r/{id}/files`, so concurrent uploads can never exceed them):
the file is *reserved* there: `files_received += 1`, `bytes_received += size`.
`files_received + 1 ≤ max_files` and `bytes_received + size ≤ max_bytes`
(ciphertext). Each file also needs plaintext ≤ `limits.max_file_size`.
Abandoned uploads give their reservation back when garbage-collected (24 h).
A link whose owner lost access (role or required claim missing at a
revalidation or login, or `dropr user revoke`; `users.access_lost_at`)
answers 410 `closed` (page and `POST /api/r/{id}/files`) until the owner
signs in again with the role (audit I-3). A disabled owner
(`users.disabled_at`, `dropr user disable`) gets the same answer until
`dropr user enable`.

**Shares of an owner who lost access** (audit 2026-11b L-2): the same
events, and `dropr user disable`, expire every live share link of the owner
in the transaction that records them (`expires_at = min(expires_at, now)`),
delete the download tokens of those links, and so end the share uploads in
progress (part PUT and finalize answer 410 `expired`). A later login or
`dropr user enable` does not bring them back; the cleanup job deletes their
files. Only a missing role or required claim counts at revalidation: an
unreachable provider, a rejected refresh token or a bad token ends the
session and nothing else. As defense in depth, share token issue, token use,
the share page, part PUT, finalize and share creation also refuse an owner
that is disabled or has `access_lost_at` set (410 `expired`; share creation
404).
Deleting a received file does not. **single_use** closes the link
(`closed_at`) when its first file is finalized; uploads reserved before that
may still finish.

### Uploads (shared by A and B)
| Method | Path | Notes |
|---|---|---|
| PUT | `/upload/{upload_id}/part/{n}` | `Authorization: Bearer <upload_token>`; `n` canonical decimal `< parts`; body = exactly the part's ciphertext size (a wrong `Content-Length` is refused before reading; a short/long chunked body stores nothing) → 204; re-PUT replaces atomically (a newer PUT of the same part stops an older one still running, which gets 429); body limit 33 562 624; the read and write deadlines slide with progress (2 min stall), then 60 s to write the reply (audit 2026-11b L-1); at most 6 concurrent part PUTs per upload token |
| GET | `/upload/{upload_id}` | Bearer token → `{parts_present: [n…], complete}` |
| POST | `/upload/{upload_id}/finalize` | Bearer token, `{parts}` → verifies every part present with its exact size, marks complete → `{upload_id, complete: true}`. **Idempotent**: finalizing a complete upload returns the same 200 body. 409 `incomplete` if parts are missing; 404 if the upload was deleted (revoked, collected) meanwhile; 410 `expired` if its link expired or, for a share, its owner lost access |

- **Sizes**: every `size` and every request `max_bytes` / `bytes_received`
  in the API is **ciphertext** bytes (server-verifiable). Only
  `limits.max_file_size` and the page `data-*` limits are plaintext.
- Ciphertext size for plaintext size `P`: `segments = max(1, ceil(P/65536))`,
  `C = P + 16*segments`. The server checks the declared `size` is a possible
  `C` (FORMAT.md §4.3), `parts == max(1, ceil(C / 33 562 624)) ≤ 3200`, the
  plaintext against `limits.max_file_size`, the owner's quota and free disk
  space **before** accepting parts.
- **Upload tokens**: 256-bit random, stored as SHA-256 (`blobs.upload_token_hash`),
  compared in constant time, scoped to one blob. Parts are accepted until
  finalize, for 24 h after creation, and while the link is unexpired (410
  `expired` otherwise). After finalize the token only authenticates status
  and the idempotent finalize.
- A share or inbox row exists from creation but is visible (lists, pages,
  tokens) only once its blob is complete.
- **Quota**: per owner, the sum of the ciphertext `size` of all their blobs,
  complete or uploading, including files received through their request
  links. `users.quota_bytes` overrides `limits.user_quota`.
- **Disk**: a new upload is refused (507 `disk_full`) unless
  `free − size − reserved ≥ limits.disk_headroom` (default max(1 GiB, 5 % of
  the file system)), where `reserved` is what the uploads in progress still
  have to write (Σ over incomplete blobs of declared size − bytes already on
  disk; audit L-6). The reservation ends at finalize or garbage collection. A
  full disk during a part write is also 507.
- **Part commit vs finalize** (audit L-3): a part body is written to a temp
  file without locks; the rename into place happens under a per-blob lock
  after re-reading the upload row (409 `already_complete` if it was finalized
  meanwhile, 404 if deleted). Finalize verifies the parts and marks the blob
  complete under the same lock, so no part can land in a complete blob.
- **Storage**: `data_dir/blobs/<id[0:2]>/<id[2:4]>/<id>/partNNNNN`; parts are
  written to a temp file, fsynced, renamed, and the directory fsynced.

### Downloads
`GET /dl/{token}` serves `application/octet-stream`, `Content-Disposition:
attachment; filename="dropr-download.bin"`, `Cache-Control: no-store`,
CORP same-origin, `Accept-Ranges: bytes`, no `Last-Modified`/`ETag`.

- **Range**: no header → 200 full. One range `bytes=a-b`, `bytes=a-` or
  `bytes=-n` → 206 with `Content-Range`. Anything else (several ranges, other
  units, malformed, unsatisfiable) → 416 with `Content-Range: bytes */size`.
  `If-Range` present → 200 full (no validator can match). HEAD: headers only,
  never counted.
- **Counting**: the first GET of a share token that serves bytes increments
  `download_count` exactly once (zero-byte answers such as 416 do not count) (refused with 410 `exhausted` once the count reached
  `max_downloads`, also for tokens issued earlier); later requests with the
  same token (resumes) never count.
- **Byte budget** (audit L-2): one token serves at most
  `2 × size + min(size, 1 MiB)` ciphertext bytes in total
  (`dl_tokens.served_bytes`): each GET reserves the bytes it will send before
  answering, and gives back what it did not send. Past the budget: 410
  `token_used`; the browser then fetches a new token, whose first use counts
  another download. A download interrupted and resumed any number of times
  fits (resumes restart at the last verified segment), unlimited full
  re-downloads with one counted token do not. The token stays single-share and
  may still be handed on within its budget.
- **Token lifetime**: sliding, valid 1 h after its last use, at most 24 h after
  issuance, never past the share's expiry.
- **Inbox tokens** also require the owner's session (404 otherwise, checked
  before any of the byte budget is spent) and answer
  410 `expired` once their request link expired; their sliding lifetime never
  passes the request's expiry.
- The write deadline slides with progress (2 min stall), so 100 GB downloads
  are bounded by progress, not duration.
- **Slow and concurrent transfers** (audit L-4): part uploads and downloads
  are cut when they average less than `limits.min_transfer_rate` (default
  4 KiB/s) over a 60 s window (uploads: 408 `too_slow`, retried by the
  client; downloads: the body stops short and the client resumes). At most
  `limits.max_transfers` (512) run at once, `limits.max_transfers_per_ip`
  (32) per client address (IPv6 keyed on the /56 for this cap; the rate
  limiters stay on the /64), and 6 per upload token or download token;
  beyond, 429 `too_many_transfers` with `Retry-After: 5` (audit 2026-11b
  M-1). A newer PUT of the same part stops the older one (which gets 429), so
  a client resuming after a dropped connection is not locked out by its own
  stale request.

### Link lifecycle
- **Expiry and revocation delete the blobs** (DESIGN.md §6), for both link
  types: an expired or revoked **request link takes every file it received
  with it**, so owners must download received files before the link expires.
  Expired links stop working immediately (410 `expired`); the cleanup job
  (every 5 min, and `dropr gc`) deletes their rows and files. After that the
  link is unknown (404).
- The cleanup job also deletes incomplete uploads older than 24 h (releasing
  request reservations), expired download tokens, and
  blob directories without a row (older than 1 h).
- `dropr user purge` deletes the affected blob files immediately.

### Error codes
| Code | Status | Meaning |
|---|---|---|
| `bad_request` | 400 | malformed, unknown fields, wrong content type, out-of-range value |
| `invalid_size` | 400 | declared size/parts is no possible ciphertext geometry |
| `bad_part`, `wrong_part_size`, `bad_parts` | 400 | part index, part body size, finalize part count |
| `too_slow` | 408 | part upload below the minimum transfer rate |
| `unauthenticated` | 401 | no valid session |
| `bad_token` | 401 | missing or wrong upload token |
| `csrf` | 403 | cross-site state-changing request (JSON on API paths, an HTML error page elsewhere) |
| `not_found` | 404 | unknown or revoked link, upload, item; other owners' objects |
| `already_complete`, `incomplete`, `link_full` | 409 | state conflicts |
| `expired`, `exhausted`, `closed`, `token_used` | 410 | link (or upload) expired, download limit reached, link closed (single use, or owner lost access), download token byte budget spent |
| `too_large`, `quota_exceeded` | 413 | file/body too large, owner quota |
| `rate_limited` | 429 | per-IP limit, per-user owner write limit or object cap, with `Retry-After` (JSON on API paths, plain text on pages) |
| `too_many_transfers` | 429 | concurrent transfer cap (total, per client address, or per upload/download token) |
| `disk_full` | 507 | free disk below headroom |
| `internal` | 500 | server error |

Per-IP rate limits (keyed hashes): `/s/{id}`, `/r/{id}`, `/api/s/{id}/download`
and `/api/r/{id}/files` share one limiter (60/min, burst 30), `/upload/*`
(900/min, burst 200), `/dl/*` (120/min, burst 60), and `/auth/login`,
`/auth/callback`, `/auth/frontchannel-logout` share another (30/min, burst
10). Part PUTs and `/dl/*` also count against the concurrent transfer caps
(see Downloads).

Per-user owner write limit (audit 2026-11b M-3): creating and deleting shares
and request links, setting a label, deleting an inbox file and issuing an
inbox download token share one limiter per account (300/min, burst 100;
429 `rate_limited`). Object caps per owner: 5000 live shares, 5000 live
request links, 500 open incomplete request uploads (and 100 per request
link); beyond, 429 `rate_limited`.

### State-changing request protection
Every request other than GET, HEAD and OPTIONS: reject (403 `csrf`) unless
`Sec-Fetch-Site` ∈ {`same-origin`, `none`} (`same-site` is refused: sibling
subdomains are not trusted). Absent header → `Origin` must equal the public
origin; both absent → reject. This complements `SameSite=Strict` on the
session cookie. Upload endpoints are same-origin `fetch` too.

## 4. Data model (SQLite, strict tables)

Extends DESIGN.md §8 with the columns the protocol needs:

```
users     (id TEXT PK, issuer, subject, display_name, created_at, disabled_at, quota_bytes NULL, access_lost_at NULL)  UNIQUE(issuer, subject)
sessions  (id_hash BLOB PK, user_id FK, refresh_token_enc BLOB, oidc_sid TEXT, created_at, last_seen_at, revalidated_at)
blobs     (id TEXT PK, owner_id FK, parts INT, size INT, complete INT, upload_token_hash BLOB, created_at)
shares    (id TEXT PK, owner_id FK, blob_id FK, size, meta BLOB, expires_at, max_downloads NULL, download_count, created_at)
requests  (id TEXT PK, owner_id FK, expires_at, max_files, max_bytes, single_use, files_received, bytes_received, created_at, label_meta BLOB(49..512) NULL, closed_at NULL)
inbox     (id TEXT PK, request_id FK, owner_id FK, blob_id FK, size, meta BLOB, wrapped_key BLOB(80), created_at /*finalize time*/)
dl_tokens (token_hash BLOB PK, blob_id FK, share_id NULL, expires_at /*sliding*/, counted INT, served_bytes INT, created_at)
```

Migrations: `0001_init.sql` (the tables above without the additions),
`0002_passkeys_files.sql` (`users.webauthn_handle`, `webauthn_ceremonies`,
`requests.label_meta`, `requests.closed_at`, `dl_tokens.created_at`),
`0003_security_fixes.sql` (`passkey_grants`, `users.access_lost_at`,
`dl_tokens.served_bytes`), `0004_remove_passkeys.sql` (drops `passkeys`,
`user_keys`, `webauthn_ceremonies`, `passkey_grants`,
`users.webauthn_handle`, `sessions.unlocked_at`, `sessions.rotated_from`; deletes every request link
and received file, whose keys were wrapped by the dropped passkeys and are
unrecoverable; the orphan sweep then removes their blob files).
`blobs.id` is the `upload_id` of the API. Every owner-scoped query filters on
the session's `owner_id`; other owners' objects answer 404. Deleting a blob
row cascades to its share or inbox row and download tokens; blob files are
removed after the transaction commits (the orphan sweep catches failures).

Times are Unix seconds (INTEGER). Secrets in DB are hashes (SHA-256) or
AES-256-GCM ciphertext under the file-loaded `refresh_key`.

## 5. Config (`dropr.toml`)

```toml
public_url   = "https://drop.example.com"
mode         = "production"          # or "dev" (allows client_secret, http://localhost)
data_dir     = "/data"
listen       = ":8443"               # proxy mode: "127.0.0.1:8080" or "unix:/run/dropr.sock"
tls          = "acme"                # or "proxy"
acme_email   = "admin@example.com"
redirect_http = false                # listen :8080 → 301 https
trusted_proxies = []                 # CIDRs, proxy mode only
refresh_key_file = "/run/secrets/refresh_key"   # 32 random bytes (raw or base64)
login_label  = "Sign in"

[limits]
max_file_size  = "5GB"     # ≤ 100GB
user_quota     = "50GB"
default_expiry = "7d"

[oidc]   # see DESIGN.md §5.1
```

Additional keys (all optional; unknown keys are rejected):

| Key | Default | Notes |
|---|---|---|
| `redirect_listen` | `":8080"` | address of the `redirect_http` server (ACME mode only) |
| `log_level` | `"info"` | `debug`, `info`, `warn`, `error` |
| `oidc.client_key_id` | – | `kid` header of client assertions (Keycloak matches keys by kid; Entra uses `x5t#S256`) |
| `oidc.client_assertion_alg` | auto | `PS256`/`RS256` (RSA) or `ES256` (P-256); auto = first advertised, PS256 if none advertised |
| `oidc.client_assertion_x5t_sha1` | `false` | also send the legacy SHA-1 `x5t` header |
| `oidc.client_secret_file` | – | dev mode only, with `client_auth = "client_secret"` |
| `oidc.allow_unadvertised_pkce` | `false` | accept a provider that supports PKCE S256 without advertising it (Entra ID) |
| `limits.disk_headroom` | auto | free space that must remain after accepting an upload (and the remaining bytes of uploads in progress); auto = max(1 GiB, 5 % of the file system) |
| `limits.max_transfers` | `512` | concurrent part uploads + downloads, instance-wide |
| `limits.max_transfers_per_ip` | `32` | the same per client address (IPv6 per /56); ≤ `max_transfers` |
| `limits.min_transfer_rate` | `"4KB"` | per second, averaged over 60 s; slower transfers are cut; `"0"` disables |
| `trust_unix_socket_proxy` | `false` | proxy mode on a `unix:` socket: trust the peer's X-Forwarded-For without `trusted_proxies` |

Proxy mode (audit L-1): with a TCP listener, `trusted_proxies` must list the
reverse proxy's address; with a `unix:` socket, `trusted_proxies` or
`trust_unix_socket_proxy = true` is required (the peer is necessarily the
proxy, but trusting its header stays explicit). Production refuses to start
otherwise (every client would share one address and one rate-limit bucket);
dev mode warns. X-Forwarded-For entries may carry a port (`ip:port`,
`[v6]:port`; audit 2026-11b L-5). At runtime Dropr warns once if a request's
client address cannot be determined, if X-Forwarded-For arrives from an
untrusted peer, or if a trusted proxy sends entries it still cannot parse
(one warning per process).
Secret files (`refresh_key_file`, `oidc.client_key_file`,
`oidc.client_secret_file`) readable by group or others give a warning;
readable by others refuses production. Files under `/run/credentials/` and
`/run/secrets/` are exempt (their modes belong to the service manager or
container runtime); symlinks are resolved first, so a link there that points
elsewhere is checked like any other file.

Production startup warnings (never refusals): `limits.min_transfer_rate = "0"`;
an explicit `limits.disk_headroom` above 0 but below 256 MiB; a client key
equal to the committed TEST-ONLY key; a refresh key file of exactly 32
printable ASCII bytes (taken as a raw key, so probably a passphrase).

Logging (`log/slog`, JSON): every line written while serving a request
carries its request ID (`rid`); the request line also carries the client's
keyed IP hash and, when a session exists, the user ID (`user`).
Owner actions also get their own INFO lines: share created/deleted, request
link created/deleted, inbox file deleted, download token issued, and part
upload superseded (a newer PUT of the same part stopped an older one).
`dropr user revoke|disable|enable|purge|migrate` write a WARN `admin action` line to stderr
with the action, the Unix UID that ran it and the user ID (`migrate`: also the
old and new issuer and subject) (audit 2026-11b L-9).

`dropr backup --out FILE` writes the copy inside a fresh 0700 temporary
directory next to `FILE`, then hard-links it into place, so the file is never
visible under the umask; it refuses a symlink at `--out` (audit 2026-11b L-10).

Changing a secret or the origin:

- **`refresh_key`** encrypts stored refresh tokens and the login-state cookie;
  it never protects files. Rotate by replacing the file and restarting. Stored
  refresh tokens become undecryptable, so sessions can no longer revalidate
  and users sign in again; logins in flight fail once. After a suspected leak,
  rotate, run `dropr user disable` for anyone who must lose access now, and
  revoke sessions at the provider: the old key plus a database copy exposes
  refresh tokens until they expire.
- **OIDC client key**: see [oidc.md](oidc.md).
- **`public_url`**: request link private keys live in owners' browsers per
  origin. A new scheme or host makes every received file unreadable and breaks
  every link already handed out. Pick it once; move only after owners have
  downloaded their received files.

Sizes use binary units (`5GB` = 5 GiB, so `100GB` = 3200 × 32 MiB parts).

Asset manifest: the TypeScript build writes hashed files plus
`internal/web/static/manifest.json`, a flat JSON object mapping logical names
to file paths relative to that directory, e.g.
`{"dashboard.js": "dashboard-5KQ2ZJ3C.js", "sw.js": "sw.js"}`. Pages reference
logical names; files not in the manifest (e.g. `app.css`) are fingerprinted at
startup. `sw.js` is served from `/sw.js` with `Service-Worker-Allowed: /_dl/` (its only
scope; a root-scope registration is refused).

## 6. Testing conventions

- Go: table tests, `t.Parallel()`, `httptest`, native fuzz targets (`FuzzXxx`)
  for every parser of untrusted input (Range, IDs, JSON bodies, part geometry,
  claim paths). A fake OIDC provider (`internal/auth/oidc/oidctest`) signs
  tokens with an in-memory RSA/EC key for negative tests (alg none, HS256,
  wrong iss/aud/nonce, expired, missing role).
- `go vet`, `golangci-lint run`, `govulncheck ./...` must be clean
  (`make check` = build, lint, race tests, govulncheck; `make fuzz` runs every
  fuzz target for `FUZZTIME`).
- Translations: `TestCatalogsComplete` (internal/i18n) scans the templates and
  Go sources for msgids; `web/test/i18n.test.ts` checks that every locale has
  every key and a French text for every API error code the Go code emits.
- `make test-keycloak`: real logins against the dev Keycloak
  (`-tags keycloak`).
- Web: `npm test` runs node's test runner (`node --test`, TypeScript run
  natively) against WebCrypto in Node 24 (X25519, HKDF, AES-GCM): crypto
  modules against the FORMAT.md vectors, plus the uploader, downloader,
  service-worker protocol, request-key store, API client and formatting.
  `npm run typecheck` covers pages, worker and tests.
- E2E (`make e2e`): Playwright in Chromium, Firefox and WebKit (browsers from
  nixpkgs) against the dev Keycloak: both flows, resume, tampering, expiry,
  revocation, download limits, roles, CSRF, headers, accessibility, request
  link keys, languages and themes.
- `nix flake check`: reference builds, `go vet` and Go tests, web typecheck
  and tests.
