# Dropr OWASP Top 10 code audit (2026-11b)

Date: 2026-11-07. Scope: the repository at commit a16fbdf (`docs: align
DESIGN and THREAT_MODEL with the code`), after the passkey removal and the
fixes of the [first audit](security-audit-2026-11.md).
Method: static review in six parallel areas, one per group of OWASP Top 10
(2021) categories (A01 access control; A02/A08 cryptography and integrity;
A03 injection; A04/A05/A10 design, configuration and SSRF; A06/A09
dependencies and logging; A07 authentication and sessions), each against the
spec (DESIGN, ARCHITECTURE, FORMAT, PAGES, THREAT_MODEL, SECURITY.md). Every
Medium and Low finding was then re-verified against the code. Nothing was run
except static tooling: `govulncheck`, `go vet`, `npm audit` (web, e2e).
Code comments cite the finding IDs as "audit 2026-11b L-7".

Confidence labels: **CONFIRMED** means the code path was traced with no
ambiguity (nothing was exploited live). **LIKELY** means the code path exists
but the impact depends on deployment or provider behavior that was not
verified. **SPECULATIVE** means a plausible chain with an unverified step.

**Verdict:** no Critical or High finding. The core security properties hold:
end-to-end cryptography (streaming AEAD, HPKE, KDF domain separation), access
control (owner filters, capability tokens, atomic caps), OIDC (PKCE, issuer
and algorithm pinning), CSRF, XSS (strict CSP with Trusted Types, no HTML
sinks) and SQL (placeholders only). The findings cluster around
**availability** (A04) and the **lifecycle of access after revocation**
(A01/A07).

## Summary

| ID | Severity | OWASP | Title |
|---|---|---|---|
| M-1 | Medium | A04 | Global transfer slots can be held by about 16 IP addresses |
| M-2 | Medium | A04 | Upload reservations need no bytes: one request link can make the whole instance answer 507 |
| M-3 | Medium | A04 | Owner API has no rate limit or object cap; SQLite growth is outside the quota |
| L-1 | Low | A04 | Part PUT write deadline is fixed at 60 s: uploaders below about 4.5 Mbit/s fail |
| L-2 | Low | A01 | Shares and share upload tokens survive the owner losing access |
| L-3 | Low | A01/A07 | No local lockout: `user revoke` is undone at the next login; `disabled_at` is never set |
| L-4 | Low | A07 | Front-channel logout is a silent no-op when the provider omits `sid` |
| L-5 | Low | A05 | `X-Forwarded-For` entries with `ip:port` collapse every client onto the proxy |
| L-6 | Low | A08 | Release integrity: unsigned tags still release; asset hashes are not signed |
| L-7 | Low | A02 | The browser deletes request-link private keys the server stops listing |
| L-8 | Low | A02 | Encrypted metadata is not padded: exact name/type and label lengths leak |
| L-9 | Low | A09 | Security events lack actor and request ID; admin CLI actions are not logged |
| L-10 | Low | A05 | `dropr backup` output is readable under the umask until `VACUUM INTO` finishes |

Areas reviewed with **no findings** (each checked explicitly):
- STREAM, HPKE and the KDF: nonce layout, counter and final flag, labels and
  domain separation, `requestId` bound in the HPKE `info`, all-zero DH check,
  metadata bound to the blob size. Request-link private keys are generated
  non-extractable and never leave the browser; links are built from the stored
  public key only.
- Access control: owner filters on every owner-scoped query; upload and
  download tokens scoped to one object; atomic download counting and request
  cap reservation; uniform 404 for unknown, expired and foreign objects.
- OIDC and sessions: PKCE S256, `state` and `nonce` in a sealed `__Host-`
  cookie, RFC 9207 `iss` check, issuer pinning, asymmetric algorithms only,
  `aud`/`azp`, time checks, revalidation with the `sub` check; hashed,
  fixation-safe, rotated session IDs; refresh tokens encrypted with the
  session hash as AAD.
- Injection: `html/template` only, no `template.HTML`; no Trusted Types sinks
  in `web/src`; SQL uses placeholders only; blob paths are built only from
  validated IDs; strict JSON decoding with trailing-data checks on the API.
- SSRF (A10): the server never fetches a user-controlled URL. The OIDC client
  refuses redirects, requires TLS 1.2+, has timeouts and caps token and
  userinfo bodies at 1 MiB.
- Dependencies: `govulncheck` finds nothing reachable; `npm audit` reports 0
  vulnerabilities in `web/` and `e2e/`.

---

## M-1. Global transfer slots can be held by about 16 IP addresses

- **Severity:** Medium (A04)
- **Location:** `internal/httpx/streams.go:34-52`, `internal/server/server.go:107`, `internal/config/config.go:201-206`
- **Description:** `max_transfers` (512) is global, `max_transfers_per_ip` is 32, and a stream survives as long as it moves `min_transfer_rate` (4 KiB/s). Nothing limits concurrent PUTs to the same upload or part.
- **Exploit scenario:** An attacker holding any link (a public request link is enough) opens 32 slow part PUTs or downloads from each of 16 IPv4 addresses, or from 16 /64s inside one IPv6 /60, and holds all 512 slots with about 2 MiB/s of total bandwidth. Every other upload and download is refused.
- **Recommended fix:**
  - Cap concurrent streams per upload or token (at most the parallelism the client uses, 4 to 6).
  - Key IPv6 on /56 for the stream cap.
  - Reserve a share of the slots for authenticated owners; consider a higher minimum rate on parts.
- **Confidence:** CONFIRMED (code trace).

## M-2. Upload reservations need no bytes

- **Severity:** Medium (A04)
- **Location:** `internal/server/files.go:35-54`, `internal/store/files.go:91-110`, `:338-391`
- **Description:** Since the first audit's L-6 fix, `checkSpace` counts the declared size of every incomplete blob as reserved. Creating a request upload reserves its full size against the disk and the owner's quota with zero bytes sent. The reservation lasts until garbage collection (24 h) and can be renewed. The space check also runs before the request ID is validated (a disk-full oracle).
- **Exploit scenario:** With one request link, the attacker reserves up to the link's `max_bytes` or the owner's quota (default 50 GB). On a disk with less free space than that, **every** upload on the instance answers 507, and the owner's quota stays locked.
- **Recommended fix:**
  - Expire reservations that see no progress quickly (for example 15 min without a part).
  - Count only the parts in flight plus a bounded look-ahead instead of the full declared size.
  - Cap open incomplete uploads per request link and per IP; validate the request ID before the space check.
- **Confidence:** CONFIRMED (code trace).

## M-3. Owner API has no rate limit and no object cap

- **Severity:** Medium (A04)
- **Location:** `internal/server/server.go:225-238`, `internal/server/api.go:20-29`
- **Description:** Owner routes (`POST /api/shares`, `POST /api/requests`, label updates) only require a session. Each share costs 16 bytes of quota but about 4 KB of SQLite; database growth is outside the quota and the disk headroom check. Many incomplete uploads also make every `checkSpace` and the orphan sweep O(n).
- **Exploit scenario:** A single low-privilege account, or a stolen session, scripts share creation and fills the disk.
- **Recommended fix:** Rate-limit owner write routes; cap live shares, requests and incomplete uploads per user; include the database file in the headroom check.
- **Confidence:** LIKELY.

## L-1. Part PUT write deadline does not slide

- **Severity:** Low (A04, reliability)
- **Location:** `internal/server/server.go:242-243`, `internal/httpx/middleware.go:45-58`, `internal/blob/serve.go:228-230`
- **Description:** The part route sets a 2 min read deadline (slid by `ProgressReader`) and a 60 s write deadline; only the read deadline slides. A part is 33,562,624 bytes, so any part slower than about 560 KB/s (about 4.5 Mbit/s uplink) passes its write deadline. On HTTP/1.1 the part is stored but the 204 cannot be written; on HTTP/2 the stream is reset mid-body. Slow uploaders may never finish.
- **Recommended fix:** Slide the write deadline in `ProgressReader` with the read deadline, or set it after the body has been read. Verify first with a throttled client over HTTP/2.
- **Confidence:** CONFIRMED by reading; not tested live.

## L-2. Shares outlive the owner's access

- **Severity:** Low (A01)
- **Location:** `internal/store/files.go:555-575` (`CreateShareToken`), `:625`, `internal/server/pages.go:105`, `internal/server/transfer.go:77`
- **Description:** The owner-state check of the first audit's I-3 fix only guards request links. After the role is withdrawn or `dropr user revoke`, share links keep serving until expiry (at most 30 days, possibly with unlimited downloads), share upload tokens keep accepting parts and finalize for 24 h, and request uploads reserved before the revocation can still finish.
- **Exploit scenario:** A stolen session mints 30-day shares that keep publishing content on the organization's domain after the account is revoked; only `dropr user purge` stops them.
- **Recommended fix:** Apply `disabled_at IS NULL AND access_lost_at IS NULL` in share token issue, the share page, part PUT and finalize; or document the behavior and offer a way to close a user's links.
- **Confidence:** CONFIRMED (code trace).

## L-3. No local lockout

- **Severity:** Low (A01/A07)
- **Location:** `internal/store/users.go:77-80`; `disabled_at` is read (`users.go:285`, `files.go:356`, session load) but never written
- **Description:** `dropr user revoke` sets `access_lost_at` and deletes the sessions, but the next successful login clears it. THREAT_MODEL R10 and "Departed user", DESIGN and `docs/oidc.md` presented revoke as immediate removal.
- **Recommended fix:** A `disable`/`enable` command that sets `disabled_at`; reword the documentation to match the code.
- **Confidence:** CONFIRMED (code trace).

## L-4. Front-channel logout is a no-op without `sid`

- **Severity:** Low (A07)
- **Location:** `internal/auth/oidc/verify.go:114`, `internal/auth/oidc/handlers.go:237-259`
- **Description:** A missing `sid` claim is stored as an empty string, so `DeleteSessionsByOIDCSID` matches nothing and the handler still answers 200, with no warning anywhere. Entra may emit `sid` only as an optional claim, while `docs/oidc.md` said none were needed (not verified against a tenant). Keycloak always sends it, so development and CI cannot catch this.
- **Recommended fix:** Warn (once per provider) at login when `sid` is absent; check and correct the Entra section of `docs/oidc.md`.
- **Confidence:** CONFIRMED for the code path; the Entra default is unverified.

## L-5. `X-Forwarded-For` entries with ports

- **Severity:** Low (A05)
- **Location:** `internal/httpx/clientip.go:53-58`
- **Description:** `netip.ParseAddr("1.2.3.4:5678")` fails, the walk stops and the client address becomes the proxy. Proxies that append ports (Azure Application Gateway does) put every client in one bucket.
- **Exploit scenario:** One client exhausts the authentication rate limiter for everyone (the first audit's L-1, again), and the 32-slot per-IP stream cap applies to the whole instance.
- **Recommended fix:** Fall back to `netip.ParseAddrPort`; warn when a trusted proxy sends unparsable entries.
- **Confidence:** CONFIRMED (code trace).

## L-6. Release integrity

- **Severity:** Low (A08)
- **Location:** `.github/workflows/ci.yml:139` (`git tag -v … || echo ::warning::`), `:162-166` (only `SHA256SUMS` is signed); `SECURITY.md` "Check what a running instance serves"
- **Description:** An unsigned or wrongly signed `v*` tag still yields a signed release. `cosign sign-blob` covers only the binary checksums, not `dropr-assets-*.sha256`, which the "check a running instance" procedure relies on: whoever can replace that release asset can make a backdoored bundle pass the check without breaking any signature. The release job also does not depend on the end-to-end tests.
- **Speculative add-on:** the release job (holding `id-token: write` and `contents: write`) shares the magic-nix-cache with jobs that run `npm ci` outside the Nix sandbox on `main`, and builds the binaries with `nix develop -c go build` instead of the Nix derivation.
- **Exploit scenario:** Needs repository write access, a token with `contents: write`, or a foothold in a CI job on `main` (cache poisoning, unverified).
- **Recommended fix:** Fail on a bad tag signature against published maintainer keys; sign the asset hashes too; make the release job depend on the end-to-end job; disable the shared cache (or make it read-only) in the release job; build the binaries from the flake package.
- **Confidence:** CONFIRMED (workflow); SPECULATIVE for the cache path.

## L-7. The server's list drives browser key deletion

- **Severity:** Low (A02)
- **Location:** `web/src/lib/request-keys.ts:148-162`, called from `web/src/inbox.ts:63` and `web/src/links.ts:150`; `web/src/dashboard.ts:203`
- **Description:** `prune` deletes every local private key whose request the server no longer lists (60 s grace). A database restored from an old backup, a bug, or a malicious server permanently destroys keys that exist nowhere else (THREAT_MODEL R7). On creation, `put` also silently overwrites a record with the server-chosen ID; the error path would then ask the server to delete that existing request.
- **Recommended fix:** Tombstone instead of deleting (purge after N days, or on explicit user action); refuse to overwrite an existing ID.
- **Confidence:** CONFIRMED (code trace).

## L-8. Metadata length leak

- **Severity:** Low (A02)
- **Location:** `web/src/crypto/meta.ts:135`, `web/src/crypto/requestkey.ts:353`
- **Description:** Name and type, and request labels, are encrypted without padding. The server knows the plaintext size from the blob length, so `|meta|` gives it `|name| + |type|` exactly (UTF-8 bytes, JSON escapes included), and `|label_meta| = 48 + |label|`. FORMAT §8.7 and THREAT_MODEL R2 did not mention it.
- **Recommended fix:** Pad to buckets in a versioned format, or document the leak.
- **Confidence:** CONFIRMED (code trace).

## L-9. Security logging gaps

- **Severity:** Low (A09)
- **Location:** `internal/httpx/middleware.go:83`, `:118`; `cmd/dropr/main.go:213-315`
- **Description:** The request log has no user ID. `RequestID()` is never called, so OIDC login, logout and denial lines carry neither the request ID nor the IP hash. Link creation and deletion and downloads appear only as route and status. All security events are INFO, so `log_level = "warn"` drops them. `dropr user revoke|purge|migrate` leave no trace; `migrate` relinks an account to another identity invisibly. This contradicted THREAT_MODEL §5.2 ("R" row).
- **Recommended fix:** A context-aware log handler adding the request ID and user ID; explicit audit events at WARN; log admin CLI actions.
- **Confidence:** CONFIRMED (code trace).

## L-10. Backup file permissions

- **Severity:** Low (A05)
- **Location:** `internal/db/db.go:149-162`
- **Description:** `VACUUM INTO` creates the file under the process umask; `chmod 0600` runs afterwards. A local user can open the file during the copy.
- **Recommended fix:** `VACUUM INTO` refuses an existing non-empty target, so write into a fresh 0700 temporary directory next to the destination, then rename.
- **Confidence:** CONFIRMED (code trace).

## Informational

- **Revocation and sessions:** re-login does not delete the previous session (the SameSite=Strict cookie is absent on the provider callback, `session.go:118-123`); refresh tokens are not revoked at the provider on logout or revoke; front-channel logout by `sid` is unauthenticated (as the specification mandates; rate-limited); idle departed users' request links stay open until expiry (`SessionsDueForRevalidation` is unused); the inbox download token budget is debited before the owner check (`transfer.go:251-265`).
- **Abuse and limits:** `max_downloads` is consumed by zero-byte responses (416, a 1-byte Range); per-/64 IPv6 keying lets address rotation bypass rate limits; no listener connection cap (first audit L-4, partial); concurrent PUTs of the same part write 32 MiB temporary files outside the reservation, and crash leftovers are never swept.
- **Configuration:** production accepts `min_transfer_rate = "0"` and a tiny `disk_headroom`; the secret-permission exemption is a path-prefix check; the committed TEST-ONLY key is not refused; `LoadRefreshKey` accepts any 32-byte file as a raw key (`secrets.go:56`), so a 32-character passphrase becomes the master key.
- **Spoofing:** `cleanDisplayName` (`users.go:51`) keeps bidi, invisible and C1 characters, which are shown on the anonymous request page; reuse the file-name sanitizer's character class.
- **Parsing:** `decodeClaims` (`verify.go:171`) uses `d.More()` instead of the `Token() == io.EOF` trailing-data check used in `httpx/json.go` (after signature verification only).
- **Specification drift:** FORMAT §8.10 claimed constant-time comparison, but `constantTimeEqual` was unused; the request ID bound into the HPKE `info` came from `data-request-id`, not the URL path as FORMAT §6 says; `Assets.Hashes()` is unused; a stale passkey-era comment in `b64.ts`; THREAT_MODEL R10 overstated revoke.
- **Dependencies:** GO-2026-5932 in `golang.org/x/crypto/openpgp` (not imported, not reachable; bump when fixed). No Dependabot or Renovate configuration; no `toolchain` line in `go.mod`.
- **SSRF residuals:** discovery endpoints are not tied to the issuer host; discovery and JWKS bodies are unbounded (the provider is trusted).

## First audit (2026-11) re-check

Holding: L-2, L-3, I-1, I-2, I-4, I-7, I-8, and the L-1 warning. Obsolete:
L-5 (rotation removed), I-6 (passkeys removed). Partial: **L-1** (port-suffixed
`X-Forwarded-For`, L-5 here), **L-4** (M-1, L-1 here, no listener cap),
**I-3** (shares not covered, L-2 here). The **L-6** fix introduced M-2.

---

## Resolution

Fixed on 2026-11-07, under one constraint: no feature change (no new CLI
command or configuration key, no wire or storage format change, no
user-visible change for legitimate use). Findings whose fix would need one are
documented instead. Each entry: finding → fix → regression test(s). Contracts
updated in docs/ARCHITECTURE.md, docs/DESIGN.md, docs/FORMAT.md (§6, §8.7,
§8.10), docs/PAGES.md, docs/THREAT_MODEL.md (R2, R10, new R17),
docs/oidc.md and SECURITY.md. No schema change.

| ID | Status | Fix | Tests |
|---|---|---|---|
| M-1 | Fixed | The per-address stream cap keys IPv6 on the /56 (rate limiters stay on the /64). At most 6 concurrent streams per upload token and per download token (429 `too_many_transfers` + `Retry-After`). A newer PUT of the same part stops the older one, which gets 429, so a client resuming after a dropped connection is not locked out by its own stale request. | `TestStreamCapPerUpload`, `TestPartPutSupersedesOlderPut`, `TestTransferStreamCap` (internal/server); the /56 keying has no dedicated test |
| M-2 | Partly mitigated, residual accepted | The space check runs only after the request link is validated (no disk-full oracle). At most 100 open incomplete uploads per request link and 500 per owner (429 `rate_limited`). The caps count uploads, not bytes: one link can still reserve up to 100 × `max_file_size` (within its `max_bytes` and the owner's quota) for 24 h with no bytes sent. Expiring idle reservations earlier would change upload behavior for slow legitimate senders; documented in THREAT_MODEL §4. | `TestRequestFileSpaceCheckAfterLink` (internal/server), `TestOpenUploadCaps` (internal/store) |
| M-3 | Fixed | Per-account owner write limit (300/min, burst 100) on creating and deleting shares and request links, labels, inbox deletes and inbox download tokens. Object caps per owner: 5000 live shares, 5000 live request links (429 `rate_limited`). `POST /api/requests` also answers 507 below the disk headroom. | `TestOwnerWritesRateLimited` (internal/server), `TestLiveLinkCaps` (internal/store) |
| L-1 | Fixed | `ProgressReader` slides the write deadline together with the read deadline while a part body arrives (2 min stall); the reply then gets 60 s. | `TestProgressReaderSlidesBothDeadlines` (internal/blob) |
| L-2 | Fixed | Losing access (role or required claim missing at login or revalidation, `dropr user revoke`, `dropr user disable`) expires every live share of the owner in the same transaction (`expires_at = min(expires_at, now)`), deletes their share download tokens and so ends share uploads in progress; a later login does not bring them back. Transient revalidation failures (provider down, rejected refresh token) do not. Share token issue and use, the share page, part PUT, finalize and share creation also refuse a disabled or access-lost owner. Request links keep pausing and resuming. | `TestLosingAccessExpiresShares`, `TestInactiveOwnerShareRefused` (internal/store), `TestSharesExpireWhenOwnerLosesRole`, `TestSharesSurviveTransientRevalidationFailure` (internal/server), `TestRevalidation` account/share checks (internal/auth/oidc), `TestUserDisableEnable` (cmd/dropr) |
| L-3 | Fixed | New `dropr user disable <user>` sets `disabled_at`, ends the sessions and expires the share links; login, session load and request links refuse the account until `dropr user enable <user>`, which clears `disabled_at` only. Both are idempotent and write the WARN `admin action` line. `dropr user list` shows the disable date. | `TestDisableEnableUser` (internal/store), `TestDisabledOwner` (internal/server), `TestUserDisableEnable` (cmd/dropr) |
| L-4 | Fixed (warning and docs) | Dropr logs one WARN per process when an ID token has no `sid` (front-channel logout cannot match sessions). oidc.md and DESIGN explain that front-channel logout needs `sid`, and tell Entra admins to check for it and enable the `sid` optional claim if needed. | none (log warning only) |
| L-5 | Fixed | `X-Forwarded-For` entries with a port (`ip:port`, `[v6]:port`) are parsed; one warning per process when a trusted proxy sends entries that still cannot be parsed. | `TestIPResolver` (port cases), `TestRealIPWarnsOnUnparsableForwardedFor` (internal/httpx) |
| L-6 | Fixed, except flake-built binaries | The release job refuses a tag that is not annotated, does not point at the built commit, or is not SSH-signed by a key in the allowed signers list written by the workflow (fingerprints published in SECURITY.md). Both `SHA256SUMS` and `dropr-assets-*.sha256` are cosign-signed and their bundles published; SECURITY.md verifies the asset hashes before using them. The release job no longer uses the shared magic-nix-cache. Dependabot (Go modules, npm in `web/` and `e2e/`, GitHub Actions; weekly) was added. Not done: building the binaries from the flake package (its version is the commit, not the tag, and arm64 needs cross-compilation). | CI workflow (runs on the next tag) |
| L-7 | Partly fixed, residual documented | Creating a request link never overwrites a stored key: the store uses IndexedDB `add`, a duplicate ID fails with a dedicated error, and the dashboard then leaves the existing request alone instead of deleting it. Prune semantics (deleting keys of links the server no longer lists) are a design decision and unchanged: documented as THREAT_MODEL R17 and in ARCHITECTURE §3. | "never overwrites a stored record, whoever owns it" (web/test/request-keys.test.ts) |
| L-8 | Fixed | Metadata JSON and request labels are zero-padded before sealing to the smallest power of two ≥ 128 bytes (metadata ≤ 512, labels ≤ 256), so `meta` is 144, 272 or 528 bytes and `label_meta` 176 or 304 bytes. Openers reject non-canonical padding (wrong bucket, non-zero pad bytes) as a format error, and the API rejects any other length with 400. No format version change (no deployment). FORMAT §5.1 and §8.7 describe the residual bucket leak. | `TestPaddedLengths`, `FuzzJSONRequests` (internal/server); "pads to a 128/256/512-byte bucket", "rejects non-canonical padding" (web/test/meta.test.ts); "pads to 128 or 256 bytes…", "rejects non-canonical padding" (web/test/requestkey.test.ts) |
| L-9 | Fixed | Every log line written while serving a request carries its request ID (`rid`); the request line carries the user ID when a session exists. New INFO lines: share created/deleted, request link created/deleted, inbox file deleted, download token issued, part upload superseded. `dropr user revoke|purge|migrate` write a WARN `admin action` JSON line to stderr with the action, the Unix UID and the user ID (`migrate`: old and new issuer and subject). | `TestLoggerUserAndRequestID` (internal/httpx), `TestMiddlewareLogsUser` (internal/auth/session), `TestUserCommands` audit lines (cmd/dropr) |
| L-10 | Fixed | `dropr backup` writes the copy inside a fresh 0700 temporary directory next to the destination and hard-links it into place, so it is never readable under the umask; a symlink at `--out` is refused. | `TestPlaceNewKeepsExisting` (internal/db), `TestGCBackupVersion` (cmd/dropr) |

Informational items:

| Item | Status | Fix | Tests |
|---|---|---|---|
| Re-login keeps the previous session | Fixed | The hash of the browser's current session travels in the sealed OIDC state cookie; a successful callback deletes that session (a cancelled or refused sign-in keeps it). | `TestLoginEndsPresentedSessionWithoutCallbackCookie` (internal/auth/oidc) |
| Refresh tokens not revoked at the IdP | Fixed for logout | Logout revokes the refresh token at the `revocation_endpoint` when discovery advertises one (RFC 7009, background, best effort). `dropr user revoke` and failed revalidation still drop it locally only. | `TestLogoutRevokesRefreshToken` (internal/auth/oidc) |
| `decodeClaims` trailing data | Fixed | Trailing data after the claims object is refused. | `TestLookupAndHasRole` (internal/auth/oidc) |
| Unbounded discovery and JWKS bodies | Fixed | Every provider response body, discovery and JWKS included, is capped at 1 MiB. | `TestCappedResponses` (internal/auth/oidc) |
| Display name spoofing | Fixed | Display names lose controls (C0, DEL, C1), bidi, invisible and other default-ignorable characters, and runs of spaces collapse to one, as for file names; no NFC normalization on the server. | `TestDisplayNameSanitized` (internal/store) |
| Inbox token budget debited before the owner check | Fixed | A token used without the owner's session answers 404 before any budget is spent. | `TestDownloadChecksBeforeSpending` (internal/server), `TestUseDownloadTokenChecksFirst` (internal/store) |
| `max_downloads` consumed by zero-byte responses | Fixed | Only the first GET that serves bytes counts (416 and other zero-byte answers do not). | `TestDownloadChecksBeforeSpending` (416 case, internal/server) |
| Weak production configuration accepted | Fixed (warnings) | Production warns (never refuses) on `min_transfer_rate = "0"`, an explicit `disk_headroom` below 256 MiB, the committed TEST-ONLY client key, and a refresh key file of 32 printable ASCII bytes (likely a passphrase). | `TestTransferLimits`, `TestRefreshKeyPassphraseWarning`, `TestTestOnlyKeyDetected` (internal/config) |
| Secret-permission exemption by path prefix | Fixed | Symlinks are resolved and containment in `/run/credentials` or `/run/secrets` is checked; a link there pointing elsewhere is permission-checked. | `TestInManagedDir` (internal/config) |
| Request ID for HPKE from `data-request-id` | Fixed | The request page reads the ID from the URL path and refuses to upload if the page's `data-request-id` differs. | web typecheck; e2e request flow |
| Dead `constantTimeEqual`, stale `b64.ts` comment | Fixed | Helper removed; FORMAT §8.10 reworded to what the code does; comment corrected. | – |
| IPv6 /64 rate-limit keying | Documented, not changed | Rate limiters stay on the /64 (only the stream cap moved to /56). | – |
| Unauthenticated front-channel logout by `sid` | Accepted | Mandated by the specification; rate-limited. | – |
| Idle departed users' request links | Accepted | They stay open until expiry or the next revalidation or login that finds the role missing (THREAT_MODEL R10). | – |
| GO-2026-5932 (`x/crypto/openpgp`) | Pending upstream | Not imported, not reachable; bump `golang.org/x/crypto` when a fix is released (Dependabot will propose it). | `govulncheck` in CI |
