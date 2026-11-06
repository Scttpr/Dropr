# Dropr pre-release security audit

Date: 2026-11-05. Scope: the repository as it stood during the audit (another engineer was integrating at the same time; `session.go`, `passkey.go` and `server.go` changed while I was reading them, and the line numbers below match the final state I read).
Method: manual review of the spec (PLAN, ARCHITECTURE, FORMAT, PAGES, THREAT_MODEL) against the code, plus `go test ./...` and `npm test`, plus throwaway tests in a scratch copy of the repo.
Test status: web tests 203/203 pass. Go tests pass except `internal/server TestAnonymousPagesAndHeaders` ("GET /api/nope: 404"). That failure comes from the routing/notFound work in progress, not from a security problem.

Confidence labels: **CONFIRMED** means I demonstrated it or traced the code path with no ambiguity. **PLAUSIBLE** means the code path exists, but exploiting it depends on timing or environment.

## Summary

| ID | Severity | Title |
|---|---|---|
| M-1 | Medium | Passkey add/delete is gated only by the 8 h session unlock flag: a stolen unlocked session can swap in attacker passkeys and destroy the owner's key access |
| L-1 | Low | Proxy mode without `trusted_proxies` silently puts every client in one rate-limit bucket (login lockout for all) |
| L-2 | Low | `max_downloads` is weak: one counted token allows unlimited full re-downloads for up to 24 h and can be handed on |
| L-3 | Low | Part PUT is TOCTOU against finalize: a part can replace data in an already-complete blob |
| L-4 | Low | Trickle (slow-rate) uploads and downloads hold connections indefinitely; no cap on concurrent connections |
| L-5 | Low | Session rotation can store a stale refresh token when it races with revalidation (session killed; possible IdP reuse-detection revocation) |
| L-6 | Low | Disk-space check does not count in-flight reservations; concurrent uploads can push the volume (and SQLite) to ENOSPC |
| I-1 | Info | `/sw.js` sends `Service-Worker-Allowed: /` while only `/_dl/` is needed |
| I-2 | Info | Finalize answers 200 when GC or revocation deleted the blob row between the checks |
| I-3 | Info | Request links of users who lost the role keep accepting anonymous uploads |
| I-4 | Info | File-name sanitizer keeps whitespace runs and invisible fillers (extension spoofing in UI and save dialogs) |
| I-5 | Info | First passkey registration (new account, or after `reset-keys`) is claimable by whoever signs in first |
| I-6 | Info | Inbox file count is shown on the dashboard and the inbox page without unlock |
| I-7 | Info | Secret files are not checked for loose permissions |
| I-8 | Info | Responses produced by `net/http` itself (400/431 on malformed requests) carry no security headers |

Areas reviewed with **no findings** (each checked explicitly):
- STREAM: nonce layout, counter bound and last flag, segmenter hold-back, part encryption with absolute indexes, resume (Content-Range is checked exactly, the decryptor restarts at segment k, nothing unauthenticated is released, truncation, reordering and trailing data all fail).
- HPKE against RFC 9180: suite IDs, LabeledExtract/Expand byte order, psk_id_hash/info_hash, `kem_context = enc‖pkR`, all-zero DH check. Request-id binding in `info`.
- Keywrap: KEK = HKDF(PRF, salt = userHandle) and non-extractable; the JWK is parsed strictly and x is checked against d; the public key always comes from the authenticated JWK and never from the server.
- PRF: the eval salt is forced on the client, the output is stripped from the JSON sent to the server and zeroed after use.
- Request-link public key cannot be swapped by the server. Metadata is size-bound to the blob. Fragment never reaches requests or logs.
- OIDC: state, nonce and PKCE in a sealed `__Host-` cookie; RFC 9207 `iss` check; issuer pinning; asymmetric algorithms only; aud/azp; time checks; revalidation by ID token or userinfo with the sub check; refresh token encrypted with AAD = session hash; front-channel logout restricted to iss+sid.
- Sessions: hashed, fixation-safe, rotated at unlock, idle and absolute timeouts.
- WebAuthn: UV required, origin and RP ID pinned, single-use ceremonies keyed to the session and consumed before rotation, clone-counter refusal.
- CSRF: global middleware on every non-GET route, all 18 state-changing routes enumerated; the only GETs with side effects are `/auth/login`, front-channel logout and `/dl` with a bearer token.
- Owner filters on every owner-scoped query (shares, requests, labels, inbox, inbox tokens, passkeys). Upload-token scope. Atomic download counting and request-cap reservation (single writer, `BEGIN IMMEDIATE`). Quota covers both flows.
- Blob paths are built only from validated IDs. Range parser rejects overflow and multi-range. Geometry bounds hold.
- Headers and CSP match PLAN §7 on pages, API, assets, errors, 404, `/dl` and SW responses. No Trusted Types sinks in `web/src`. Only `html/template`, no `template.HTML` anywhere. Cookie flags correct. TLS config correct. XFF walk correct. Logs hold keyed IP hashes only. Secrets are file-only and production refuses `client_secret` and http issuers.

---

## M-1. Passkey management is gated only by the long-lived unlock flag

- **Severity:** Medium
- **Location:** `internal/auth/passkey/passkey.go:285` (RegisterBegin), `:380` (RegisterFinish), `:410` (AddPasskey call), `:603` (Delete); `internal/store/passkeys.go:124-135` (only the public key is compared); `internal/auth/session/session.go:109-110` (UnlockMaxAge defaults to the 8 h absolute lifetime)
- **Description:** Adding another passkey and deleting passkeys each require only `IsUnlocked(sess)`. That flag is set by any earlier unlock in the same session and lasts the whole session (up to 8 h, renewed by activity). The server cannot verify `wrapped_privkey`. For an additional registration it checks only that `pubkey` equals `user_keys.pubkey`, and that public key is public: it sits in every request link. Delete only enforces "keep ≥ 2".
- **Exploit scenario:** An attacker gets the cookie of an unlocked session (the "stolen session cookie" attacker in THREAT_MODEL §4), or uses a shared or kiosk browser where the owner unlocked and walked away:
  1. Register two attacker authenticators with garbage `wrapped_privkey` and the owner's real public key. Both pass.
  2. `DELETE /api/passkeys/{id}` every legitimate passkey. It succeeds because the attacker's two keep the count ≥ 2.
  - Result 1: the owner can never decrypt the inbox again. Every remaining wrapped blob is garbage, and unlock fails with "This passkey could not unlock your key".
  - Result 2: the attacker keeps durable server-side unlock capability. Combined with stolen IdP credentials later, this passes every unlock gate (inbox metadata, request-link creation, passkey management) long after the cookie expired.
  - THREAT_MODEL claims "passkey step-up". Here the step-up is not tied to the sensitive action.
- **Recommended fix:**
  - Require a fresh user-verified assertion from an existing passkey within the same request flow (for example a ceremony of kind `manage`, ≤ 5 min old) for `RegisterBegin` (when passkeys exist) and for `Delete`. Do not rely on the session-wide flag for these.
  - Optionally require the client to prove the new blob decrypts. The server cannot check this, but the UI can re-unlock with the new passkey before the server commits it, which at least stops honest-client mistakes.
  - Record passkey adds and deletes, and surface them to the owner.
- **Confidence:** CONFIRMED (code trace; no live ceremony test).

## L-1. Proxy mode without `trusted_proxies` puts every client in one rate-limit bucket

- **Severity:** Low
- **Location:** `internal/httpx/clientip.go:43-48`; `internal/config/config.go:244-252, 264-271` (no check or warning); limiters in `internal/server/server.go` (auth limiter 30/min, burst 10)
- **Description:** With `tls = "proxy"` over TCP and an empty `trusted_proxies` (the default in `deploy/dropr.example.toml`), the TCP peer, which is the proxy, becomes the client address for every request. A Unix-socket deployment whose proxy does not send `X-Forwarded-For` behaves the same: all requests resolve to an invalid address and share one bucket.
- **Exploit scenario:** One anonymous client sends about 1 request every 2 s to `/auth/login`. Login is then refused with 429 for everyone. The same applies to `/s`, `/r`, `/api/r/.../files`, `/dl` and `/upload` with their own limits.
- **Recommended fix:**
  - In production, refuse to start with `tls="proxy"`, a TCP listener and no `trusted_proxies`, or at least log a loud warning.
  - At runtime, warn once when a request from a non-trusted peer carries `X-Forwarded-For`.
- **Confidence:** CONFIRMED (code trace).

## L-2. One counted download token allows unlimited full downloads

- **Severity:** Low
- **Location:** `internal/store/files.go:616-631` (`UseDownloadToken`); `internal/server/transfer.go` (`handleDownload`)
- **Description:** Only the first use of a token counts. Every later GET, including full non-Range GETs, is served, and each use slides the expiry by 1 h, up to 24 h after issue. ARCHITECTURE allows this for "resumes", but nothing restricts reuse to resumes.
- **Exploit scenario:** I ran a throwaway store test with `max_downloads = 1`. One token served 20 full downloads spread over 16 h. The holder can also pass the token and FK to third parties, so the limit means "≤ N tokens", not "≤ N downloads".
- **Recommended fix:** After the first counted use, accept only Range requests starting at offset > 0. Alternatively, record the highest offset served and refuse requests starting at 0 once the full length has been delivered. Shorten the absolute lifetime for counted share tokens.
- **Confidence:** CONFIRMED (test: scratch `internal/store/zz_audit_test.go` → "successful full GETs with one token: 20").

## L-3. A part PUT can land after finalize

- **Severity:** Low
- **Location:** `internal/server/transfer.go:104` (completion checked once, at the start), `:122` (`WritePart` renames later with no re-check); `internal/blob/store.go` (`WritePart`)
- **Description:** A PUT that started before finalize (bodies may stream for many minutes, since the stall timer slides) renames its part into place after the blob has been marked complete. This contradicts "After finalize the token only authenticates status and the idempotent finalize."
- **Exploit scenario:** An anonymous request-link uploader finalizes, waits for the owner to look at the file, then completes a pending PUT with different ciphertext. Because the uploader holds FK, the new content still authenticates, so the file changes silently after the owner has seen it. A download in progress may also mix old and new parts and fail as "damaged".
- **Recommended fix:** After `WritePart`, re-check `complete` inside a DB transaction and delete the part if the blob is complete. Better: write parts while holding a per-blob lock that finalize also takes. Or store parts under a staging directory that finalize moves atomically.
- **Confidence:** CONFIRMED (trace). The race window is real but needs the uploader's cooperation.

## L-4. Trickle connections are not bounded

- **Severity:** Low
- **Location:** `internal/blob/serve.go:138` (`deadlineWriter`), `:156` (`ProgressReader`); `internal/server/run.go` (no `ReadTimeout`/`WriteTimeout` by design, no connection cap)
- **Description:** Deadlines slide on any progress at all. One byte per minute keeps a PUT or a `/dl` response alive indefinitely: up to 24 h for uploads, as long as the token slides for downloads. There is no minimum rate and no limit on concurrent connections per IP or in total. In `acme` mode the binary faces the internet directly.
- **Exploit scenario:** With one public request link (or a share link), an attacker opens thousands of trickling PUTs. These are allowed even against the same upload and part, and each holds an fd, a goroutine and a 32 KiB copy buffer, plus a temp file. The rate limits (burst 200, then 900/min for uploads) bound how fast they open, not how many stay open. The result is fd and memory exhaustion.
- **Recommended fix:**
  - Enforce a minimum throughput (for example a 64 KiB/s average over 30 s) in `ProgressReader` and `deadlineWriter`.
  - Cap concurrent in-flight PUTs per upload (one per part) and concurrent streams per client-IP hash.
  - Set a global connection limit with `netutil.LimitListener`.
- **Confidence:** PLAUSIBLE (trace; not load-tested).

## L-5. Rotation can race with revalidation and store a stale refresh token

- **Severity:** Low
- **Location:** `internal/auth/session/session.go:212-228` (`Rotate` re-seals `s.rec.RefreshTokenEnc` from the in-memory record, then `RotateSession` moves the row); `internal/auth/oidc/revalidate.go`
- **Description:** Rotation takes no per-session lock and re-reads nothing. If a concurrent request on the same session revalidates between `Load` and `RotateSession`, and the IdP rotates refresh tokens, the new session row gets the old refresh token.
- **Exploit scenario:** This is a reliability problem rather than an attack. The next revalidation fails and kills the session. With Keycloak "revoke refresh token" (reuse detection), the IdP session may be revoked entirely.
- **Recommended fix:** Do the re-seal inside the `RotateSession` transaction from the row as currently stored. Alternatively, take `p.locks` for the session hash during rotation.
- **Confidence:** PLAUSIBLE.

## L-6. Free-space check ignores in-flight reservations

- **Severity:** Low
- **Location:** `internal/blob/store.go:84` (`CheckSpace`); `internal/server/files.go` (`checkSpace` at creation only)
- **Description:** Each creation checks `free − size ≥ headroom` against current free space. Nothing reserves the declared but not yet written bytes, so N concurrent uploads each pass. The total is bounded only by per-owner quotas, and the sum of quotas can exceed the disk.
- **Exploit scenario:** Several request links, or several owners, start large uploads at once. The volume fills to ENOSPC. The headroom (meant to protect SQLite's WAL) is consumed and DB writes start failing instance-wide.
- **Recommended fix:** Subtract the bytes not yet written by incomplete blobs from free space in `CheckSpace` (`SUM(size) WHERE complete=0`, minus the bytes already on disk, or simply `SUM(size)` as a conservative bound). Keep the WAL headroom check in `WritePart` too.
- **Confidence:** CONFIRMED (trace).

## I-1. `/sw.js` grants scope `/`

- **Location:** `internal/web/assets.go:208`
- **Description:** The worker is registered with scope `/_dl/` (`web/src/lib/downloader.ts`), but `Service-Worker-Allowed: /` would also accept a root-scope registration of the same script. This matters only under script injection, but it would turn that into persistent interception of every page.
- **Recommended fix:** Send `Service-Worker-Allowed: /_dl/`, or drop the header and serve the worker from `/_dl/sw.js`.
- **Confidence:** CONFIRMED.

## I-2. Finalize reports success for a deleted blob

- **Location:** `internal/server/transfer.go:196`
- **Description:** `CompleteUpload` returns `ErrComplete` when 0 rows were updated, which also happens when the row was deleted by the stale-upload GC at about 24 h or by revocation. The handler maps that to 200 `{complete:true}`.
- **Recommended fix:** Distinguish "already complete" from "row gone" (re-select inside the transaction) and answer 404/410 in the second case.
- **Confidence:** CONFIRMED (trace).

## I-3. Request links outlive the owner's authorization

- **Location:** `internal/store/files.go` (`CreateRequestFile`), `internal/server/pages.go` (`handleRequestPage`)
- **Description:** Anonymous uploads keep landing in the quota and disk of an owner whose role was removed or who was `revoke`d. Revocation ends sessions only, and no `disabled_at` setter exists.
- **Recommended fix:** Document this behavior, or close links on `user revoke` and on refused revalidation.

## I-4. File-name sanitization and spoofing

- **Location:** `web/src/crypto/meta.ts:59-61` (and the mirror in `web/src/lib/swproto.ts`)
- **Description:** Bidi controls are removed (good), but these are kept: runs of spaces and U+2000–U+200A, U+00A0, U+3164/U+115F (Hangul fillers), U+180E and U+00AD. An anonymous uploader can send `invoice.pdf<many U+2003>.exe`, which UI truncation and some save dialogs display as `invoice.pdf`.
- **Recommended fix:**
  - Collapse all `\p{Zs}` runs to one space.
  - Strip default-ignorable code points (`\p{Default_Ignorable_Code_Point}`, keeping ZWJ/ZWNJ if desired).
  - Always show the extension separately in the inbox UI.

## I-5. First passkey registration is first-come

- **Location:** `internal/auth/passkey/passkey.go:285` (no unlock needed when there are 0 passkeys); `cmd/dropr/main.go` (`reset-keys`)
- **Description:** On a new account, or after `reset-keys`, whoever signs in first with valid IdP credentials creates the account key pair. Request links are then minted to that key.
- **Recommended fix:** Accept this for new accounts. For `reset-keys`, consider a one-time enrollment code printed by the CLI.

## I-6. Inbox count shown without unlock

- **Location:** `internal/server/pages.go` (`handleHome`, `handleInbox` → `CountInbox`)
- **Description:** Minor metadata visible to an IdP-credential-only attacker. This is consistent with the threat model, which lets such an attacker "see link metadata".

## I-7. Secret file permissions not checked

- **Location:** `internal/config/secrets.go` (`readSecretFile`)
- **Recommended fix:** Warn, or refuse in production, when the refresh key or client key file is group- or world-readable (mode & 0o077) and is not under `/run/credentials` or `/run/secrets`.

## I-8. `net/http` generated errors lack headers

- **Description:** 400 and 431 responses produced before routing have no CSP or nosniff. They are text/plain with nothing reflected, so the impact is nil. Noted for completeness of the "every response type" requirement.

---

## Resolution

Fixed on 2026-11-05 before release. Each entry: finding → fix → regression
test(s). Contracts updated in docs/ARCHITECTURE.md (§3, §4, §5), docs/PAGES.md,
docs/FORMAT.md §5 and docs/THREAT_MODEL.md. Schema change: migration
`0003_security_fixes.sql`.

| ID | Status | Fix | Tests |
|---|---|---|---|
| M-1 | Fixed | Adding or deleting a passkey needs a **grant**: a fresh, user-verified assertion by an existing passkey of the account, made in the same session for that action (`unlock/begin` with `purpose: "add"`, or `"delete"` + `passkey_id`). `unlock/finish` stores one grant per session (`passkey_grants`, 5 min, single-use, cascades with the session). `register/begin` consumes an "add" grant; `DELETE /api/passkeys/{id}` consumes a "delete" grant for exactly that ID; otherwise 403 `reauth_required`. The 8 h unlock flag no longer authorizes either. Initial setup (0 passkeys): no grant needed, but the first registration must carry a `confirm` assertion by the new credential over a server challenge from `register/begin` (the browser already ran that `get()` for the PRF output; it is now server-challenged and verified), and the confirmed first registration leaves the "add" grant for the second passkey, so setup still costs three prompts at most. Adds and deletes are logged at WARN. Client: `registerPasskey` sends the confirmation, `unlockExtractable` asks for an "add" grant, new `deletePasskey`; the setup page re-confirms with the first passkey on `reauth_required`. | Go: `TestPasskeyManagementNeedsFreshAssertion` (unlock flag not enough; bound to action, target, session; ≤ 5 min; single-use), `TestPasskeyInitialSetupWindow`, `TestPasskeyRegistrationAndUnlock` (internal/server). Web: `passkey flows` › "registers two passkeys…", "adding a passkey later confirms…", "deletes a passkey after an assertion bound to that passkey", "uses PRF results returned directly by create()…". E2E: smoke (setup unchanged for the user). |
| L-1 | Fixed | Production refuses `tls = "proxy"` on a TCP listener without `trusted_proxies`, and on a `unix:` socket without `trusted_proxies` or the new explicit `trust_unix_socket_proxy = true` (the peer is necessarily the proxy, but trusting its header must be stated; the unix peer is no longer trusted implicitly). Dev mode warns. At runtime Dropr warns once when a client address cannot be determined and when X-Forwarded-For arrives from an untrusted peer. | `TestRefusals` (cases "proxy without trusted_proxies", "unix proxy without trust", "unix trust on tcp", "unix trust in acme"), `TestProxyTrust` (internal/config) |
| L-2 | Fixed | Each download token has a byte budget of `2 × size + min(size, 1 MiB)` (`dl_tokens.served_bytes`): a GET reserves the bytes it will send (Range-aware, HEAD free) before answering and refunds what it did not send; beyond the budget 410 `token_used` (the downloader then requests a new token, whose first use counts another download). Interrupted and resumed downloads (resume from the last verified segment) fit; unlimited full re-downloads do not. Handing on a token within its budget remains possible (THREAT_MODEL R14). | `TestDownloadTokenByteBudget` (internal/server), `TestWriteReadServe` (Planned == bytes sent, internal/blob) |
| L-3 | Fixed | Part bodies are still written to a temp file without locks, but the rename happens under a per-blob lock after re-reading the upload row (409 `already_complete` if finalized meanwhile, 404 if deleted). Finalize verifies and marks complete under the same lock. | `TestPartPutRacingFinalize` (a PUT stalled mid-body across finalize leaves the complete blob untouched, internal/server), `TestWritePartIfCommitUnderLock` (internal/blob) |
| L-4 | Fixed | Minimum transfer rate for part uploads and downloads (`limits.min_transfer_rate`, default 4 KiB/s averaged over 60 s; uploads get 408 `too_slow` and retry, downloads stop short and resume). Concurrent transfer caps (`limits.max_transfers` 512, `limits.max_transfers_per_ip` 32; 429 `too_many_transfers` + Retry-After). | `TestMinimumRate` (internal/blob), `TestTransferStreamCap` (internal/server), `TestTransferLimits` + `TestRefusals` limits cases (internal/config) |
| L-5 | Fixed | Session rotation takes the session manager's per-session lock (also taken by revalidation, which moved there from the OIDC package) and builds the new row from the row as stored inside the rotation transaction, re-sealing the latest refresh token. | `TestRotateKeepsConcurrentlyRefreshedToken`, `TestRotateWaitsForSessionLock` (internal/auth/session); `TestMutex` (internal/keyed) |
| L-6 | Fixed | The free-space check at upload creation adds what the uploads in progress still have to write (Σ declared size − bytes on disk over incomplete blobs). The reservation ends at finalize or garbage collection, since only incomplete blobs count. | `TestDiskSpaceCountsInflightUploads` (internal/server) |
| I-1 | Fixed | `/sw.js` sends `Service-Worker-Allowed: /_dl/`. | `TestAssetsManifestAndHandlers` (Service-Worker-Allowed assertion, internal/web) |
| I-2 | Fixed | `CompleteUpload` distinguishes "already complete" (`ErrComplete`, idempotent 200) from "row gone" (`ErrNotFound` → 404). | `TestFinalizeDeletedUpload` (internal/server) |
| I-3 | Fixed | New `users.access_lost_at`: set when a revalidation or a login finds the role (or a required claim) missing, and by `dropr user revoke`; cleared by the next successful login. Request links of such owners (and of disabled accounts) answer 410 `closed` on the page and on `POST /api/r/{id}/files`. | `TestRequestLinkClosedWhenOwnerLosesRole` (internal/server) |
| I-4 | Fixed | The file-name sanitizer (crypto core and the service-worker mirror) strips every default-ignorable code point (Hangul fillers U+115F/U+1160/U+3164/U+FFA0, soft hyphen, U+180E, invisible operators, bidi controls…) plus U+2800, keeping ZWJ/ZWNJ, variation selectors and emoji tags, and collapses runs of `\p{Zs}` to one space. FORMAT.md §5 updated. | `sanitizeFileName` cases marked "Audit I-4" (web/test/meta.test.ts), `safeDownloadName` (web/test/swproto.test.ts) |
| I-5 | Mitigated, residual accepted | Setup window bound to the session that starts it (409 `setup_in_progress` for other sessions while a registration is pending); the first passkey must prove a user-verified assertion; the second needs the first's grant. Whoever completes the first registration still owns the account key: documented as THREAT_MODEL R13 (advice: phishing-resistant MFA, prompt setup after `reset-keys`, watch "passkey added" logs; an enrollment code is future work). | `TestPasskeyInitialSetupWindow` |
| I-6 | Fixed | The inbox count (dashboard tile, `/inbox` `data-count`) is rendered only for a session holding a passkey unlock. | `TestInboxCountHiddenUntilUnlock` (internal/server), `TestPagesFollowDOMContract` (internal/web) |
| I-7 | Fixed | Secret files readable by group/others log a warning; world-readable refuses production. Files under `/run/credentials/` and `/run/secrets/` are exempt (their modes belong to systemd / the container runtime). | `TestSecretFilePermissions` (internal/config) |
| I-8 | Partly fixed, rest accepted | Responses generated by ServeMux itself (path-cleaning redirects, 404/405) already pass the header middleware: now covered by a test. Answers `net/http` writes before any handler (400 malformed request line, 431, HTTP-to-HTTPS 400) cannot carry headers without replacing the HTTP server; they are fixed `text/plain` with nothing reflected. Documented in THREAT_MODEL §5.4. | `TestMuxGeneratedResponsesHaveHeaders` (internal/server) |

Related UX fixes made at the same time: "Expires in N" now rounds up to the
largest unit that fits in both `internal/web/format.go` and
`web/src/lib/format.ts` (a fresh 7-day link reads "7 days" on the dashboard
and the recipient page; shared test table in `TestFormatExpiry` and
web/test/format.test.ts); the dashboard's "Active links (N)" tile is updated
client-side after a share upload or request-link creation.

---

*Note, 2026-11-06:* the M-1 row above describes the first registration's `confirm` assertion as required. It is now optional: `register/finish` accepts a first passkey without it (the registration ceremony already proves possession with user verification over a server challenge), and still verifies it whenever present. The session unlock and the "add" grant for the second passkey are unchanged.
