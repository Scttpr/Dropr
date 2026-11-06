# Dropr — Plan

Self-hosted, end-to-end encrypted file drop. One instance. Accounts come from a standard OIDC provider, with Microsoft Entra ID as the officially supported one. Each file has exactly one owner.

## 1. Scope

Exactly two flows. Everything else returns 404.

| # | Actor | Action |
|---|---|---|
| A | Authenticated **owner** | Uploads a file and gets a **share link**. Anyone with the link can download. |
| B | Authenticated **owner** | Creates a **request link**. Anyone with it can upload files that only that owner can read. |

Users are strictly isolated. An account sees only the files and links it owns. There is no sharing between accounts, other than through the two link types above.

Non-goals: local accounts, public sign-up, folders, previews, comments, editing, federation, multi-instance, peer-to-peer transfer (all data goes through the single server).

## 2. Decisions

| Topic | Decision |
|---|---|
| Identity | Generic OIDC is the **only** way to log in. No local accounts, no fallback admin login. |
| Supported provider | Microsoft Entra ID is officially supported, with a setup guide and release testing. Other compliant providers (Keycloak, Authentik, Okta, ...) should work but are best-effort. Keycloak is used in CI. |
| Request link key | Each request link has its own X25519 key pair, generated in the owner's browser when the link is created. The private key stays in that browser (IndexedDB, non-extractable). OIDC proves identity; the browser profile holds the keys. |
| Users | Several accounts per instance. Access is granted by a role claim from the provider (in Entra, an app role). A file belongs to exactly one owner. |
| File size | Configurable per instance and per request link. Default 5 GB, hard maximum 100 GB. |
| Lost browser data | Files received through a link open only in the browser profile that created it. Clearing that site's data, or losing the device, makes them unreadable. Accepted. The UI says so where links are created and listed. |
| Backend language | Go |
| Architecture | **Monolith**: one Go binary serves the HTML pages, the API and the static assets, all embedded with `go:embed`. Pages are rendered on the server. The only browser JavaScript is what must run client-side: encryption, request link keys, streaming transfers. |
| Hosting | Self-hosted, one container, one data volume, on a domain you own. HTTPS is built in (ACME), or the app can run behind an existing reverse proxy. |

## 3. Cryptography (server never sees plaintext)

- **Share link (A)**: the browser generates a random 256-bit key. File content and metadata (name, type) are encrypted with it. The key is placed in the URL fragment: `https://host/s/<id>#<key>`. Browsers never send the fragment to the server.
- **Request link (B)**: each request link has its own X25519 key pair, generated in the owner's browser when the link is created. The link carries the public key in its fragment: `https://host/r/<id>#<pubkey>`. The uploader encrypts a random file key to it with HPKE (RFC 9180, DHKEM-X25519 / HKDF-SHA256 / AES-256-GCM).
- **Link private key**: generated non-extractable and stored as a `CryptoKey` in the browser's IndexedDB. It never leaves that browser profile, and no script, Dropr's included, can export it. The server never sees or stores either half of the pair.
- **Public key trust**: the link's public key comes from the browser that generated it, never from the server, so a compromised server can't swap in its own key.
- **Trade-off**: received files open only in the browser profile that created the link. Clearing that site's data or losing the device loses them. In exchange, neither the operator nor someone holding only the owner's provider login can read them.
- **Stream format**: STREAM construction (as used by age and Tink). AES-256-GCM over 64 KiB plaintext segments, with nonce = prefix ‖ 32-bit counter ‖ last-segment flag. This blocks truncation, reordering and splicing. The 32-bit counter allows files up to 256 TB, far above the 100 GB cap.
- **Primitives**: WebCrypto only (AES-GCM, X25519, HKDF). No custom primitives. Validate against published test vectors.

## 4. Large files (up to 100 GB)

- **Upload**: the browser reads `File.slice()` parts of 32 MiB (512 segments each), encrypts each part, and uploads parts independently with `PUT /upload/<id>/part/<n>`. Uploads resume after network drops, and a few parts upload in parallel. Memory use stays bounded.
- **Finalize**: the client declares the total part count. The server checks every part is present and that the size is within quota, then marks the blob complete. Incomplete uploads are garbage-collected after 24 h.
- **Download**: parts are fetched with HTTP Range requests, decrypted as a stream, and written to disk through:
  1. `showSaveFilePicker()` (File System Access API) where available (Chromium), otherwise
  2. a service worker that serves a streamed `Content-Disposition: attachment` response (Firefox, Safari).
  Downloads never load the whole file into memory and can resume.
- **Download counting** (`max_downloads`): the server issues a short-lived download token per session. The count goes up when the token is first used, and Range requests within that token don't count again.
- **Storage**: the server checks free disk space before accepting an upload and enforces a total quota per owner. Blobs are stored in sharded directories (`ab/cd/<id>`).

## 5. Authentication

### 5.1 OIDC (generic)

Dropr uses only standard OIDC: discovery, Authorization Code, refresh tokens, RP-initiated logout. Nothing provider-specific is hard-coded; provider differences live in config.

```toml
[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "..."
client_auth     = "private_key_jwt"        # or "client_secret" (dev mode only)
client_key_file = "/run/secrets/oidc_key"  # PEM key + cert for private_key_jwt
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"                  # dotted path allowed, e.g. "realm_access.roles"
required_role   = "Dropr.User"
display_claim   = "name"
required_claims = { tid = "<tenant-id>" }  # optional exact-match checks
revalidate_every = "15m"
```

- **Issuer pinning**: one issuer, loaded via discovery at startup. `iss` must match it exactly. Multi-tenant or "common" issuers are refused.
- **Flow**: Authorization Code + PKCE (S256), with `state` and `nonce`. These are kept in a short-lived `__Host-` cookie with `SameSite=Lax`, which is required so the browser sends it back on the cross-site redirect from the provider. The callback deletes it. Redirect URI: `https://<host>/auth/callback`, exact match.
- **Callback landing**: the callback sets the session cookie and answers with a small same-origin page that then goes to the dashboard. Browsers don't send `SameSite=Strict` cookies within a redirect chain that started cross-site.
- **Client authentication**: `private_key_jwt` (RFC 7523) with a certificate or key. A client secret is accepted only in dev mode.
- **ID token checks** (`go-oidc`): signature against the discovered JWKS (asymmetric algorithms only, never `none` or HS*), `iss`, `aud`, `azp` when present, `exp`, `nbf`, `iat` with small clock skew, `nonce`, plus every `required_claims` entry.
- **User identity**: `(iss, sub)`, the standard stable identifier. Never email, `preferred_username` or `name`; those are display only.
- **Authorization**: `role_claim` must contain `required_role` on every login and every revalidation. Otherwise access is denied (403 page, no account created).
- **MFA**: delegated to the provider. Dropr doesn't do MFA itself; the provider's setup guide covers enforcing it.
- **Revalidation**: the server stores the refresh token (AES-256-GCM encrypted at rest) and refreshes it every `revalidate_every`. The new ID token must pass all checks above, carry the same `sub`, and still have the role. If the refresh fails or any check fails, the session is killed. Providers refuse refresh tokens for disabled users and revoked sessions.
- **Logout**: ends the local session, then RP-initiated logout via the discovered `end_session_endpoint` when the provider has one. Front-channel logout is also supported when the provider offers it.
- **Provisioning**: an account is created just-in-time on first successful login. Removing the role blocks access. The data stays until an admin purges it.
- **Changing provider**: changes every user's `(iss, sub)`. `dropr user migrate --from-issuer ... --map file.csv` relinks existing accounts and their data to the new identities.

### 5.1.1 Microsoft Entra ID (officially supported)

- Single-tenant app registration. `issuer = https://login.microsoftonline.com/<tenant-id>/v2.0`, plus `required_claims = { tid = "<tenant-id>" }` as an extra safety check.
- `sub` in Entra is pairwise per app registration, so it stays stable as long as you keep the same app registration. Don't recreate it.
- Define the app role `Dropr.User` (`role_claim = "roles"`). In the Enterprise Application, set "Assignment required = Yes" and assign users or groups. App roles are used instead of group claims to avoid group-overage issues.
- Upload the certificate as the app credential (`private_key_jwt`).
- MFA: a Conditional Access policy targeting the app, ideally with phishing-resistant authentication strength.
- Disabling a user or using "Revoke sessions" makes the next refresh fail, so the Dropr session dies within 15 min.

### 5.1.2 Other providers (best-effort)

- **Keycloak**: `role_claim = "realm_access.roles"` or a client-role mapper. Used in CI for automated E2E tests.
- **Authentik / Authelia**: `role_claim = "groups"`.
- Any provider must support discovery, PKCE, refresh tokens and, in production, `private_key_jwt`. Dropr refuses to start in production mode otherwise.

### 5.2 Request link keys (browser only)

- **No setup step**: the first login lands on the dashboard. There is no key endpoint and no unlock.
- **Creation**: the dashboard generates the link's key pair, creates the request on the server, then stores the private key in IndexedDB under the request ID. If storing fails, the browser deletes the new request: a link is never handed out without its key. It also asks for persistent storage so the browser does not evict the keys.
- **Use**: the inbox opens each received file with the key of its link. Files received through a link created in another browser are listed without a name and cannot be downloaded there; they can still be deleted.
- **Cleanup**: revoking a link deletes its key. Keys of links that expired or were revoked elsewhere are pruned when the link list loads.
- Flow A (upload and share) needs OIDC only.

### 5.3 Sessions

- Server-side sessions with a `__Host-` cookie, `Secure; HttpOnly; SameSite=Strict`. The cookie holds a random 256-bit ID; the database stores only its SHA-256 hash.
- 30 min idle timeout, 8 h absolute timeout, plus OIDC revalidation every 15 min.
- The session ID rotates at login.

### 5.4 Admin CLI

Admin access is shell access to the host. There is no admin web UI.

- `dropr user list`
- `dropr user revoke <user>`: kills all sessions now
- `dropr user purge <user>`: deletes the user and all their data
- `dropr user migrate`: relinks accounts after a provider change (§5.1)
- `dropr gc`, `dropr backup --out FILE`, `dropr healthcheck`

## 6. Links

- IDs: 128-bit random, base64url.
- Expiry is mandatory: 1 h / 1 day / 7 days (default) / 30 days.
- Share link: optional `max_downloads`. Request link: `max_files`, `max_bytes` (≤ instance cap), optional single-use.
- The owner can revoke any link at any time. Revoking or expiring deletes the blobs, not just the rows.
- A cleanup job runs every 5 minutes.

## 7. Web hardening

- **TLS**, two modes:
  - `tls = "acme"` (default): the Go binary gets and renews Let's Encrypt certificates itself (`golang.org/x/crypto/acme/autocert`, TLS-ALPN-01 challenge, so only port 443 is needed). Certificates are cached in the data volume. TLS 1.2 minimum with AEAD cipher suites only; TLS 1.3 preferred. Port 80, if enabled, only redirects to HTTPS. Set a CAA record for the domain.
  - `tls = "proxy"`: plain HTTP on a local address or Unix socket, behind your own reverse proxy. `X-Forwarded-For` / `X-Forwarded-Proto` are trusted **only** from the configured `trusted_proxies`. Dropr refuses to start in this mode if `public_url` isn't `https://`.
  - In both modes: HSTS with `includeSubDomains; preload`.
- **Server timeouts**: `ReadHeaderTimeout`, idle timeout and header size limits on the Go `http.Server`, plus per-route body limits (one part for uploads, a few KiB for the API). These protect against slowloris attacks and oversized requests now that no proxy sits in front.
- **CSP**: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; form-action 'self' <issuer origin>; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types dropr-sw` (the single policy turns exactly `/sw.js` into a TrustedScriptURL for `serviceWorker.register()`, a Trusted Types sink)
- **Headers**: `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, a strict `Permissions-Policy`, and `Cache-Control: no-store` on link pages and the API.
- **CSRF**: SameSite=Strict session cookie, plus checks on `Origin` and `Sec-Fetch-Site` for every state-changing request. The OIDC callback is the only cross-site entry point and is protected by `state` + PKCE.
- **Uploaded content** is never rendered. The browser decrypts it and saves it as a download.
- **Abuse limits on request links**: size/count caps per link, per-IP rate limits (in memory, keyed by a hash), and a quota per owner. The inbox UI warns that files come from outside.
- **Logs**: no plaintext IPs, tokens or link fragments (fragments never reach the server anyway). 7-day retention.
- **Browser code integrity**: no third-party JS, minimal dependencies, reproducible build, published asset hashes.
- **Secrets**: the OIDC client key and the refresh-token encryption key are loaded from files (Docker secrets), never from environment variables or the database.

## 8. Stack

| Layer | Choice |
|---|---|
| Backend | Go, single static binary. Standard library plus `coreos/go-oidc/v3`, `golang.org/x/oauth2`, `modernc.org/sqlite` (pure Go). |
| Database | SQLite, WAL mode |
| Blobs | Local disk volume |
| Pages | Server-rendered with Go `html/template` (contextual auto-escaping). No inline scripts or styles, so the strict CSP holds. Every page works as a plain HTML document; JS only adds the crypto parts. |
| Browser code | A few small TypeScript modules, no framework, bundled with esbuild and embedded in the binary: `crypto` (STREAM, HPKE), `request-keys` (IndexedDB store of the link private keys), `uploader`, `downloader` (+ service worker), `decrypt-names` (fills in encrypted filenames on the inbox and share pages), one entry module per page, plus `prefs` (language and theme) and typed EN/FR catalogs. |
| Deployment | One distroless container running as non-root, read-only root filesystem, one data volume (SQLite, blobs, ACME cache). Listens on 8443 inside the container, mapped to host port 443. |
| Dev environment | Nix flake (Go, Node, esbuild). A dev Compose profile starts Keycloak with a seeded realm, so login works locally without a real tenant. |
| CI | Go tests + fuzzing, browser-module tests, Playwright E2E against Keycloak |

### Data model

```
users     (id, issuer, subject, display_name, created_at, disabled_at)   -- UNIQUE(issuer, subject)
sessions  (id_hash, user_id, refresh_token_enc, created_at, last_seen_at, revalidated_at)
shares    (id, owner_id, blob_id, size, expires_at, max_downloads, download_count)
requests  (id, owner_id, expires_at, max_files, max_bytes, single_use, files_received)
inbox     (id, request_id, owner_id, blob_id, size, created_at)
blobs     (id, parts, size, complete, created_at)
```

## 9. UX

**Login**: one button, "Sign in" (the label is configurable, e.g. "Sign in with Microsoft"). Signing in lands straight on the dashboard.

**Owner dashboard**
```
┌──────────────────────────────────────────┐
│   [  Drop a file here to share  ]        │
│                                          │
│   [ Ask someone to send me a file ]      │
│                                          │
│   Received files (3)    Active links (2) │
└──────────────────────────────────────────┘
```
- After an upload: a progress bar (resumable), then the link with **Copy** and the expiry (7 days preselected).
- After creating a request link: the link with **Copy**, and a note that files sent through it open only in this browser.
- Received: name, size, date, **Download** and **Delete**. Files received through a link created in another browser show size, date and **Delete** only.

**Share recipient**: filename, size, a big **Download** button, "Expires in 6 days". No login.

**Request uploader**: "Send a file to Alice", a drop zone, progress, then "✓ Sent. You can close this page." No login.

Errors are written in plain language: "This link has expired."

**Language and theme**: English and French, picked from the browser's
language and switchable on every page; light theme by default, plus dark and
"follow the system". Both work without JavaScript (a small form in the page
header) and are remembered in cookies.

## 10. Self-hosting

- Requirements: a domain, ports 80/443, disk space for the blobs plus headroom for files up to 100 GB, and an OIDC provider where you can register a client.
- **Entra setup guide** (official, step by step):
  1. App registration, single-tenant, web redirect URI `https://<host>/auth/callback`
  2. Upload the certificate credential
  3. Define the app role `Dropr.User`
  4. Enterprise app: set "Assignment required = Yes" and assign users or groups
  5. Recommended: a Conditional Access policy requiring phishing-resistant MFA
- **Keycloak example config** shipped as a reference (best-effort, also used in CI).
- `docker compose up -d`. One service, plus `dropr.toml` (`public_url`, `tls`, the `[oidc]` section) and the secrets files. Running the binary directly (for example as a systemd service) works too.
- On startup, Dropr checks provider discovery and its capabilities (PKCE S256, `private_key_jwt`, refresh tokens). In production mode it refuses to start if any check fails.
- Backups: back up SQLite (online backup API) and the blob volume. Blobs are already encrypted. The database holds encrypted refresh tokens and HPKE-wrapped file keys, so protect it. Request link private keys are not on the server: they live in the owners' browser profiles, outside any server backup.
- Updates: pinned image digests and a signed release tag.

## 11. Milestones

1. **Skeleton**: Go module, config, SQLite migrations, TLS modes (ACME + proxy), `html/template` layout and asset embedding, security-header middleware, generic OIDC login/logout/revalidation, sessions, the dev Keycloak profile. Automated tests against Keycloak, plus a manual check against a real Entra test tenant.
2. **Crypto core**: STREAM and HPKE in TypeScript. Test vectors plus property tests (round-trip, truncation, reordering, tampering).
3. **Request link keys**: a key pair per request link, generated in the browser, private key non-extractable in IndexedDB. (First built with passkeys and the WebAuthn PRF extension; replaced, see ARCHITECTURE.md §2.)
4. **Files**: share/request APIs, chunked resumable uploads, Range downloads, expiry cleanup, quotas, rate limits.
5. **Pages + browser modules**: server-rendered dashboard, share page, request page and inbox, wired to the upload, download, request-key and filename-decryption modules. Streaming downloads through File System Access or the service worker.
6. **Hardening and tests**: Go native fuzzing, `govulncheck`, `npm audit`, Mozilla Observatory. Playwright E2E for both flows in Chromium, Firefox and WebKit. Negative cases: expired, revoked, oversized, tampered, truncated, wrong key, role removed, wrong issuer/audience/nonce, `alg: none` / HS256 tokens. A 100 GB soak test.
7. **Release**: THREAT_MODEL.md, Entra setup guide, Keycloak example, a release check against Entra, reproducible build, Compose file, external review before real use.

## 12. Threat model summary

| Attacker | Outcome |
|---|---|
| Network | TLS 1.3 + HSTS. Nothing readable. |
| Database or disk theft | Ciphertext, sizes, timestamps, HPKE-wrapped file keys, encrypted refresh tokens. No plaintext, no filenames, no private keys. |
| Stolen provider credentials | Attacker can share new files and see link metadata, but **cannot read the inbox** without the owner's browser profile. Mitigated by MFA at the provider (Conditional Access in Entra). |
| Departed user | Role removed or account disabled at the provider, so the session dies within 15 min. `dropr user revoke` for immediate effect. |
| Link interception | Whoever holds a share link can read the file until expiry or revocation. Use short expiry and download limits. |
| Malicious uploader | Can only reach owners through their request links. Bounded by caps. Files are never rendered. |
| Compromised server serving malicious JS | **Residual risk** of browser E2E. Mitigated by minimal dependencies, reproducible builds and published hashes. |
| Compromised OIDC provider | Attacker can log in as any user but still cannot read inboxes without the owners' browser profiles. |
| Control of the owner's browser profile | Device access, malware or XSS can *use* the link keys stored there to open received files, but cannot export them. Protected by the OS account and disk encryption. |
| Lost browser data | Clearing the site's data or losing the device makes files received through that browser's links unreadable, by design. |
