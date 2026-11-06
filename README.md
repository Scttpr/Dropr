# Dropr

Self-hosted, end-to-end encrypted file drop. One Go binary, one data volume,
your own domain, and your existing identity provider for accounts.

Two flows, nothing else:

* **Share**: an owner uploads a file and gets a link. Anyone with the link can
  download it, until it expires or is revoked.
* **Request**: an owner creates a request link. Anyone with it can send files
  that only that owner can read.

Files go up to 100 GB (default cap 5 GB), uploaded in resumable 32 MiB parts
and streamed to disk on download.

## Security model in six bullets

* **The server never sees plaintext.** Files and their names are encrypted in
  the browser (AES-256-GCM STREAM, WebCrypto only). Share-link keys live in the
  URL fragment, which browsers never send to the server.
* **Request links use HPKE** (RFC 9180, X25519). The owner's private key is
  wrapped by a **passkey with the WebAuthn PRF extension** and exists unwrapped
  only in browser memory. Stolen login credentials do not open the inbox.
* **Login is OIDC only**, single pinned issuer, PKCE, `private_key_jwt`
  client authentication in production, and a required role claim re-checked
  every 15 minutes. Microsoft Entra ID is officially supported; Keycloak is
  used in CI. There are no local accounts.
* **Hardened web surface**: strict CSP with Trusted Types and no inline code,
  HSTS preload, `__Host-` SameSite=Strict sessions, CSRF checks, built-in
  Let's Encrypt (or run behind your proxy), no third-party scripts.
* **Verifiable browser code**: reproducible build, zero runtime JavaScript
  dependencies, published asset hashes. See [SECURITY.md](SECURITY.md).
* **Honest limits**: a server operator can still serve malicious JavaScript,
  and the server sees sizes and timing. Read the
  [threat model](docs/THREAT_MODEL.md) before real use. Lost passkeys mean a
  lost inbox, by design.

## Quickstart (development)

Needs Nix with flakes and podman.

```sh
nix develop            # Go, Node, esbuild, tooling
make keycloak-up       # dev Keycloak on :8180 with a seeded "dropr" realm
make dev               # builds the browser modules, then Dropr on http://localhost:8080
```

Open <http://localhost:8080> and sign in as `alice` (`alice-dev-password`).
`mallory` has no role and is refused. Credentials are public test values
(see `deploy/compose.dev.yaml`).

```sh
make check             # build, lint, race tests, govulncheck
make test-keycloak     # integration tests with real logins
make e2e               # real-browser smoke (Playwright: Chromium, Firefox, WebKit)
make fuzz FUZZTIME=20s
cd web && npm ci && npm run typecheck && npm test
make keycloak-down
```

## Build and run

```sh
nix build .#dropr        # static binary with embedded assets
nix build .#web-assets   # hashed JS bundle, manifest.json, sw.js
nix build .#image        # distroless-style OCI image (reproducible)
nix flake check          # vet, tests, web tests, VM test
```

Without Nix: `podman build -f deploy/Containerfile -t dropr .`.
After changing Go or npm dependencies run `make hashes` to refresh
`nix/hashes.nix`. Flake builds only see files known to git (`git add` new files).

## Deploy

[docs/operations.md](docs/operations.md) covers the NixOS module, Compose
(`deploy/compose.yaml`), binary + systemd, TLS modes, backups, upgrades, the
admin CLI and capacity planning for 100 GB files.

## Documentation

| Document | Content |
|---|---|
| [docs/setup-entra.md](docs/setup-entra.md) | Microsoft Entra ID setup, step by step |
| [docs/setup-keycloak.md](docs/setup-keycloak.md) | Keycloak realm, client and mappers |
| [docs/operations.md](docs/operations.md) | Install, configure, back up, upgrade, rotate |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, attackers, STRIDE, residual risks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | HTTP surface, data model, contracts |
| [docs/FORMAT.md](docs/FORMAT.md) | Normative byte formats and test vectors |
| [PLAN.md](PLAN.md) | Product plan and decisions |
| [SECURITY.md](SECURITY.md) | Reporting, supported versions, verifying releases |

## Status

Pre-release; external review is required before real use (PLAN.md,
milestone 7).

## License

MIT, see [LICENSE](LICENSE).
