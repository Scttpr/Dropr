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

The interface is in English and French (picked from the browser's language,
switchable on every page) with a light theme by default, plus dark and
follow-the-system themes. Adding a language means one Go catalog
(`internal/i18n`) and one TypeScript catalog (`web/src/lib/locales`); tests
fail on any missing translation.

## Security model in six bullets

* **The server never sees plaintext.** Files and their names are encrypted in
  the browser (AES-256-GCM STREAM, WebCrypto only). Share-link keys live in the
  URL fragment, which browsers never send to the server.
* **Request links use HPKE** (RFC 9180, X25519) with a key pair per link,
  generated in the owner's browser. The private key is stored there,
  non-extractable, and never reaches the server. Stolen login credentials do
  not open the inbox.
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
  [threat model](docs/THREAT_MODEL.md) before real use. Files received through
  a request link open only in the browser that created it: clearing its site
  data loses them, by design.

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
(`deploy/docker/`), binary + systemd (`deploy/debian/`, step by step in [docs/deploy-debian.md](docs/deploy-debian.md)), TLS modes, backups, upgrades, the
admin CLI and capacity planning for 100 GB files.

## Documentation

| Document | Content |
|---|---|
| [docs/setup-entra.md](docs/setup-entra.md) | Microsoft Entra ID setup, step by step |
| [docs/setup-keycloak.md](docs/setup-keycloak.md) | Keycloak realm, client and mappers |
| [docs/deploy-debian.md](docs/deploy-debian.md) | Production install on Debian/Ubuntu: Docker or bare-metal systemd |
| [docs/operations.md](docs/operations.md) | Install, configure, back up, upgrade, rotate |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, attackers, STRIDE, residual risks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | HTTP surface, data model, contracts |
| [docs/FORMAT.md](docs/FORMAT.md) | Normative byte formats and test vectors |
| [docs/PAGES.md](docs/PAGES.md) | Page ↔ browser module DOM contract, language and theme |
| [docs/security-audit-2026-11.md](docs/security-audit-2026-11.md) | Internal security audit: findings and fixes |
| [PLAN.md](PLAN.md) | Product plan and decisions |
| [SECURITY.md](SECURITY.md) | Reporting, supported versions, verifying releases |

## Status

Pre-release; external review is required before real use (PLAN.md,
milestone 7).

## License

MIT, see [LICENSE](LICENSE).
