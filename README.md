# Dropr

Self-hosted, end-to-end encrypted file drop. One Go binary, your domain, and
your existing OIDC identity provider for accounts.

Two flows, nothing else:

* **Share**: an owner uploads a file and gets a link. Anyone with the link can
  download it until it expires or is revoked.
* **Request**: an owner creates a request link. Anyone with it can send files
  that only that owner can read.

Files go up to 100 GB (default cap 5 GB). Uploads are resumable; downloads
stream to disk. The interface is in English and French, with light, dark and
system themes.

## Security model

* **The server never sees plaintext.** Files and their names are encrypted in
  the browser (AES-256-GCM STREAM, WebCrypto only). Share-link keys live in the
  URL fragment, which browsers never send to the server.
* **Request links use HPKE** (RFC 9180, X25519) with one key pair per link,
  generated in the owner's browser. The private key stays there,
  non-extractable. Stolen login credentials do not open the inbox.
* **Login is OIDC only**: one pinned issuer, PKCE, `private_key_jwt` in
  production, and a required role claim re-checked every 15 minutes. No local
  accounts.
* **Strict web surface**: CSP with Trusted Types and no inline code, HSTS,
  `__Host-` SameSite=Strict sessions, CSRF checks, no third-party scripts.
* **Verifiable browser code**: reproducible build, zero runtime JavaScript
  dependencies, published asset hashes. See [SECURITY.md](SECURITY.md).
* **Honest limits**: whoever controls the server can serve malicious
  JavaScript, and the server sees sizes and timing. Files received through a
  request link open only in the browser that created the link; clearing its
  site data loses them, by design. Read the
  [threat model](docs/THREAT_MODEL.md) before real use.

## Build

```sh
nix build .#dropr    # result/bin/dropr
make build           # bin/dropr (from `nix develop`)
```

Either way you get one static binary with the browser modules, templates and
styles embedded. Release binaries for Linux amd64 and arm64 are published with
signed checksums ([verifying a release](SECURITY.md#verifying-a-release)).

## Run

```sh
(umask 077; openssl rand -base64 32 > refresh_key)   # encrypts stored refresh tokens
dropr serve --config dropr.toml
```

[`dropr.example.toml`](dropr.example.toml) is the commented configuration
reference. Dropr needs:

* an OIDC provider where you can register a client and issue a role claim
  ([docs/oidc.md](docs/oidc.md));
* a domain; Dropr either gets its own Let's Encrypt certificate
  (`tls = "acme"`) or runs behind your reverse proxy (`tls = "proxy"`);
* one data directory (`data_dir`) for the SQLite database, the encrypted blobs
  and the ACME cache.

In production mode, Dropr refuses to start on an unsafe configuration (plain
HTTP, a client secret, a provider without PKCE or refresh tokens, a proxy
without `trusted_proxies`, world-readable secret files). `dropr help` lists the
admin commands: `user list|revoke|purge|migrate`, `gc`, `backup`,
`healthcheck`, `version`. There is no admin web UI.

## Documentation

| Document | Content |
|---|---|
| [docs/oidc.md](docs/oidc.md) | Identity provider requirements, Entra ID and Keycloak |
| [docs/DESIGN.md](docs/DESIGN.md) | Scope, decisions and their rationale |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, attackers, STRIDE, residual risks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | HTTP surface, data model, configuration, contracts |
| [docs/FORMAT.md](docs/FORMAT.md) | Normative byte formats and test vectors |
| [docs/PAGES.md](docs/PAGES.md) | Page and browser module DOM contract |
| [SECURITY.md](SECURITY.md) | Reporting, supported versions, verifying releases |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and tests |

## Status

Pre-release. An external security review is required before real use.

## License

MIT, see [LICENSE](LICENSE).
