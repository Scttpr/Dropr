# Operating Dropr

Audience: the person who runs one Dropr instance. Dropr is one static binary
(or one container), one data directory, one TOML file and two secret files.

Requirements: a domain you own (choose it once, see
[Changing the domain](#changing-the-domain)), an OIDC provider where you can
register a client ([Entra](setup-entra.md) or [Keycloak](setup-keycloak.md)),
and disk space ([capacity](#capacity-planning)).

## Configuration reference

`dropr serve --config /etc/dropr/dropr.toml`. Unknown keys are rejected and
the file is validated at startup; production mode refuses unsafe settings.
Annotated example: `deploy/dropr.example.toml`.

| Key | Default | Notes |
|---|---|---|
| `public_url` | required | `https://host[:port]`, no path. `http://localhost` only in dev mode |
| `mode` | `production` | `dev` allows `client_secret` auth and `http://localhost` |
| `data_dir` | required | SQLite (`dropr.db`), blobs, ACME cache (`acme/`) |
| `listen` | `:8443` (acme), `127.0.0.1:8080` (proxy) | `host:port` or `unix:/abs/path` (proxy mode) |
| `tls` | `acme` | `acme` or `proxy` |
| `acme_email` | none | Contact for Let's Encrypt |
| `redirect_http` | `false` | ACME mode: serve an HTTP to HTTPS redirect on `redirect_listen` |
| `redirect_listen` | `:8080` | Address of that redirect listener |
| `trusted_proxies` | `[]` | Proxy mode: addresses or CIDRs whose `X-Forwarded-*` are trusted. Required in production for a TCP `listen` |
| `trust_unix_socket_proxy` | `false` | Proxy mode on a `unix:` socket: trust the peer's `X-Forwarded-For` (the alternative to `trusted_proxies` there) |
| `refresh_key_file` | required | 32 random bytes, raw or base64 |
| `login_label` | `Sign in` | Button text, 1-64 characters |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` |
| `limits.max_file_size` | `5GB` | At most `100GB`. Binary units (`5GB` = 5 GiB) |
| `limits.user_quota` | `50GB` | Per-owner total |
| `limits.default_expiry` | `7d` | `1h`, `1d`, `7d` or `30d` |
| `limits.disk_headroom` | automatic: max(1 GiB, 5% of the file system) | Free space always kept back when accepting uploads, on top of what uploads in progress still have to write |
| `limits.max_transfers` | `512` | Concurrent part uploads and downloads (429 beyond) |
| `limits.max_transfers_per_ip` | `32` | The same per client address |
| `limits.min_transfer_rate` | `4KB` | Per second over 60 s; slower transfers are cut (clients resume). `0` disables |
| `oidc.*` | see setup guides | `issuer`, `client_id`, `client_auth`, `client_key_file`, `client_key_id`, `client_assertion_alg`, `client_assertion_x5t_sha1`, `client_secret_file`, `scopes`, `role_claim`, `required_role`, `display_claim`, `required_claims`, `revalidate_every` (1m to 1h), `allow_unadvertised_pkce` |

Secrets are read from files only, never from environment variables or the TOML.
Keep them `chmod 600`: a group- or world-readable secret file logs a warning,
and a world-readable one stops a production start (files under
`/run/credentials/` and `/run/secrets/` are exempt).

## Installation

### NixOS module

Add the flake and the module, then configure the service. Secret files stay
outside the Nix store and are passed with systemd `LoadCredential`.

```nix
{
  inputs.dropr.url = "github:scttpr/dropr";   # your fork or release tag
  outputs = { nixpkgs, dropr, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        dropr.nixosModules.default
        {
          services.dropr = {
            enable = true;
            openFirewall = true;
            refreshKeyFile = "/var/lib/secrets/dropr/refresh_key";
            oidcKeyFile    = "/var/lib/secrets/dropr/oidc_key.pem";
            settings = {
              public_url = "https://drop.example.com";
              acme_email = "admin@example.com";
              oidc = {
                issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0";
                client_id = "<application-id>";
                required_role = "Dropr.User";
                required_claims.tid = "<tenant-id>";
                allow_unadvertised_pkce = true;
              };
            };
          };
        }
      ];
    };
  };
}
```

* The service runs as a `DynamicUser` named `dropr`, with state in
  `/var/lib/dropr` (mode 0700), `ProtectSystem=strict`, a system-call filter,
  `MemoryDenyWriteExecute`, no capabilities (only `CAP_NET_BIND_SERVICE` when
  `listen` or `redirect_listen` uses a port below 1024).
* `listen` defaults to `:8443` in ACME mode. To serve on 443 directly set
  `settings.listen = ":443"`; the module then grants the capability.
* Admin commands: `sudo dropr-admin user list` (a wrapper that runs `dropr` in
  a transient unit with the same user, state directory and credentials).
* Behind a proxy: `settings = { tls = "proxy"; listen = "127.0.0.1:8080";
  trusted_proxies = [ "127.0.0.1" ]; ... }` and `services.nginx` or Caddy in front.
* Upgrade: `nix flake update dropr && nixos-rebuild switch`.

### Debian 13 (systemd) or Docker Compose

[deploy-debian.md](deploy-debian.md) is the step-by-step production guide,
with two ready-made kits:

* **Compose** (`deploy/docker/`): `setup.sh` lays out `/opt/dropr`
  (`compose.yaml`, `.env` with the image digest, `dropr.toml`, `secrets/`,
  `data/`, `backups/`), generates the secrets, installs a daily backup timer
  and upgrades with `--image <digest>` (backup, recreate, health check). The
  container runs as UID 65532 from a shell-less image with a read-only root,
  `cap_drop: ALL`, `no-new-privileges`, pid and memory limits.
* **Debian 13 and systemd** (`deploy/debian/`, the recommended path):
  `install.sh --binary FILE` or `--version vX.Y.Z` (downloads the release
  binary and verifies its signature) creates the `dropr` user, `/etc/dropr`
  with credentials sealed by `systemd-creds` (TPM2 when present), a sandboxed
  `dropr.service` plus an AppArmor profile, the admin tools, daily backups
  with optional restic off-site copies, a self-check timer with a failure
  hook for your alerting, and a 7-day journal namespace. The guide also gives
  a host baseline (SSH, nftables, sysctl, updates, NTS time) as snippets. Rerunning it upgrades
  (backup, atomic swap, health check).

Both images (Nix and Containerfile) install the binary as `/bin/dropr` and
declare a healthcheck: the image has no shell or curl, so
`dropr healthcheck --config /etc/dropr/dropr.toml` probes `GET /healthz` on the
configured listener (TCP, Unix socket, or TLS in ACME mode) and exits 0 when
healthy. From outside, `GET /healthz` returns `ok` (use it for load balancers
and monitoring). Build the image yourself with `nix build .#image`
(reproducible) or `docker build -f deploy/Containerfile .` (portable; add
`--target binary --output type=local,dest=out` to get just the static binary).

## TLS modes

**`tls = "acme"` (default).** Dropr obtains and renews a Let's Encrypt
certificate for the host in `public_url` using TLS-ALPN-01, so only **port 443**
must reach the process (publish host 443 to container 8443). Requirements: the
name resolves publicly to this host; outbound HTTPS to the ACME CA; `data_dir`
persistent (certificates and the account key are cached in `data_dir/acme`).
TLS 1.2 minimum, AEAD suites only, TLS 1.3 preferred. Set a CAA record
(`0 issue "letsencrypt.org"`). `redirect_http = true` adds a port-80 listener
that only redirects to HTTPS. Only the `public_url` host is accepted for
certificates.

**`tls = "proxy"`.** Plain HTTP on `listen` (loopback or a Unix socket) behind
your reverse proxy, which terminates TLS. `public_url` must be `https://`, and
`trusted_proxies` must list the proxy's address (on a `unix:` socket:
`trusted_proxies` or `trust_unix_socket_proxy = true`); production refuses to
start otherwise, because every client would then share the proxy's address
and one rate-limit bucket (one client could block sign-in for everyone). Proxy requirements:

* allow request bodies of at least 32 MiB parts (ciphertext part size is
  33 562 624 bytes; nginx `client_max_body_size 64m`);
* do not buffer uploads or downloads (nginx `proxy_request_buffering off;
  proxy_buffering off;`), keep HTTP/1.1 to the upstream, pass `Range`;
* timeouts long enough for slow 32 MiB part uploads (nginx
  `proxy_read_timeout 300s; proxy_send_timeout 300s`);
* pass `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`; do not strip or add
  security headers (Dropr sets HSTS, CSP and the rest);
* serve only this app on its own origin; the root path, no sub-path.

Caddy needs nothing beyond `reverse_proxy 127.0.0.1:8080` (disable response
buffering with `flush_interval -1` for downloads).

In both modes Dropr sends `Strict-Transport-Security: max-age=63072000;
includeSubDomains; preload`. Only submit to the preload list if every
subdomain of the domain will serve HTTPS.

## Admin CLI

Admin access is shell access. Every command takes
`--config` (default `/etc/dropr/dropr.toml`) and, like the server, reads the
secret files named in it, so run it as the service user with the service's
credentials: `sudo dropr-admin ...` (NixOS module and `deploy/debian`), or
`docker compose exec dropr /bin/dropr ... --config /etc/dropr/dropr.toml`.

| Command | Effect |
|---|---|
| `dropr serve` | Run the server |
| `dropr user list` | Table of accounts: ID, name, subject, created, sessions, issuer |
| `dropr user revoke <user>` | End all sessions now and pause their request links until they sign in again (use after disabling someone at the IdP) |
| `dropr user purge <user> [--yes]` | Delete the user and all their data, blob files included (if some files cannot be removed it says so, and `dropr gc` finishes the job) |
| `dropr user migrate --from-issuer URL --map file.csv [--to-issuer URL] [--dry-run] [--yes]` | Relink accounts to a new provider; see below |
| `dropr gc` | Run the cleanup jobs once (the server also runs them every 5 minutes) |
| `dropr backup --out FILE` | Consistent online backup of the SQLite database; `FILE` must not exist |
| `dropr healthcheck [--url URL]` | Probe `GET /healthz` of the local server, exit 0 when healthy (the container healthcheck) |
| `dropr version` | Version, Go version, VCS revision, schema version |

`<user>` is a user ID or a subject matching exactly one account. Destructive
commands ask you to type `yes` unless `--yes` is given.

## Backups

Back up two things: the database and the blob directory.

```sh
# 1. database, while the server runs (SQLite online backup, WAL safe)
dropr backup --config /etc/dropr/dropr.toml --out /backup/dropr-$(date +%F).db
# 2. blobs (data_dir/blobs): any file-level tool, e.g. restic or rsync
restic backup /var/lib/dropr/blobs
```

Take the database backup **first**, then the blobs: blobs that have no row are
removed by GC after restore, whereas a row without its blob is a broken file.
Blobs are ciphertext already. The database holds HPKE-wrapped file keys and
encrypted refresh tokens: **encrypt the backup and restrict access to it**.
Also back up the secret files separately (`refresh_key`, `oidc_key.pem`);
without `refresh_key` restored sessions simply need a new login.

Request link private keys are **not** on the server and not in any server
backup: each lives in the browser profile that created the link. A restore
brings received files back only for owners who still have that browser
profile; files received through links created in a profile that was since
cleared stay unreadable.

Restore: stop Dropr, place the backup as `data_dir/dropr.db` (remove any stale
`dropr.db-wal` and `dropr.db-shm`), restore `blobs/`, start, run `dropr gc`.
The ACME cache (`data_dir/acme`) can be recreated automatically (watch Let's
Encrypt rate limits if you restore repeatedly).

## Upgrades

1. Read the release notes and verify the release (SECURITY.md).
2. `dropr backup` first. Database migrations run automatically at startup and
   are not reversible; the backup is your rollback.
3. Replace the binary or image (pin by digest), restart. Debian kits:
   `install.sh` again or `setup.sh --image <digest>` (both back up first). Compose:
   change the digest, `docker compose up -d`. NixOS: `nixos-rebuild switch`.
4. Check `dropr version`, the startup log (discovery results and warnings) and
   `/healthz`.

### Upgrading to schema 4 (passkeys removed)

Migration `0004_remove_passkeys.sql` removes the passkey workflow. Received
files used to be encrypted to an account key wrapped by the owner's passkeys;
each request link now has its own key, kept in the owner's browser
(ARCHITECTURE.md §2). The old keys cannot be carried over, so the migration
**deletes every request link and every received file** (the orphan sweep then
removes their blob files) and drops the `passkeys`, `user_keys`,
`webauthn_ceremonies` and `passkey_grants` tables. Share links, accounts and
sessions are kept. The `dropr user reset-keys` command no longer exists.

Before upgrading:

1. Tell users to **download every received file** they want to keep, and that
   their request links will stop working.
2. Take the backup (step 2 above), after they are done.
3. After the upgrade, users create new request links. Files sent through a
   link open only in the browser that created it, so they should create links
   in their everyday browser profile, not a private window.

Rolling back to an older release needs the pre-upgrade backup (the schema
change is not reversible), and restores the old links and files with it.

Browsers cache `/assets` immutably under content-hashed names and the service
worker `/sw.js` has a fixed name, so clients pick up new code at their next
navigation.

## Monitoring and logs

* **Logs**: one JSON object per line on stdout (`journalctl -u dropr`,
  `docker logs`). Request lines carry method, route pattern, status, bytes,
  duration, a keyed IP hash and a request ID; no plaintext IPs, tokens or link
  fragments. Dropr keeps no log files and enforces no retention itself: the
  plan is 7 days, set it in journald (`MaxRetentionSec=7d`) or your log driver.
* **Health**: `GET /healthz` returns 200 `ok`. Alert on it from outside.
* **Alert on**: startup failures (the log names the failed check), repeated
  `5xx`, the OIDC client certificate warning ("expires within 30 days"),
  low free disk space, and TLS certificate age.
* `log_level = "debug"` is for troubleshooting only.

## Capacity planning

* **Ciphertext overhead** is 16 bytes per 64 KiB segment (about 0.024%), plus
  small rows. A 100 GiB file stores as about 100.02 GiB in 3200 parts of 32 MiB
  (`512 * 65552 = 33 562 624` bytes each, last part shorter).
* **Disk**: the server checks free space before accepting an upload and
  enforces `limits.user_quota`. Budget: quota sum of active owners, plus
  headroom for **in-flight uploads** (incomplete uploads are kept up to 24 hours
  before GC, so several concurrent 100 GB attempts can need several times that),
  plus backups. `max_file_size` = `100GB` needs at least 100 GiB free per
  concurrent upload.
* **Raise limits deliberately**: `max_file_size` defaults to 5 GB; the hard
  maximum is 100 GB (config rejects more); `user_quota` should be at least
  `max_file_size`.
* **Filesystem**: use a filesystem that handles many files of 32 MiB (ext4, XFS,
  ZFS). Blobs are sharded (`ab/cd/<id>`). Keep `data_dir` on a local disk;
  SQLite WAL is not safe on network filesystems.
* **Bandwidth and time**: all bytes pass through the server. 100 GB at
  100 Mbit/s is about 2.3 hours each way; uploads resume part by part after
  drops. Reverse proxies and load balancers must not impose an overall request
  timeout shorter than one part transfer.
* **Memory and CPU**: the server streams; encryption runs in the browser. Memory
  is dominated by concurrent 32 MiB part bodies in flight.
* Links expire (1 h to 30 d) and expiry deletes blobs, so steady-state usage
  tracks active links, not history.

## Key rotation

**Refresh key (`refresh_key_file`).** Encrypts the stored refresh tokens and
the sealed login-state cookie. Rotate by replacing the file and restarting.
Consequences: refresh tokens stored under the old key cannot be decrypted, so
existing sessions can no longer be revalidated and users have to sign in again;
logins in flight fail once. No file data is affected (the key never protects
files). Rotate when the key may have leaked, together with `dropr user revoke`
for anyone you want out immediately, and revoke sessions at the IdP, since a
leaked key plus a database copy exposes refresh tokens until they expire.

**OIDC client key and certificate.** Rotate before the certificate expires
(Dropr warns 30 days ahead and refuses to start in production after expiry).
Procedure with Entra: generate a new key and certificate, **upload the new
certificate alongside the old one**, replace `oidc_key.pem`, restart, confirm
logins, then delete the old certificate from the app registration. Keycloak:
import the new certificate, update `client_key_id` if needed, restart.

**Request link keys.** Not managed by the operator: each request link has its
own key pair, generated in the owner's browser and deleted with the link. To
"rotate", the owner revokes a link and creates a new one.

## Changing the domain

Request link private keys are stored in the owners' browsers per origin (the
scheme and host of `public_url`). **Changing the domain makes every stored key
unreachable** from the new origin: files already received become unreadable,
and the links already handed out point to the old host. Share links change
too, and the redirect URI at the IdP must be updated. Pick the domain once. A
move is only safe after owners have downloaded their received files; then
have them revoke their old request links (or let the links expire) and create
new ones on the new domain.

## Changing identity provider

Every user's `(issuer, subject)` changes. Relink existing accounts and data
with a CSV of `old_subject,new_subject` lines:

```sh
dropr user migrate --from-issuer https://old-issuer --map map.csv --dry-run
dropr user migrate --from-issuer https://old-issuer --map map.csv
```

`--to-issuer` defaults to `oidc.issuer` of the config. Sessions of the migrated
accounts end. Never recreate an Entra app registration if you can avoid it:
`sub` is pairwise per registration.

## Troubleshooting startup

Dropr validates the configuration and the provider before listening; the error
names the failed check. Common ones: `public_url must be https://` (production),
`tls = "acme" requires public_url to be a public DNS name`,
`oidc.client_auth = "client_secret" is only allowed in dev mode`,
`provider does not advertise PKCE S256 support` (Entra: set
`allow_unadvertised_pkce = true`), `oidc client certificate is not valid now`.
