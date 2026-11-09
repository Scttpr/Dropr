# Deploying Dropr

**English** · [Français](fr/deploiement.md)

A production deployment on one Linux host (amd64 or arm64) with systemd.
Reference material lives elsewhere: every configuration key in
[dropr.example.toml](../dropr.example.toml) and
[ARCHITECTURE.md §5](ARCHITECTURE.md#5-config-droprtoml), the identity
provider in [oidc.md](oidc.md), residual risks in
[THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Before you start

* **A dedicated host name**, such as `drop.example.com`. Dropr is served at the
  root of its own origin. **Choose it once**: request link keys live in owners'
  browsers, bound to the origin, so changing the scheme or host name makes
  every received file unreadable and breaks every link already sent.
* **An OIDC provider** where you can register a `private_key_jwt` client and
  put a role in the ID token ([oidc.md](oidc.md)).
* **Disk** for the encrypted files, with room for the largest upload you allow.

## 2. Install a verified binary

Download `dropr-<version>-linux-amd64` (or `-arm64`) and the
`dropr-<version>-SHA256SUMS*` files from the latest release, then check the
signature with [cosign](https://github.com/sigstore/cosign):

```sh
V=v1.0.1
cosign verify-blob --bundle dropr-$V-SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dropr-$V-SHA256SUMS
sha256sum -c --ignore-missing dropr-$V-SHA256SUMS
install -m 0755 dropr-$V-linux-amd64 /usr/local/bin/dropr
```

Building from a signed tag and provenance attestations are covered in
[SECURITY.md](../SECURITY.md#verifying-a-release).

## 3. Account and secrets

Run as root. The service account owns its two secrets; the configuration
stays root-owned and read-only to the service.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin dropr
install -d -m 0750 -o root -g dropr /etc/dropr
cd /etc/dropr && umask 077

# Encrypts stored refresh tokens. Never store it with database backups.
openssl rand -base64 32 > refresh_key

# OIDC client key: private key followed by its certificate.
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout key.pem -out cert.pem
cat key.pem cert.pem > oidc_key && rm key.pem

chown dropr:dropr refresh_key oidc_key && chmod 0400 refresh_key oidc_key
```

Register the client at your provider and upload `cert.pem`
([oidc.md](oidc.md)). Dropr warns 30 days before the certificate expires and
refuses to start once it has.

## 4. Configuration

`/etc/dropr/dropr.toml`, mode `0640`, owner `root:dropr`. This example uses
Entra ID; [oidc.md](oidc.md) gives the `[oidc]` block for Keycloak.

```toml
public_url       = "https://drop.example.com"
mode             = "production"
data_dir         = "/var/lib/dropr"
listen           = ":443"
tls              = "acme"
acme_email       = "admin@example.com"
refresh_key_file = "/etc/dropr/refresh_key"

[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "<application-id>"
client_auth     = "private_key_jwt"
client_key_file = "/etc/dropr/oidc_key"
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"
required_role   = "Dropr.User"
required_claims = { tid = "<tenant-id>" }
allow_unadvertised_pkce = true
```

In `acme` mode Dropr gets its own Let's Encrypt certificate through
TLS-ALPN-01: only port 443 must be reachable from the Internet. Add a DNS CAA
record that allows Let's Encrypt for the host name.

**Behind a reverse proxy** instead, set `tls = "proxy"`,
`listen = "127.0.0.1:8080"` and `trusted_proxies = ["127.0.0.1"]`. The proxy
must send `X-Forwarded-For`, accept request bodies of at least 33 MiB
(`client_max_body_size 64m;` in nginx), buffer neither requests nor responses,
and leave Dropr's security headers untouched.

## 5. systemd unit

`/etc/systemd/system/dropr.service`:

```ini
[Unit]
Description=Dropr
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/dropr serve --config /etc/dropr/dropr.toml
Restart=on-failure
User=dropr
Group=dropr
StateDirectory=dropr
StateDirectoryMode=0700
UMask=0077

# Binds port 443 without root. Remove both lines behind a reverse proxy.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now dropr
journalctl -u dropr -f
```

In production mode Dropr refuses to start on an unsafe configuration and logs
why. Then sign in at `https://drop.example.com` with an account that has the
role; `sudo -u dropr dropr user list` should show it. A log line
`ID token has no sid claim` means front-channel logout will not work: fix it at
the provider ([oidc.md](oidc.md)).

**Check the served code** after every deploy, from outside the server, with
the script in
[SECURITY.md](../SECURITY.md#check-what-a-running-instance-serves). Any `DIFF`
means the instance does not serve the released code.

## 6. Operations

Admin commands run as the service account: `sudo -u dropr dropr help`.

* **Backups.** `sudo -u dropr dropr backup --out <file>` writes a consistent
  copy of the database while Dropr runs; also copy `/var/lib/dropr/blobs`
  (already encrypted). Keep `refresh_key` out of these backups.
* **Request link keys are not on the server.** They live in the owner's
  browser profile: clearing site data, a private window or a lost device makes
  received files unreadable. Tell users to create request links in their usual
  browser and download received files promptly.
* **Restore only a database newer than the open request links.** An older one
  that lacks a live link makes the owner's browser delete that link's key, and
  its files are lost.
* **Offboarding.** Remove the role at the provider, then
  `sudo -u dropr dropr user disable <user>`.
* **Upgrades.** Verify the new binary (§2), back up, replace it,
  `systemctl restart dropr`, check the served code (§5). Only the latest
  release gets security fixes.
