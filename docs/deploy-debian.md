# Deploying Dropr on Debian or Ubuntu

This guide covers a production install on one Debian 12/13 or Ubuntu
22.04/24.04 server, in one of two ways:

| | [Bare metal (systemd)](#bare-metal-systemd) | [Docker (Compose)](#docker-compose) |
|---|---|---|
| Kit | `deploy/debian/` | `deploy/docker/` |
| Entry point | `sudo deploy/debian/install.sh` | `sudo deploy/docker/setup.sh` |
| Runs as | system user `dropr`, systemd sandbox (exposure score 1.5) | UID 65532 in a distroless image, read-only root, no capabilities |
| Secrets | `LoadCredential` from root-only `/etc/dropr/credentials` (optionally TPM-sealed) | bind-mounted files, 0400, owned by the container user |
| Upgrades | `install.sh` again: backup, atomic swap, health check | `setup.sh --image`: backup, recreate, health check |
| Choose it when | you want the smallest stack and the tightest sandbox | you already run Docker and pin images by digest |

Both run the same binary with the same config keys, and both have built-in
Let's Encrypt, so the only open ports are 443 (and 80 for the redirect). Read
[operations.md](operations.md) for the configuration reference, backups,
key rotation and capacity planning, and [THREAT_MODEL.md](THREAT_MODEL.md)
before real use.

Run both scripts from a checkout of a verified release tag:

```sh
git clone https://github.com/scttpr/dropr && cd dropr
git verify-tag v0.1.0 && git checkout v0.1.0
```

## 1. Server baseline

These steps apply to both workflows. The scripts check some of them but never
change your firewall, SSH or Docker daemon settings.

* **A dedicated host or VM.** Dropr's guarantees depend on the server serving
  genuine JavaScript (THREAT_MODEL.md), so anyone with root on the host can
  defeat them. Keep the host single-purpose and the list of administrators short.
* **Security updates**: `apt install unattended-upgrades` and keep it enabled
  (`dpkg-reconfigure -plow unattended-upgrades`).
* **SSH**: key authentication only (`PasswordAuthentication no`,
  `PermitRootLogin no` in a file under `/etc/ssh/sshd_config.d/`).
* **Clock**: keep NTP running (`timedatectl` shows `System clock synchronized:
  yes`). OIDC client assertions and tokens are rejected when the clock drifts.
* **DNS**: an A/AAAA record for the host in `public_url`, and a CAA record
  `0 issue "letsencrypt.org"`. Choose the name once: request link keys are stored per
  origin in the owners' browsers
  ([Changing the domain](operations.md#changing-the-domain)).
* **Firewall**: allow 22 (preferably from your admin addresses only), 80 and
  443. With ufw on the bare-metal install:

  ```sh
  ufw default deny incoming && ufw allow OpenSSH && ufw allow 80,443/tcp && ufw enable
  ```

  For Docker, see [the firewall note](#docker-and-the-host-firewall): Docker
  bypasses ufw.
* **Disk**: put the data directory (`/var/lib/dropr` or `/opt/dropr/data`) on
  a local ext4 or XFS file system sized as in
  [Capacity planning](operations.md#capacity-planning), never on NFS/SMB
  (SQLite WAL is not safe there). A separate mount with `nodev,nosuid,noexec`
  is a good idea.
* **Identity provider**: register the application first:
  [Entra ID](setup-entra.md) or [Keycloak](setup-keycloak.md). Both scripts
  generate the client key pair and leave the public certificate next to the
  config for you to upload.

## Bare metal (systemd)

### Get the binary

Pick one:

```sh
# a) Release binary: install.sh downloads it, checks SHA-256 and verifies the
#    keyless cosign signature of the checksum file (cosign must be installed).
sudo deploy/debian/install.sh --version v0.1.0

# b) Build from the checkout with Docker or Podman (no Go/Node on the host):
docker build -f deploy/Containerfile --build-arg VERSION=v0.1.0 \
  --target binary --output type=local,dest=out .
sudo deploy/debian/install.sh --binary out/dropr

# c) Reproducible Nix build (on any machine with Nix), then copy it over:
nix build .#dropr && scp result/bin/dropr server:
sudo deploy/debian/install.sh --binary ~/dropr
```

### Install

The first run of `install.sh`:

1. creates the system user `dropr` (no shell, no home outside the state directory);
2. installs `/usr/local/bin/dropr`, `/usr/local/sbin/dropr-admin` and
   `/usr/local/lib/dropr/run-with-credentials`;
3. creates `/etc/dropr` (root:dropr 0750) with `dropr.toml` (0640) and
   `/etc/dropr/credentials` (root 0700) with a fresh `refresh_key` and, unless
   `--no-oidc-key`, `oidc_key.pem` plus the public `/etc/dropr/oidc_cert.pem`;
4. installs `dropr.service`, `dropr-backup.service` and `.timer`, and a
   journal namespace with 7-day retention (`/etc/systemd/journald@dropr.conf`);
5. stops there while the config still contains placeholders.

Then:

1. Upload `/etc/dropr/oidc_cert.pem` to the app registration (Entra:
   *Certificates & secrets*, Keycloak: client *Keys*).
2. Edit `/etc/dropr/dropr.toml`: `public_url`, `acme_email` and every `<...>`.
   The secret paths under `/run/credentials/dropr.service/` stay as they are.
3. Start and watch the startup checks:

   ```sh
   sudo systemctl enable --now dropr
   journalctl --namespace=dropr -f
   ```

The service listens on 443 directly (the only capability it holds is
`CAP_NET_BIND_SERVICE`) and on 80 for the redirect. The first HTTPS request
obtains the certificate.

### What the sandbox does

`dropr.service` runs as `dropr` with `ProtectSystem=strict` (everything
read-only except `/var/lib/dropr`), private `/tmp` and `/dev`, hidden `/proc`,
no access to `/home` or to `/etc/dropr/credentials`, a `@system-service`
system-call allow-list without privileged calls, `MemoryDenyWriteExecute`, no
new privileges, no namespaces, and only IPv4/IPv6/Unix sockets. Check it with
`systemd-analyze security dropr`. Local changes go into a drop-in
(`sudo systemctl edit dropr`), which upgrades keep.

**Optional: TPM-sealed secrets.** On a host with a TPM2 (most physical
servers and many VMs), seal the credentials to the machine so a copy of the
disk is useless without it:

```sh
cd /etc/dropr/credentials
systemd-creds encrypt --with-key=tpm2 --name=refresh_key refresh_key refresh_key.cred
systemd-creds encrypt --with-key=tpm2 --name=oidc_key oidc_key.pem oidc_key.cred
sudo systemctl edit dropr     # then the same for dropr-backup:
#   [Service]
#   LoadCredential=
#   LoadCredentialEncrypted=refresh_key:/etc/dropr/credentials/refresh_key.cred
#   LoadCredentialEncrypted=oidc_key:/etc/dropr/credentials/oidc_key.cred
```

Restart, confirm that logins work, then `shred -u` the plaintext files (keep
an offline copy of them in your secret store: they cannot be unsealed on other
hardware). `dropr-admin` reads the plaintext paths; adjust its
`LoadCredential` lines the same way if you remove them.

### Admin, backups, logs

```sh
sudo dropr-admin user list               # any `dropr` admin command (operations.md "Admin CLI")
sudo dropr-admin version
sudo systemctl start dropr-backup        # backup now; the timer runs daily
ls -l /var/backups/dropr                 # kept 14 days (DROPR_BACKUP_KEEP_DAYS)
journalctl --namespace=dropr --since -1h # request logs, kept 7 days
systemctl list-timers dropr-backup
```

`dropr-admin` runs the CLI as the `dropr` user in a transient unit with the
same credentials, so the secrets are never readable by a login account.

The backup timer copies the **database** only. Ship `/var/backups/dropr` and
then `/var/lib/dropr/blobs` off the host, encrypted, with your backup tool
(restic, borg), in that order; see [Backups](operations.md#backups) for why and
for the restore procedure. Back up `/etc/dropr` (config and credentials)
separately.

### Upgrade and rollback

```sh
git fetch --tags && git verify-tag v0.2.0 && git checkout v0.2.0
sudo deploy/debian/install.sh --version v0.2.0     # or --binary FILE
```

On a running service this backs up the database (and stops if that fails),
keeps the old binary as `/usr/local/bin/dropr.previous`, swaps in the new one,
refreshes the units, restarts and waits for `/healthz`. Migrations run at
startup and are not reversible; to roll back, stop the service, restore the
pre-upgrade backup (newest file in `/var/backups/dropr`, see
[Backups](operations.md#backups)) and move `dropr.previous` back.

### Behind nginx or Caddy

Only when Dropr must share ports 80/443 with other sites. In `dropr.toml` set
`tls = "proxy"`, `listen = "127.0.0.1:8080"`, `trusted_proxies =
["127.0.0.1"]` and remove `redirect_http`/`redirect_listen`. Drop the
capability:

```sh
sudo systemctl edit dropr
#   [Service]
#   CapabilityBoundingSet=
#   AmbientCapabilities=
```

`deploy/debian/nginx-dropr.conf` is a complete nginx site (no buffering, 64 MiB
bodies, long timeouts, X-Forwarded-For overwritten rather than appended). Caddy:
`reverse_proxy 127.0.0.1:8080 { flush_interval -1 }`. Requirements in
[TLS modes](operations.md#tls-modes).

## Docker (Compose)

### Install Docker

Use Docker's own repository, which ships the Compose v2 plugin
(<https://docs.docker.com/engine/install/debian/> or `.../ubuntu/`):

```sh
apt install docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Recommended daemon settings in `/etc/docker/daemon.json` (they apply to every
container on the host, so review them first), then `systemctl restart docker`:

```json
{
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false,
  "userland-proxy": false,
  "log-driver": "journald"
}
```

Optionally add `"userns-remap": "default"` so that container UIDs are
unprivileged on the host as well; `setup.sh` detects it and sets the file
owners accordingly. Membership in the `docker` group is root-equivalent: give
it to nobody you would not give root.

### Set up

```sh
sudo deploy/docker/setup.sh                    # creates /opt/dropr (--dir to change)
```

This creates:

```
/opt/dropr/compose.yaml     replaced on every run; customise in compose.override.yaml
/opt/dropr/.env             DROPR_IMAGE and host settings (0600)
/opt/dropr/dropr.toml       config template, redirect_http = true
/opt/dropr/oidc_cert.pem    public certificate to upload to the IdP
/opt/dropr/secrets/         refresh_key, oidc_key.pem: 0400, owned by UID 65532, directory root 0700
/opt/dropr/data/            /data in the container (UID 65532, 0700)
/opt/dropr/backups/         /backups in the container
```

and a `dropr-backup.timer` on the host that runs `dropr backup` in the
container daily. Then:

1. Upload `/opt/dropr/oidc_cert.pem` to the app registration.
2. Edit `/opt/dropr/dropr.toml` (`public_url`, `acme_email`, every `<...>`).
3. Choose the image. A release image, after verifying its signature
   ([SECURITY.md](../SECURITY.md#verify-the-container-image)):

   ```sh
   sudo deploy/docker/setup.sh --image ghcr.io/scttpr/dropr@sha256:<digest>
   ```

   or one you build from the verified checkout:

   ```sh
   docker build -f deploy/Containerfile --build-arg VERSION=v0.1.0 -t dropr:v0.1.0 .
   sudo deploy/docker/setup.sh --image dropr:v0.1.0
   ```

`setup.sh` starts the container once nothing is left to fill in and waits for
its health check.

### What the container does

UID 65532 from a distroless image without a shell, read-only root file
system, `cap_drop: ALL`, `no-new-privileges`, a small `noexec` tmpfs on
`/tmp`, `pids_limit`, a memory ceiling (`DROPR_MEM_LIMIT`, default 4g), and
Docker's default seccomp and AppArmor profiles. Only `/data` and `/backups`
are writable. Container port 8443 is published on host 443, 8080 on host 80.

### Docker and the host firewall

Docker inserts its own iptables rules for published ports, **ahead of ufw and
firewalld**, so ports 443 and 80 are reachable even if ufw denies them. Filter
container traffic in the `DOCKER-USER` chain if needed, and publish on a single
address with `DROPR_BIND` in `.env` on multi-homed hosts. Make sure nothing else
in Compose files on this host publishes ports you do not mean to expose.

### Admin, backups, logs

```sh
cd /opt/dropr
docker compose exec dropr /bin/dropr user list --config /etc/dropr/dropr.toml
sudo systemctl start dropr-backup     # backup now; files appear in /opt/dropr/backups (14 days)
docker compose logs -f                # or: journalctl CONTAINER_TAG=dropr
docker compose ps                     # health status
```

With the journald log driver, Dropr's logs land in the system journal. The
project's plan is 7 days of request logs; if this host should keep nothing
longer, set it system-wide in `/etc/systemd/journald.conf.d/retention.conf`
(`[Journal]` / `MaxRetentionSec=7d`) and `systemctl restart systemd-journald`.

Ship `/opt/dropr/backups` and then `/opt/dropr/data/blobs` off the host,
encrypted, in that order, and back up `/opt/dropr/secrets` and `dropr.toml`
separately ([Backups](operations.md#backups)).

### Upgrade and rollback

```sh
sudo deploy/docker/setup.sh --image ghcr.io/scttpr/dropr@sha256:<new digest>
```

This pulls the image, backs up the database (stops if that fails), writes the
new digest into `.env`, recreates the container and waits for it to be healthy.
It prints the previous image for a rollback; if the new version migrated the
schema, restore the pre-upgrade backup from `/opt/dropr/backups` first
([Backups](operations.md#backups)).

## 2. After every deploy

* `curl -fsS https://drop.example.com/healthz` prints `ok`, from outside.
* Check the TLS setup from outside, e.g. `testssl.sh drop.example.com` (TLS 1.2+
  with AEAD suites only, HSTS present).
* Compare the served browser code with the release hashes
  ([SECURITY.md, "Check what a running instance serves"](../SECURITY.md#check-what-a-running-instance-serves)),
  ideally from a monitoring host on a schedule.
* Sign in with an account that has the required role, and confirm that one
  without it is refused.
* Alert on `/healthz`, free disk space, the OIDC certificate expiry warning in
  the logs and the age of the newest backup
  ([Monitoring](operations.md#monitoring-and-logs)).
