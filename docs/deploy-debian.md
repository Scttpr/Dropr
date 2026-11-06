# Deploying Dropr on Debian 13

This guide covers a production install on one server. The recommended path is
a dedicated **Debian 13** host hardened by `harden-host.sh`, with Dropr
installed as a sandboxed systemd service by `install.sh`. Docker Compose is the
alternative for other distributions or for hosts that already run Docker.

| | [Debian 13 (systemd)](#debian-13-systemd) | [Docker (Compose)](#docker-compose) |
|---|---|---|
| Kit | `deploy/debian/` | `deploy/docker/` |
| Entry points | `harden-host.sh`, then `install.sh` | `deploy/docker/setup.sh` |
| Host | Debian 13 only (systemd >= 257) | any Linux with Docker |
| Runs as | system user `dropr`: systemd sandbox (exposure 1.4) plus an AppArmor profile | UID 65532 in a distroless image, read-only root, no capabilities |
| Secrets | `systemd-creds`, sealed to the TPM2 when there is one | bind-mounted files, 0400 |
| Operations | backups, off-site copies (restic), self-check and alerts included | backup timer; the rest is yours |
| Upgrades | `install.sh` again: backup, atomic swap, health check | `setup.sh --image`: backup, recreate, health check |

Both run the same binary with the same config keys and terminate TLS
themselves with Let's Encrypt, so the only open ports are 443, 80 for the
redirect, and SSH. Read [operations.md](operations.md) for the configuration
reference, backups, key rotation and capacity planning, and
[THREAT_MODEL.md](THREAT_MODEL.md) before real use.

Run the scripts from a checkout of a verified release tag:

```sh
git clone https://github.com/scttpr/dropr && cd dropr
git verify-tag v0.1.0 && git checkout v0.1.0
```

## 1. Before you start

* **A dedicated host or VM.** Dropr's guarantees depend on the server serving
  genuine JavaScript (THREAT_MODEL.md), so anyone with root on the host can
  defeat them. Keep the host single-purpose and the list of administrators
  short.
* **A TPM2 and Secure Boot**, if you can choose: physical servers, and VMs
  with a vTPM (Azure Trusted Launch, GCE Shielded VM, AWS NitroTPM, Proxmox).
  With a TPM2, a copy of the disk cannot decrypt Dropr's secrets.
* **Disk**: put `/var/lib/dropr` on a local ext4 or XFS file system sized as in
  [Capacity planning](operations.md#capacity-planning), never on NFS/SMB (SQLite
  WAL is not safe there), ideally its own mount with `nodev,nosuid,noexec`.
* **An admin account** with an SSH key in `~/.ssh/authorized_keys` and `sudo`.
  `harden-host.sh` turns off passwords and root logins, and refuses to run
  without one.
* **DNS**: an A/AAAA record for the name in `public_url`, and a CAA record
  `0 issue "letsencrypt.org"`. Choose the name once: request link keys are stored
  per origin in the owners' browsers
  ([Changing the domain](operations.md#changing-the-domain)).
* **Identity provider**: register the application:
  [Entra ID](setup-entra.md) or [Keycloak](setup-keycloak.md). The install
  generates the client key pair and leaves the public certificate next to the
  config for you to upload.

## Debian 13 (systemd)

### 2. Harden the host

```sh
sudo deploy/debian/harden-host.sh --admin-user alice --admin-cidr 203.0.113.7/32 --dry-run
sudo deploy/debian/harden-host.sh --admin-user alice --admin-cidr 203.0.113.7/32
```

`--dry-run` prints the diff of every file it would write. The real run sets:

| Part | What it does |
|---|---|
| `sysctl` | hides kernel pointers and logs; no unprivileged BPF, user namespaces or perf; ptrace for root only; no kexec or SysRq; no ICMP redirects or source routing |
| `ssh` | logins only for the `--admin-user` accounts, by key only; no root; 3 attempts; no forwarding; hybrid post-quantum (ML-KEM, sntrup) and curve25519 key exchange, AEAD ciphers |
| `firewall` | nftables with default drop: SSH from the `--admin-cidr` networks only (or `--ssh-from-anywhere`, rate-limited per address), 80 and 443, essential ICMP; outbound open |
| `updates` | unattended security upgrades, rebooting at `--reboot-time` (04:00) when a kernel or libc fix needs it |
| `time` | chrony with **NTS** (authenticated time) from three operators, adjusting only when two agree; OIDC tokens and client assertions fail on a drifting clock |

SSH and the firewall are applied together under a guard: a transient timer
rolls both back after two minutes unless you confirm, from a **new** SSH
session, that you can still log in and use `sudo`. Replaced files are kept as
`<file>.dropr-orig`. Skip any part with `--skip NAME` (for example when your
provider's firewall does the filtering); rerunning is safe and only asks for
confirmation when SSH or firewall rules change. The report at the end flags a
missing TPM2, AppArmor turned off, or a data mount without
`nodev,nosuid,noexec`.

### 3. Get the binary

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

### 4. Install

| Option | Effect |
|---|---|
| `--binary FILE` | install this static Linux binary |
| `--version vX.Y.Z` | download the release binary, check SHA-256 and the cosign bundle |
| `--skip-signature` | with `--version`: accept the binary when cosign is not installed (checksum only; avoid) |
| `--no-oidc-key` | do not generate the OIDC client key and certificate (bring your own) |
| `--no-start` | install files only; do not start or restart the service |
| `--unsupported-os` | continue on a system other than Debian 13 (systemd >= 257 is still required) |

The first run of `install.sh`:

1. creates the system user `dropr` (no shell, no home outside the state directory);
2. installs `/usr/local/bin/dropr`, the admin tools `dropr-admin`,
   `dropr-credential` and `dropr-offsite` in `/usr/local/sbin`, and their
   helpers in `/usr/local/lib/dropr`;
3. creates `/etc/dropr` (root:dropr 0750) with `dropr.toml` (0640), and
   `/etc/dropr/credentials` (root 0700) with the refresh key, the OIDC client key
   (unless `--no-oidc-key`; its public certificate goes to
   `/etc/dropr/oidc_cert.pem`) and the alert settings, each **encrypted** with
   `systemd-creds`;
4. installs and loads the AppArmor profile, the units (service, backup timer,
   off-site backup, self-check timer, alerts) and a journal namespace with
   7-day retention;
5. stops there while the config still contains placeholders.

Then:

1. Upload `/etc/dropr/oidc_cert.pem` to the app registration (Entra:
   *Certificates & secrets*, Keycloak: client *Keys*).
2. Edit `/etc/dropr/dropr.toml`: `public_url`, `acme_email` and every `<...>`.
   The secret paths under `/run/credentials/dropr.service/` stay as they are.
3. Run `install.sh` again with the same arguments: it starts Dropr, the
   self-check timer, and waits for `/healthz`. Watch the startup checks with
   `journalctl --namespace=dropr -f`.

The service listens on 443 directly and on 80 for the redirect. The first
HTTPS request obtains the certificate.

### What protects what

* **systemd sandbox** (`systemd-analyze security dropr`, exposure 1.4):
  `dropr` runs unprivileged with only `CAP_NET_BIND_SERVICE`, may bind only
  :443 and :80, sees the file system read-only except `/var/lib/dropr`, cannot
  execute anything but its own binary, has private `/tmp`, `/dev` and IPC, a
  hidden `/proc`, no access to `/home` or the credential store, a
  `@system-service` system-call allow-list without privileged or resource
  calls, `MemoryDenyWriteExecute`, no namespaces, TCP only, and no route to
  link-local addresses (cloud metadata services).
* **AppArmor** (`/etc/apparmor.d/usr.local.bin.dropr`, enforce mode): a second,
  independent wall around every `dropr` process (service, backup, self-check,
  admin CLI): its config, its data and backups, the decrypted credentials of
  its own units, and nothing else. Denials appear in `journalctl -k -g apparmor`;
  local additions go in `/etc/apparmor.d/local/usr.local.bin.dropr`.
* **Sealed secrets**: `/etc/dropr/credentials/*.cred` are encrypted with
  `systemd-creds --with-key=auto` (the host key and, when present, the TPM2).
  systemd decrypts them only into the memory of the units that load them.
  Without a TPM2 they are sealed to `/var/lib/systemd/credential.secret`
  only, which a full disk copy includes. If the TPM is replaced or the disk
  moves to other hardware, nothing can decrypt them: generate new ones
  (`head -c 32 /dev/urandom | base64 | sudo dropr-credential set refresh_key -`
  signs everyone out; a new OIDC key needs its certificate uploaded, see
  [Key rotation](operations.md#key-rotation)).
* **The host**: `harden-host.sh` above. Local changes to the units go into
  drop-ins (`sudo systemctl edit dropr`), which upgrades keep.

### Admin, credentials, logs

```sh
sudo dropr-admin user list               # any `dropr` admin command (operations.md "Admin CLI")
sudo dropr-credential list               # sealed credentials
sudo dropr-credential edit alert_env     # decrypt, edit, re-seal (plaintext stays on /run)
journalctl --namespace=dropr --since -1h # request logs, kept 7 days
systemctl list-timers 'dropr-*'
```

`dropr-admin` and `dropr-offsite` run as the `dropr` user in transient units
with the same credentials and sandbox as the services, so no login account
ever reads the secrets.

### Backups and off-site copies

`dropr-backup.timer` takes a consistent copy of the **database** every day into
`/var/backups/dropr` (kept 14 days, `DROPR_BACKUP_KEEP_DAYS`). After each
successful backup, `dropr-offsite.service` copies the newest database backup
and then the blobs to a [restic](https://restic.net) repository, encrypted, and
prunes it (14 daily, 8 weekly, 12 monthly snapshots). It stays off until you
configure it:

```sh
sudo apt install restic
sudo dropr-credential edit restic_env
#   RESTIC_REPOSITORY=s3:https://s3.example.com/dropr-backups
#   RESTIC_PASSWORD=<long random value: keep a copy off this host>
#   AWS_ACCESS_KEY_ID=...
#   AWS_SECRET_ACCESS_KEY=...
sudo dropr-offsite init
sudo systemctl start dropr-backup        # backup now, then the off-site copy
sudo dropr-offsite snapshots
sudo dropr-offsite restore-test          # restore the latest database and verify it; do it monthly
```

Any restic backend that needs no external program works (S3-compatible,
B2, Azure, GCS, rest-server); give the repository its own credentials with
write access to that bucket only, and object lock or versioning if the
provider has them, so a compromised host cannot delete the history. Without
`RESTIC_PASSWORD` the backups are unreadable.

Recovery after losing the host: harden and install a new one, stop Dropr,
`sudo dropr-offsite restic restore latest --tag db --target /var/cache/dropr-offsite/restore`
and the same with `--tag blobs`, then put the database and blobs in place as in
[Backups](operations.md#backups). Keep a copy of `/etc/dropr/dropr.toml` with
your other configuration; the credentials are bound to the old machine and
are regenerated as above.

### Monitoring and alerts

`dropr-check.timer` runs every 15 minutes and checks `/healthz`, free space on
`/var/lib/dropr` (10%), the age of the newest database backup and off-site copy
(26 h), and the expiry of the certificate served on :443 (14 days) and of the
OIDC client certificate (30 days). Thresholds are `Environment=` lines in
`sudo systemctl edit dropr-check` (see `/usr/local/lib/dropr/check`).

A failure of the check, the service, the backup or the off-site copy starts
`dropr-alert@<unit>.service`, which posts the unit name and its last log lines
to a webhook and/or sends an email, at most once per unit every 6 hours:

```sh
sudo dropr-credential edit alert_env
#   ALERT_WEBHOOK=https://ntfy.sh/<a-long-random-topic>
#   ALERT_WEBHOOK_FORMAT=json              # for Slack or Mattermost
#   ALERT_EMAIL=ops@example.com            # needs a sendmail: apt install msmtp-mta
sudo systemctl start dropr-alert@test.service
```

Also watch the host from outside (`/healthz`, the served code against the
release hashes): see [After every deploy](#after-every-deploy).

### Upgrade and rollback

```sh
git fetch --tags && git verify-tag v0.2.0 && git checkout v0.2.0
sudo deploy/debian/install.sh --version v0.2.0     # or --binary FILE
```

On a running service this backs up the database (and stops if that fails),
keeps the old binary as `/usr/local/bin/dropr.previous`, swaps in the new one,
refreshes the units and the AppArmor profile, restarts and waits for
`/healthz`. Plaintext secrets from an install made before sealed credentials
are sealed and shredded. Migrations run at startup and are not reversible; to
roll back, stop the service, restore the pre-upgrade backup (newest file in
`/var/backups/dropr`, see [Backups](operations.md#backups)) and move
`dropr.previous` back.

### Behind nginx or Caddy

Only when Dropr must share ports 80/443 with other sites; the default setup
keeps one less daemon running as root. In `dropr.toml` set `tls = "proxy"`,
`listen = "127.0.0.1:8080"`, `trusted_proxies = ["127.0.0.1"]` and remove
`redirect_http` and `redirect_listen`. Then adjust the sandbox:

```sh
sudo systemctl edit dropr
#   [Service]
#   CapabilityBoundingSet=
#   AmbientCapabilities=
#   SocketBindAllow=tcp:8080
#   # for listen = "unix:/run/dropr/dropr.sock" instead:
#   # RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
#   # RuntimeDirectory=dropr
```

and open the proxy's own ports in the firewall if they differ from 80/443.
`deploy/debian/nginx-dropr.conf` is a complete nginx site for Debian 13 (no
buffering, 64 MiB bodies, long timeouts, X-Forwarded-For overwritten rather
than appended). Caddy: `reverse_proxy 127.0.0.1:8080 { flush_interval -1 }`.
Requirements in [TLS modes](operations.md#tls-modes).

### Testing the kit

`deploy/debian/test/vm.sh up` boots the official Debian 13 cloud image in QEMU,
runs `harden-host.sh`, then `test/smoke.sh`: a fresh install, a start behind
nginx against a stub IdP over local TLS, an upgrade, the admin CLI, backups, an
off-site copy to a local restic repository with a restore test, the self-check,
AppArmor confinement without denials and the host hardening. It takes a static
binary in `BIN` (default `result/bin/dropr` from `nix build .#dropr`).
`vm.sh browse` then switches the VM to the dev Keycloak realm and opens
Chromium on it, to use the installed Dropr by hand.

## Docker (Compose)

For other distributions, or hosts that already run Docker. [Before you
start](#1-before-you-start) applies here too. On Debian 13 you can still run
`harden-host.sh` with `--skip firewall`: Docker manages its own nftables rules,
which the generated ruleset would flush; filter as in
[the firewall note](#docker-and-the-host-firewall).

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

## After every deploy

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
