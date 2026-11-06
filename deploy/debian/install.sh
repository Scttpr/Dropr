#!/usr/bin/env bash
# Install or upgrade Dropr on a Debian 13 server as a hardened systemd
# service. Run as root from a checkout of the release tag (after
# deploy/debian/harden-host.sh on a fresh host):
#
#   sudo deploy/debian/install.sh --binary ./dropr          # a binary you built or downloaded
#   sudo deploy/debian/install.sh --version v0.1.0          # download + verify the release binary
#
# First run: creates the dropr system user, /etc/dropr (config, credentials
# encrypted with systemd-creds and sealed to the TPM2 when there is one), the
# units, the AppArmor profile, the admin wrapper and the daily backup timer, then
# stops so you can edit /etc/dropr/dropr.toml. Run it again (or
# `systemctl enable --now dropr`) once the config is filled in.
#
# Later runs upgrade: back up the database, swap the binary atomically,
# refresh the units, restart and check health. Existing config and secrets are
# never overwritten. Full guide: docs/deploy-debian.md.
set -euo pipefail

REPO="${DROPR_REPO:-Scttpr/Dropr}"
PREFIX=/usr/local
CONF_DIR=/etc/dropr
CRED_DIR=$CONF_DIR/credentials
STATE_DIR=/var/lib/dropr
BACKUP_DIR=/var/backups/dropr
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

binary=""
version=""
skip_signature=false
gen_oidc_key=true
start=true
unsupported_os=false

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options:
  --binary FILE        install this dropr binary (static linux build)
  --version vX.Y.Z     download the release binary from GitHub and verify it
                       (SHA-256 and keyless cosign signature)
  --skip-signature     with --version: accept a binary without cosign
                       verification (integrity only; not recommended)
  --no-oidc-key        do not generate the OIDC client key and certificate
  --no-start           install files only; do not start or restart the service
  --unsupported-os     continue on a system other than Debian 13 (systemd >= 257
                       is still required: older versions ignore part of the sandbox)
EOF
}

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) binary=${2:?--binary needs a file}; shift 2 ;;
    --version) version=${2:?--version needs a tag}; shift 2 ;;
    --skip-signature) skip_signature=true; shift ;;
    --no-oidc-key) gen_oidc_key=false; shift ;;
    --no-start) start=false; shift ;;
    --unsupported-os) unsupported_os=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# --- Preflight -----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 ...)"
[ -n "$binary" ] || [ -n "$version" ] || { usage >&2; die "give --binary FILE or --version vX.Y.Z"; }
[ -z "$binary" ] || [ -z "$version" ] || die "--binary and --version are exclusive"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required"

# shellcheck source=/dev/null
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID%%.*}" -lt 13 ] 2>/dev/null; then
  $unsupported_os || die "this kit targets Debian 13 (found ${PRETTY_NAME:-unknown}); use deploy/docker elsewhere, or pass --unsupported-os"
  warn "unsupported system '${PRETTY_NAME:-unknown}'; continuing"
fi

# Older systemd ignores directives it does not know, which would silently
# weaken the sandbox (PrivateTmp=disconnected, ProtectControlGroups=strict...).
sd_version=$(systemctl --version | awk 'NR==1 {print $2}')
[ "${sd_version%%.*}" -ge 257 ] 2>/dev/null \
  || die "systemd >= 257 is required (found ${sd_version})"
command -v systemd-creds >/dev/null || die "systemd-creds is required"

units="dropr.service dropr-backup.service dropr-backup.timer dropr-offsite.service
       dropr-check.service dropr-check.timer dropr-alert@.service"
libs="run-with-credentials offsite check alert"
sbins="dropr-admin dropr-credential dropr-offsite"
# shellcheck disable=SC2086 # word lists
for f in $units $libs $sbins journald@dropr.conf dropr.toml apparmor/usr.local.bin.dropr; do
  [ -f "$SRC_DIR/$f" ] || die "missing $SRC_DIR/$f (run from a Dropr checkout)"
done

# On tmpfs and root-only: secrets pass through here before they are sealed.
workdir=$(mktemp -d -p /run dropr-install.XXXXXX)
trap 'rm -rf "$workdir"' EXIT

# --- Obtain and check the binary ----------------------------------------------
if [ -n "$version" ]; then
  command -v curl >/dev/null || die "curl is required for --version (apt install curl)"
  case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
    amd64|x86_64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) die "no release binary for this architecture; build one and use --binary" ;;
  esac
  base="https://github.com/${REPO}/releases/download/${version}"
  asset="dropr-${version}-linux-${arch}"
  sums="dropr-${version}-SHA256SUMS"
  log "Downloading ${asset} from ${base}"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$workdir/$asset" "$base/$asset"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$workdir/$sums" "$base/$sums"
  if command -v cosign >/dev/null; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$workdir/$sums.sigstore.json" "$base/$sums.sigstore.json"
    log "Verifying the signature of ${sums}"
    cosign verify-blob --bundle "$workdir/$sums.sigstore.json" \
      --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/ci\.yml@refs/tags/v" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$workdir/$sums" || die "signature verification failed"
  elif $skip_signature; then
    warn "cosign not installed: checking SHA-256 only, which proves integrity, not origin"
  else
    die "cosign is required to verify the release (https://docs.sigstore.dev/cosign/system_config/installation/), or pass --skip-signature"
  fi
  (cd "$workdir" && grep -E "  ${asset}\$" "$sums" | sha256sum -c --strict -) \
    || die "SHA-256 mismatch for ${asset}"
  binary="$workdir/$asset"
fi

[ -f "$binary" ] || die "no such file: $binary"
install -m 0755 "$binary" "$workdir/dropr"
# Read the whole output: `| head -n1` under pipefail fails on SIGPIPE.
new_version=$("$workdir/dropr" version 2>/dev/null) \
  || die "$binary does not run on this host (wrong architecture or not a dropr binary)"
new_version=${new_version%%$'\n'*}
log "Installing ${new_version}"

# --- User and directories -----------------------------------------------------
if ! getent passwd dropr >/dev/null; then
  log "Creating system user dropr"
  useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home \
    --shell /usr/sbin/nologin --comment "Dropr file drop" dropr
fi
install -d -o root  -g dropr -m 0750 "$CONF_DIR"
install -d -o root  -g root  -m 0700 "$CRED_DIR"
install -d -o dropr -g dropr -m 0700 "$STATE_DIR"
install -d -o dropr -g dropr -m 0700 "$BACKUP_DIR"
install -d -o root  -g root  -m 0755 "$PREFIX/lib/dropr"

# --- Secrets ----------------------------------------------------------------------
# Encrypted with systemd-creds: --with-key=auto seals to the host key and the
# TPM2 when the machine has one, so a copy of the disk cannot decrypt them.
# Losing them is recoverable: a new refresh key only signs everyone out, a new
# OIDC key needs its certificate uploaded to the IdP (operations.md "Key rotation").
seal() { # seal NAME SOURCE: encrypt SOURCE as credential NAME
  systemd-creds encrypt --with-key=auto --name="$1" "$2" "$CRED_DIR/$1.cred.new"
  chmod 0600 "$CRED_DIR/$1.cred.new"
  mv -f "$CRED_DIR/$1.cred.new" "$CRED_DIR/$1.cred"
}
if systemd-creds has-tpm2 >/dev/null 2>&1; then sealing="host key + TPM2"; else
  sealing="host key only (no TPM2: a full disk copy can decrypt them)"
fi
# Plaintext files from an older install: seal them, then remove them.
for pair in refresh_key:refresh_key oidc_key:oidc_key.pem; do
  name=${pair%%:*} plain=$CRED_DIR/${pair#*:}
  if [ -s "$plain" ] && [ ! -s "$CRED_DIR/$name.cred" ]; then
    log "Sealing $plain as $name.cred ($sealing)"
    seal "$name" "$plain"
    shred -u "$plain"
  fi
done
if [ ! -s "$CRED_DIR/refresh_key.cred" ]; then
  log "Generating the refresh key ($sealing)"
  head -c 32 /dev/urandom | base64 > "$workdir/refresh_key"
  seal refresh_key "$workdir/refresh_key"
fi
if [ ! -s "$CRED_DIR/oidc_key.cred" ] && $gen_oidc_key; then
  command -v openssl >/dev/null || die "openssl is required to generate the OIDC client key (apt install openssl), or pass --no-oidc-key"
  log "Generating the OIDC client key and a 2-year self-signed certificate"
  (umask 077
   openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 -subj "/CN=dropr" \
     -keyout "$workdir/key.pem" -out "$workdir/cert.pem" 2>/dev/null
   cat "$workdir/key.pem" "$workdir/cert.pem" > "$workdir/oidc_key.pem")
  seal oidc_key "$workdir/oidc_key.pem"
  install -m 0644 "$workdir/cert.pem" "$CONF_DIR/oidc_cert.pem"
  oidc_cert_new=true
fi
if [ ! -s "$CRED_DIR/alert_env.cred" ]; then
  cat > "$workdir/alert_env" <<'EOF'
# Dropr alert settings: sudo dropr-credential edit alert_env
# Test: sudo systemctl start dropr-alert@test.service
#ALERT_WEBHOOK=https://ntfy.sh/<a-long-random-topic>
#ALERT_WEBHOOK_FORMAT=text          # or json for Slack/Mattermost ({"text": ...})
#ALERT_EMAIL=ops@example.com        # needs a sendmail, e.g. apt install msmtp-mta
#ALERT_REPEAT_HOURS=6
EOF
  seal alert_env "$workdir/alert_env"
fi
chown root:root "$CRED_DIR"/* 2>/dev/null || true
chmod 0600 "$CRED_DIR"/* 2>/dev/null || true

# --- Config ---------------------------------------------------------------------
if [ ! -e "$CONF_DIR/dropr.toml" ]; then
  log "Installing the config template as $CONF_DIR/dropr.toml"
  install -o root -g dropr -m 0640 "$SRC_DIR/dropr.toml" "$CONF_DIR/dropr.toml"
else
  chown root:dropr "$CONF_DIR/dropr.toml"
  chmod 0640 "$CONF_DIR/dropr.toml"
fi

# --- Units and helpers ----------------------------------------------------------
for f in $units; do install -m 0644 "$SRC_DIR/$f" "/etc/systemd/system/$f"; done
for f in $libs;  do install -m 0755 "$SRC_DIR/$f" "$PREFIX/lib/dropr/$f"; done
for f in $sbins; do install -m 0755 "$SRC_DIR/$f" "$PREFIX/sbin/$f"; done
install -m 0644 "$SRC_DIR/journald@dropr.conf" /etc/systemd/journald@dropr.conf
systemctl daemon-reload

# --- AppArmor (before any restart: profiles attach when the binary starts) ------
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ] && command -v apparmor_parser >/dev/null; then
  install -m 0644 "$SRC_DIR/apparmor/usr.local.bin.dropr" /etc/apparmor.d/usr.local.bin.dropr
  install -d /etc/apparmor.d/local
  [ -e /etc/apparmor.d/local/usr.local.bin.dropr ] || install -m 0644 /dev/null /etc/apparmor.d/local/usr.local.bin.dropr
  apparmor_parser -r -W /etc/apparmor.d/usr.local.bin.dropr || die "the AppArmor profile failed to load"
  log "AppArmor profile loaded in enforce mode"
else
  warn "AppArmor is not enabled: dropr runs confined by the systemd sandbox only"
fi

# --- Binary (upgrade: back up first) -----------------------------------------------
was_active=false
systemctl is-active --quiet dropr.service && was_active=true
if $was_active && [ -x "$PREFIX/bin/dropr" ]; then
  log "Backing up the database before the upgrade (migrations are not reversible)"
  systemctl start dropr-backup.service || die "pre-upgrade backup failed; nothing changed (journalctl -u dropr-backup)"
  cp -p "$PREFIX/bin/dropr" "$PREFIX/bin/dropr.previous"
fi
install -o root -g root -m 0755 "$workdir/dropr" "$PREFIX/bin/dropr.new"
mv -f "$PREFIX/bin/dropr.new" "$PREFIX/bin/dropr"

# After the binary is in place, or verify reports ExecStart as missing.
if command -v systemd-analyze >/dev/null; then
  # shellcheck disable=SC2086 # word list
  (cd /etc/systemd/system && systemd-analyze verify $units) \
    2>&1 | grep -v -e '_key' -e '_env' -e 'dropr-alert@.service' >&2 || true
fi

systemctl enable --quiet dropr-backup.timer
systemctl start dropr-backup.timer

# --- Start ----------------------------------------------------------------------------
ready=true
grep -Eq '<tenant-id>|<application-id>|drop\.example\.com|admin@example\.com' "$CONF_DIR/dropr.toml" && ready=false
[ -s "$CRED_DIR/oidc_key.cred" ] || ready=false

if ! $start; then
  log "Files installed (--no-start)"
elif ! $ready; then
  log "Installed. Before starting:"
  cat <<EOF
  1. Register Dropr at your identity provider (docs/setup-entra.md or
     docs/setup-keycloak.md).$( [ "${oidc_cert_new:-false}" = true ] && printf '\n     Upload the public certificate %s/oidc_cert.pem as the client credential.' "$CONF_DIR")$( [ -s "$CRED_DIR/oidc_key.cred" ] || printf '\n     Seal your client key (PEM): systemd-creds encrypt --with-key=auto \\\n       --name=oidc_key key.pem %s/oidc_key.cred' "$CRED_DIR")
  2. Edit $CONF_DIR/dropr.toml: public_url, acme_email and every <...> value.
  3. Point DNS at this host, set a CAA record: 0 issue "letsencrypt.org".
     harden-host.sh already opens TCP 80 and 443.
  4. sudo deploy/debian/install.sh again (or systemctl enable --now dropr),
     then: journalctl --namespace=dropr -f
EOF
  exit 0
else
  systemctl enable --quiet dropr.service dropr-check.timer
  systemctl start dropr-check.timer
  if $was_active; then
    log "Restarting dropr"
    systemctl restart dropr.service
  else
    log "Starting dropr"
    systemctl start dropr.service
  fi
  for _ in $(seq 1 30); do
    if "$PREFIX/sbin/dropr-admin" healthcheck >/dev/null 2>&1; then
      log "Healthy: $("$PREFIX/bin/dropr" version | sed -n 1p)"
      exit 0
    fi
    sleep 2
  done
  warn "dropr did not report healthy within 60 s; check: journalctl --namespace=dropr -e"
  if $was_active && [ -x "$PREFIX/bin/dropr.previous" ]; then
    warn "previous binary kept at $PREFIX/bin/dropr.previous; the pre-upgrade database backup is the newest file in $BACKUP_DIR"
  fi
  exit 1
fi
