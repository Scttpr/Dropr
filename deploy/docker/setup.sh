#!/usr/bin/env bash
# Set up or upgrade a Compose deployment of Dropr on a Debian or Ubuntu
# server with Docker Engine and the Compose plugin. Run as root from a
# checkout of the release tag:
#
#   sudo deploy/docker/setup.sh                                   # lay out /opt/dropr
#   sudo deploy/docker/setup.sh --image ghcr.io/scttpr/dropr@sha256:<digest>
#
# First run: creates the deployment directory (compose.yaml, .env, dropr.toml,
# secrets/, data/, backups/), generates the secrets and installs the daily
# backup timer, then stops until dropr.toml and DROPR_IMAGE are filled in.
#
# With --image on a running deployment: backs up the database, switches .env
# to the new image, recreates the container and waits until it is healthy.
# Existing config and secrets are never overwritten. Guide: docs/deploy-debian.md.
set -euo pipefail

DIR=/opt/dropr
IMAGE=""
gen_oidc_key=true
UID_DROPR=65532
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options:
  --dir DIR         deployment directory (default /opt/dropr)
  --image REF       image to deploy, pinned by digest (repo@sha256:...) or a
                    local tag you built
  --no-oidc-key     do not generate the OIDC client key and certificate
EOF
}

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=${2:?--dir needs a path}; shift 2 ;;
    --image) IMAGE=${2:?--image needs a reference}; shift 2 ;;
    --no-oidc-key) gen_oidc_key=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 ...)"
case "$DIR" in /*) ;; *) die "--dir must be an absolute path" ;; esac
command -v docker >/dev/null || die "Docker Engine is required (https://docs.docker.com/engine/install/debian/)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is required (apt install docker-compose-plugin)"
for f in compose.yaml env.example dropr-backup.service dropr-backup.timer ../dropr.example.toml; do
  [ -f "$SRC_DIR/$f" ] || die "missing $SRC_DIR/$f (run from a Dropr checkout)"
done
case "$IMAGE" in
  ""|*@sha256:*) ;;
  */*) warn "$IMAGE is not pinned by digest; a registry tag can be moved under you" ;;
esac

compose() { docker compose --project-directory "$DIR" "$@"; }

# With userns-remap the container's UID 65532 is a subordinate UID on the host.
if docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q 'name=userns'; then
  sub_start=$(awk -F: '$1 == "dockremap" { print $2; exit }' /etc/subuid)
  [ -n "$sub_start" ] || die "userns-remap is on but /etc/subuid has no dockremap range; set the owner of data/, backups/ and secrets/* yourself"
  UID_DROPR=$((sub_start + 65532))
  log "userns-remap detected: container UID 65532 is host UID $UID_DROPR"
fi

# --- Layout -----------------------------------------------------------------------
install -d -o root -g root -m 0750 "$DIR"
install -d -o root -g root -m 0700 "$DIR/secrets"
install -d -o "$UID_DROPR" -g "$UID_DROPR" -m 0700 "$DIR/data" "$DIR/backups"
install -m 0644 "$SRC_DIR/compose.yaml" "$DIR/compose.yaml"
[ -e "$DIR/.env" ] || install -m 0600 "$SRC_DIR/env.example" "$DIR/.env"
if [ ! -e "$DIR/dropr.toml" ]; then
  log "Installing the config template as $DIR/dropr.toml"
  # compose.yaml publishes port 80 for the HTTPS redirect.
  sed 's/^redirect_http = false/redirect_http = true /' "$SRC_DIR/../dropr.example.toml" > "$DIR/dropr.toml"
  chmod 0644 "$DIR/dropr.toml"
fi

# --- Secrets ------------------------------------------------------------------------
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
if [ ! -s "$DIR/secrets/refresh_key" ]; then
  log "Generating secrets/refresh_key"
  (umask 077; head -c 32 /dev/urandom | base64 > "$DIR/secrets/refresh_key")
fi
if [ ! -s "$DIR/secrets/oidc_key.pem" ] && $gen_oidc_key; then
  if command -v openssl >/dev/null; then
    log "Generating the OIDC client key and a 2-year self-signed certificate"
    (umask 077
     openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 -subj "/CN=dropr" \
       -keyout "$workdir/key.pem" -out "$workdir/cert.pem" 2>/dev/null
     cat "$workdir/key.pem" "$workdir/cert.pem" > "$DIR/secrets/oidc_key.pem")
    install -m 0644 "$workdir/cert.pem" "$DIR/oidc_cert.pem"
    oidc_cert_new=true
  else
    warn "openssl not found: create $DIR/secrets/oidc_key.pem yourself (docs/setup-entra.md)"
  fi
fi
# Bind-mounted secrets keep host ownership: readable by the container user
# only, inside a directory only root can enter.
for s in "$DIR"/secrets/*; do
  [ -e "$s" ] || continue
  chown "$UID_DROPR:$UID_DROPR" "$s"
  chmod 0400 "$s"
done

# --- Backup timer -------------------------------------------------------------------
sed "s#@DIR@#$DIR#g" "$SRC_DIR/dropr-backup.service" > /etc/systemd/system/dropr-backup.service
install -m 0644 "$SRC_DIR/dropr-backup.timer" /etc/systemd/system/dropr-backup.timer
chmod 0644 /etc/systemd/system/dropr-backup.service
systemctl daemon-reload
systemctl enable --quiet --now dropr-backup.timer

# --- Host checks (advice only; nothing is changed) ----------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  warn "ufw is active, but Docker-published ports bypass ufw rules: 443 and 80 will be reachable regardless"
fi
if ! docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q 'name=seccomp'; then
  warn "Docker reports no seccomp support; the container runs without a system-call filter"
fi

# --- Image and start -------------------------------------------------------------------
set_env() { # KEY VALUE: replace or append in .env
  if grep -q "^$1=" "$DIR/.env"; then
    sed -i "s#^$1=.*#$1=$2#" "$DIR/.env"
  else
    printf '%s=%s\n' "$1" "$2" >> "$DIR/.env"
  fi
}

running=false
[ -n "$(compose ps --status running --quiet dropr 2>/dev/null)" ] && running=true

if [ -n "$IMAGE" ]; then
  case "$IMAGE" in *[[:space:]#]*) die "invalid image reference" ;; esac
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "Pulling $IMAGE"
    docker pull --quiet "$IMAGE" >/dev/null
  fi
  if $running; then
    log "Backing up the database before the upgrade (migrations are not reversible)"
    systemctl start dropr-backup.service || die "pre-upgrade backup failed; nothing changed (journalctl -u dropr-backup)"
    previous=$(sed -n 's/^DROPR_IMAGE=//p' "$DIR/.env")
  fi
  set_env DROPR_IMAGE "$IMAGE"
fi

ready=true
grep -q '^DROPR_IMAGE=.' "$DIR/.env" || ready=false
grep -Eq '<tenant-id>|<application-id>|drop\.example\.com|admin@example\.com' "$DIR/dropr.toml" && ready=false
[ -s "$DIR/secrets/oidc_key.pem" ] || ready=false

if ! $ready; then
  log "Deployment directory ready: $DIR. Before starting:"
  cat <<EOF
  1. Register Dropr at your identity provider (docs/setup-entra.md or
     docs/setup-keycloak.md).$( [ "${oidc_cert_new:-false}" = true ] && printf '\n     Upload the public certificate %s/oidc_cert.pem as the client credential.' "$DIR")
  2. Edit $DIR/dropr.toml: public_url, acme_email and every <...> value.
  3. Set DROPR_IMAGE in $DIR/.env to a verified digest (SECURITY.md), or
     rerun with --image REF.
  4. Point DNS at this host, allow TCP 443 and 80, set a CAA record:
     0 issue "letsencrypt.org".
  5. sudo $0 --dir $DIR        # starts it; or: cd $DIR && docker compose up -d
EOF
  exit 0
fi

log "Starting dropr ($(sed -n 's/^DROPR_IMAGE=//p' "$DIR/.env"))"
compose up -d --wait --wait-timeout 120 dropr && {
  log "Healthy. Logs: cd $DIR && docker compose logs -f"
  exit 0
}
warn "dropr did not become healthy; check: cd $DIR && docker compose logs --tail 100"
if [ -n "${previous:-}" ]; then
  warn "roll back with: sudo $0 --dir $DIR --image $previous (restore the pre-upgrade backup from $DIR/backups if the schema changed)"
fi
exit 1
