#!/usr/bin/env bash
# Test the Debian 13 deployment in a QEMU VM booted from the official cloud
# image: smoke.sh runs deploy/debian/install.sh end to end. Runs as your
# user; qemu and cloud-localds come from nixpkgs when they are missing.
#
#   nix build .#dropr                    # or BIN=path/to/static/dropr
#   test/debian/vm.sh up          # download, boot, run smoke.sh
#   test/debian/vm.sh smoke       # again: an upgrade run
#   test/debian/vm.sh browse      # dev Keycloak + Chromium: use Dropr
#   test/debian/vm.sh ssh
#   test/debian/vm.sh down        # power off, keep the disk
#   test/debian/vm.sh destroy     # power off, delete the disk
#
# browse runs a Keycloak container with the dev realm on 127.0.0.1:8181,
# switches the VM to it (browse.sh) and opens Chromium with a throwaway
# profile that resolves *.dropr.test to 127.0.0.1:8443 (forwarded to the
# VM) and pins the VM's two certificates; nothing is added to the system
# trust store or /etc/hosts. Users: alice / alice-dev-password.
#
# Environment: BIN, SSH_PORT (2222).
# State: ~/.cache/dropr-debian-test/ (base images are kept across destroy).
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
RELEASE=trixie
BIN=${BIN:-$ROOT/result/bin/dropr}
SSH_PORT=${SSH_PORT:-2222}
WEB_PORT=8443   # part of the public URL and issuer, so not configurable
KC_PORT=8181    # the dev Keycloak of `make keycloak-up` keeps 8180
KC_NAME=dropr-smoke-keycloak
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/dropr-debian-test
STATE=$CACHE/$RELEASE

log() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

num=13
image=debian-$num-genericcloud-amd64.qcow2
base_url=https://cloud.debian.org/images/cloud/$RELEASE/latest

if ! command -v qemu-system-x86_64 >/dev/null || ! command -v cloud-localds >/dev/null; then
  if [ -n "${DROPR_VM_NIX_SHELL:-}" ] || ! command -v nix >/dev/null; then
    die "needs qemu-system-x86_64, qemu-img and cloud-localds (cloud-utils)"
  fi
  DROPR_VM_NIX_SHELL=1 exec nix shell nixpkgs#qemu nixpkgs#cloud-utils --command "$0" "$@"
fi

ssh_opts=(-i "$STATE/id_ed25519" -p "$SSH_PORT" -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
# shellcheck disable=SC2029 # remote commands are meant to expand locally
vm() { ssh "${ssh_opts[@]}" debian@127.0.0.1 "$@"; }
running() { [ -s "$STATE/qemu.pid" ] && kill -0 "$(cat "$STATE/qemu.pid")" 2>/dev/null; }

create() {
  mkdir -p "$CACHE/images" "$STATE"
  if [ ! -s "$CACHE/images/$image" ]; then
    log "Downloading $image"
    curl -fL --proto '=https' -o "$CACHE/images/$image.part" "$base_url/$image"
    curl -fsSL --proto '=https' -o "$CACHE/images/SHA512SUMS-$RELEASE" "$base_url/SHA512SUMS"
    (cd "$CACHE/images" && grep -E "  $image\$" "SHA512SUMS-$RELEASE" | sed "s/$image\$/$image.part/" \
      | sha512sum -c --strict -) || die "SHA-512 mismatch for $image"
    mv "$CACHE/images/$image.part" "$CACHE/images/$image"
  fi
  log "Creating the VM disk and cloud-init seed"
  qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/images/$image" "$STATE/disk.qcow2" 10G
  ssh-keygen -q -t ed25519 -N '' -C dropr-smoke -f "$STATE/id_ed25519"
  cat > "$STATE/user-data" <<EOF
#cloud-config
hostname: dropr-smoke
manage_etc_hosts: true
ssh_authorized_keys:
  - $(cat "$STATE/id_ed25519.pub")
EOF
  printf 'instance-id: dropr-smoke-%s\nlocal-hostname: dropr-smoke\n' "$(date +%s)" > "$STATE/meta-data"
  cloud-localds "$STATE/seed.iso" "$STATE/user-data" "$STATE/meta-data"
}

boot() {
  local accel=()
  if [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); else log "no /dev/kvm: booting without acceleration (slow)"; fi
  log "Booting Debian $num (console log: $STATE/console.log)"
  qemu-system-x86_64 "${accel[@]}" -name dropr-smoke -m 2048 -smp 2 \
    -drive "file=$STATE/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$STATE/seed.iso,if=virtio,format=raw,readonly=on" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$WEB_PORT-:443" \
    -display none -serial "file:$STATE/console.log" \
    -daemonize -pidfile "$STATE/qemu.pid"
  log "Waiting for SSH on 127.0.0.1:$SSH_PORT"
  for _ in $(seq 1 90); do
    vm true 2>/dev/null && break
    running || die "qemu exited; see $STATE/console.log"
    sleep 2
  done
  vm true || die "no SSH after 3 minutes; see $STATE/console.log"
  vm cloud-init status --wait >/dev/null || true
}

push() {
  running || die "VM not running (vm.sh up)"
  log "Copying deploy/debian and test/debian into the VM"
  tar -C "$ROOT" -cf - deploy/debian test/debian | vm 'sudo rm -rf /src && sudo mkdir -p /src && sudo tar -C /src -xf -'
}

smoke() {
  [ -f "$BIN" ] || die "no binary at $BIN (nix build .#dropr, or set BIN)"
  push
  vm 'sudo tee /root/dropr >/dev/null && sudo chmod 0755 /root/dropr' < "$(realpath "$BIN")"
  ssh "${ssh_opts[@]}" -t debian@127.0.0.1 sudo /src/test/debian/smoke.sh /root/dropr
}

keycloak() {
  local image
  image=$(sed -n 's#^ *image: *\(quay\.io/keycloak/[^ ]*\)#\1#p' "$ROOT/deploy/compose.dev.yaml")
  [ -n "$image" ] || die "no Keycloak image in deploy/compose.dev.yaml"
  # The dev realm, plus the VM's callback, logout and front-channel URLs.
  sed -e 's#"https://localhost:8443/auth/callback"#&, "https://drop.dropr.test:8443/auth/callback"#' \
      -e 's#https://localhost:8443/login"#https://localhost:8443/login\#\#https://drop.dropr.test:8443/login"#' \
      -e 's#"http://localhost:8080/auth/frontchannel-logout"#"https://drop.dropr.test:8443/auth/frontchannel-logout"#' \
      "$ROOT/deploy/keycloak/dropr-realm.json" > "$STATE/realm.json"
  log "Starting Keycloak ($KC_NAME on 127.0.0.1:$KC_PORT, issuer https://kc.dropr.test:$WEB_PORT/realms/dropr)"
  podman rm -f "$KC_NAME" >/dev/null 2>&1 || true
  podman run -d --name "$KC_NAME" -p "127.0.0.1:$KC_PORT:$KC_PORT" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -v "$STATE/realm.json:/opt/keycloak/data/import/dropr-realm.json:ro,Z" \
    "$image" start-dev --import-realm --http-port="$KC_PORT" \
    --hostname="https://kc.dropr.test:$WEB_PORT" >/dev/null
  for _ in $(seq 1 90); do
    curl -fsS "http://127.0.0.1:$KC_PORT/realms/dropr/.well-known/openid-configuration" >/dev/null 2>&1 && return 0
    sleep 2
  done
  podman logs --tail 30 "$KC_NAME" >&2
  die "Keycloak did not become ready"
}

browse() {
  [ "$(id -u)" -ne 0 ] || die "run browse as your user, not root (it starts Chromium)"
  command -v chromium >/dev/null || die "chromium not found"
  running || die "VM not running (vm.sh up)"
  tr '\0' ' ' < "/proc/$(cat "$STATE/qemu.pid")/cmdline" | grep -q -- "-:443" \
    || die "this VM was booted without the web port forward; run vm.sh down, then vm.sh up"
  keycloak
  push
  vm 'sudo tee /root/dropr-pkjwt.pem >/dev/null' < "$ROOT/deploy/keycloak/test-keys/dropr-pkjwt.TEST-ONLY.pem"
  ssh "${ssh_opts[@]}" -t debian@127.0.0.1 sudo /src/test/debian/browse.sh /root/dropr-pkjwt.pem
  local spki
  # shellcheck disable=SC2016 # expands in the VM
  spki=$(vm 'for c in /etc/letsencrypt/live/drop.dropr.test/fullchain.pem /etc/nginx/dropr-smoke-kc/fullchain.pem; do
      sudo openssl x509 -in "$c" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    done' | paste -sd, -)
  log "Opening Chromium: https://drop.dropr.test:$WEB_PORT  (alice / alice-dev-password, bob / bob-dev-password)"
  nohup chromium --user-data-dir="$STATE/chromium" --no-first-run \
    --host-resolver-rules="MAP *.dropr.test 127.0.0.1" \
    --ignore-certificate-errors-spki-list="$spki" \
    "https://drop.dropr.test:$WEB_PORT/" >/dev/null 2>&1 &
}

down() {
  running || return 0
  log "Powering off"
  vm sudo systemctl poweroff 2>/dev/null || true
  for _ in $(seq 1 30); do running || return 0; sleep 1; done
  kill "$(cat "$STATE/qemu.pid")"
}

case "${1:-}" in
  up)
    if running; then log "VM already running"; else
      [ -s "$STATE/disk.qcow2" ] || create
      boot
    fi
    smoke
    ;;
  smoke)   smoke ;;
  browse)  browse ;;
  ssh)     shift; exec ssh "${ssh_opts[@]}" -t debian@127.0.0.1 "$@" ;;
  down)    podman rm -f "$KC_NAME" >/dev/null 2>&1 || true; down ;;
  destroy) podman rm -f "$KC_NAME" >/dev/null 2>&1 || true; down; rm -rf "$STATE"; log "Removed $STATE" ;;
  *) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
