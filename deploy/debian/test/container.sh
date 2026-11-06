#!/usr/bin/env bash
# Run smoke.sh in a Debian container with systemd as PID 1. Covers the
# installer's file work (user, permissions, config, units, nginx) only:
# systemd 257 under Podman does not create LoadCredential directories, even
# for a bare root unit, so dropr cannot start and the runtime checks fail.
# The service itself is tested by vm.sh.
#
#   nix build .#dropr                          # or BIN=path/to/static/dropr
#   sudo deploy/debian/test/container.sh up    # build, start, run smoke.sh
#   sudo deploy/debian/test/container.sh smoke # again: an upgrade run
#   sudo deploy/debian/test/container.sh shell
#   sudo deploy/debian/test/container.sh down
#
# Environment: RELEASE (trixie, bookworm), BIN, PODMAN (podman or docker).
# Rootful is recommended; rootless podman may refuse the unit's namespaces.
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$DIR/../../.." && pwd)
RELEASE=${RELEASE:-trixie}
BIN=${BIN:-$ROOT/result/bin/dropr}
PODMAN=${PODMAN:-podman}
NAME=dropr-smoke-$RELEASE
IMAGE=localhost/dropr-smoke:$RELEASE

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# sudo may keep the caller's XDG_RUNTIME_DIR; rootful podman would then leave
# root-owned state in /run/user/<uid> that breaks the user's rootless podman.
[ "$(id -u)" -ne 0 ] || unset XDG_RUNTIME_DIR

smoke() {
  [ -f "$BIN" ] || die "no binary at $BIN (nix build .#dropr, or set BIN)"
  # Copied on every run so a rebuilt binary is picked up (result/ is a symlink).
  $PODMAN cp "$(realpath "$BIN")" "$NAME:/root/dropr"
  $PODMAN exec -t "$NAME" /src/deploy/debian/test/smoke.sh /root/dropr
}

case "${1:-}" in
  up)
    $PODMAN build --build-arg "RELEASE=$RELEASE" -t "$IMAGE" -f "$DIR/Containerfile" "$DIR"
    $PODMAN rm -f "$NAME" >/dev/null 2>&1 || true
    run_args=(-d --name "$NAME" --hostname dropr-smoke --privileged
              --add-host drop.dropr.test:127.0.0.1 --add-host idp.dropr.test:127.0.0.1
              -v "$ROOT/deploy/debian:/src/deploy/debian:ro")
    case "$PODMAN" in *podman*) run_args+=(--systemd=always) ;; *) run_args+=(--cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw) ;; esac
    $PODMAN run "${run_args[@]}" "$IMAGE" >/dev/null
    echo "Waiting for systemd in $NAME ..."
    $PODMAN exec "$NAME" systemctl is-system-running --wait >/dev/null 2>&1 || true
    smoke
    ;;
  smoke) smoke ;;
  shell) exec $PODMAN exec -it "$NAME" bash ;;
  down)  $PODMAN rm -f "$NAME" ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
