#!/usr/bin/env bash
# Recompute the fixed-output hashes in nix/hashes.nix (Go vendor hash and npm
# dependency hash). Run after changing go.mod/go.sum or web/package-lock.json:
#
#   scripts/update-hashes.sh        (or: make hashes)
#
# It builds each fixed-output derivation with a fake hash and copies the hash
# Nix reports. Files must be visible to the flake: new files need `git add`
# (or `git add -N`) first.
set -euo pipefail
cd "$(dirname "$0")/.."

file=nix/hashes.nix
fake="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

set_hash() { # key value
  sed -i -E "s|^(  $1 = \")[^\"]*(\";)|\1$2\2|" "$file"
}

update() { # key attr
  local key=$1 attr=$2 out got
  set_hash "$key" "$fake"
  if out=$(nix build --no-link ".#$attr" 2>&1); then
    echo "$key: unchanged (fake hash accepted?)" >&2
    exit 1
  fi
  got=$(grep -oE 'got: +sha256-[A-Za-z0-9+/=]+' <<<"$out" | head -1 | awk '{print $2}')
  if [ -z "$got" ]; then
    echo "$out" >&2
    echo "could not determine the $key hash" >&2
    exit 1
  fi
  set_hash "$key" "$got"
  echo "$key = $got"
}

update npmDeps web-assets
update vendor dropr.goModules
echo "verifying..."
nix build --no-link .#web-assets .#dropr
echo "ok"
