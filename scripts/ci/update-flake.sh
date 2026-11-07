#!/usr/bin/env bash
# Weekly toolchain bump (deps.yml): update flake.lock (nixpkgs: Go, Node,
# browsers, linters), keep e2e's @playwright/test equal to the new nixpkgs
# playwright-driver, and recompute the fixed-output hashes.
set -euo pipefail
cd "$(dirname "$0")/../.."

nix flake update

playwright=$(nix eval --raw --inputs-from . nixpkgs#playwright-driver.version)
(cd e2e && nix develop .#ci -c npm install --save-exact --no-audit --no-fund "@playwright/test@$playwright")

scripts/update-hashes.sh
