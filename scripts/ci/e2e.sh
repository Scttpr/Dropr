#!/usr/bin/env bash
# Run the Playwright suite on a CI runner, inside the default dev shell:
#
#   nix develop -c scripts/ci/e2e.sh chromium [firefox webkit]
#
# Expects Keycloak on :8180 (.github/actions/keycloak).
set -euo pipefail
cd "$(dirname "$0")/../.."

# nixpkgs' WebKit (WPE) loads EGL through libglvnd, which looks for vendor
# files under /run/opengl-driver. That path exists on NixOS only; elsewhere
# WebKit aborts with "Could not create EGL display" and every newPage fails.
# Point libglvnd at the flake-pinned mesa (software rendering, no GPU needed).
mesa=$(nix build --no-link --print-out-paths --inputs-from . nixpkgs#mesa)
export __EGL_VENDOR_LIBRARY_FILENAMES="$mesa/share/glvnd/egl_vendor.d/50_mesa.json"

if [ "$(node -p 'require("./e2e/package.json").devDependencies["@playwright/test"]')" != "$PLAYWRIGHT_VERSION" ]; then
  echo "e2e/package.json @playwright/test must equal nixpkgs playwright-driver $PLAYWRIGHT_VERSION" >&2
  exit 1
fi

projects=()
for p in "$@"; do projects+=("--project=$p"); done

cd e2e
npm ci --no-audit --no-fund
npx playwright test "${projects[@]}"
