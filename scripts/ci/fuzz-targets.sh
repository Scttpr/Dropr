#!/usr/bin/env bash
# Print every native Go fuzz target as a JSON array of {"pkg","target"}
# objects, for a GitHub Actions matrix (nightly.yml).
set -euo pipefail
cd "$(dirname "$0")/../.."

for pkg in $(go list ./...); do
  go test -list '^Fuzz' "$pkg" | { grep '^Fuzz' || true; } | while read -r target; do
    jq -nc --arg pkg "$pkg" --arg target "$target" '{pkg: $pkg, target: $target}'
  done
done | jq -sc .
