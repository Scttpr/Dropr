#!/usr/bin/env bash
# Build the release files into dist/, inside the ci dev shell:
#
#   nix develop .#ci -c scripts/ci/release-build.sh v1.2.3
#
# dist/ then holds the static binaries, their CycloneDX SBOMs, the web asset
# hashes and both checksum lists. Every artifact is built twice from clean
# caches and the two builds must be bit-identical.
set -euo pipefail
cd "$(dirname "$0")/../.."

version=$1
dist=dist
rm -rf "$dist" && mkdir -p "$dist"

# Web assets: hermetic Nix build, rebuilt once to prove determinism.
nix build -o web-assets .#web-assets
nix build --rebuild .#web-assets
{ (cd web-assets && sha256sum -- *); (cd internal/web/static && sha256sum app.css favicon.svg); } |
  sort -k2 > "$dist/dropr-assets-$version.sha256"

# The binaries embed exactly the web assets hashed above.
cp -r web-assets/. internal/web/static/

build() { # arch output
  env CGO_ENABLED=0 GOOS=linux GOARCH="$1" GOFLAGS=-mod=readonly \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$2" ./cmd/dropr
}

for arch in amd64 arm64; do
  bin="$dist/dropr-$version-linux-$arch"
  build "$arch" "$bin"
  GOCACHE=$(mktemp -d) build "$arch" "$bin.rebuild"
  cmp "$bin" "$bin.rebuild"
  rm "$bin.rebuild"

  GOOS=linux GOARCH=$arch cyclonedx-gomod app -json -licenses -packages -files=false \
    -output "$bin.cdx.json" -main cmd/dropr .
done

(cd "$dist" && sha256sum "dropr-$version-linux-amd64" "dropr-$version-linux-arm64") \
  > "$dist/dropr-$version-SHA256SUMS"
cat "$dist/dropr-$version-SHA256SUMS" "$dist/dropr-assets-$version.sha256"
