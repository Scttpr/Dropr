# Security policy

## Reporting a vulnerability

Dropr is a volunteer open-source project without a dedicated security contact.
Please do not open a public issue for security problems; use GitHub private
vulnerability reporting on the repository ("Security" tab, "Report a
vulnerability") instead.

Include the version (`dropr version`), the configuration relevant to the issue
(without secrets), and reproduction steps. Reports are handled on a best-effort
basis, with no guaranteed response time. Please allow a reasonable time for a
fix before public disclosure.

In scope: the Dropr server, the browser modules, the container image and Nix
packaging, and the documentation where it would lead to an insecure setup.
Out of scope: the items listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
section 7 and the accepted residual risks in section 6 (unless you find a way
to make them worse than described).

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.
After 1.0: the latest minor release of the current major version.

## Verifying a release

Dropr's end-to-end encryption relies on the browser running genuine code, so
the browser bundle is built reproducibly and its hashes are published.

### What a release contains

* `dropr-assets-<version>.sha256`: `sha256sum` output for every file produced by
  `nix build .#web-assets` (hashed `*.js` files, `manifest.json`, `sw.js`), plus
  the two hand-written static files `app.css` and `favicon.svg` from
  `internal/web/static/`. Those two are not built by esbuild; the release job
  hashes them from the tagged source. Compare the stylesheet the page links to
  (its URL is in the page source; the server fingerprints it at startup) with
  the `app.css` entry.
* The container image `ghcr.io/scttpr/dropr@sha256:...` (registry name pending),
  its cosign signature (keyless, GitHub OIDC identity of the release workflow)
  and an SBOM (SPDX JSON).
* Static Linux binaries `dropr-<version>-linux-amd64` and `-arm64` (with the
  same embedded assets), `dropr-<version>-SHA256SUMS` and its keyless cosign
  bundle `dropr-<version>-SHA256SUMS.sigstore.json`.
  `deploy/debian/install.sh --version` verifies both; by hand:
  `cosign verify-blob --bundle dropr-<version>-SHA256SUMS.sigstore.json
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/ci\.yml@refs/tags/v'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
  dropr-<version>-SHA256SUMS && sha256sum -c --ignore-missing dropr-<version>-SHA256SUMS`.
* A signed git tag.

### Reproduce the hashes yourself

```sh
git clone https://github.com/scttpr/dropr && cd dropr
git verify-tag v0.1.0 && git checkout v0.1.0
nix build .#web-assets
{ (cd result && sha256sum *); (cd internal/web/static && sha256sum app.css favicon.svg); } | sort -k2 > mine.sha256
sort -k2 dropr-assets-v0.1.0.sha256 | diff - mine.sha256 && echo "assets match the release"
```

The build is deterministic: content-hashed file names, no source maps, fixed
timestamps, locked dependencies (`web/package-lock.json`, fixed-output hash in
`nix/hashes.nix`). `nix build --rebuild .#web-assets` checks that two builds
agree. The file names embed a content hash, so a mismatch is visible in the page
source already.

### Check what a running instance serves

The script tags in the page reference `/assets/<name>-<hash>.js` (with a
Subresource Integrity attribute), and the service worker is served at `/sw.js`.
For each line of the release hash file:

```sh
HOST=https://drop.example.com
while read -r sum file; do
  case "$file" in
    sw.js) url="$HOST/sw.js" ;;
    manifest.json) continue ;;                 # build metadata, not served to browsers
    *) url="$HOST/assets/$file" ;;
  esac
  got=$(curl -fsS "$url" | sha256sum | cut -d' ' -f1)
  [ "$got" = "$sum" ] && echo "ok   $file" || echo "DIFF $file"
done < <(sed 's/  */ /' dropr-assets-v0.1.0.sha256)
```

Any `DIFF`, or a page that references a script not in the release list, means
the instance does not serve the released code. Do not enter secrets or open
sensitive links there. Operators should run this check after every deploy and
may run it from a monitoring host on a schedule. A compromised server can
serve different bytes to different clients, so run the check from more than one
network position and from outside the server.

### Verify the container image

```sh
cosign verify ghcr.io/scttpr/dropr@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/ci\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Compose users pin the image by digest (`DROPR_IMAGE` in `.env`, see `deploy/docker/`). The Nix-built
image is reproducible: `nix build .#image` yields the same layers as the release
(the digest of the pushed image may differ in manifest packaging).

## Dependencies and supply chain

* Browser: zero runtime dependencies. Dev dependencies (esbuild, TypeScript)
  are pinned exactly in `web/package.json` and locked.
* Go: standard library plus a short, audited list (`go.mod`); `govulncheck` and
  `npm audit` run in CI.
* No third-party scripts, fonts, analytics or CDN assets are ever loaded.
