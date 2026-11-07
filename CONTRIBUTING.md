# Contributing

Dropr does two things: share a file through a link, and receive files through a
request link. Changes that keep it small and correct are welcome. New features
outside those two flows are not (see [docs/DESIGN.md](docs/DESIGN.md) §1).

Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Development setup

You need Nix with flakes enabled and podman. Everything else comes from the dev
shell.

```sh
nix develop          # Go, Node, esbuild, golangci-lint, Playwright browsers, podman-compose
make keycloak-up     # dev Keycloak on :8180 with the seeded "dropr" realm (dev/keycloak)
make dev             # builds the browser modules, then Dropr on http://localhost:8080
```

Open <http://localhost:8080> and sign in as `alice` / `alice-dev-password` (or
`bob` / `bob-dev-password`). `mallory` / `mallory-dev-password` has no role and
is refused. These are public test values, defined in
[dev/compose.yaml](dev/compose.yaml). The Keycloak admin console is at
<http://localhost:8180> (`admin` / `admin`). `make keycloak-down` stops it.

[dev/dropr.toml](dev/dropr.toml) is the dev configuration. It uses a client
secret, which only dev mode allows; its last comment shows how to switch to
`private_key_jwt` with the test key in `dev/keycloak/test-keys/`.

From a host shell, `make` wraps each command in `nix develop -c`, so the
targets also work outside the dev shell.

## Tests

```sh
make check                    # build, golangci-lint, race tests, govulncheck
make test-keycloak            # Go integration tests with real logins (needs make keycloak-up)
make e2e                      # Playwright: Chromium, Firefox, WebKit (needs make keycloak-up)
make e2e E2E_PROJECTS=chromium
make fuzz FUZZTIME=20s        # every native fuzz target
cd web && npm ci && npm run typecheck && npm test
nix flake check               # reference builds, go vet and tests, web tests
```

Playwright browsers come from nixpkgs. Never run `npx playwright install`.

## Things to know

* **Contracts live in `docs/`.** [ARCHITECTURE.md](docs/ARCHITECTURE.md)
  (HTTP surface, data model, configuration), [FORMAT.md](docs/FORMAT.md)
  (byte formats, test vectors) and [PAGES.md](docs/PAGES.md) (page and browser
  module DOM contract) bind the Go server, the browser modules and the tests.
  A change to one side updates the contract and every other side in the same
  commit.
* **Dependency changes**: after changing `go.mod` or a `package-lock.json`, run
  `make hashes` to refresh `nix/hashes.nix`.
* **The flake only sees files known to git.** `git add` new files before
  `nix build` or `nix flake check`.
* **Translations**: user-facing text goes in both the Go catalog
  (`internal/i18n`) and the TypeScript catalogs (`web/src/lib/locales`). Tests
  fail on a missing translation.
* **No runtime JavaScript dependencies**, and Go stays standard library first.
* **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), one logical
  change each.
