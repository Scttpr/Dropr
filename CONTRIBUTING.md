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
make cover                    # race tests with a coverage profile (coverage.out)
make lint-ci                  # actionlint, zizmor and shellcheck on .github/ and scripts/
make test-keycloak            # Go integration tests with real logins (needs make keycloak-up)
make e2e                      # Playwright: Chromium, Firefox, WebKit (needs make keycloak-up)
make e2e E2E_PROJECTS=chromium
make fuzz FUZZTIME=20s        # every native fuzz target
cd web && npm ci && npm run typecheck && npm test
nix flake check               # reference builds, go vet and tests, web tests
```

Playwright browsers come from nixpkgs. Never run `npx playwright install`.

## Continuous integration

Workflows live in `.github/workflows/`; each file starts with a comment that
says when it runs and why. Long shell steps are scripts in `scripts/ci/`, so
they can be run and read outside a workflow.

| Workflow | Runs on | Does |
|---|---|---|
| `ci.yml` | PRs, main | lint, race tests, Nix builds, Keycloak integration, e2e, fuzz smoke (main) |
| `security.yml` | PRs, main, daily | CodeQL, dependency review (PRs), govulncheck, npm audit, OSV-Scanner |
| `scorecard.yml` | main, weekly | OpenSSF Scorecard |
| `nightly.yml` | daily | 5 minutes of fuzzing per target, corpus kept between nights |
| `release.yml` | `v*` tags | verify the tag, reproducible build, SBOMs, signatures, attestations, release |
| `deps.yml` | Dependabot PRs, weekly | `make hashes` on Dependabot PRs; weekly `flake.lock` bump PR |

* On a PR, `ci.yml` runs only the jobs whose inputs changed (a docs-only PR
  runs almost nothing) and e2e in Chromium only. Add the `e2e:all-browsers`
  label to also run Firefox and WebKit. Main runs everything.
* `main` requires the `ci-ok` and `security-ok` checks, which summarise their
  workflows, and linear history (PRs are rebased).
* A release needs a signed tag on a commit of `main` whose `ci-ok` and
  `security-ok` are green: tag after main's CI has passed.
* Failed scheduled runs open a `ci-failure` issue.
* Actions are pinned by commit SHA. Dependabot proposes updates after a 7-day
  cooldown; `make lint-ci` (zizmor) flags unpinned or risky workflow changes.

## Things to know

* **Contracts live in `docs/`.** [ARCHITECTURE.md](docs/ARCHITECTURE.md)
  (HTTP surface, data model, configuration), [FORMAT.md](docs/FORMAT.md)
  (byte formats, test vectors) and [PAGES.md](docs/PAGES.md) (page and browser
  module DOM contract) bind the Go server, the browser modules and the tests.
  A change to one side updates the contract and every other side in the same
  commit.
* **Dependency changes**: after changing `go.mod` or a `package-lock.json`, run
  `make hashes` to refresh `nix/hashes.nix`. On Dependabot PRs, `deps.yml`
  does it for you.
* **The flake only sees files known to git.** `git add` new files before
  `nix build` or `nix flake check`.
* **Translations**: user-facing text goes in both the Go catalog
  (`internal/i18n`) and the TypeScript catalogs (`web/src/lib/locales`). Tests
  fail on a missing translation.
* **No runtime JavaScript dependencies**, and Go stays standard library first.
* **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), one logical
  change each.
