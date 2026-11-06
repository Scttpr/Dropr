# Dropr developer tasks. Commands run inside the Nix dev shell: either call
# `make` from `nix develop` (make comes with the shell), or from a host make,
# in which case each command is wrapped in `nix develop -c`.
NIX      ?= $(if $(IN_NIX_SHELL),,nix develop -c)
GO       ?= $(NIX) go
NPM      ?= $(NIX) npm
COMPOSE  ?= $(NIX) podman-compose -f deploy/compose.dev.yaml
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
FUZZTIME ?= 20s

.PHONY: build build-go web web-deps test test-race lint vuln fuzz check dev keycloak-up keycloak-down \
	test-keycloak e2e e2e-deps soak hashes nix-build clean

# Browser bundles: content-hashed page modules, sw.js and manifest.json are
# written into internal/web/static (gitignored) and embedded by go:embed.
# The Go code builds and tests without them (pages then load no script).
web-deps: web/node_modules/.package-lock.json
web/node_modules/.package-lock.json: web/package-lock.json
	cd web && $(NPM) ci --no-audit --no-fund

web: web-deps
	cd web && $(NPM) run build

build: web build-go

build-go:
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/dropr ./cmd/dropr

test:
	$(GO) test ./...

# The race detector needs cgo; the dev shell provides a C toolchain.
test-race:
	$(NIX) env CGO_ENABLED=1 go test -race ./...

lint:
	$(NIX) golangci-lint run ./...

vuln:
	$(NIX) govulncheck ./...

# Runs every native fuzz target for $(FUZZTIME) each.
fuzz:
	@set -e; for pkg in $$($(GO) list ./... 2>/dev/null); do \
	  for f in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "== $$pkg $$f"; $(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg; \
	  done; \
	done

check: build lint test-race vuln

# Local server against the dev Keycloak (start it first: make keycloak-up).
dev: web-deps
	@mkdir -p .dev-data && chmod 700 .dev-data
	@test -f .dev-data/refresh_key || (umask 077 && $(NIX) openssl rand -base64 32 > .dev-data/refresh_key)
	cd web && $(NPM) run build -- --dev
	$(GO) run ./cmd/dropr serve --config deploy/dropr.dev.toml

keycloak-up:
	$(COMPOSE) up -d
	@echo "Waiting for Keycloak on http://localhost:8180 ..."
	@for i in $$(seq 1 90); do \
	  curl -fsS http://localhost:8180/realms/dropr/.well-known/openid-configuration >/dev/null 2>&1 && { echo ready; exit 0; }; \
	  sleep 2; done; echo "Keycloak did not become ready" >&2; exit 1

keycloak-down:
	$(COMPOSE) down

# Integration test performing real logins against the dev Keycloak.
test-keycloak:
	$(GO) test -tags keycloak -count=1 -run Keycloak -v ./internal/server/

# Real-browser smoke tests (Playwright, browsers from nixpkgs; never run
# `playwright install`). Needs the dev Keycloak (make keycloak-up).
# E2E_PROJECTS="chromium" limits the browsers.
e2e-deps: e2e/node_modules/.package-lock.json
e2e/node_modules/.package-lock.json: e2e/package-lock.json
	cd e2e && $(NPM) ci --no-audit --no-fund

e2e: build e2e-deps
	cd e2e && $(NIX) npx playwright test $(foreach p,$(E2E_PROJECTS),--project=$(p))

# Soak/perf (not part of e2e): streams SOAK_SIZE (default 2GiB; up to 100GiB)
# through the real HTTP API with the browser crypto modules and reports
# throughput and peak RSS. Needs Keycloak. SOAK_DIR defaults to ~/.cache/dropr-soak.
soak: build
	cd e2e && $(NIX) node --experimental-strip-types soak/soak.ts

# Recompute nix/hashes.nix (vendorHash, npmDepsHash) after dependency changes.
hashes:
	scripts/update-hashes.sh

# Reference builds: binary, web assets, OCI image.
nix-build:
	nix build .#dropr .#web-assets .#image

clean:
	rm -rf bin .dev-data
	cd internal/web/static && rm -f manifest.json ./*.js
