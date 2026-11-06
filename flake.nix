{
  description = "Dropr — self-hosted, end-to-end encrypted file drop";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      lib = nixpkgs.lib;

      # Hashes of fixed-output inputs. Recompute with scripts/update-hashes.sh
      # (or `make hashes`) after changing go.mod/go.sum or web/package-lock.json.
      hashes = import ./nix/hashes.nix;

      version = self.shortRev or self.dirtyShortRev or "dev";

      # Only what each build needs, so editing docs/ or deploy/ never rebuilds.
      webFiles = lib.fileset.unions [
        ./web/package.json
        ./web/package-lock.json
        ./web/tsconfig.json
        ./web/tsconfig.sw.json
        ./web/src
        ./web/test
        ./web/scripts
      ];
      webSrc = lib.fileset.toSource { root = ./web; fileset = webFiles; };
      goSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.difference
          (lib.fileset.unions [ ./go.mod ./go.sum ./cmd ./internal ./deploy/dropr.example.toml ./deploy/dropr.dev.toml ])
          # Build output of the TypeScript build; it comes from web-assets.
          (lib.fileset.fileFilter
            (f: f.hasExt "js" || f.name == "manifest.json")
            ./internal/web/static);
      };

      mkPackages = pkgs:
        let
          web-assets = pkgs.buildNpmPackage {
            pname = "dropr-web-assets";
            inherit version;
            src = webSrc;
            npmDepsHash = hashes.npmDeps;
            # esbuild output is deterministic: hashed names, no sourcemaps.
            buildPhase = ''
              runHook preBuild
              npm run build -- --outdir "$out"
              runHook postBuild
            '';
            installPhase = "true";
            dontNpmInstall = true;
            dontFixup = true;
          };

          dropr = pkgs.buildGoModule {
            pname = "dropr";
            inherit version;
            src = goSrc;
            vendorHash = hashes.vendor;
            subPackages = [ "cmd/dropr" ];
            env.CGO_ENABLED = "0";
            flags = [ "-trimpath" ];
            ldflags = [ "-s" "-w" "-X main.version=${version}" ];
            # Embed the browser assets (go:embed in internal/web).
            preBuild = ''
              cp -r ${web-assets}/. internal/web/static/
            '';
            # Tests run in checks.<system>.go-test, not on every build.
            doCheck = false;
            meta = {
              description = "Self-hosted, end-to-end encrypted file drop";
              homepage = "https://github.com/scttpr/dropr";
              license = lib.licenses.mit;
              mainProgram = "dropr";
            };
          };

          image = pkgs.dockerTools.buildLayeredImage {
            name = "dropr";
            tag = "latest";
            created = "1970-01-01T00:00:01Z";
            contents = [ dropr pkgs.cacert pkgs.tzdata ];
            # /data must be writable by the unprivileged user.
            fakeRootCommands = ''
              mkdir -p data tmp etc/dropr
              chown 65532:65532 data
              chmod 0700 data
              chmod 1777 tmp
            '';
            config = {
              Entrypoint = [ "/bin/dropr" "serve" "--config" "/etc/dropr/dropr.toml" ];
              User = "65532:65532";
              WorkingDir = "/data";
              ExposedPorts = { "8443/tcp" = { }; };
              # The image has no shell: the binary probes its own /healthz.
              # Durations are nanoseconds (Docker image config).
              Healthcheck = {
                Test = [ "CMD" "/bin/dropr" "healthcheck" "--config" "/etc/dropr/dropr.toml" ];
                Interval = 30000000000;
                Timeout = 5000000000;
                StartPeriod = 20000000000;
                Retries = 3;
              };
              Volumes = { "/data" = { }; };
              Env = [
                "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
                "ZONEINFO=/share/zoneinfo"
              ];
              Labels = {
                "org.opencontainers.image.title" = "dropr";
                "org.opencontainers.image.description" = "Self-hosted, end-to-end encrypted file drop";
                "org.opencontainers.image.source" = "https://github.com/scttpr/dropr";
                "org.opencontainers.image.licenses" = "MIT";
                "org.opencontainers.image.version" = version;
              };
            };
          };
        in
        { inherit web-assets dropr image; default = dropr; };

      mkChecks = pkgs:
        let
          p = mkPackages pkgs;
          webCheck = p.web-assets.overrideAttrs (old: {
            pname = "dropr-web-check";
            # test/i18n.test.ts reads the server's messages and error codes
            # from ../internal, so the tests need those files next to web/.
            # npmDeps keeps coming from webSrc (same package-lock.json).
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                webFiles
                ./internal/i18n/fr.go
                ./internal/server/api.go
                ./internal/httpx/problem.go
                ./internal/httpx/streams.go
              ];
            };
            sourceRoot = "source/web";
            buildPhase = ''
              runHook preBuild
              npm run typecheck
              npm test
              runHook postBuild
            '';
            installPhase = "touch $out";
          });
          goCheck = p.dropr.overrideAttrs (old: {
            pname = "dropr-go-check";
            doCheck = true;
            subPackages = [ "cmd/..." "internal/..." ];
            # The Keycloak integration tests are behind the `keycloak` build tag.
            preCheck = ''
              go vet ./...
            '';
            installPhase = "touch $out";
          });
        in
        {
          inherit (p) dropr web-assets;
          go-test = goCheck;
          web = webCheck;
          image = p.image;
          nixos-vm = import ./nix/vm-test.nix { inherit pkgs self; };
        };
    in
    {
      packages = forAll mkPackages;
      checks = forAll mkChecks;

      nixosModules.default = import ./nix/module.nix { inherit self; };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
            golangci-lint
            govulncheck
            delve
            nodejs_24
            esbuild
            typescript
            sqlite
            openssl
            jq
            gnumake
            curl
            podman-compose
            playwright-driver
            skopeo
            cosign
            syft
          ];
          env = {
            CGO_ENABLED = "0";
            # Playwright on NixOS: use the browsers packaged by nixpkgs. The npm
            # @playwright/test version MUST equal pkgs.playwright-driver.version.
            PLAYWRIGHT_BROWSERS_PATH = "${pkgs.playwright-driver.browsers}";
            PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS = "true";
            PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1";
            PLAYWRIGHT_VERSION = pkgs.playwright-driver.version;
          };
        };
      });
    };
}
