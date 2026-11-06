# NixOS module for Dropr. Import via `nixosModules.default` of the flake.
#
#   services.dropr = {
#     enable = true;
#     settings = {
#       public_url = "https://drop.example.com";
#       acme_email = "admin@example.com";
#       oidc = { issuer = "..."; client_id = "..."; required_role = "Dropr.User"; };
#     };
#     refreshKeyFile = "/var/lib/secrets/dropr/refresh_key";
#     oidcKeyFile    = "/var/lib/secrets/dropr/oidc_key.pem";
#   };
#
# Secrets are never copied to the Nix store: the files are passed to the
# service with systemd LoadCredential and appear read-only under
# /run/credentials/dropr.service/.
{ self }:
{ config, lib, pkgs, ... }:
let
  inherit (lib) mkOption mkEnableOption mkIf types;
  cfg = config.services.dropr;
  tomlFormat = pkgs.formats.toml { };

  # Ports the service binds, to decide whether CAP_NET_BIND_SERVICE is needed.
  portOf = addr:
    let m = builtins.match ".*:([0-9]+)" addr;
    in if lib.hasPrefix "unix:" addr || m == null then null else lib.toInt (builtins.head m);
  listen = cfg.settings.listen or (if (cfg.settings.tls or "acme") == "proxy" then "127.0.0.1:8080" else ":8443");
  redirectListen = cfg.settings.redirect_listen or ":8080";
  boundPorts = lib.filter (p: p != null) (
    [ (portOf listen) ]
    ++ lib.optional (cfg.settings.redirect_http or false) (portOf redirectListen)
  );
  needsPrivPort = lib.any (p: p < 1024) boundPorts;

  # Credentials appear under /run/credentials/<unit>; the admin CLI runs in
  # a transient unit of another name, hence one config file per unit.
  mkConfig = unit:
  let
  credDir = "/run/credentials/${unit}.service";
  secretSettings =
    { refresh_key_file = "${credDir}/refresh_key"; }
    // lib.optionalAttrs (cfg.oidcKeyFile != null) {
      oidc.client_key_file = "${credDir}/oidc_key";
    }
    // lib.optionalAttrs (cfg.oidcClientSecretFile != null) {
      oidc.client_secret_file = "${credDir}/oidc_client_secret";
    };
  in tomlFormat.generate "${unit}.toml" (lib.recursiveUpdate
    ({ data_dir = "/var/lib/dropr"; } // cfg.settings)
    secretSettings);
  configFile = mkConfig "dropr";
  adminConfigFile = mkConfig "dropr-admin";

  credentials =
    [ "refresh_key:${cfg.refreshKeyFile}" ]
    ++ lib.optional (cfg.oidcKeyFile != null) "oidc_key:${cfg.oidcKeyFile}"
    ++ lib.optional (cfg.oidcClientSecretFile != null) "oidc_client_secret:${cfg.oidcClientSecretFile}";

  # Admin CLI: runs `dropr` as the same dynamic user, with the same state
  # directory and credentials, via a transient unit.
  adminCli = pkgs.writeShellScriptBin "dropr-admin" ''
    if [ -t 0 ]; then mode=--pty; else mode=--pipe; fi
    exec ${config.systemd.package}/bin/systemd-run --quiet "$mode" --wait --collect --unit=dropr-admin \
      --property=DynamicUser=yes --property=User=dropr \
      --property=StateDirectory=dropr --property=StateDirectoryMode=0700 \
      ${lib.concatMapStringsSep " " (c: "--property=LoadCredential=${c}") credentials} \
      ${cfg.package}/bin/dropr "$@" --config ${adminConfigFile}
  '';
in
{
  options.services.dropr = {
    enable = mkEnableOption "Dropr, a self-hosted end-to-end encrypted file drop";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.dropr;
      defaultText = lib.literalExpression "dropr.packages.\${system}.dropr";
      description = "The Dropr package.";
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          public_url = "https://drop.example.com";
          tls = "proxy";
          listen = "127.0.0.1:8080";
          trusted_proxies = [ "127.0.0.1" ];
          oidc = {
            issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0";
            client_id = "<application-id>";
            required_role = "Dropr.User";
          };
        }
      '';
      description = ''
        Contents of dropr.toml (see deploy/dropr.example.toml). Do not set
        `refresh_key_file`, `oidc.client_key_file` or `oidc.client_secret_file`
        here: use the dedicated options below, which load the secrets through
        systemd credentials. `data_dir` defaults to /var/lib/dropr.
      '';
    };

    refreshKeyFile = mkOption {
      type = types.path;
      description = "File with the refresh-token encryption key (`openssl rand -base64 32`). Not copied to the Nix store.";
    };

    oidcKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "PEM file with the private_key_jwt private key followed by its certificate. Not copied to the Nix store.";
    };

    oidcClientSecretFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "OIDC client secret file (dev mode only).";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open the TCP ports Dropr listens on (and the HTTP redirect port when enabled).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.settings ? refresh_key_file);
        message = "services.dropr.settings.refresh_key_file must not be set; use services.dropr.refreshKeyFile.";
      }
      {
        assertion = !((cfg.settings.oidc or { }) ? client_key_file) && !((cfg.settings.oidc or { }) ? client_secret_file);
        message = "Use services.dropr.oidcKeyFile / oidcClientSecretFile instead of oidc.client_key_file / client_secret_file.";
      }
    ];

    environment.systemPackages = [ cfg.package adminCli ];
    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall boundPorts;

    systemd.services.dropr = {
      description = "Dropr end-to-end encrypted file drop";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/dropr serve --config ${configFile}";
        Restart = "on-failure";
        RestartSec = "5s";
        TimeoutStopSec = "30s";
        LimitNOFILE = 65536;

        DynamicUser = true;
        User = "dropr";
        StateDirectory = "dropr";
        StateDirectoryMode = "0700";
        LoadCredential = credentials;
        UMask = "0077";

        # Sandbox
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        NoNewPrivileges = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        RemoveIPC = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        CapabilityBoundingSet = if needsPrivPort then [ "CAP_NET_BIND_SERVICE" ] else [ "" ];
        AmbientCapabilities = if needsPrivPort then [ "CAP_NET_BIND_SERVICE" ] else [ "" ];
      };
    };
  };
}
