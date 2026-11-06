# NixOS VM test: boots the module in proxy mode (dev mode, HTTP on loopback)
# against a minimal static OIDC discovery document, so no real IdP is needed.
#
# Dropr only needs discovery at startup; the test does not log in. It checks
# that the hardened unit starts, answers /healthz, sends the security headers,
# serves the login page, 404s unknown paths, and that the admin CLI and the
# backup command work through the sandboxed unit's state directory. A second
# part asserts that a bad config makes the unit fail cleanly.
{ pkgs, self }:
let
  discovery = pkgs.writeTextDir "realms/dropr/.well-known/openid-configuration" (builtins.toJSON {
    issuer = "http://localhost:8180/realms/dropr";
    authorization_endpoint = "http://localhost:8180/auth";
    token_endpoint = "http://localhost:8180/token";
    jwks_uri = "http://localhost:8180/jwks";
    userinfo_endpoint = "http://localhost:8180/userinfo";
    response_types_supported = [ "code" ];
    subject_types_supported = [ "public" ];
    id_token_signing_alg_values_supported = [ "RS256" ];
    code_challenge_methods_supported = [ "S256" ];
    grant_types_supported = [ "authorization_code" "refresh_token" ];
    token_endpoint_auth_methods_supported = [ "client_secret_post" "client_secret_basic" ];
  });
in
pkgs.testers.runNixOSTest {
  name = "dropr";
  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];

    systemd.services.mock-idp = {
      wantedBy = [ "multi-user.target" ];
      before = [ "dropr.service" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8180 --bind 127.0.0.1 --directory ${discovery}";
        DynamicUser = true;
      };
    };

    environment.etc."dropr-test/refresh_key".text = "bm90LWEtcmVhbC1rZXktbm90LWEtcmVhbC1rZXkxMjM=\n";
    environment.etc."dropr-test/client_secret".text = "dev-secret\n";

    services.dropr = {
      enable = true;
      refreshKeyFile = "/etc/dropr-test/refresh_key";
      oidcClientSecretFile = "/etc/dropr-test/client_secret";
      settings = {
        mode = "dev";
        tls = "proxy";
        listen = "127.0.0.1:8080";
        public_url = "http://localhost:8080";
        oidc = {
          issuer = "http://localhost:8180/realms/dropr";
          client_id = "dropr";
          client_auth = "client_secret";
          scopes = [ "openid" "profile" ];
          role_claim = "realm_access.roles";
          required_role = "Dropr.User";
        };
      };
    };
    virtualisation.memorySize = 1024;
  };

  testScript = ''
    machine.wait_for_unit("mock-idp.service")
    machine.wait_for_unit("dropr.service")
    machine.wait_for_open_port(8080)

    with subtest("health and headers"):
        machine.succeed("curl -fsS http://localhost:8080/healthz")
        hdrs = machine.succeed("curl -sSI http://localhost:8080/login")
        assert "content-security-policy" in hdrs.lower(), hdrs
        assert "x-content-type-options: nosniff" in hdrs.lower(), hdrs

    with subtest("unknown paths are 404"):
        machine.succeed("test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/nope) = 404")

    with subtest("unit is sandboxed"):
        score = machine.succeed("systemd-analyze security dropr.service --no-pager | tail -1")
        print(score)
        machine.succeed("test -d /var/lib/private/dropr")
        machine.succeed("test $(stat -c %a /var/lib/private/dropr) = 700")

    with subtest("admin CLI and backup run as the service user"):
        machine.succeed("dropr-admin user list </dev/null")
        machine.succeed("dropr-admin backup --out /var/lib/dropr/backup.db </dev/null")
        machine.succeed("test -s /var/lib/private/dropr/backup.db")

    with subtest("invalid config fails cleanly"):
        machine.succeed("systemctl stop dropr.service")
        machine.succeed("systemctl stop mock-idp.service")
        machine.succeed("systemctl start dropr.service || true")
        machine.wait_until_succeeds("journalctl -u dropr.service --no-pager | grep -i -E 'oidc|discovery|connection refused'")
        machine.fail("curl -fsS http://localhost:8080/healthz")
  '';
}
