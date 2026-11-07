#!/usr/bin/env bash
# Smoke test of deploy/debian/install.sh on a throwaway Debian 13 VM made by
# vm.sh (hostname dropr-smoke). Never run it on a real server: it edits
# /etc/hosts, trusts a local CA, adds nginx sites, points Dropr at a stub
# identity provider and sets up a local restic repository.
#
#   sudo test/debian/smoke.sh /path/to/dropr
#
# First run: fresh install (the installer must stop for configuration), then
# the test config (nginx in front, tls = "proxy", stub IdP over local TLS) and
# a second run that starts the service. Every run then upgrades over the
# running service and checks the result. Sign-in cannot complete: the stub IdP
# only serves discovery, which is all Dropr needs to start.
set -euo pipefail

bin=${1:?usage: smoke.sh /path/to/dropr}
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../deploy/debian" && pwd)
DROP=drop.dropr.test
IDP=idp.dropr.test
WORK=/root/dropr-smoke
BACKUPS=/var/backups/dropr

pass=0
fail=0
ok()   { printf '\033[32m  ok\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '\033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
backups() { find "$BACKUPS" -maxdepth 1 -type f -name 'dropr-*.db' 2>/dev/null | wc -l; }
inst() { "$SRC/install.sh" --binary "$bin" 2>&1 | tee "$WORK/install-$1.log"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$(hostname)" = dropr-smoke ] \
  || die "refusing to run on '$(hostname)': this rewrites system config; use vm.sh"
[ -f "$bin" ] || die "no such file: $bin"
mkdir -p "$WORK"

# --- Prerequisites ---------------------------------------------------------------
step "Prerequisites"
missing=()
for p in nginx:nginx openssl:openssl curl:curl update-ca-certificates:ca-certificates; do
  command -v "${p%%:*}" >/dev/null || missing+=("${p#*:}")
done
if [ ${#missing[@]} -gt 0 ]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
fi
for name in "$DROP" "$IDP"; do
  grep -qw "$name" /etc/hosts || echo "127.0.0.1 $name" >> /etc/hosts
done
# shellcheck source=/dev/null
. /etc/os-release
echo "$PRETTY_NAME, systemd $(systemctl --version | awk 'NR==1 {print $2}'), $(nginx -v 2>&1), virt: $(systemd-detect-virt || true)"

# --- Local CA and certificates -------------------------------------------------------
# The Dropr certificate goes where certbot would put it, so the shipped nginx
# site only needs its server name changed.
leaf() {
  local name=$1 dir=$2
  mkdir -p "$dir"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name" \
    -keyout "$dir/privkey.pem" -out "$WORK/$name.csr" 2>/dev/null
  openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 30 -sha256 -out "$dir/fullchain.pem" \
    -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$name") 2>/dev/null
  chmod 0600 "$dir/privkey.pem"
}
if [ ! -s "$WORK/ca.crt" ]; then
  step "Local CA and certificates"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=Dropr smoke test CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
  leaf "$DROP" "/etc/letsencrypt/live/$DROP"
  leaf "$IDP" /etc/nginx/dropr-smoke-idp
  install -m 0644 "$WORK/ca.crt" /usr/local/share/ca-certificates/dropr-smoke-ca.crt
  update-ca-certificates >/dev/null
fi

# --- nginx: stub IdP and the shipped Dropr site --------------------------------------
step "nginx (stub IdP at https://$IDP, Dropr at https://$DROP)"
install -d /var/www/dropr-smoke-idp
cat > /var/www/dropr-smoke-idp/openid-configuration.json <<EOF
{
  "issuer": "https://$IDP",
  "authorization_endpoint": "https://$IDP/authorize",
  "token_endpoint": "https://$IDP/token",
  "jwks_uri": "https://$IDP/jwks",
  "end_session_endpoint": "https://$IDP/logout",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "code_challenge_methods_supported": ["S256"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
EOF
echo '{"keys": []}' > /var/www/dropr-smoke-idp/jwks.json
cat > /etc/nginx/sites-available/dropr-smoke-idp <<EOF
server {
    listen 443 ssl;
    server_name $IDP;
    ssl_certificate     /etc/nginx/dropr-smoke-idp/fullchain.pem;
    ssl_certificate_key /etc/nginx/dropr-smoke-idp/privkey.pem;
    root /var/www/dropr-smoke-idp;
    default_type application/json;
    location = /.well-known/openid-configuration { try_files /openid-configuration.json =404; }
    location = /jwks { try_files /jwks.json =404; }
    location / { return 404; }
}
EOF
sed "s/drop\.example\.com/$DROP/g" "$SRC/nginx-dropr.conf" > /etc/nginx/sites-available/dropr
ln -sf ../sites-available/dropr /etc/nginx/sites-enabled/dropr
ln -sf ../sites-available/dropr-smoke-idp /etc/nginx/sites-enabled/dropr-smoke-idp
if out=$(nginx -t 2>&1); then ok "nginx -t accepts the shipped site"; else bad "nginx -t"; fi
grep -Ei 'warn|emerg' <<<"$out" | sed 's/^/        /' || true
systemctl enable --quiet nginx
systemctl restart nginx
check "stub IdP discovery over TLS" curl -fsS "https://$IDP/.well-known/openid-configuration"

# --- Fresh install --------------------------------------------------------------------
if [ ! -x /usr/local/bin/dropr ]; then
  step "Fresh install (must stop for configuration)"
  inst fresh || die "fresh install failed; nothing to test (log: $WORK/install-fresh.log)"
  ok "installer exits 0"
  check "stops before starting (placeholders in config)" grep -q "Before starting" "$WORK/install-fresh.log"
  check "service not started" test "$(systemctl is-active dropr || true)" != active
  check "dropr system user exists" getent passwd dropr
  check "/etc/dropr/credentials is root 0700" test "$(stat -c %U:%a /etc/dropr/credentials)" = root:700
  check "refresh_key.cred is root 0600" test "$(stat -c %U:%a /etc/dropr/credentials/refresh_key.cred)" = root:600
  check "OIDC client key generated and sealed" test -s /etc/dropr/credentials/oidc_key.cred
  check "no plaintext secrets left" test -z "$(find /etc/dropr/credentials -type f ! -name '*.cred')"
  check "dropr.toml is root:dropr 0640" test "$(stat -c %U:%G:%a /etc/dropr/dropr.toml)" = root:dropr:640
  check "backup timer enabled" systemctl is-enabled dropr-backup.timer

  step "Test configuration (behind nginx, stub IdP)"
  cat > /etc/dropr/dropr.toml <<EOF
# Written by test/debian/smoke.sh.
public_url       = "https://$DROP"
mode             = "production"
data_dir         = "/var/lib/dropr"
tls              = "proxy"
listen           = "127.0.0.1:8080"
trusted_proxies  = ["127.0.0.1"]
refresh_key_file = "/run/credentials/dropr.service/refresh_key"
login_label      = "Sign in (smoke test IdP)"

[oidc]
issuer          = "https://$IDP"
client_id       = "dropr-smoke"
client_auth     = "private_key_jwt"
client_key_file = "/run/credentials/dropr.service/oidc_key"
scopes          = ["openid", "profile"]
role_claim      = "roles"
required_role   = "Dropr.User"
display_claim   = "name"
EOF
  # As docs/deploy-debian.md "Behind nginx or Caddy" says.
  install -d /etc/systemd/system/dropr.service.d
  printf '[Service]\nCapabilityBoundingSet=\nAmbientCapabilities=\nSocketBindAllow=tcp:8080\n' \
    > /etc/systemd/system/dropr.service.d/proxy.conf
  systemctl daemon-reload

  step "Second run (must start and report healthy)"
  if inst start; then ok "installer exits 0"; else bad "installer failed"; fi
  check "reports healthy" grep -q "Healthy" "$WORK/install-start.log"
fi

# --- Upgrade over the running service ----------------------------------------------
step "Upgrade over the running service"
before=$(backups)
if inst upgrade; then ok "installer exits 0"; else bad "installer failed"; fi
check "pre-upgrade database backup taken" test "$(backups)" -gt "$before"
check "previous binary kept" test -x /usr/local/bin/dropr.previous
check "reports healthy" grep -q "Healthy" "$WORK/install-upgrade.log"

# --- Runtime checks ------------------------------------------------------------------
step "Runtime checks"
check "service active" systemctl is-active dropr
check "no restarts" test "$(systemctl show -P NRestarts dropr)" = 0
check "healthz through nginx (TLS via local CA)" curl -fsS "https://$DROP/healthz"
check "http:// redirects to https://" \
  test "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://$DROP/x")" = "301 https://$DROP/x"
hdrs=$(curl -fsS -D - -o /dev/null "https://$DROP/login" || true)
if grep -qi '^content-security-policy:' <<<"$hdrs"; then ok "security headers pass through nginx"; else bad "no Content-Security-Policy header on /login"; fi
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "https://$DROP/auth/login")
case $loc in
  https://*.dropr.test*client_id=*) ok "sign-in redirects to the IdP" ;;  # stub or browse.sh Keycloak
  *) bad "sign-in redirect: got '$loc'" ;;
esac
check "dropr-admin user list" dropr-admin user list
before=$(backups)
systemctl start dropr-backup.service || true
check "dropr-backup.service writes a backup" test "$(backups)" -gt "$before"
check "dropr user cannot read the credentials" bash -c '! runuser -u dropr -- cat /etc/dropr/credentials/refresh_key.cred'
pid=$(systemctl show -P MainPID dropr)
check "confined by the AppArmor profile (enforce)" grep -qx 'dropr (enforce)' "/proc/$pid/attr/apparmor/current"
denials=$(journalctl -k -q -o cat -g 'apparmor="DENIED".*profile="dropr"' --no-pager 2>/dev/null || true)
if [ -z "$denials" ]; then ok "no AppArmor denials for dropr"; else
  bad "AppArmor denials for dropr:"; sort -u <<<"$denials" | tail -n 15 | sed 's/^/        /'
fi
check "logs land in the dropr journal namespace" test -n "$(journalctl --namespace=dropr -q -n 1 -o cat)"
echo "        $(systemd-analyze security dropr.service --no-pager 2>/dev/null | tail -n 1)"

# --- Operations ----------------------------------------------------------------------
step "Operations (self-check, alerts, off-site backups)"
check "dropr-check.timer active" systemctl is-active dropr-check.timer
if systemctl start dropr-check.service; then ok "self-check passes"; else
  bad "self-check failed:"; journalctl -u dropr-check -n 12 -o cat --no-pager | sed 's/^/        /'
fi
check "failure hook runs (dropr-alert@test)" systemctl start dropr-alert@test.service
command -v restic >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq restic >/dev/null
if [ ! -e /etc/dropr/credentials/restic_env.cred ]; then
  # A repository in the unit's cache directory stands in for S3 or rest-server.
  printf 'RESTIC_REPOSITORY=/var/cache/dropr-offsite/smoke-repo\nRESTIC_PASSWORD=%s\n' "$(openssl rand -hex 16)" \
    | dropr-credential set restic_env - >/dev/null
  dropr-offsite init >/dev/null
fi
rm -f /var/lib/dropr-offsite/last-success
systemctl start dropr-backup.service   # OnSuccess= starts dropr-offsite.service
for _ in $(seq 1 60); do
  [ -e /var/lib/dropr-offsite/last-success ] || systemctl is-failed --quiet dropr-offsite || { sleep 2; continue; }
  break
done
if [ -e /var/lib/dropr-offsite/last-success ]; then ok "off-site backup follows dropr-backup"; else
  bad "off-site backup did not complete:"; journalctl -u dropr-offsite -n 12 -o cat --no-pager | sed 's/^/        /'
fi
check "off-site restore test" dropr-offsite restore-test

# --- Summary -------------------------------------------------------------------------
printf '\n\033[1m%d passed, %d failed\033[0m (installer logs in %s)\n' "$pass" "$fail" "$WORK"
if [ "$fail" -gt 0 ]; then
  step "systemctl status dropr"
  systemctl status dropr --no-pager -l || true
  step "journalctl --namespace=dropr (last 40)"
  journalctl --namespace=dropr -n 40 --no-pager || true
  exit 1
fi
