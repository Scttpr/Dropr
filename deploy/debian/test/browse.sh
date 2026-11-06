#!/usr/bin/env bash
# Switch the smoke VM from the stub IdP to the dev Keycloak realm so Dropr can
# be used from a browser on the host. Run by `vm.sh browse` after smoke.sh;
# never on a real server.
#
#   browser --> 127.0.0.1:8443 --(qemu)--> VM nginx :443 --> Dropr 127.0.0.1:8080
#                                                      \--> kc.dropr.test --> host Keycloak 10.0.2.2:8181
#
# Dropr reaches the issuer as https://kc.dropr.test:8443 too (nginx also
# listens on 8443 in the VM), so browser and server see the same issuer URL.
# Uses the committed TEST-ONLY private_key_jwt key of the dev realm.
set -euo pipefail

key=${1:?usage: browse.sh /path/to/dropr-pkjwt.TEST-ONLY.pem}
DROP=drop.dropr.test
KC=kc.dropr.test
PORT=8443
WORK=/root/dropr-smoke
CERTS=/etc/nginx/dropr-smoke-kc

log() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$(hostname)" = dropr-smoke ] || die "refusing to run on '$(hostname)'; use vm.sh browse"
[ -s "$WORK/ca.crt" ] && [ -x /usr/local/bin/dropr ] || die "run smoke.sh first"

grep -qw "$KC" /etc/hosts || echo "127.0.0.1 $KC" >> /etc/hosts

if [ ! -s "$CERTS/fullchain.pem" ]; then
  log "Certificate for $KC"
  mkdir -p "$CERTS"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$KC" \
    -keyout "$CERTS/privkey.pem" -out "$WORK/$KC.csr" 2>/dev/null
  openssl x509 -req -in "$WORK/$KC.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 30 -sha256 -out "$CERTS/fullchain.pem" \
    -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$KC") 2>/dev/null
  chmod 0600 "$CERTS/privkey.pem"
fi

log "nginx: $KC proxies the host Keycloak"
cat > /etc/nginx/sites-available/dropr-smoke-kc <<EOF
server {
    listen 443 ssl;
    listen $PORT ssl;
    server_name $KC;
    ssl_certificate     $CERTS/fullchain.pem;
    ssl_certificate_key $CERTS/privkey.pem;
    location / {
        # 10.0.2.2 is the host as seen from QEMU user networking.
        proxy_pass http://10.0.2.2:8181;
        proxy_set_header Host \$host;
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
    }
}
EOF
ln -sf ../sites-available/dropr-smoke-kc /etc/nginx/sites-enabled/dropr-smoke-kc
nginx -t 2>&1 | grep -v 'listen ... http2' >&2 || true
systemctl reload nginx

curl -fsS "https://$KC:$PORT/realms/dropr/.well-known/openid-configuration" >/dev/null \
  || die "Keycloak not reachable from the VM through https://$KC:$PORT (is the host container up?)"

log "Dropr: dev realm, client dropr-pkjwt (TEST-ONLY key)"
cred=/etc/dropr/credentials/oidc_key.pem
[ -e "$cred.generated" ] || cp -p "$cred" "$cred.generated"
install -o root -g root -m 0600 "$key" "$cred"
cat > /etc/dropr/dropr.toml <<EOF
# Written by deploy/debian/test/browse.sh (dev Keycloak realm, TEST-ONLY key).
public_url       = "https://$DROP:$PORT"
mode             = "production"
data_dir         = "/var/lib/dropr"
tls              = "proxy"
listen           = "127.0.0.1:8080"
trusted_proxies  = ["127.0.0.1"]
refresh_key_file = "/run/credentials/dropr.service/refresh_key"
login_label      = "Sign in with Keycloak (smoke VM)"

[oidc]
issuer          = "https://$KC:$PORT/realms/dropr"
client_id       = "dropr-pkjwt"
client_auth     = "private_key_jwt"
client_key_file = "/run/credentials/dropr.service/oidc_key"
client_key_id   = "dropr-dev-test"
scopes          = ["openid", "profile"]
role_claim      = "realm_access.roles"
required_role   = "Dropr.User"
display_claim   = "name"
EOF
chown root:dropr /etc/dropr/dropr.toml
chmod 0640 /etc/dropr/dropr.toml

systemctl reset-failed dropr.service 2>/dev/null || true
systemctl restart dropr.service
for _ in $(seq 1 30); do
  if dropr-admin healthcheck >/dev/null 2>&1; then log "Dropr healthy"; exit 0; fi
  sleep 2
done
journalctl --namespace=dropr -n 30 --no-pager
die "dropr did not become healthy"
