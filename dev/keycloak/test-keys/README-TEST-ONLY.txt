TEST-ONLY KEY MATERIAL — NEVER USE IN PRODUCTION
=================================================

These files are committed on purpose so the dev Keycloak realm and CI can
exercise private_key_jwt client authentication. The private key is public;
anyone can impersonate the "dropr-pkjwt" client of the dev realm with it.

  dropr-pkjwt.TEST-ONLY.pem       RSA-2048 private key + self-signed cert
                                  (oidc.client_key_file for the dev client)
  dropr-pkjwt.TEST-ONLY.cert.pem  the certificate alone

The matching public key is embedded in ../dropr-realm.json (client
"dropr-pkjwt", attribute jwks.string, kid "dropr-dev-test").

dev/dropr.toml shows how to use this key (its last comment). For a real
deployment generate your own key pair as described in docs/oidc.md and
upload its certificate to your provider.
