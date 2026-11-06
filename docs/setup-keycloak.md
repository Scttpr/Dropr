# Setting up Keycloak (best-effort provider)

Keycloak is used for local development and for the automated end-to-end
tests, so the configuration below is exercised on every CI run. It is
"best-effort" for production: it works, but only Microsoft Entra ID has a
release check against a real tenant (see [setup-entra.md](setup-entra.md)).
Other compliant providers (Authentik, Authelia, Okta, ...) need the same
ingredients: discovery, Authorization Code with PKCE S256, refresh tokens,
`private_key_jwt`, and a role or group claim in the ID token.

Tested with Keycloak 26.5.

## Fastest path: the shipped dev realm

`deploy/keycloak/dropr-realm.json` is imported by `deploy/compose.dev.yaml`
(`make keycloak-up`). It defines:

* realm `dropr`, realm role `Dropr.User`
* users `alice` and `bob` (with the role) and `mallory` (without), with public
  test passwords listed in `deploy/compose.dev.yaml`
* client `dropr` (client secret, **dev mode only**) and client `dropr-pkjwt`
  (`private_key_jwt`, the production authentication method)
* both clients: PKCE S256 required, front-channel logout URL, refresh tokens on,
  and a mapper putting realm roles in the ID token as `realm_access.roles`

Everything in it is a public test value. Never reuse its keys or passwords. Use
it as a template for a real realm.

## Production realm, step by step

1. **Realm**: create a dedicated realm (not `master`). Set *Realm settings,
   General, Require SSL* to `all requests`. Configure your authentication flow
   with MFA (WebAuthn passwordless or OTP). Dropr delegates MFA to the provider.
2. **Role**: Realm roles, create `Dropr.User`. Assign it to users, or to a
   group (Groups, Role mapping) so that membership grants access.
3. **Client**: Clients, Create client.
   * Client type OpenID Connect, Client ID e.g. `dropr`
   * Capability config: **Client authentication ON**, Standard flow ON, every
     other flow (direct access grants, implicit, service accounts) OFF
   * Valid redirect URIs: `https://<host>/auth/callback` (exact)
   * Valid post logout redirect URIs: `https://<host>/login`
   * Web origins: leave empty
4. **Authentication method**, Credentials tab: set **Signed JWT**.
   * Generate a key pair and certificate (command below), then under
     *Keys*, switch *Use JWKS URL* off and **Import** `dropr-cert.pem`
     (format Certificate PEM), or paste a JWKS (`kid` must equal
     `oidc.client_key_id`).
   * Set *Signature algorithm* to `PS256` (or `RS256`).
5. **PKCE**: Advanced tab, Advanced settings, *Proof Key for Code Exchange Code
   Challenge Method* = `S256`.
6. **Logout**: Settings, Logout settings: Front channel logout ON, Front-channel
   logout URL `https://<host>/auth/frontchannel-logout`, *Front-channel logout
   session required* ON.
7. **Role mapper**: Client scopes, `<client>-dedicated`, Add mapper, By
   configuration, **User Realm Role**:
   * Name `realm roles in ID token`
   * Token Claim Name `realm_access.roles`, Claim JSON Type String, Multivalued ON
   * Add to ID token **ON** (Dropr reads the ID token, not the access token)

   Keycloak adds `realm_access.roles` to *access* tokens by default, not to ID
   tokens. This mapper is the step people miss; without it every login is
   denied with 403. A client role mapper works as well; then set `role_claim`
   to `resource_access.<client-id>.roles`.
8. **Refresh tokens**: Realm settings, Tokens: leave *Revoke Refresh Token* off
   (the default). Set *SSO Session Idle*
   at least as long as Dropr's session idle timeout (30 min) and *SSO Session
   Max* to at least 8 hours so Keycloak does not end sessions earlier than
   intended. Disabling a user or ending a session in Keycloak makes the next
   Dropr revalidation fail.

Key pair for step 4:

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout dropr-key.pem -out dropr-cert.pem
cat dropr-key.pem dropr-cert.pem > oidc_key.pem    # Dropr's oidc.client_key_file
```

## Dropr configuration

```toml
[oidc]
issuer           = "https://auth.example.com/realms/<realm>"
client_id        = "dropr"
client_auth      = "private_key_jwt"
client_key_file  = "/run/secrets/oidc_key"
client_key_id    = "dropr-key-1"          # Keycloak matches keys by kid
client_assertion_alg = "PS256"
scopes           = ["openid", "profile", "offline_access"]
role_claim       = "realm_access.roles"
required_role    = "Dropr.User"
display_claim    = "name"
revalidate_every = "15m"
```

Keycloak advertises PKCE S256 in discovery, so `allow_unadvertised_pkce` is not
needed. Production mode requires an `https://` issuer and `private_key_jwt`.

`client_key_id` is the `kid` Dropr puts in the client assertion header. When
you import a certificate, Keycloak derives the `kid` itself: read it from the
*Keys* tab (or the realm's JWKS) and use that value. With a pasted JWKS you
choose it.

Offline tokens: with `offline_access` in `scopes`, Keycloak issues offline
refresh tokens that survive the end of the SSO session. Dropr then relies on
the user being disabled or the offline session being revoked to cut access. If
you prefer revalidation to follow the SSO session, use
`scopes = ["openid", "profile"]` as `deploy/dropr.dev.toml` does.

## Local development

```sh
nix develop
make keycloak-up     # Keycloak on http://localhost:8180, realm "dropr" imported
make dev             # Dropr on http://localhost:8080 using deploy/dropr.dev.toml
make test-keycloak   # integration tests with real logins
make keycloak-down
```

Keycloak admin console: <http://localhost:8180> (admin / admin). To exercise
`private_key_jwt` locally, follow the comment at the bottom of
`deploy/dropr.dev.toml` (client `dropr-pkjwt`, test key under
`deploy/keycloak/test-keys/`).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| 403 after a successful Keycloak login | ID token has no `realm_access.roles` containing `Dropr.User`: add the mapper with "Add to ID token", assign the role to the user, check `role_claim`. |
| `invalid_grant` / `Invalid redirect uri` | Redirect URI not exactly `https://<host>/auth/callback`. |
| `invalid_client` at token endpoint with `private_key_jwt` | `client_key_id` does not match the imported key's `kid`, wrong signature algorithm, or the certificate does not match the key. |
| Startup: provider does not advertise PKCE S256 | PKCE not enabled for the Keycloak version/realm; upgrade Keycloak. |
| Startup: refresh_token grant missing | Client has refresh tokens disabled (`use.refresh.tokens`). |
| Logged out after 30 min | Keycloak SSO Session Idle shorter than expected, or the user was disabled. |
