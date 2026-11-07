# Identity provider (OIDC)

Dropr has no local accounts. Every login goes through one OpenID Connect
provider, and access is granted by a role claim in the ID token. Microsoft
Entra ID is the officially supported provider. Keycloak is used in development
and CI. Other compliant providers (Authentik, Okta, ...) are best-effort: they
work if they meet the requirements below.

The `[oidc]` keys are documented in [dropr.example.toml](../dropr.example.toml)
and [ARCHITECTURE.md](ARCHITECTURE.md) §5. The design is in
[DESIGN.md](DESIGN.md) §5.1.

## What Dropr requires

| Requirement | Why | Enforced |
|---|---|---|
| **One issuer**, loaded through discovery, matched exactly against `iss` | Identity is `(iss, sub)`. A multi-tenant issuer would accept tokens from any tenant | Templated issuers (`{tenantid}`) and Entra's `common`, `organizations`, `consumers` are refused at startup |
| **Authorization Code with PKCE S256** | Code injection and login CSRF | Production refuses a provider that does not advertise S256, unless `allow_unadvertised_pkce = true` |
| **`private_key_jwt`** (RFC 7523) client authentication | No shared secret to leak | `client_auth = "client_secret"` is dev mode only |
| **Refresh tokens** | Revalidation | Production refuses a provider that offers neither the `refresh_token` grant nor `offline_access` |
| **A role claim** in the ID token containing `required_role` | Authorization | Checked at every login and every revalidation |
| **Asymmetric ID token signatures** | `none` and HS* are never accepted | Startup fails if discovery lists no asymmetric algorithm |
| **`https://` endpoints** | | `http://localhost` is allowed in dev mode only |

Details:

* **Redirect URI**: `https://<host>/auth/callback`, exact match, derived from
  `public_url`. Register nothing else.
* **Logout**: `https://<host>/login` is the post-logout redirect URI
  (RP-initiated logout, when discovery has an `end_session_endpoint`).
  `https://<host>/auth/frontchannel-logout` is the front-channel logout URL;
  when the provider calls it, Dropr ends the matching sessions. Sessions are
  matched by the `sid` claim of the ID token they were opened with: if the
  provider does not put `sid` in ID tokens, front-channel logout matches
  nothing (the call still succeeds) and Dropr logs a warning. Check that your
  provider emits `sid`.
* **Role claim**: `role_claim` is a claim name or a dotted path
  (`realm_access.roles`). The value may be a string or an array of strings.
  Without `required_role` in it, login is refused with a 403 page and no
  account is created.
* **Revalidation**: every `revalidate_every` (default 15 minutes, between 1m
  and 1h), Dropr redeems the stored refresh token. The new ID token must pass
  every login check, carry the same `sub` and still hold the role. Any failure,
  including an unreachable provider, ends the session. Disabling a user or
  revoking their sessions at the provider therefore takes effect within that
  interval. If a refresh returns no ID token, Dropr checks the userinfo
  endpoint instead and fails closed when it lacks the role.
* **Lost access**: when a revalidation or login finds the role (or a
  required claim) missing, the user's share links expire for good and their
  request links pause until a login with the role. Other revalidation failures
  (provider unreachable, refresh token rejected, bad token) only end the
  session.
* **`dropr user revoke <user>`** ends the user's sessions at once, expires
  their share links and pauses their request links. It is not a lockout: it
  does not stop the next login, and a successful login (with the role) reopens
  the request links (the shares stay expired).
* **`dropr user disable <user>`** is the local lockout: Dropr refuses the
  account's logins and sessions, and its request links stay closed, until
  `dropr user enable <user>`; it also ends the sessions and expires the share
  links. To remove someone, take the role away (or disable the account) at the
  provider first, then run `dropr user disable`; `dropr user purge` deletes
  their links and files.
* **`required_claims`**: optional exact string matches on ID token claims, for
  example `{ tid = "<tenant-id>" }`. They cannot override registered claims
  (`iss`, `aud`, `sub`, `exp`, ...).
* **Client key**: `client_key_file` holds one unencrypted PEM private key (RSA
  of at least 2048 bits, or EC P-256), followed by its certificate when the
  provider identifies keys by certificate. Encrypted keys are refused; protect
  the file with permissions. Production refuses an expired certificate and
  Dropr warns 30 days before expiry. The assertion algorithm is the first of
  PS256, RS256 (RSA) or ES256 (EC) that the provider advertises;
  `client_assertion_alg` overrides it. To rotate, register the new certificate
  next to the old one, replace the file, restart, confirm a login, then remove
  the old certificate.
* **MFA** is the provider's job. Require it, phishing-resistant if possible:
  a stolen login cannot read received files, but it can create shares and new
  request links in the owner's name.
* **Do not change the issuer or recreate the client registration** casually.
  A new issuer, or a provider whose `sub` is pairwise per client, gives every
  user a new identity. `dropr user migrate` relinks existing accounts.

A key pair and certificate for `private_key_jwt`:

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout key.pem -out cert.pem
cat key.pem cert.pem > oidc_key.pem    # oidc.client_key_file
```

Upload `cert.pem` to the provider. Keep `oidc_key.pem` on the Dropr host only.

## Microsoft Entra ID

1. **App registration**: single tenant ("Accounts in this organizational
   directory only"), platform **Web**, redirect URI
   `https://<host>/auth/callback`. Note the Application (client) ID and the
   Directory (tenant) ID. Do not create a client secret.
2. **Certificate**: Certificates & secrets, upload `cert.pem`. Entra finds the
   key through the `x5t#S256` header Dropr sends; nothing else to set.
3. **App role**: create a role with value `Dropr.User` (case-sensitive),
   allowed member type Users/Groups. App roles avoid Entra's group-overage
   behavior.
4. **Enterprise application**: set *Assignment required* to Yes, then assign
   the role to users or groups. Unassigned users are refused by Entra before
   reaching Dropr.
5. **Front-channel logout URL**: `https://<host>/auth/frontchannel-logout`.
   Add `https://<host>/login` as a post-logout URI if your tenant requires it.
6. **Conditional Access**: a policy targeting the app that requires
   phishing-resistant MFA is strongly recommended.

The `roles`, `sub`, `tid` and `name` claims are in the v2.0 ID token by
default. Front-channel logout also needs `sid` in the ID token: check that
your tenant emits it, and if not, enable it as an optional claim (Token
configuration → Add optional claim → ID → `sid`). Dropr logs one WARN per
process ("ID token has no sid claim") when a login's ID token lacks it, so
sign in once after setup and check the log. Leave public client flows and
implicit grant disabled.

```toml
[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "<application-id>"
client_auth     = "private_key_jwt"
client_key_file = "/run/secrets/oidc_key"
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"
required_role   = "Dropr.User"
display_claim   = "name"
required_claims = { tid = "<tenant-id>" }
allow_unadvertised_pkce = true
```

* `allow_unadvertised_pkce = true` is required: Entra supports PKCE S256 but
  does not list it in discovery. Dropr always sends the S256 challenge.
* `required_claims.tid` is optional but recommended. Dropr warns without it
  and refuses to start if it differs from the tenant in `issuer`.
* `offline_access` provides the refresh token used for revalidation.
* Entra's `sub` is pairwise per app registration. Recreating the registration
  changes every user's identity.
* Sovereign cloud hosts (`login.microsoftonline.us`, `login.chinacloudapi.cn`,
  ...) follow the same rules.

## Keycloak

[dev/keycloak/dropr-realm.json](../dev/keycloak/dropr-realm.json) is the dev
realm, imported by `make keycloak-up`. It is a working template: realm role
`Dropr.User`, a `private_key_jwt` client (`dropr-pkjwt`) and a dev-only
client-secret client (`dropr`), PKCE S256 required, front-channel logout and a
role mapper. All keys and passwords in it are public test values.

For a real realm:

1. Use a dedicated realm (not `master`) with MFA in its authentication flow.
2. Create the realm role `Dropr.User` and assign it to users or a group.
3. Create an OpenID Connect client with client authentication on, standard
   flow only, redirect URI `https://<host>/auth/callback`, post-logout
   redirect URI `https://<host>/login`.
4. Credentials: **Signed JWT**, signature algorithm PS256 or RS256. Import
   `cert.pem` under *Keys* and note the `kid` Keycloak shows.
5. Advanced: PKCE method `S256`. Logout: front-channel logout URL
   `https://<host>/auth/frontchannel-logout`.
6. **Role mapper**: in the client's dedicated scope, add a *User Realm Role*
   mapper, claim name `realm_access.roles`, multivalued, **Add to ID token
   on**. Keycloak puts realm roles in the access token only by default; without
   this mapper every login gets a 403.

```toml
[oidc]
issuer          = "https://auth.example.com/realms/<realm>"
client_id       = "dropr"
client_auth     = "private_key_jwt"
client_key_file = "/run/secrets/oidc_key"
client_key_id   = "<kid from the Keys tab>"
scopes          = ["openid", "profile"]
role_claim      = "realm_access.roles"
required_role   = "Dropr.User"
display_claim   = "name"
```

* Keycloak matches client keys by `kid`: set `client_key_id` to the value it shows.
* Keycloak advertises PKCE S256; `allow_unadvertised_pkce` is not needed.
* With `offline_access` in `scopes`, Keycloak issues offline tokens that
  survive the end of the SSO session; access is then cut only by disabling the
  user or revoking the offline session. Without it (as above), revalidation
  follows the SSO session, so keep *SSO Session Idle* at least 30 minutes and
  *SSO Session Max* at least 8 hours (Dropr's own session limits).
* A client role works too: `role_claim = "resource_access.<client-id>.roles"`.
