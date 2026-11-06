# Setting up Microsoft Entra ID

Entra ID is the officially supported identity provider. Plan about 20 minutes.
You need an account that can create app registrations and manage Enterprise
applications (Application Administrator or higher) and, for step 8, Conditional
Access (Conditional Access Administrator).

Dropr is a single-tenant OIDC client that authenticates to the token endpoint
with a certificate (`private_key_jwt`). No client secret is ever created.

Placeholders used below: `<host>` = your Dropr domain (for example
`drop.example.com`), `<tenant-id>` = your directory (tenant) ID,
`<application-id>` = the app's Application (client) ID.

> **Choose the domain first.** Passkeys are bound to the domain (WebAuthn RP
> ID). Changing it later invalidates every passkey. See
> [operations.md](operations.md#changing-the-domain).

> **Do not recreate the app registration later.** Entra's `sub` claim is
> pairwise per app registration. A new registration gives every user a new
> identity, which orphans their Dropr data (recoverable only with
> `dropr user migrate`, see [operations.md](operations.md#changing-identity-provider)).

## 1. Register the application

Entra admin center, Entra ID, App registrations, New registration.

| Field | Value |
|---|---|
| Name | `Dropr` |
| Supported account types | **Accounts in this organizational directory only (single tenant)** |
| Redirect URI | platform **Web**, `https://<host>/auth/callback` |

Dropr compares the redirect URI exactly. No wildcards, no trailing slash, no
second URI.

Copy **Application (client) ID** and **Directory (tenant) ID** from the
Overview page.

## 2. Generate the certificate credential

Do this on a trusted machine, not on the Dropr host if you can avoid it. Dropr
supports RSA keys of at least 2048 bits and EC P-256. RSA 3072 with PS256 is
recommended.

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout dropr-key.pem -out dropr-cert.pem
# The file Dropr reads: private key first, then the certificate.
cat dropr-key.pem dropr-cert.pem > oidc_key.pem
```

`oidc_key.pem` is what `oidc.client_key_file` points to. Dropr rejects
encrypted private keys; protect the file with permissions (and the Docker or
systemd secret mechanism) instead. Only `dropr-cert.pem` (public) is uploaded
to Entra. Delete `dropr-key.pem` and `dropr-cert.pem` from the working
directory when finished, or keep them in your secret store.

Dropr refuses to start in production if the certificate has expired, and logs a
warning when it expires within 30 days. **Put the expiry date in your calendar.**
Rotation is described in [operations.md](operations.md#rotating-the-oidc-certificate).

## 3. Upload the certificate

App registration, Certificates & secrets, Certificates, Upload certificate:
choose `dropr-cert.pem`. Do **not** create a client secret.

Dropr signs client assertions (PS256 for RSA keys unless the provider advertises another algorithm) and sends the certificate's
`x5t#S256` thumbprint header, which is how Entra finds the key. Nothing needs
to be set for this. If you need RS256, set `oidc.client_assertion_alg = "RS256"`.

## 4. Define the app role `Dropr.User`

App registration, App roles, Create app role:

| Field | Value |
|---|---|
| Display name | `Dropr user` |
| Allowed member types | Users/Groups |
| Value | `Dropr.User` (exactly; case-sensitive) |
| Description | May use Dropr |
| Do you want to enable this app role | yes |

Dropr denies every login whose `roles` claim lacks this value, on every login
and every revalidation (default every 15 minutes). App roles are used instead
of group claims to avoid Entra's group-overage behavior (more than 200 groups).

## 5. Require assignment (Enterprise application)

Entra ID, Enterprise applications, **Dropr** (same name), Properties:

* **Assignment required?** = **Yes**. Save.
* **Visible to users?** as you prefer (No hides the tile in My Apps).

Users and groups, Add user/group: select users or a group and the role
**Dropr user**. Only assigned users can sign in; Entra refuses everyone else
with AADSTS50105 before Dropr is involved. The role check in Dropr is a second,
independent barrier.

## 6. Token configuration

* **Optional claims**: none required. `roles`, `sub`, `tid` and `name` are in
  the v2.0 ID token by default.
* Manifest (App registration, Manifest): confirm
  `"requestedAccessTokenVersion": 2` or `null`, and that
  `"accessTokenAcceptedVersion"` is not 1. Dropr only uses the ID token, but the
  v2.0 issuer `https://login.microsoftonline.com/<tenant-id>/v2.0` must be what
  appears in `iss`.
* API permissions: the default `User.Read` delegated permission is enough.
  `openid`, `profile` and `offline_access` need no admin consent. Optionally
  click "Grant admin consent" so users never see a consent prompt.
* Authentication: leave "Allow public client flows" **No**, and do not enable
  implicit grant or hybrid flow tokens.

## 7. Front-channel logout

App registration, Authentication, **Front-channel logout URL**:
`https://<host>/auth/frontchannel-logout`. When a user signs out elsewhere,
Entra loads this URL and Dropr ends the matching sessions. Sign-out from Dropr returns to `https://<host>/login` (RP-initiated logout);
if your tenant requires post-logout URIs to be registered, add that URL too.

## 8. Conditional Access (strongly recommended)

Dropr delegates MFA to Entra, and the passkey protects the inbox, not the
login. Require phishing-resistant sign-in for the app:

Entra ID, Conditional Access, Policies, New policy:

* Users: the Dropr group (and exclude your emergency-access accounts).
* Target resources: **Cloud apps**, select **Dropr**.
* Grant: **Require authentication strength**, **Phishing-resistant MFA**
  (FIDO2 security key, Windows Hello for Business, certificate-based).
* Optional: sign-in frequency 8 hours (matches Dropr's absolute session limit).
* Start in report-only mode, check the sign-in logs, then enable.

Disabling a user or choosing "Revoke sessions" in Entra makes the next
refresh fail, so the Dropr session dies within `revalidate_every` (15 minutes).
For an immediate effect also run `dropr user revoke <user>`.

## 9. Configure Dropr

Store the secrets with mode 0400 owned by the service user (or as Docker
secrets, see [operations.md](operations.md#container-compose)):

```sh
openssl rand -base64 32 > refresh_key       # encrypts stored refresh tokens
```

`dropr.toml`:

```toml
public_url       = "https://<host>"
mode             = "production"
data_dir         = "/data"
tls              = "acme"                       # or "proxy", see operations.md
acme_email       = "admin@example.com"
refresh_key_file = "/run/secrets/refresh_key"
login_label      = "Sign in with Microsoft"

[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "<application-id>"
client_auth     = "private_key_jwt"
client_key_file = "/run/secrets/oidc_key"        # key PEM followed by cert PEM
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"
required_role   = "Dropr.User"
display_claim   = "name"
required_claims = { tid = "<tenant-id>" }
revalidate_every = "15m"
# Entra supports PKCE S256 but does not list it in its discovery document.
allow_unadvertised_pkce = true
```

Notes on the keys:

* `issuer` must be the single-tenant v2.0 issuer. Dropr refuses `common`,
  `organizations`, `consumers` and templated issuers at startup.
* `required_claims.tid` is an extra check that the token comes from your
  tenant. If you omit it Dropr starts but warns; if it disagrees with the
  tenant in `issuer`, Dropr refuses to start.
* `allow_unadvertised_pkce = true` is **required for Entra**. Without it,
  startup fails with "provider does not advertise PKCE S256 support". Dropr
  still always sends a PKCE S256 challenge.
* `offline_access` is needed for the refresh token Dropr uses to revalidate the
  session.
* Sovereign clouds (`login.microsoftonline.us`, `login.chinacloudapi.cn`) are
  recognized with the same rules.

Start Dropr and check the log for the discovery result and any warnings. A
misconfigured provider stops startup with the failing check named.

## 10. Verify

1. Open `https://<host>`, click **Sign in with Microsoft**, sign in as an
   assigned user. You should land on the passkey setup page.
2. Sign in as an unassigned user: Entra shows AADSTS50105.
3. Temporarily remove the role from your test user. Within
   `revalidate_every` the Dropr session ends, or sign-in is denied with a 403
   page.

## Troubleshooting

| Error | Where | Cause and fix |
|---|---|---|
| `AADSTS50011` The redirect URI does not match | Entra sign-in page | `https://<host>/auth/callback` is not registered exactly (scheme, host, port, path, trailing slash), or `public_url` differs from the registered host. Fix the Web redirect URI or `public_url`. |
| `AADSTS700027` Client assertion contains an invalid signature | Dropr log, token endpoint error | The uploaded certificate does not match the key in `oidc_key.pem`, the key was regenerated without re-uploading, or a different app registration is used. Compare thumbprints: `openssl x509 -in dropr-cert.pem -noout -fingerprint -sha1` against the portal. |
| `AADSTS700024` Client assertion is not within its valid time range | Dropr log | Host clock is wrong. Fix NTP. |
| `AADSTS700025` / `AADSTS7000218` client is public / must provide a client_assertion or client_secret | Dropr log | "Allow public client flows" is on, or the credential was not sent. Set it to No and confirm `client_auth = "private_key_jwt"`. |
| `AADSTS50105` Your administrator has configured the application to block users unless they are specifically granted access | Entra sign-in page | Assignment required is on and the user (or one of their groups) has no role assignment. Assign the **Dropr user** role. |
| `AADSTS7000215` Invalid client secret provided | Dropr log | Entra received a client secret or no usable assertion. Dropr never sends secrets in production. Check that `oidc.client_auth` is `private_key_jwt` and the app registration has a certificate, not just a secret. |
| `AADSTS900971` No reply address provided / `AADSTS50194` not configured as multi-tenant | Entra | Redirect URI missing, or the issuer in `dropr.toml` is wrong for a single-tenant app. Use the tenant-specific issuer. |
| `AADSTS65001` The user or administrator has not consented | Entra | Grant admin consent (step 6) or let the user consent. |
| `AADSTS53003` Blocked by Conditional Access | Entra | The user does not satisfy the authentication strength. Intended behavior; enroll a phishing-resistant method. |
| Dropr refuses to start: "provider does not advertise PKCE S256 support" | Dropr log | Set `allow_unadvertised_pkce = true`. |
| Dropr refuses to start: "multi-tenant Entra issuer ... is refused" | Dropr log | Use `https://login.microsoftonline.com/<tenant-id>/v2.0`. |
| Login succeeds at Entra, Dropr shows 403 | Dropr | The ID token has no `roles` claim containing `Dropr.User`. Check the app role Value, the assignment, and that the user signed in to this app (not a cached session for another). |
| Users are logged out after about 15 minutes | Dropr log | The refresh failed: `offline_access` missing from `scopes`, user disabled or revoked, or Conditional Access (sign-in frequency, or a location/device condition) rejects the non-interactive refresh. |
| Startup warning: certificate expires within 30 days | Dropr log | Rotate the certificate (operations.md). |

Entra error codes and their meaning are listed at
<https://learn.microsoft.com/entra/identity-platform/reference-error-codes>.
