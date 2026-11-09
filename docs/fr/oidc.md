# Fournisseur d'identité (OIDC)

[English](../oidc.md) · **Français** — traduction de [docs/oidc.md](../oidc.md),
qui fait foi en cas de divergence.

Dropr n'a pas de comptes locaux. Toute connexion passe par un seul fournisseur
OpenID Connect, et l'accès est accordé par une revendication de rôle dans l'ID
token. Microsoft Entra ID est le fournisseur officiellement pris en charge.
Keycloak sert au développement et à la CI. Les autres fournisseurs conformes
(Authentik, Okta, ...) sont pris en charge au mieux : ils fonctionnent s'ils
remplissent les exigences ci-dessous.

Les clés `[oidc]` sont documentées dans
[dropr.example.toml](../../dropr.example.toml) et
[ARCHITECTURE.md](../ARCHITECTURE.md) §5. La conception est décrite dans
[DESIGN.md](../DESIGN.md) §5.1. Le déroulé complet d'un déploiement est dans
[deploiement.md](deploiement.md).

## Ce que Dropr exige

| Exigence | Pourquoi | Contrôle |
|---|---|---|
| **Un seul émetteur**, chargé par découverte, comparé exactement à `iss` | L'identité est `(iss, sub)`. Un émetteur multi-locataire accepterait des jetons de n'importe quel locataire | Les émetteurs à gabarit (`{tenantid}`) et les `common`, `organizations`, `consumers` d'Entra sont refusés au démarrage |
| **Authorization Code avec PKCE S256** | Injection de code et CSRF de connexion | La production refuse un fournisseur qui n'annonce pas S256, sauf `allow_unadvertised_pkce = true` |
| Authentification client **`private_key_jwt`** (RFC 7523) | Aucun secret partagé à divulguer | `client_auth = "client_secret"` est réservé au mode dev |
| **Refresh tokens** | Revalidation | La production refuse un fournisseur qui ne propose ni le grant `refresh_token` ni `offline_access` |
| **Une revendication de rôle** dans l'ID token contenant `required_role` | Autorisation | Vérifiée à chaque connexion et à chaque revalidation |
| **Signatures d'ID token asymétriques** | `none` et HS* ne sont jamais acceptés | Le démarrage échoue si la découverte ne liste aucun algorithme asymétrique |
| **Points d'accès en `https://`** | | `http://localhost` n'est autorisé qu'en mode dev |

Détails :

* **URI de redirection** : `https://<hôte>/auth/callback`, correspondance
  exacte, déduite de `public_url`. N'enregistrez rien d'autre.
* **Déconnexion** : `https://<hôte>/login` est l'URI de redirection après
  déconnexion (déconnexion initiée par le client, quand la découverte fournit un
  `end_session_endpoint`). `https://<hôte>/auth/frontchannel-logout` est l'URL
  de déconnexion front-channel ; quand le fournisseur l'appelle, Dropr ferme les
  sessions correspondantes. Les sessions sont retrouvées par la revendication
  `sid` de l'ID token avec lequel elles ont été ouvertes : si le fournisseur ne
  met pas `sid` dans les ID tokens, la déconnexion front-channel ne trouve rien
  (l'appel réussit quand même) et Dropr journalise un avertissement. Vérifiez
  que votre fournisseur émet `sid`.
* **Revendication de rôle** : `role_claim` est un nom de revendication ou un
  chemin pointé (`realm_access.roles`). La valeur peut être une chaîne ou un
  tableau de chaînes. Si `required_role` n'y figure pas, la connexion est
  refusée avec une page 403 et aucun compte n'est créé.
* **Revalidation** : tous les `revalidate_every` (15 minutes par défaut, entre
  1m et 1h), Dropr échange le refresh token stocké. Le nouvel ID token doit
  passer tous les contrôles de connexion, porter le même `sub` et contenir
  toujours le rôle. Tout échec, y compris un fournisseur injoignable, ferme la
  session. Désactiver un utilisateur ou révoquer ses sessions chez le
  fournisseur prend donc effet dans cet intervalle. Si un rafraîchissement ne
  renvoie pas d'ID token, Dropr interroge le point d'accès userinfo à la place
  et refuse si le rôle y manque.
* **Perte d'accès** : quand une revalidation ou une connexion constate que le
  rôle (ou une revendication exigée) manque, les liens de partage de
  l'utilisateur expirent définitivement et ses liens de demande sont mis en
  pause jusqu'à une connexion avec le rôle. Les autres échecs de revalidation
  (fournisseur injoignable, refresh token rejeté, jeton invalide) ferment
  seulement la session.
* **`dropr user revoke <user>`** ferme immédiatement les sessions de
  l'utilisateur, expire ses liens de partage et met en pause ses liens de
  demande. Ce n'est pas un blocage : la connexion suivante n'est pas empêchée,
  et une connexion réussie (avec le rôle) rouvre les liens de demande (les
  partages restent expirés).
* **`dropr user disable <user>`** est le blocage local : Dropr refuse les
  connexions et les sessions du compte, et ses liens de demande restent fermés,
  jusqu'à `dropr user enable <user>` ; la commande ferme aussi les sessions et
  expire les liens de partage. Pour retirer quelqu'un, retirez le rôle (ou
  désactivez le compte) chez le fournisseur d'abord, puis lancez
  `dropr user disable` ; `dropr user purge` supprime ses liens et ses fichiers.
* **`required_claims`** : correspondances exactes optionnelles sur des
  revendications de l'ID token, par exemple `{ tid = "<tenant-id>" }`. Elles ne
  peuvent pas remplacer les revendications enregistrées (`iss`, `aud`, `sub`,
  `exp`, ...).
* **Clé client** : `client_key_file` contient une clé privée PEM non chiffrée
  (RSA d'au moins 2048 bits, ou EC P-256), suivie de son certificat quand le
  fournisseur identifie les clés par certificat. Les clés chiffrées sont
  refusées ; protégez le fichier par ses permissions. La production refuse un
  certificat expiré et Dropr avertit 30 jours avant l'expiration. L'algorithme
  d'assertion est le premier de PS256, RS256 (RSA) ou ES256 (EC) que le
  fournisseur annonce ; `client_assertion_alg` le force. Pour faire une
  rotation, enregistrez le nouveau certificat à côté de l'ancien, remplacez le
  fichier, redémarrez, vérifiez une connexion, puis supprimez l'ancien
  certificat.
* **Le MFA** est l'affaire du fournisseur. Exigez-le, résistant à
  l'hameçonnage si possible : une connexion volée ne permet pas de lire les
  fichiers reçus, mais elle permet de créer des partages et de nouveaux liens de
  demande au nom du propriétaire.
* **Ne changez pas d'émetteur et ne recréez pas l'enregistrement du client** à
  la légère. Un nouvel émetteur, ou un fournisseur dont le `sub` est propre à
  chaque client (pairwise), donne une nouvelle identité à chaque utilisateur.
  `dropr user migrate` rattache les comptes existants.

Une paire de clés et un certificat pour `private_key_jwt` :

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout key.pem -out cert.pem
cat key.pem cert.pem > oidc_key.pem    # oidc.client_key_file
```

Déposez `cert.pem` chez le fournisseur. Gardez `oidc_key.pem` sur l'hôte Dropr
uniquement.

## Microsoft Entra ID

1. **Inscription d'application** (App registration) : mono-locataire
   (« Comptes dans cet annuaire organisationnel uniquement »), plateforme
   **Web**, URI de redirection `https://<hôte>/auth/callback`. Notez l'ID
   d'application (client) et l'ID de l'annuaire (locataire). Ne créez pas de
   secret client.
2. **Certificat** : Certificats et secrets, déposez `cert.pem`. Entra retrouve
   la clé grâce à l'en-tête `x5t#S256` qu'envoie Dropr ; rien d'autre à régler.
3. **Rôle d'application** : créez un rôle de valeur `Dropr.User` (sensible à la
   casse), types de membres autorisés Utilisateurs/Groupes. Les rôles
   d'application évitent le comportement de dépassement de groupes (group
   overage) d'Entra.
4. **Application d'entreprise** : passez *Affectation obligatoire* à Oui, puis
   attribuez le rôle à des utilisateurs ou des groupes. Entra refuse les
   utilisateurs non affectés avant qu'ils n'atteignent Dropr.
5. **URL de déconnexion front-channel** :
   `https://<hôte>/auth/frontchannel-logout`. Ajoutez `https://<hôte>/login`
   comme URI après déconnexion si votre locataire l'exige.
6. **Accès conditionnel** : une stratégie ciblant l'application et exigeant un
   MFA résistant à l'hameçonnage est fortement recommandée.

Les revendications `roles`, `sub`, `tid` et `name` sont présentes par défaut
dans l'ID token v2.0. La déconnexion front-channel a aussi besoin de `sid` dans
l'ID token : vérifiez que votre locataire l'émet, sinon ajoutez-la comme
revendication facultative (Configuration du jeton → Ajouter une revendication
facultative → ID → `sid`). Dropr journalise un WARN par processus (« ID token
has no sid claim ») quand l'ID token d'une connexion n'en a pas : connectez-vous
une fois après la configuration et consultez le journal. Laissez désactivés les
flux de client public et l'octroi implicite.

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

* `allow_unadvertised_pkce = true` est obligatoire : Entra prend en charge PKCE
  S256 mais ne l'annonce pas dans la découverte. Dropr envoie toujours le défi
  S256.
* `required_claims.tid` est optionnel mais recommandé. Dropr avertit en son
  absence et refuse de démarrer s'il diffère du locataire de `issuer`.
* `offline_access` fournit le refresh token utilisé pour la revalidation.
* Le `sub` d'Entra est propre à chaque inscription d'application. Recréer
  l'inscription change l'identité de tous les utilisateurs.
* Les clouds souverains (`login.microsoftonline.us`,
  `login.chinacloudapi.cn`, ...) suivent les mêmes règles.

## Keycloak

[dev/keycloak/dropr-realm.json](../../dev/keycloak/dropr-realm.json) est le
realm de développement, importé par `make keycloak-up`. C'est un modèle
fonctionnel : rôle de realm `Dropr.User`, un client `private_key_jwt`
(`dropr-pkjwt`) et un client à secret réservé au dev (`dropr`), PKCE S256
obligatoire, déconnexion front-channel et un mapper de rôle. Toutes les clés et
tous les mots de passe qu'il contient sont des valeurs de test publiques.

Pour un vrai realm :

1. Utilisez un realm dédié (pas `master`) avec le MFA dans son flux
   d'authentification.
2. Créez le rôle de realm `Dropr.User` et attribuez-le à des utilisateurs ou à
   un groupe.
3. Créez un client OpenID Connect avec l'authentification client activée, le
   flux standard uniquement, l'URI de redirection
   `https://<hôte>/auth/callback` et l'URI de redirection après déconnexion
   `https://<hôte>/login`.
4. Identifiants : **Signed JWT**, algorithme de signature PS256 ou RS256.
   Importez `cert.pem` sous *Keys* et notez le `kid` qu'affiche Keycloak.
5. Avancé : méthode PKCE `S256`. Déconnexion : URL de déconnexion front-channel
   `https://<hôte>/auth/frontchannel-logout`.
6. **Mapper de rôle** : dans le scope dédié du client, ajoutez un mapper *User
   Realm Role*, nom de revendication `realm_access.roles`, multivalué, **Add to
   ID token activé**. Par défaut, Keycloak ne met les rôles de realm que dans
   l'access token ; sans ce mapper, chaque connexion reçoit une 403.

```toml
[oidc]
issuer          = "https://auth.example.com/realms/<realm>"
client_id       = "dropr"
client_auth     = "private_key_jwt"
client_key_file = "/run/secrets/oidc_key"
client_key_id   = "<kid de l'onglet Keys>"
scopes          = ["openid", "profile"]
role_claim      = "realm_access.roles"
required_role   = "Dropr.User"
display_claim   = "name"
```

* Keycloak associe les clés client par `kid` : mettez dans `client_key_id` la
  valeur qu'il affiche.
* Keycloak annonce PKCE S256 ; `allow_unadvertised_pkce` est inutile.
* Avec `offline_access` dans `scopes`, Keycloak émet des jetons hors ligne qui
  survivent à la fin de la session SSO ; l'accès n'est alors coupé qu'en
  désactivant l'utilisateur ou en révoquant la session hors ligne. Sans lui
  (comme ci-dessus), la revalidation suit la session SSO : gardez *SSO Session
  Idle* à au moins 30 minutes et *SSO Session Max* à au moins 8 heures (les
  limites de session propres à Dropr).
* Un rôle de client fonctionne aussi :
  `role_claim = "resource_access.<client-id>.roles"`.
