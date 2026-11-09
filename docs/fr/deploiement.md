# Déployer Dropr

Ce guide décrit la mise en production d'une instance Dropr, de l'obtention du
binaire à l'exploitation courante. Il complète la documentation de référence en
anglais, qui fait foi en cas de divergence :

* configuration : [dropr.example.toml](../../dropr.example.toml) et
  [ARCHITECTURE.md §5](../ARCHITECTURE.md#5-config-droprtoml) ;
* fournisseur d'identité : [oidc.md](oidc.md) (traduction de
  [docs/oidc.md](../oidc.md)) ;
* vérification des versions : [SECURITY.md](../../SECURITY.md#verifying-a-release) ;
* risques résiduels : [THREAT_MODEL.md](../THREAT_MODEL.md).

## 1. Ce qu'il faut

* **Un hôte Linux** (amd64 ou arm64). Dropr est un seul processus,
  `dropr serve`, sans base de données, cache ni file de messages externes.
* **Un domaine dédié**. Dropr est toujours servi à la racine de sa propre
  origine : `public_url` n'a pas de chemin (`https://drop.example.com`, pas
  `https://example.com/drop`).
* **Un fournisseur OIDC** où vous pouvez enregistrer un client
  `private_key_jwt` et émettre une revendication de rôle dans l'ID token.
  Microsoft Entra ID est le fournisseur officiellement pris en charge ;
  Keycloak sert au développement et à la CI. Voir [oidc.md](oidc.md).
* **Du disque** pour les blobs chiffrés, plus une marge pour des fichiers
  jusqu'à `limits.max_file_size` (100 Go au maximum). Un seul répertoire,
  `data_dir`, contient la base SQLite (`dropr.db`), les blobs (`blobs/`) et le
  cache ACME (`acme/`).

> **Choisissez `public_url` une fois pour toutes.** Les clés privées des liens
> de demande vivent dans les navigateurs des propriétaires, rattachées à
> l'origine. Changer de schéma ou de nom d'hôte rend illisibles tous les
> fichiers reçus et casse tous les liens déjà distribués.

## 2. Obtenir et vérifier le binaire

Deux possibilités.

**Binaire publié.** Chaque version publie `dropr-<version>-linux-amd64` et
`-arm64`, statiques, avec les fichiers web embarqués. Vérifiez-les avant
installation (nécessite [cosign](https://github.com/sigstore/cosign)) :

```sh
V=v1.0.1    # la version téléchargée
cosign verify-blob --bundle dropr-$V-SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dropr-$V-SHA256SUMS
sha256sum -c --ignore-missing dropr-$V-SHA256SUMS
```

Ou, avec la CLI GitHub, vérifiez l'attestation de provenance, qui prouve aussi
quel workflow, quel commit et quel tag ont produit le binaire :

```sh
gh attestation verify dropr-$V-linux-amd64 --repo Scttpr/Dropr \
  --signer-workflow Scttpr/Dropr/.github/workflows/release.yml
```

Les versions jusqu'à v1.0.0 incluse étaient signées par `ci.yml` et non
`release.yml` : remplacez `release\.yml` par `ci\.yml` dans l'identité
ci-dessus. Elles n'ont ni attestation ni SBOM.

**Build depuis les sources.** Avec Nix, depuis un tag signé :

```sh
git clone https://github.com/scttpr/dropr && cd dropr
git verify-tag v1.0.1 && git checkout v1.0.1
nix build .#dropr    # result/bin/dropr
```

`git verify-tag` demande la clé du mainteneur dans un fichier de signataires
autorisés ; la procédure et l'empreinte de la clé sont dans
[SECURITY.md](../../SECURITY.md#reproduce-the-hashes-yourself).

Installez ensuite le binaire, par exemple dans `/usr/local/bin/dropr`.
`dropr version` affiche la version installée.

## 3. Préparer l'hôte

Faites tourner Dropr sous un compte système dédié, sans shell, propriétaire de
`data_dir` :

```sh
useradd --system --home-dir /var/lib/dropr --shell /usr/sbin/nologin dropr
install -d -m 0700 -o dropr -g dropr /var/lib/dropr
install -d -m 0750 -o root  -g dropr /etc/dropr
```

Les commandes d'administration (`dropr user ...`, `dropr backup`, `dropr gc`)
lisent la même configuration et la même base : lancez-les sous ce même compte
(`sudo -u dropr dropr ...`).

## 4. Les secrets

Dropr charge ses deux secrets depuis des fichiers, jamais depuis le fichier de
configuration, l'environnement ou la base.

**Clé des refresh tokens** (`refresh_key_file`) : 32 octets aléatoires. Elle
chiffre les refresh tokens stockés et le cookie d'état de connexion ; elle ne
protège jamais les fichiers.

```sh
(umask 077; openssl rand -base64 32 > refresh_key)
```

**Clé client OIDC** (`oidc.client_key_file`) : une clé privée PEM non chiffrée
(RSA d'au moins 2048 bits ou EC P-256), suivie de son certificat :

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout key.pem -out cert.pem
cat key.pem cert.pem > oidc_key.pem
```

Déposez `cert.pem` chez le fournisseur ; `oidc_key.pem` ne quitte pas l'hôte
Dropr. Supprimez `key.pem` une fois le fichier combiné créé.

Permissions : un fichier secret lisible par le groupe ou les autres déclenche un
avertissement ; lisible par les autres, la production refuse de démarrer. Les
fichiers sous `/run/credentials/` (credentials systemd) et `/run/secrets/`
(secrets de conteneur) sont exemptés, leurs modes relevant du gestionnaire de
services ou du runtime ; un lien symbolique est résolu d'abord, donc un lien qui
pointe ailleurs est contrôlé comme n'importe quel fichier.

Gardez `refresh_key` à l'écart de la base et de ses sauvegardes : la base plus
cette clé exposent les refresh tokens tant qu'ils sont valides.

## 5. Configurer le fournisseur d'identité

Enregistrez un client mono-locataire avec :

* URI de redirection : `https://<hôte>/auth/callback` (correspondance exacte,
  rien d'autre) ;
* URI de redirection après déconnexion : `https://<hôte>/login` ;
* URL de déconnexion front-channel : `https://<hôte>/auth/frontchannel-logout` ;
* authentification client par certificat (`private_key_jwt`), sans secret ;
* un rôle (par exemple `Dropr.User`) placé dans l'ID token et attribué aux
  utilisateurs autorisés ;
* MFA exigé, résistant à l'hameçonnage si possible.

Les pas à pas pour Entra ID et Keycloak sont dans [oidc.md](oidc.md).

## 6. Écrire `dropr.toml`

Partez de [dropr.example.toml](../../dropr.example.toml). Le chemin par défaut
est `/etc/dropr/dropr.toml` ; toutes les commandes acceptent `--config`. Les
clés inconnues sont des erreurs.

```toml
public_url   = "https://drop.example.com"
mode         = "production"
data_dir     = "/var/lib/dropr"
listen       = ":8443"              # voir §7
tls          = "acme"               # ou "proxy"
acme_email   = "admin@example.com"
refresh_key_file = "/etc/dropr/refresh_key"
login_label  = "Se connecter avec Microsoft"

[limits]
max_file_size  = "5GB"              # 100GB au maximum (unités binaires : 5GB = 5 Gio)
user_quota     = "50GB"
default_expiry = "7d"               # 1h, 1d, 7d ou 30d

[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "<application-id>"
client_auth     = "private_key_jwt"
client_key_file = "/etc/dropr/oidc_key"
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"
required_role   = "Dropr.User"
display_claim   = "name"
required_claims = { tid = "<tenant-id>" }
allow_unadvertised_pkce = true      # Entra ID uniquement
```

Les secrets placés dans `/etc/dropr` doivent appartenir à `root:dropr` en mode
`0640`, ce qui donne un avertissement au démarrage, ou à `dropr` en `0600`.

Clés optionnelles utiles :

| Clé | Défaut | Rôle |
|---|---|---|
| `log_level` | `"info"` | `debug`, `info`, `warn`, `error` |
| `redirect_http` / `redirect_listen` | `false` / `":8080"` | mode ACME : un second écouteur qui redirige HTTP vers HTTPS (301) |
| `limits.disk_headroom` | auto | espace libre à conserver après avoir accepté un envoi ; auto = max(1 Gio, 5 % du disque) |
| `limits.max_transfers` | `512` | envois de parts + téléchargements simultanés, pour toute l'instance |
| `limits.max_transfers_per_ip` | `32` | idem par adresse cliente (IPv6 par /56) |
| `limits.min_transfer_rate` | `"4KB"` | par seconde, moyenné sur 60 s ; les transferts plus lents sont coupés ; `"0"` désactive |
| `oidc.revalidate_every` | `"15m"` | entre 1m et 1h |

La liste complète est dans
[ARCHITECTURE.md §5](../ARCHITECTURE.md#5-config-droprtoml).

## 7. TLS : ACME ou reverse proxy

### Mode `acme` (par défaut)

Dropr obtient et renouvelle lui-même ses certificats Let's Encrypt, par le défi
TLS-ALPN-01 : **seul le port 443 est nécessaire**, et il doit être joignable
depuis Internet. Les certificats sont mis en cache dans `data_dir/acme`.

* Écoutez sur 443 : `listen = ":443"`, ou sur un port haut redirigé vers 443
  par le pare-feu. Pour lier 443 sans root, donnez au service la capacité
  `CAP_NET_BIND_SERVICE` (par exemple `AmbientCapabilities=` dans une unité
  systemd).
* Le port 80 est optionnel ; s'il est activé (`redirect_http = true`), il ne fait
  que rediriger vers HTTPS.
* Ajoutez un enregistrement DNS CAA qui autorise Let's Encrypt pour le domaine.

### Mode `proxy`

Dropr parle HTTP en clair sur une adresse locale ou un socket Unix, derrière
votre propre reverse proxy qui termine TLS.

```toml
tls             = "proxy"
listen          = "127.0.0.1:8080"
trusted_proxies = ["127.0.0.1"]
```

ou, sur un socket Unix :

```toml
tls    = "proxy"
listen = "unix:/run/dropr.sock"
trust_unix_socket_proxy = true      # ou trusted_proxies
```

Règles :

* `public_url` doit rester en `https://` ; Dropr refuse de démarrer sinon.
* **`trusted_proxies` est obligatoire** avec un écouteur TCP (l'adresse du
  proxy, en CIDR). Sur un socket Unix, il faut `trusted_proxies` ou
  `trust_unix_socket_proxy = true`. Sans cela, tous les clients partageraient
  une seule adresse et un seul compteur de limitation de débit : la production
  refuse de démarrer.
* Le proxy doit transmettre `X-Forwarded-For`. `X-Forwarded-Proto` et
  `X-Forwarded-Host` sont ignorés : `public_url` fait autorité.
* Les envois se font par parts d'un peu plus de 32 Mio chiffrées : la taille de
  corps acceptée par le proxy doit être d'au moins 33 Mio (par exemple
  `client_max_body_size 64m;` sous nginx). Désactivez la mise en tampon des
  requêtes et des réponses pour ne pas stocker de gros fichiers sur le proxy, et
  laissez des délais assez longs pour des téléchargements de plusieurs Go.
* Dropr pose lui-même HSTS, la CSP et les autres en-têtes de sécurité : le proxy
  ne doit pas les remplacer.

## 8. Démarrer et superviser

```sh
sudo -u dropr dropr serve --config /etc/dropr/dropr.toml
```

Au démarrage, Dropr valide la configuration puis interroge la découverte du
fournisseur. En production, il refuse de démarrer sur : un `public_url` ou un
émetteur qui n'est pas en `https`, l'authentification `client_secret`, un
fournisseur sans PKCE S256, sans `private_key_jwt` ou sans refresh tokens, un
émetteur multi-locataire, le mode proxy sans `trusted_proxies`, un fichier
secret lisible par tous, un certificat client expiré. Le message d'erreur
indique la cause.

Faites tourner `dropr serve` sous votre gestionnaire de services (systemd ou
conteneur) avec redémarrage automatique. Le dépôt ne fournit pas d'unité prête
à l'emploi ; les points à reprendre :

* exécution sous le compte `dropr`, accès en écriture à `data_dir` seulement ;
* `CAP_NET_BIND_SERVICE` si Dropr lie le port 443 ;
* secrets passés de préférence par `LoadCredential=` (systemd), qui les expose
  sous `/run/credentials/` ;
* sonde de santé : `dropr healthcheck` interroge `GET /healthz` du serveur local
  et renvoie 0 s'il est sain (`--url` pour une autre adresse).

Les journaux sont des lignes JSON sur la sortie standard (`log/slog`), sans
adresse IP en clair (empreintes à clé seulement), ni jetons, ni fragments de
liens. Chaque ligne porte l'identifiant de requête (`rid`). La rétention est
l'affaire de votre collecteur ; 7 jours suffisent.

Les tâches de nettoyage (liens expirés, envois abandonnés, sessions et jetons
expirés, blobs orphelins) tournent dans
`dropr serve` toutes les 5 minutes. `dropr gc` les lance une fois à la main.

### Première connexion

1. Ouvrez `https://<hôte>/` et connectez-vous avec un compte qui a le rôle.
   Un compte sans le rôle reçoit une page 403 et aucun compte n'est créé.
2. Vérifiez les journaux. Si vous voyez `ID token has no sid claim`, la
   déconnexion front-channel ne fonctionnera pas : activez `sid` chez le
   fournisseur ([oidc.md](oidc.md)).
3. `sudo -u dropr dropr user list` doit afficher le compte.

### Vérifier le code servi

Le chiffrement de bout en bout repose sur le fait que le navigateur exécute le
code publié. Après chaque déploiement, comparez les fichiers servis par
l'instance aux empreintes signées de la version
(`dropr-assets-<version>.sha256`). Le script est dans
[SECURITY.md](../../SECURITY.md#check-what-a-running-instance-serves) ; lancez-le
depuis l'extérieur du serveur, et idéalement depuis plusieurs réseaux et à
intervalles réguliers depuis un hôte de supervision. Toute ligne `DIFF` signifie
que l'instance ne sert pas le code publié.

## 9. Exploitation

### Sauvegardes

```sh
sudo -u dropr dropr backup --out /var/backups/dropr/dropr-$(date +%F).db
```

`dropr backup` écrit une copie cohérente de la base, à chaud. Sauvegardez aussi
`data_dir/blobs` : ils sont déjà chiffrés. La base contient les refresh tokens
chiffrés et les clés de fichiers enveloppées par HPKE : protégez-la, et ne
stockez pas `refresh_key` avec elle.

Ce qu'aucune sauvegarde serveur ne couvre : **les clés privées des liens de
demande ne sont pas sur le serveur**. Elles vivent dans le profil de navigateur
du propriétaire. Effacer les données du site, une fenêtre privée, un profil
réinitialisé ou un appareil perdu rendent les fichiers reçus illisibles. Dites
aux utilisateurs de créer leurs liens de demande dans leur navigateur habituel
et de télécharger rapidement les fichiers reçus.

Restauration : restaurez la base uniquement depuis une sauvegarde postérieure à
la création des liens de demande en cours. Une base plus ancienne qui omet un
lien vivant fait supprimer sa clé par le navigateur du propriétaire, et les
fichiers de ce lien sont alors perdus. Demandez aux propriétaires de télécharger
leurs fichiers reçus avant une restauration.

### Gérer les comptes

`<user>` est un identifiant utilisateur, ou un sujet qui correspond à un seul
compte (`dropr user list` les affiche).

| Commande | Effet |
|---|---|
| `dropr user list` | liste les comptes |
| `dropr user revoke <user>` | ferme immédiatement les sessions, expire les liens de partage, met en pause les liens de demande. Ce n'est pas un blocage : la prochaine connexion avec le rôle rouvre les liens de demande |
| `dropr user disable <user>` | blocage local : connexions et sessions refusées, liens de demande fermés, jusqu'à `enable`. Ferme aussi les sessions et expire les liens de partage |
| `dropr user enable <user>` | lève un `disable` (les liens de partage expirés le restent) |
| `dropr user purge <user>` | supprime le compte, ses liens et ses fichiers |
| `dropr user migrate` | rattache les comptes existants après un changement d'émetteur |

Chaque action d'administration écrit une ligne WARN `admin action` sur la
sortie d'erreur, avec l'UID Unix qui l'a lancée.

**Départ d'un utilisateur** : retirez le rôle (ou désactivez le compte) chez le
fournisseur d'abord, puis `dropr user disable <user>`. Sans action locale, la
session meurt de toute façon à la revalidation suivante (15 minutes par défaut).
`dropr user purge` supprime ensuite ses données.

### Rotation des secrets

* **`refresh_key`** : remplacez le fichier et redémarrez. Les sessions ne
  peuvent plus se revalider et les utilisateurs se reconnectent ; les connexions
  en cours échouent une fois. Après une fuite suspectée : rotation,
  `dropr user disable` pour qui doit perdre l'accès tout de suite, et révocation
  des sessions chez le fournisseur.
* **Clé client OIDC** : enregistrez le nouveau certificat à côté de l'ancien
  chez le fournisseur, remplacez le fichier, redémarrez, vérifiez une connexion,
  puis supprimez l'ancien certificat. Dropr avertit 30 jours avant l'expiration
  du certificat et refuse de démarrer en production s'il a expiré.

### Mettre à jour

Téléchargez et vérifiez la nouvelle version (§2), sauvegardez la base,
remplacez le binaire, redémarrez, puis vérifiez le code servi (§8). Seule la
dernière version reçoit les correctifs de sécurité
([SECURITY.md](../../SECURITY.md#supported-versions)).

## 10. Avant la mise en production

* [ ] `public_url` définitif, en `https://`, sans chemin.
* [ ] Binaire vérifié (cosign ou attestation) ou construit depuis un tag signé.
* [ ] `mode = "production"`, démarrage sans erreur.
* [ ] Secrets hors du fichier de configuration, non lisibles par les autres ;
      `refresh_key` stocké à part des sauvegardes de la base.
* [ ] Client OIDC mono-locataire, `private_key_jwt`, rôle dans l'ID token,
      attribution obligatoire, MFA exigé.
* [ ] `sid` présent dans l'ID token (pas d'avertissement au premier login).
* [ ] Mode ACME : port 443 joignable, enregistrement CAA. Mode proxy :
      `trusted_proxies`, taille de corps ≥ 33 Mio, pas de mise en tampon.
* [ ] Sauvegardes de la base et des blobs planifiées, restauration testée.
* [ ] Vérification des fichiers servis après déploiement.
* [ ] Utilisateurs informés : un lien de partage est le secret ; les fichiers
      reçus ne s'ouvrent que dans le navigateur qui a créé le lien de demande.
