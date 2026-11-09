# Dropr

[English](README.md) · **Français**

Dépôt de fichiers chiffré de bout en bout, auto-hébergé. Un seul binaire Go,
votre domaine, et votre fournisseur d'identité OIDC existant pour les comptes.

Deux usages, rien de plus :

* **Partage** : un propriétaire envoie un fichier et obtient un lien. Toute
  personne qui a le lien peut télécharger le fichier jusqu'à son expiration ou
  sa révocation.
* **Demande** : un propriétaire crée un lien de demande. Toute personne qui a
  ce lien peut envoyer des fichiers que seul ce propriétaire pourra lire.

Les fichiers vont jusqu'à 100 Go (plafond par défaut : 5 Go). Les envois
reprennent après une coupure ; les téléchargements sont écrits au fil de l'eau
sur le disque. L'interface est en anglais et en français, avec des thèmes
clair, sombre et système.

## Modèle de sécurité

* **Le serveur ne voit jamais le contenu en clair.** Les fichiers et leurs noms
  sont chiffrés dans le navigateur (AES-256-GCM STREAM, WebCrypto uniquement).
  La clé d'un lien de partage est dans le fragment de l'URL, que les navigateurs
  n'envoient jamais au serveur.
* **Les liens de demande utilisent HPKE** (RFC 9180, X25519) avec une paire de
  clés par lien, générée dans le navigateur du propriétaire. La clé privée y
  reste, non exportable. Des identifiants de connexion volés n'ouvrent pas la
  boîte de réception.
* **Connexion uniquement par OIDC** : un seul émetteur épinglé, PKCE,
  `private_key_jwt` en production, et un rôle obligatoire revérifié toutes les
  15 minutes. Pas de comptes locaux.
* **Surface web stricte** : CSP avec Trusted Types et aucun code en ligne, HSTS,
  sessions `__Host-` SameSite=Strict, contrôles CSRF, aucun script tiers.
* **Code navigateur vérifiable** : build reproductible, aucune dépendance
  JavaScript à l'exécution, empreintes des fichiers publiées. Voir
  [SECURITY.md](SECURITY.md).
* **Limites assumées** : qui contrôle le serveur peut servir du JavaScript
  malveillant, et le serveur voit les tailles et les horaires. Les fichiers
  reçus par un lien de demande ne s'ouvrent que dans le navigateur qui a créé le
  lien ; effacer les données du site les rend illisibles, par conception. Lisez
  le [modèle de menace](docs/THREAT_MODEL.md) (en anglais) avant un usage réel.

## Déployer

Le guide de production est dans
**[docs/fr/deploiement.md](docs/fr/deploiement.md)** : binaire vérifié,
secrets, configuration, unité systemd durcie, sauvegardes.

En bref :

```sh
nix build .#dropr    # result/bin/dropr
make build           # bin/dropr (depuis `nix develop`)
```

Vous obtenez un binaire statique unique, avec les modules navigateur, les
gabarits et les styles embarqués. Des binaires Linux amd64 et arm64 sont publiés
à chaque version avec des sommes de contrôle signées, ainsi qu'une image
conteneur signée ([vérifier une version](docs/fr/deploiement.md#2-installer-un-binaire-vérifié)).

```sh
(umask 077; openssl rand -base64 32 > refresh_key)   # chiffre les refresh tokens stockés
dropr serve --config dropr.toml
```

Dropr a besoin :

* d'un fournisseur OIDC où vous pouvez enregistrer un client et émettre une
  revendication de rôle ([docs/fr/oidc.md](docs/fr/oidc.md)) ;
* d'un domaine ; Dropr obtient lui-même son certificat Let's Encrypt
  (`tls = "acme"`) ou tourne derrière votre reverse proxy (`tls = "proxy"`) ;
* d'un répertoire de données (`data_dir`) pour la base SQLite, les blobs
  chiffrés et le cache ACME.

En mode production, Dropr refuse de démarrer sur une configuration dangereuse
(HTTP en clair, secret client, fournisseur sans PKCE ni refresh tokens, proxy
sans `trusted_proxies`, fichiers secrets lisibles par tous). `dropr help` liste
les commandes d'administration : `user list|revoke|disable|enable|purge|migrate`,
`gc`, `backup`, `healthcheck`, `version`. Il n'y a pas d'interface web
d'administration.

## Documentation

En français :

| Document | Contenu |
|---|---|
| [docs/fr/deploiement.md](docs/fr/deploiement.md) | Déploiement de production : binaire, secrets, unité systemd, exploitation |
| [docs/fr/oidc.md](docs/fr/oidc.md) | Exigences du fournisseur d'identité, Entra ID et Keycloak |

En anglais (référence) :

| Document | Contenu |
|---|---|
| [docs/oidc.md](docs/oidc.md) | Identity provider requirements, Entra ID and Keycloak |
| [docs/DESIGN.md](docs/DESIGN.md) | Périmètre, décisions et leurs raisons |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Actifs, attaquants, STRIDE, risques résiduels |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Surface HTTP, modèle de données, configuration, contrats |
| [docs/FORMAT.md](docs/FORMAT.md) | Formats binaires normatifs et vecteurs de test |
| [docs/PAGES.md](docs/PAGES.md) | Contrat DOM des pages et des modules navigateur |
| [SECURITY.md](SECURITY.md) | Signalement, versions maintenues, vérification des versions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Environnement de développement et tests |

En cas de divergence, la version anglaise fait foi.

## État

Pré-version. Une revue de sécurité externe est nécessaire avant un usage réel.

## Licence

MIT, voir [LICENSE](LICENSE).
