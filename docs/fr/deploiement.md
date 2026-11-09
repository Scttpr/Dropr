# Déployer Dropr

[English](../deploy.md) · **Français** — traduction de
[docs/deploy.md](../deploy.md), qui fait foi en cas de divergence.

Un déploiement de production sur un hôte Linux (amd64 ou arm64), géré par
systemd ou Docker.
La référence est ailleurs : toutes les clés de configuration dans
[dropr.example.toml](../../dropr.example.toml) et
[ARCHITECTURE.md §5](../ARCHITECTURE.md#5-config-droprtoml), le fournisseur
d'identité dans [oidc.md](oidc.md), les risques résiduels dans
[THREAT_MODEL.md](../THREAT_MODEL.md).

## 1. Avant de commencer

* **Un nom d'hôte dédié**, par exemple `drop.example.com`. Dropr est servi à la
  racine de sa propre origine. **Choisissez-le une fois pour toutes** : les clés
  des liens de demande vivent dans les navigateurs des propriétaires,
  rattachées à l'origine ; changer de schéma ou de nom d'hôte rend illisibles
  tous les fichiers reçus et casse tous les liens déjà envoyés.
* **Un fournisseur OIDC** où vous pouvez enregistrer un client
  `private_key_jwt` et placer un rôle dans l'ID token ([oidc.md](oidc.md)).
* **Du disque** pour les fichiers chiffrés, avec la place du plus gros envoi
  autorisé.

## 2. Installer un binaire vérifié

Téléchargez `dropr-<version>-linux-amd64` (ou `-arm64`) et les fichiers
`dropr-<version>-SHA256SUMS*` de la dernière version, puis vérifiez la
signature avec [cosign](https://github.com/sigstore/cosign) :

```sh
V=v1.0.1
cosign verify-blob --bundle dropr-$V-SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dropr-$V-SHA256SUMS
sha256sum -c --ignore-missing dropr-$V-SHA256SUMS
install -m 0755 dropr-$V-linux-amd64 /usr/local/bin/dropr
```

Le build depuis un tag signé et les attestations de provenance sont décrits
dans [SECURITY.md](../../SECURITY.md#verifying-a-release).

## 3. Compte et secrets

En root. Le compte de service possède ses deux secrets ; la configuration
reste à root, en lecture seule pour le service.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin dropr
install -d -m 0750 -o root -g dropr /etc/dropr
cd /etc/dropr && umask 077

# Chiffre les refresh tokens stockés. Jamais avec les sauvegardes de la base.
openssl rand -base64 32 > refresh_key

# Clé client OIDC : clé privée suivie de son certificat.
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 730 \
  -subj "/CN=dropr" -keyout key.pem -out cert.pem
cat key.pem cert.pem > oidc_key && rm key.pem

chown dropr:dropr refresh_key oidc_key && chmod 0400 refresh_key oidc_key
```

Enregistrez le client chez le fournisseur et déposez-y `cert.pem`
([oidc.md](oidc.md)). Dropr avertit 30 jours avant l'expiration du certificat
et refuse de démarrer une fois qu'il a expiré.

## 4. Configuration

`/etc/dropr/dropr.toml`, mode `0640`, propriétaire `root:dropr`. L'exemple
utilise Entra ID ; [oidc.md](oidc.md) donne le bloc `[oidc]` pour Keycloak.

```toml
public_url       = "https://drop.example.com"
mode             = "production"
data_dir         = "/var/lib/dropr"
listen           = ":443"
tls              = "acme"
acme_email       = "admin@example.com"
refresh_key_file = "/etc/dropr/refresh_key"

[oidc]
issuer          = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id       = "<application-id>"
client_auth     = "private_key_jwt"
client_key_file = "/etc/dropr/oidc_key"
scopes          = ["openid", "profile", "offline_access"]
role_claim      = "roles"
required_role   = "Dropr.User"
required_claims = { tid = "<tenant-id>" }
allow_unadvertised_pkce = true
```

En mode `acme`, Dropr obtient lui-même son certificat Let's Encrypt par le
défi TLS-ALPN-01 : seul le port 443 doit être joignable depuis Internet.
Ajoutez un enregistrement DNS CAA qui autorise Let's Encrypt pour le nom
d'hôte.

**Derrière un reverse proxy**, mettez plutôt `tls = "proxy"`,
`listen = "127.0.0.1:8080"` et `trusted_proxies = ["127.0.0.1"]`. Le proxy
doit transmettre `X-Forwarded-For`, accepter des corps de requête d'au moins
33 Mio (`client_max_body_size 64m;` sous nginx), ne mettre en tampon ni les
requêtes ni les réponses, et laisser intacts les en-têtes de sécurité posés
par Dropr.

## 5. Unité systemd

`/etc/systemd/system/dropr.service` :

```ini
[Unit]
Description=Dropr
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/dropr serve --config /etc/dropr/dropr.toml
Restart=on-failure
User=dropr
Group=dropr
StateDirectory=dropr
StateDirectoryMode=0700
UMask=0077

# Lie le port 443 sans root. Supprimez ces deux lignes derrière un reverse proxy.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now dropr
journalctl -u dropr -f
```

En mode production, Dropr refuse de démarrer sur une configuration dangereuse
et en journalise la raison. Connectez-vous ensuite sur
`https://drop.example.com` avec un compte qui a le rôle ;
`sudo -u dropr dropr user list` doit l'afficher. Une ligne
`ID token has no sid claim` signifie que la déconnexion front-channel ne
fonctionnera pas : corrigez-le chez le fournisseur ([oidc.md](oidc.md)).

**Vérifiez le code servi** après chaque déploiement, depuis l'extérieur du
serveur, avec le script de
[SECURITY.md](../../SECURITY.md#check-what-a-running-instance-serves). Toute
ligne `DIFF` signifie que l'instance ne sert pas le code publié.

## 6. Ou avec Docker

Docker Engine avec Compose v2 peut faire tourner l'image signée à la place du
binaire et de l'unité (§2, §5), avec le même compte, les mêmes secrets et la
même configuration (§3, §4). L'image est le binaire publié sur distroless :
ni shell, ni gestionnaire de paquets. Les versions postérieures à v1.0.1 la
publient.

Vérifiez l'image et notez son empreinte (digest), puis créez le répertoire de
données que systemd créerait sinon :

```sh
V=<version>
cosign verify ghcr.io/scttpr/dropr:$V \
  --certificate-identity-regexp '^https://github.com/Scttpr/Dropr/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.[0].critical.image."docker-manifest-digest"'
install -d -m 0700 -o dropr -g dropr /var/lib/dropr
id dropr    # uid et gid pour le fichier compose
```

`/etc/dropr/compose.yaml` :

```yaml
services:
  dropr:
    image: ghcr.io/scttpr/dropr:<version>@sha256:<digest>
    user: "<uid>:<gid>"
    restart: unless-stopped
    stop_grace_period: 35s
    ports:
      - "443:443"
    sysctls:
      net.ipv4.ip_unprivileged_port_start: 0
    volumes:
      - /etc/dropr:/etc/dropr:ro
      - /var/lib/dropr:/var/lib/dropr
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 512
    logging:
      driver: local
```

```sh
cd /etc/dropr && docker compose up -d
docker compose logs -f
```

* Le conteneur tourne sous `dropr` : il lit les secrets et les données avec
  les permissions du §3. Le sysctl lui permet d'écouter sur le port 443 dans
  son propre espace de noms réseau, sans root ni capacités. Le contrôle de
  santé de l'image lance `dropr healthcheck` ; `docker compose ps` en affiche
  le résultat.
* **Les ports publiés contournent le pare-feu de l'hôte** : les règles ufw et
  firewalld ne s'y appliquent pas. Ne publiez que le 443, et précisez une
  adresse (`"203.0.113.10:443:443"`) si l'hôte en a plusieurs.
* Un seul conteneur : la base SQLite ne supporte pas plusieurs instances sur
  les mêmes données.
* **Derrière un reverse proxy** sur l'hôte, reprenez les réglages proxy du §4
  et remplacez `ports` et `sysctls` par `network_mode: host`. Dropr écoute alors
  sur `127.0.0.1:8080` de l'hôte et rien n'est publié.

Connectez-vous ensuite et vérifiez le code servi comme au §5.

## 7. Exploitation

Les commandes d'administration tournent sous le compte de service :
`sudo -u dropr dropr help`, ou avec Docker
`docker compose exec dropr dropr help` depuis `/etc/dropr`.

* **Sauvegardes.** `sudo -u dropr dropr backup --out <fichier>` écrit une copie
  cohérente de la base pendant que Dropr tourne ; copiez aussi
  `/var/lib/dropr/blobs` (déjà chiffrés). Avec Docker, `--out` doit être sous
  `/var/lib/dropr`, seul chemin accessible en écriture. Gardez `refresh_key`
  hors de ces sauvegardes.
* **Les clés des liens de demande ne sont pas sur le serveur.** Elles vivent
  dans le profil de navigateur du propriétaire : effacer les données du site,
  une fenêtre privée ou un appareil perdu rendent les fichiers reçus
  illisibles. Dites aux utilisateurs de créer leurs liens de demande dans leur
  navigateur habituel et de télécharger rapidement les fichiers reçus.
* **Ne restaurez qu'une base plus récente que les liens de demande ouverts.**
  Une base plus ancienne, qui ignore un lien vivant, fait supprimer sa clé par
  le navigateur du propriétaire, et les fichiers de ce lien sont perdus.
* **Départ d'un utilisateur.** Retirez le rôle chez le fournisseur, puis
  `sudo -u dropr dropr user disable <user>`.
* **Mises à jour.** Vérifiez le nouveau binaire (§2), sauvegardez, remplacez-le,
  `systemctl restart dropr`, vérifiez le code servi (§5). Avec Docker,
  vérifiez la nouvelle image (§6), sauvegardez, changez la ligne `image`,
  `docker compose up -d`. Seule la dernière version reçoit les correctifs de
  sécurité.
