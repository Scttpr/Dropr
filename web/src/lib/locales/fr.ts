/**
 * French catalog. Typography: no-break space (U+00A0) before ":" and "%",
 * narrow no-break space (U+202F) before "?", "!", ";" and inside « ».
 * Wording shared with the server (internal/i18n/fr.go) must stay identical.
 *
 * @module
 */

import type { Messages } from "./en.ts";

const plural = new Intl.PluralRules("fr");
/** French plural: 0 and 1 are singular. */
const p = (n: number, one: string, other: string): string => (plural.select(n) === "one" ? one : other);
const nb = "\u00a0";
const nnb = "\u202f";
const q = (s: string): string => `«${nnb}${s}${nnb}»`;

export const fr: Messages = {
  // ---- Formatting -------------------------------------------------------
  byteUnits: ["o", "Ko", "Mo", "Go", "To"],
  decimalSeparator: ",",
  unitSpace: nb,
  exactBytes: (n) => `${n}${nb}octets`,
  etaFewSeconds: "encore quelques secondes",
  etaSeconds: (n) => `encore environ ${n}${nb}s`,
  etaMinutes: (n) => `encore environ ${n}${nb}min`,
  etaHours: (h) => `encore environ ${h}${nb}h`,
  etaHoursMinutes: (h, m) => `encore environ ${h}${nb}h ${m}${nb}min`,
  expired: "Expiré",
  expiresInMinutes: (n) => `Expire dans ${n} ${p(n, "minute", "minutes")}`,
  expiresInHours: (n) => `Expire dans ${n} ${p(n, "heure", "heures")}`,
  expiresInDays: (n) => `Expire dans ${n} ${p(n, "jour", "jours")}`,

  // ---- Generic errors ----------------------------------------------------
  damaged: `Le fichier n'a pas pu être déchiffré${nb}: il a été endommagé ou modifié, ou le lien est erroné.`,
  malformed: "Le fichier ou le lien est mal formé.",
  cancelled: "Annulé.",
  storageFull: "Votre disque ou le stockage du navigateur est plein.",
  unexpected: "Une erreur s'est produite. Veuillez recharger la page et réessayer.",
  keyStoreUnavailable:
    `Ce navigateur ne peut pas conserver les clés de vos liens de dépôt${nb}: il ne peut donc ni créer de lien ni ouvrir les fichiers reçus par ce biais. ` +
    "Autorisez ce site à enregistrer des données (la navigation privée le bloque souvent), ou utilisez un autre navigateur.",
  ownerUnknown: "Dropr n'a pas pu déterminer quel compte est connecté et ne peut donc pas utiliser les clés de vos liens de dépôt. Veuillez recharger la page.",
  apiCodes: {
    unauthenticated: "Votre session a expiré. Veuillez vous reconnecter.",
    bad_request: "La requête n'a pas été acceptée. Veuillez recharger la page et réessayer.",
    rate_limited: "Trop de tentatives. Veuillez patienter un instant et réessayer.",
    too_large: "Ce fichier ou cette requête est trop volumineux.",
    invalid_size: "La taille du fichier ne correspond pas à ses parties. Veuillez réessayer.",
    quota_exceeded: "Il n'y a plus assez d'espace de stockage pour ce fichier.",
    disk_full: "Le serveur n'a plus d'espace disque. Veuillez réessayer plus tard.",
    not_found: `Introuvable${nb}: cet élément n'existe pas, ou a été supprimé ou révoqué.`,
    expired: "Ce lien a expiré.",
    exhausted: "Ce lien a atteint sa limite de téléchargements.",
    closed: "Ce lien n'accepte plus de fichiers.",
    link_full: `Ce lien ne peut pas accepter ce fichier${nb}: il a atteint sa limite de fichiers ou de taille.`,
    bad_token: "Ce lien d'envoi n'est pas valide. Veuillez recommencer l'envoi.",
    already_complete: "Cet envoi est déjà terminé.",
    bad_part: "Ce numéro de partie n'est pas valide pour ce fichier.",
    wrong_part_size: "Cette partie n'a pas la taille attendue.",
    bad_parts: "Le nombre de parties ne correspond pas à ce fichier.",
    incomplete: "Des parties du fichier manquent. L'envoi va reprendre.",
    token_used: "Ce lien de téléchargement a été utilisé. Rechargez la page pour télécharger à nouveau.",
    too_slow: "La connexion est trop lente. L'envoi va être relancé.",
    internal: "Une erreur s'est produite sur le serveur. Veuillez réessayer.",
    csrf: "Cette requête a été bloquée car elle ne provient pas de ce site. Rechargez la page et réessayez.",
    too_many_transfers: "Trop d'envois ou de téléchargements sont en cours. Veuillez réessayer dans un instant.",
  },
  statusExpired: "Ce lien a expiré.",
  statusExhausted: "Ce lien a atteint sa limite de téléchargements.",
  statusClosed: "Ce lien n'accepte plus de fichiers.",
  statusQuota: "Il n'y a plus assez d'espace de stockage pour ce fichier.",
  statusTooLarge: "Ce fichier est trop volumineux.",
  statusNetwork: "Impossible de joindre le serveur. Vérifiez votre connexion et réessayez.",
  statusBadRequest: "La requête n'a pas été acceptée. Veuillez recharger la page et réessayer.",
  statusUnauthenticated: "Votre session a expiré. Veuillez vous reconnecter.",
  statusForbidden: "Vous n'êtes pas autorisé à effectuer cette action.",
  statusNotFound: "Ce lien n'existe pas ou a été révoqué.",
  statusTimeout: "Le serveur a mis trop de temps à répondre. Veuillez réessayer.",
  statusConflict: "Cet élément a changé entre-temps. Veuillez recharger la page.",
  statusGone: "Ce lien a expiré ou n'est plus disponible.",
  statusRateLimited: "Trop de tentatives. Veuillez patienter un instant et réessayer.",
  statusServer: "Le serveur a rencontré un problème. Veuillez réessayer dans un instant.",
  statusUnexpected: (what) => `Réponse inattendue du serveur (${what}).`,

  // ---- Transfers ---------------------------------------------------------
  uploading: "Envoi",
  downloading: "Téléchargement",
  encryptingUploading: "Chiffrement et envoi",
  progressStart: (verb, name) => `${verb} de ${q(name)}…`,
  progressPercent: (verb, pc) => `${verb}${nb}: ${pc}${nb}%`,
  progressBytes: (done, total) => `${done} sur ${total}`,
  uploadCancelled: "Envoi annulé.",
  connectionLost: "La connexion a été perdue. L'envoi reprendra là où il s'est arrêté quand vous réessaierez.",
  downloadComplete: "Téléchargement terminé.",
  downloadCompleteCheck: "Téléchargement terminé. Consultez les téléchargements de votre navigateur.",
  downloadCancelled: "Téléchargement annulé.",
  saveFailed: "Le fichier n'a pas pu être enregistré (le téléchargement a été annulé ou le disque est plein).",
  interrupted: "Le téléchargement a été interrompu à plusieurs reprises. Vérifiez votre connexion et réessayez.",
  tooLargeForBrowser: "Ce fichier est trop volumineux pour être téléchargé dans ce navigateur.",
  helperTimeout: "L'assistant de téléchargement n'a pas répondu.",
  inMemoryNotice:
    `Votre navigateur ne peut pas enregistrer directement sur le disque${nb}: le fichier est déchiffré en mémoire et enregistré à la fin.`,
  noSecureDownload:
    "Ce navigateur ne peut pas télécharger de façon sûre des fichiers aussi volumineux. Veuillez utiliser une version récente de Chrome, Edge, Firefox ou Safari.",

  // ---- Link view ---------------------------------------------------------
  copied: "Copié",
  pressToCopy: "Appuyez sur Ctrl+C pour copier",

  // ---- Dashboard ---------------------------------------------------------
  fileTooLarge: (have, limit) => `Ce fichier est trop volumineux (${have}). La limite est de ${limit}.`,
  downloadLimitInvalid: "La limite de téléchargements doit être un nombre entier d'au moins 1, ou rester vide pour aucune limite.",
  maxFilesInvalid: "Le nombre de fichiers doit être un nombre entier d'au moins 1.",
  uploadReady: "Envoi terminé. Votre lien est prêt.",
  shareQrLabel: "QR code du lien de partage",
  creatingRequest: "Création du lien de dépôt…",
  requestReady: "Votre lien de dépôt est prêt.",
  requestQrLabel: "QR code du lien de dépôt",

  // ---- Share recipient ---------------------------------------------------
  missingKey: "Il manque la clé de ce lien (la partie après #). Demandez le lien complet à l'expéditeur.",
  incompleteLink: "Ce lien est incomplet ou endommagé. Demandez le lien complet à l'expéditeur.",
  checkingLink: "Vérification du lien…",
  wrongKey: "La clé de ce lien est erronée ou le fichier est endommagé. Demandez le lien complet à l'expéditeur.",
  shareNotFound: "Ce lien n'existe pas ou a été révoqué par son propriétaire.",
  shareGone: "Ce lien a expiré ou a atteint sa limite de téléchargements.",

  // ---- Request uploader --------------------------------------------------
  requestLinkDamaged: "Ce lien est incomplet ou endommagé. Demandez le lien complet à la personne qui vous l'a envoyé.",
  noMoreFiles: "Ce lien n'accepte plus de fichiers.",
  acceptsMore: (n) =>
    `Ce lien accepte encore ${n} ${p(n, "fichier", "fichiers")}. Veuillez choisir moins de fichiers.`,
  filesTooLarge: (total, left) => `Ces fichiers sont trop volumineux (${total}). Ce lien accepte encore jusqu'à ${left}.`,
  sentItem: (name, size) => `${name} (${size}) — envoyé`,
  cancelledAfter: (sent) => `Annulé. ${sent} ${p(sent, "fichier avait déjà été envoyé", "fichiers avaient déjà été envoyés")}.`,
  cancelledReserved: "Le lien garde la place du fichier annulé pendant 24 heures au plus.",
  errorAfter: (message, sent) =>
    `${message} ${sent} ${p(sent, "fichier avait été envoyé", "fichiers avaient été envoyés")} avant l'erreur.`,

  // ---- Inbox -------------------------------------------------------------
  loadingFiles: "Chargement de vos fichiers…",
  filesReceived: (n, failed, foreign) =>
    `${n} ${p(n, "fichier reçu", "fichiers reçus")}.` +
    (failed > 0
      ? ` ${failed} ${p(failed, "n'a pas pu être déchiffré et a peut-être été altéré", "n'ont pas pu être déchiffrés et ont peut-être été altérés")}.`
      : "") +
    (foreign > 0
      ? ` ${foreign} ${p(foreign, "a été envoyé via un lien créé dans un autre navigateur et ne peut être ouvert que dans celui-ci", "ont été envoyés via des liens créés dans un autre navigateur et ne peuvent être ouverts que dans celui-ci")}.`
      : ""),
  unreadableFile: "Fichier illisible",
  foreignFile: "Envoyé via un lien créé dans un autre navigateur",
  foreignFileNamed: (date) => `le fichier reçu le ${date} via un lien créé dans un autre navigateur`,
  download: "Télécharger",
  downloadNamed: (name) => `Télécharger ${name}`,
  delete: "Supprimer",
  deleteNamed: (name) => `Supprimer ${name}`,
  anotherDownload: "Un autre téléchargement est en cours. Attendez qu'il se termine ou annulez-le.",
  confirmDelete: (name) => `Supprimer ${q(name)}${nnb}? Cette action est irréversible.`,
  deleted: (name) => `${q(name)} supprimé.`,
  confirmDeleteForeign: (date) => `Supprimer le fichier reçu le ${date}${nnb}? Cette action est irréversible.`,
  deletedForeign: (date) => `Fichier reçu le ${date} supprimé.`,

  // ---- Links -------------------------------------------------------------
  revoke: "Révoquer",
  revokeNamed: (label) => `Révoquer le ${label}`,
  confirmRevokeShare: `Révoquer ce lien de partage${nnb}? Il cesse de fonctionner immédiatement et ses fichiers sont supprimés.`,
  confirmRevokeRequest: `Révoquer ce lien de dépôt${nnb}? Il cesse de fonctionner immédiatement et ses fichiers sont supprimés.`,
  shareRevoked: "Lien de partage révoqué.",
  requestRevoked: "Lien de dépôt révoqué.",
  shareLinkLabel: (date) => `lien de partage créé le ${date}`,
  requestLinkLabel: (date) => `lien de dépôt créé le ${date}`,
  countOf: (n, max) => `${n} sur ${max}`,
  singleUse: " (usage unique)",
  limitReached: "Limite atteinte",
  limitReachedHint: `Ce lien ne fonctionne plus. Son fichier est conservé, et compte dans votre espace de stockage, jusqu'à l'expiration du lien${nb}: révoquez-le pour supprimer le fichier dès maintenant.`,
  linkClosed: "Fermé",
  linkClosedHint: "Ce lien n'accepte plus de fichiers. Les fichiers reçus restent dans Fichiers reçus jusqu'à l'expiration du lien.",
  copyLink: "Copier le lien",
  copyLinkNamed: (label) => `Copier le ${label}`,
  otherBrowser: "Autre navigateur",
  otherBrowserHint: `Ce lien a été créé dans un autre navigateur${nb}: copiez-le depuis celui-ci.`,
  requestCopied: "Lien de dépôt copié.",
  copyFailed: "Impossible de copier le lien dans le presse-papiers.",
  loadingLinks: "Chargement de vos liens…",
  linksSummary: (shares, requests) =>
    `${shares} ${p(shares, "lien de partage", "liens de partage")}, ${requests} ${p(requests, "lien de dépôt", "liens de dépôt")}.`,
};
