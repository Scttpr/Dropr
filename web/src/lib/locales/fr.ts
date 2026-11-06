/**
 * French catalog. Typography: no-break space (U+00A0) before ":" and "%",
 * narrow no-break space (U+202F) before "?", "!", ";" and inside « ».
 * "Passkey" is « clé d'accès », as in the French interfaces of Apple,
 * Google and Microsoft. Wording shared with the server (internal/i18n/fr.go)
 * must stay identical.
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
  apiCodes: {
    unauthenticated: "Votre session a expiré. Veuillez vous reconnecter.",
    bad_request: "La requête n'a pas été acceptée. Veuillez recharger la page et réessayer.",
    ceremony_expired: "La demande de clé d'accès a expiré. Veuillez réessayer.",
    passkey_failed: "Votre clé d'accès n'a pas pu être vérifiée. Veuillez réessayer.",
    prf_unsupported:
      "Cette clé d'accès ne peut pas protéger vos fichiers, car elle ne prend pas en charge l'extension PRF. Veuillez utiliser une autre clé d'accès ou un autre navigateur.",
    reauth_required: "Confirmez d'abord avec l'une de vos clés d'accès existantes.",
    pubkey_mismatch: "Cette clé d'accès a été configurée pour une autre clé. Rechargez la page et déverrouillez d'abord avec une clé d'accès existante.",
    passkey_exists: "Cette clé d'accès est déjà enregistrée.",
    too_many_passkeys: "Vous avez enregistré le nombre maximal de clés d'accès.",
    no_passkeys: "Vous n'avez pas encore de clé d'accès. Configurez-les d'abord.",
    too_few_passkeys: "Vous devez conserver au moins deux clés d'accès.",
    setup_in_progress:
      "La configuration des clés d'accès est déjà en cours dans un autre navigateur ou onglet. Terminez-la là-bas, ou réessayez dans 5 minutes.",
    passkeys_changed: "Vos clés d'accès ont changé entre-temps. Rechargez la page et réessayez.",
    passkey_cloned: "Cette clé d'accès semble être la copie d'une autre et a été refusée. Utilisez une autre clé d'accès.",
    rate_limited: "Trop de tentatives. Veuillez patienter un instant et réessayer.",
    too_large: "Ce fichier ou cette requête est trop volumineux.",
    locked: "Déverrouillez d'abord vos fichiers reçus avec votre clé d'accès.",
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
  statusClosed: "Ce lien a été révoqué par son propriétaire.",
  statusLocked: "Déverrouillez d'abord vos fichiers reçus avec votre clé d'accès.",
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
  unlocking: "Déverrouillage avec votre clé d'accès…",
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
  errorAfter: (message, sent) =>
    `${message} ${sent} ${p(sent, "fichier avait été envoyé", "fichiers avaient été envoyés")} avant l'erreur.`,

  // ---- Inbox -------------------------------------------------------------
  loadingFiles: "Chargement de vos fichiers…",
  filesReceived: (n, failed) =>
    `${n} ${p(n, "fichier reçu", "fichiers reçus")}.` +
    (failed > 0
      ? ` ${failed} ${p(failed, "n'a pas pu être déchiffré et a peut-être été altéré", "n'ont pas pu être déchiffrés et ont peut-être été altérés")}.`
      : ""),
  unreadableFile: "Fichier illisible",
  download: "Télécharger",
  downloadNamed: (name) => `Télécharger ${name}`,
  delete: "Supprimer",
  deleteNamed: (name) => `Supprimer ${name}`,
  anotherDownload: "Un autre téléchargement est en cours. Attendez qu'il se termine ou annulez-le.",
  confirmDelete: (name) => `Supprimer ${q(name)}${nnb}? Cette action est irréversible.`,
  deleted: (name) => `${q(name)} supprimé.`,

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
  copyLink: "Copier le lien",
  copyLinkNamed: (label) => `Copier le ${label}`,
  requestCopied: "Lien de dépôt copié.",
  copyFailed: "Impossible de copier le lien dans le presse-papiers.",
  loadingLinks: "Chargement de vos liens…",
  linksSummary: (shares, requests) =>
    `${shares} ${p(shares, "lien de partage", "liens de partage")}, ${requests} ${p(requests, "lien de dépôt", "liens de dépôt")}.`,

  // ---- Passkeys ----------------------------------------------------------
  prfUnsupported:
    `L'emplacement où vous avez essayé d'enregistrer cette clé d'accès ne peut pas garder vos fichiers privés. ` +
    `Veuillez choisir un autre emplacement${nb}: cet ordinateur, une clé de sécurité, ou votre téléphone avec ` +
    `le Gestionnaire de mots de passe de Google (Android) ou Mots de passe / trousseau iCloud (iPhone). ` +
    `Microsoft Authenticator ne peut pas être utilisé pour Dropr.`,
  prfUnsupportedUnlock: "Cette clé d'accès ne peut pas ouvrir vos fichiers. Veuillez réessayer avec une autre de vos clés d'accès Dropr.",
  browserNoPrf:
    "Ce navigateur ne peut pas garder vos fichiers privés avec une clé d'accès. " +
    "Veuillez ouvrir cette page dans un autre navigateur, comme une version récente de Chrome, Edge ou Safari.",
  noWebauthn: "Ce navigateur ne prend pas en charge les clés d'accès. Veuillez ouvrir cette page dans une version récente de Chrome, Edge, Safari ou Firefox.",
  passkeyNotSaved:
    "La clé d'accès n'a pas été enregistrée. La fenêtre a peut-être été fermée, ou le délai a été dépassé. Veuillez réessayer, ou choisir un autre emplacement.",
  passkeyNotUsed: "Votre clé d'accès n'a pas été utilisée. La fenêtre a peut-être été fermée, ou le délai a été dépassé. Veuillez réessayer.",
  passkeyDuplicate: "Vous avez déjà une clé d'accès Dropr à cet endroit. Veuillez choisir un autre emplacement, comme votre téléphone ou une clé de sécurité.",
  passkeyInvalidState: "Cette clé d'accès ne peut pas être utilisée ici. Veuillez essayer une autre de vos clés d'accès.",
  passkeyWrongOrigin: "Les clés d'accès ne fonctionnent pas à cette adresse. Veuillez ouvrir Dropr depuis son lien habituel.",
  passkeyCannotSave:
    "Ce navigateur ou cet appareil ne peut pas enregistrer ce type de clé d'accès. Veuillez choisir un autre emplacement, ou essayer un autre navigateur comme Chrome, Edge ou Safari.",
  passkeyCannotUse: "Ce navigateur ou cet appareil ne peut pas utiliser votre clé d'accès. Veuillez essayer un autre navigateur comme Chrome, Edge ou Safari.",
  passkeyAborted: "La fenêtre de la clé d'accès s'est fermée avant la fin. Veuillez réessayer.",
  passkeySaveFailed: "Une erreur s'est produite lors de l'enregistrement de la clé d'accès. Veuillez réessayer, ou choisir un autre emplacement.",
  passkeyFailed: "Une erreur s'est produite avec votre clé d'accès. Veuillez réessayer.",
  passkeyNoUser: "Cette clé d'accès n'a pas indiqué à quel compte elle appartient. Veuillez essayer une autre de vos clés d'accès Dropr.",
  passkeyCannotUnlock: "Cette clé d'accès n'a pas pu déverrouiller vos fichiers. Veuillez essayer une autre de vos clés d'accès Dropr.",

  // ---- Passkey setup -----------------------------------------------------
  placeName: (c, device) => {
    switch (c) {
      case "device":
        return device === "computer" ? "cet ordinateur" : device === "phone" ? "ce téléphone" : "cette tablette";
      case "phone":
        return device === "computer" ? "votre téléphone" : "un autre téléphone ou une tablette";
      case "security-key":
        return "une clé de sécurité";
      case "auto":
        return "une autre méthode";
    }
  },
  deviceTitle: (device) => (device === "computer" ? "Cet ordinateur" : device === "phone" ? "Ce téléphone" : "Cette tablette"),
  deviceDesc: (device) =>
    `Vous la déverrouillerez avec votre empreinte digitale, votre visage ou le code PIN de ${
      device === "computer" ? "cet ordinateur" : device === "phone" ? "ce téléphone" : "cette tablette"
    }.`,
  otherDeviceTitle: "Un autre téléphone ou une tablette",
  otherDeviceDesc: "Vous scannerez un QR code avec l'appareil photo de l'autre appareil.",
  bluetoothBoth: "Activez le Bluetooth sur les deux appareils.",
  during: (c, otherDevice) => {
    switch (c) {
      case "device":
        return "Suivez les étapes à l'écran. Votre empreinte digitale, votre visage ou votre code PIN peuvent vous être demandés.";
      case "phone":
        return otherDevice
          ? "Scannez le QR code avec l'appareil photo de l'autre appareil, puis suivez les étapes qui s'y affichent."
          : "Scannez le QR code avec l'appareil photo de votre téléphone, puis suivez les étapes sur votre téléphone.";
      case "security-key":
        return "Branchez ou approchez votre clé de sécurité, puis touchez-la si elle clignote.";
      case "auto":
        return "Suivez les étapes affichées par votre navigateur.";
    }
  },
  again: (c) => {
    switch (c) {
      case "device":
        return "Presque terminé. Veuillez confirmer une dernière fois, de la même façon. C'est normal.";
      case "phone":
        return "Presque terminé. Votre téléphone va vous demander de confirmer une dernière fois. C'est normal.";
      case "security-key":
        return "Presque terminé. Touchez votre clé de sécurité une dernière fois. C'est normal.";
      case "auto":
        return "Presque terminé. Il vous sera demandé de confirmer une dernière fois. C'est normal.";
    }
  },
  phoneFailed:
    `Votre téléphone n'a pas pu enregistrer la clé d'accès. Vérifiez la liste sous ${q("Votre téléphone")}${nb}: Bluetooth activé sur les deux appareils${nnb}; ` +
    `Internet sur les deux${nnb}; et sur Android, le Gestionnaire de mots de passe de Google (Microsoft Authenticator ne peut pas être utilisé). ` +
    `Puis réessayez, ou essayez une autre méthode.`,
  reauthStatus: "Pour votre sécurité, veuillez confirmer avec votre première clé d'accès avant de créer celle de secours.",
  step1Title: `Étape 1 sur 2${nb}: votre première clé d'accès`,
  step2Title: `Étape 2 sur 2${nb}: votre clé d'accès de secours`,
  tryAgain: "Réessayer",
  createFirst: "Créer ma première clé d'accès",
  confirmFirst: "Confirmer avec ma première clé d'accès",
  createSpare: "Créer ma clé d'accès de secours",
  confirmingFirst: "D'abord, confirmez avec la clé d'accès que vous avez déjà créée…",
  thanksNowSpare: (during) => `Merci. Créez maintenant votre clé d'accès de secours. ${during}`,
  allDone: `C'est terminé${nnb}! Vos deux clés d'accès sont prêtes.`,
  takingYou: "Redirection vers Dropr…",
  firstReady: "Votre première clé d'accès est prête.",
  spareAdvice: (ideas) =>
    `Créez maintenant une clé de secours sur un autre appareil que celui que vous venez d'utiliser${ideas === "" ? "" : `, par exemple ${ideas}`}.`,
};
