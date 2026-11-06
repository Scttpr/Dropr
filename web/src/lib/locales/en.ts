/**
 * English catalog: the source of truth for the shape of every catalog
 * ({@link Messages}). Keep server-rendered wording (internal/i18n,
 * internal/web/format.go) identical where both sides show the same text.
 *
 * @module
 */

const s = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const wasWere = (n: number): string => `${n} file${n === 1 ? " was" : "s were"}`;

export const en = {
  // ---- Formatting -------------------------------------------------------
  byteUnits: ["B", "KB", "MB", "GB", "TB"] as readonly string[],
  decimalSeparator: ".",
  unitSpace: " ",
  exactBytes: (n: string): string => `${n} bytes`,
  etaFewSeconds: "a few seconds left",
  etaSeconds: (n: number): string => `about ${n} s left`,
  etaMinutes: (n: number): string => `about ${n} min left`,
  etaHours: (h: number): string => `about ${h} h left`,
  etaHoursMinutes: (h: number, m: number): string => `about ${h} h ${m} min left`,
  expired: "Expired",
  expiresInMinutes: (n: number): string => `Expires in ${s(n, "minute")}`,
  expiresInHours: (n: number): string => `Expires in ${s(n, "hour")}`,
  expiresInDays: (n: number): string => `Expires in ${s(n, "day")}`,

  // ---- Generic errors (lib/messages.ts, lib/api.ts) ------------------------
  damaged: "The file could not be decrypted: it has been damaged or altered, or the link is wrong.",
  malformed: "The file or link is malformed.",
  cancelled: "Cancelled.",
  storageFull: "Your disk or browser storage is full.",
  unexpected: "Something went wrong. Please reload the page and try again.",
  keyStoreUnavailable:
    "This browser cannot store the keys of your request links, so it cannot create links or open the files sent through them. " +
    "Allow this site to store data (private browsing often blocks it), or use another browser.",
  ownerUnknown: "Dropr could not tell which account is signed in, so it cannot use your request link keys. Please reload the page.",
  /** Translations of the server's API error messages, by error code. English uses the server's own text. */
  apiCodes: {} as Readonly<Record<string, string>>,
  statusExpired: "This link has expired.",
  statusExhausted: "This link has reached its download limit.",
  statusClosed: "This link no longer accepts files.",
  statusQuota: "There is not enough storage space left for this file.",
  statusTooLarge: "This file is too large.",
  statusNetwork: "Could not reach the server. Check your connection and try again.",
  statusBadRequest: "The request was not accepted. Please reload the page and try again.",
  statusUnauthenticated: "Your session has expired. Please sign in again.",
  statusForbidden: "You are not allowed to do this.",
  statusNotFound: "This link does not exist or has been revoked.",
  statusTimeout: "The server took too long to respond. Please try again.",
  statusConflict: "This was changed in the meantime. Please reload the page.",
  statusGone: "This link has expired or is no longer available.",
  statusRateLimited: "Too many attempts. Please wait a moment and try again.",
  statusServer: "The server had a problem. Please try again in a moment.",
  statusUnexpected: (what: string): string => `Unexpected response from the server (${what}).`,

  // ---- Transfers (lib/transfer-ui.ts, uploader, downloader) ---------------
  uploading: "Uploading",
  downloading: "Downloading",
  encryptingUploading: "Encrypting and uploading",
  progressStart: (verb: string, name: string): string => `${verb} ${name}…`,
  progressPercent: (verb: string, pc: number): string => `${verb}: ${pc}%`,
  progressBytes: (done: string, total: string): string => `${done} of ${total}`,
  uploadCancelled: "Upload cancelled.",
  connectionLost: "The connection was lost. The upload will continue where it stopped when you retry.",
  downloadComplete: "Download complete.",
  downloadCompleteCheck: "Download complete. Check your browser's downloads.",
  downloadCancelled: "Download cancelled.",
  saveFailed: "The file could not be saved (the download was cancelled or the disk is full).",
  interrupted: "The download was interrupted repeatedly. Check your connection and try again.",
  tooLargeForBrowser: "This file is too large to download in this browser.",
  helperTimeout: "The download helper did not respond.",
  inMemoryNotice: "Your browser cannot save directly to disk, so the file is decrypted in memory and saved when complete.",
  noSecureDownload: "This browser cannot download files this large securely. Please use a recent Chrome, Edge, Firefox or Safari.",

  // ---- Link view -------------------------------------------------------
  copied: "Copied",
  pressToCopy: "Press Ctrl+C to copy",

  // ---- Dashboard -------------------------------------------------------
  fileTooLarge: (have: string, limit: string): string => `This file is too large (${have}). The limit is ${limit}.`,
  downloadLimitInvalid: "The download limit must be a whole number of at least 1, or empty for no limit.",
  maxFilesInvalid: "The number of files must be a whole number of at least 1.",
  uploadReady: "Upload complete. Your link is ready.",
  shareQrLabel: "QR code of the share link",
  creatingRequest: "Creating the request link…",
  requestReady: "Your request link is ready.",
  requestQrLabel: "QR code of the request link",

  // ---- Share recipient -------------------------------------------------
  missingKey: "This link is missing its key (the part after #). Ask the sender for the complete link.",
  incompleteLink: "This link is incomplete or damaged. Ask the sender for the complete link.",
  checkingLink: "Checking the link…",
  wrongKey: "The key in this link is wrong or the file is damaged. Ask the sender for the complete link.",
  shareNotFound: "This link does not exist or has been revoked by its owner.",
  shareGone: "This link has expired or reached its download limit.",

  // ---- Request uploader ------------------------------------------------
  requestLinkDamaged: "This link is incomplete or damaged. Ask the person who sent it for the complete link.",
  noMoreFiles: "This link does not accept more files.",
  acceptsMore: (n: number): string => `This link accepts ${n} more file${n === 1 ? "" : "s"}. Please choose fewer files.`,
  filesTooLarge: (total: string, left: string): string => `These files are too large (${total}). This link accepts up to ${left} more.`,
  sentItem: (name: string, size: string): string => `${name} (${size}) — sent`,
  cancelledAfter: (sent: number): string => `Cancelled. ${wasWere(sent)} sent before.`,
  errorAfter: (message: string, sent: number): string => `${message} ${wasWere(sent)} sent before the error.`,

  // ---- Inbox -----------------------------------------------------------
  loadingFiles: "Loading your files…",
  filesReceived: (n: number, failed: number, foreign: number): string =>
    `${n} file${n === 1 ? "" : "s"} received.` +
    (failed > 0 ? ` ${failed} could not be decrypted and may have been tampered with.` : "") +
    (foreign > 0 ? ` ${foreign} ${foreign === 1 ? "was" : "were"} sent through links created in another browser and can only be opened there.` : ""),
  unreadableFile: "Unreadable file",
  foreignFile: "Sent through a link created in another browser",
  /** Accessible name of a file without a local key, for {@link deleteNamed}. */
  foreignFileNamed: (date: string): string => `the file received ${date} through a link created in another browser`,
  download: "Download",
  downloadNamed: (name: string): string => `Download ${name}`,
  delete: "Delete",
  deleteNamed: (name: string): string => `Delete ${name}`,
  anotherDownload: "Another download is in progress. Wait for it to finish or cancel it.",
  confirmDelete: (name: string): string => `Delete “${name}”? This cannot be undone.`,
  deleted: (name: string): string => `Deleted ${name}.`,
  confirmDeleteForeign: (date: string): string => `Delete the file received ${date}? This cannot be undone.`,
  deletedForeign: (date: string): string => `Deleted the file received ${date}.`,

  // ---- Links -----------------------------------------------------------
  revoke: "Revoke",
  revokeNamed: (label: string): string => `Revoke ${label}`,
  confirmRevokeShare: "Revoke this share link? It stops working immediately and its files are deleted.",
  confirmRevokeRequest: "Revoke this request link? It stops working immediately and its files are deleted.",
  shareRevoked: "Share link revoked.",
  requestRevoked: "Request link revoked.",
  shareLinkLabel: (date: string): string => `share link created ${date}`,
  requestLinkLabel: (date: string): string => `request link created ${date}`,
  countOf: (n: number, max: number): string => `${n} of ${max}`,
  singleUse: " (single use)",
  copyLink: "Copy link",
  copyLinkNamed: (label: string): string => `Copy link: ${label}`,
  otherBrowser: "Other browser",
  otherBrowserHint: "This link was created in another browser: copy it from there.",
  requestCopied: "Request link copied.",
  copyFailed: "Could not copy the link to the clipboard.",
  loadingLinks: "Loading your links…",
  linksSummary: (shares: number, requests: number): string =>
    `${shares} share link${shares === 1 ? "" : "s"}, ${requests} request link${requests === 1 ? "" : "s"}.`,
};

/** The shape every catalog implements. */
export type Messages = typeof en;
