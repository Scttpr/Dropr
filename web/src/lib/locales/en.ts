/**
 * English catalog: the source of truth for the shape of every catalog
 * ({@link Messages}). Keep server-rendered wording (internal/i18n,
 * internal/web/format.go) identical where both sides show the same text.
 *
 * @module
 */

import type { AuthenticatorChoice } from "../webauthn.ts";

type Device = "computer" | "phone" | "tablet";

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
  /** Translations of the server's API error messages, by error code. English uses the server's own text. */
  apiCodes: {} as Readonly<Record<string, string>>,
  statusExpired: "This link has expired.",
  statusExhausted: "This link has reached its download limit.",
  statusClosed: "This link has been revoked by its owner.",
  statusLocked: "Unlock your inbox with your passkey first.",
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
  unlocking: "Unlocking with your passkey…",
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
  filesReceived: (n: number, failed: number): string =>
    `${n} file${n === 1 ? "" : "s"} received.` + (failed > 0 ? ` ${failed} could not be decrypted and may have been tampered with.` : ""),
  unreadableFile: "Unreadable file",
  download: "Download",
  downloadNamed: (name: string): string => `Download ${name}`,
  delete: "Delete",
  deleteNamed: (name: string): string => `Delete ${name}`,
  anotherDownload: "Another download is in progress. Wait for it to finish or cancel it.",
  confirmDelete: (name: string): string => `Delete “${name}”? This cannot be undone.`,
  deleted: (name: string): string => `Deleted ${name}.`,

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
  requestCopied: "Request link copied.",
  copyFailed: "Could not copy the link to the clipboard.",
  loadingLinks: "Loading your links…",
  linksSummary: (shares: number, requests: number): string =>
    `${shares} share link${shares === 1 ? "" : "s"}, ${requests} request link${requests === 1 ? "" : "s"}.`,

  // ---- Passkeys (lib/passkey.ts) ---------------------------------------
  prfUnsupported:
    "The place where you tried to save this passkey can't keep your files private. " +
    "Please choose another place: this computer, a security key, or your phone with " +
    "Google Password Manager (Android) or Passwords / iCloud Keychain (iPhone). " +
    "Microsoft Authenticator can't be used for Dropr.",
  prfUnsupportedUnlock: "This passkey can't open your files. Please try again with another of your Dropr passkeys.",
  browserNoPrf:
    "This browser can't keep your files private with a passkey. " +
    "Please open this page in another browser, such as a recent Chrome, Edge or Safari.",
  noWebauthn: "This browser can't use passkeys. Please open this page in a recent Chrome, Edge, Safari or Firefox.",
  passkeyNotSaved:
    "The passkey wasn't saved. The window may have been closed, or it took too long. Please try again, or choose another place to save it.",
  passkeyNotUsed: "Your passkey wasn't used. The window may have been closed, or it took too long. Please try again.",
  passkeyDuplicate: "You already have a Dropr passkey there. Please choose another place, such as your phone or a security key.",
  passkeyInvalidState: "This passkey can't be used here. Please try another of your passkeys.",
  passkeyWrongOrigin: "Passkeys don't work on this web address. Please open Dropr from its usual link.",
  passkeyCannotSave:
    "This browser or device can't save this kind of passkey. Please choose another place, or try another browser such as Chrome, Edge or Safari.",
  passkeyCannotUse: "This browser or device can't use your passkey. Please try another browser such as Chrome, Edge or Safari.",
  passkeyAborted: "The passkey window closed before it finished. Please try again.",
  passkeySaveFailed: "Something went wrong while saving the passkey. Please try again, or choose another place to save it.",
  passkeyFailed: "Something went wrong with your passkey. Please try again.",
  passkeyNoUser: "This passkey didn't say which account it belongs to. Please try another of your Dropr passkeys.",
  passkeyCannotUnlock: "This passkey could not unlock your files. Please try another of your Dropr passkeys.",

  // ---- Passkey setup ---------------------------------------------------
  placeName: (c: AuthenticatorChoice, device: Device): string => {
    switch (c) {
      case "device":
        return `this ${device}`;
      case "phone":
        return device === "computer" ? "your phone" : "another phone or tablet";
      case "security-key":
        return "a security key";
      case "auto":
        return "another way";
    }
  },
  /** "This computer" / "This phone" / "This tablet" (option title). */
  deviceTitle: (device: Device): string => `This ${device}`,
  deviceDesc: (device: Device): string => `You'll unlock it with your fingerprint, your face, or the PIN of this ${device}.`,
  otherDeviceTitle: "Another phone or tablet",
  otherDeviceDesc: "You'll scan a QR code with the other device's camera.",
  bluetoothBoth: "Turn on Bluetooth on both devices.",
  during: (c: AuthenticatorChoice, otherDevice: boolean): string => {
    switch (c) {
      case "device":
        return "Follow the steps on your screen. You may be asked for your fingerprint, your face or your PIN.";
      case "phone":
        return otherDevice
          ? "Scan the QR code with the other device's camera, then follow the steps on it."
          : "Scan the QR code with your phone's camera, then follow the steps on your phone.";
      case "security-key":
        return "Plug in or tap your security key, then touch it if it blinks.";
      case "auto":
        return "Follow the steps your browser shows.";
    }
  },
  again: (c: AuthenticatorChoice): string => {
    switch (c) {
      case "device":
        return "Almost done. Please confirm one more time, the same way. That's normal.";
      case "phone":
        return "Almost done. Your phone will ask you one more time to confirm. That's normal.";
      case "security-key":
        return "Almost done. Touch your security key one more time. That's normal.";
      case "auto":
        return "Almost done. You'll be asked to confirm one more time. That's normal.";
    }
  },
  phoneFailed:
    "Your phone couldn't save the passkey. Please check the list under “Your phone”: Bluetooth on, on both devices; " +
    "internet on both; and on Android, Google Password Manager (Microsoft Authenticator can't be used). " +
    "Then try again, or try another way.",
  reauthStatus: "For your safety, please confirm with your first passkey before making the spare one.",
  step1Title: "Step 1 of 2: your first passkey",
  step2Title: "Step 2 of 2: your spare passkey",
  tryAgain: "Try again",
  createFirst: "Create my first passkey",
  confirmFirst: "Confirm with my first passkey",
  createSpare: "Create my spare passkey",
  confirmingFirst: "First, confirm with the passkey you already made…",
  thanksNowSpare: (during: string): string => `Thank you. Now create your spare passkey. ${during}`,
  allDone: "All done! Both of your passkeys are ready.",
  takingYou: "Taking you to Dropr…",
  firstReady: "Your first passkey is ready.",
  /** `ideas` are place names, already joined ("your phone or a security key"); empty when unknown. */
  spareAdvice: (ideas: string): string =>
    `Now make a spare one on a different device than the one you just used${ideas === "" ? "" : `, for example ${ideas}`}.`,
};

/** The shape every catalog implements. */
export type Messages = typeof en;
