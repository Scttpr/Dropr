/**
 * One place that turns any error into a plain-language sentence for the
 * user. Crypto errors are deliberately generic (no oracle).
 *
 * @module
 */

import { DecryptionError, FormatError } from "../crypto/index.ts";
import { ApiError } from "./api.ts";
import { DownloadError } from "./downloader.ts";
import { PasskeyError, PrfUnsupportedError } from "./passkey.ts";
import { isAbortError } from "./retry.ts";
import { UploadInterruptedError } from "./uploader.ts";

export const DAMAGED = "The file could not be decrypted: it has been damaged or altered, or the link is wrong.";

export function errorMessage(e: unknown): string {
  if (
    e instanceof ApiError ||
    e instanceof DownloadError ||
    e instanceof PasskeyError ||
    e instanceof PrfUnsupportedError ||
    e instanceof UploadInterruptedError
  ) {
    return e.message;
  }
  if (e instanceof DecryptionError) return DAMAGED;
  if (e instanceof FormatError) return "The file or link is malformed.";
  if (isAbortError(e)) return "Cancelled.";
  if (e instanceof Error && e.name === "QuotaExceededError") return "Your disk or browser storage is full.";
  return "Something went wrong. Please reload the page and try again.";
}
