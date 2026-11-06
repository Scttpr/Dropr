/**
 * One place that turns any error into a plain-language sentence for the
 * user. Crypto errors are deliberately generic (no oracle).
 *
 * @module
 */

import { DecryptionError, FormatError } from "../crypto/index.ts";
import { ApiError } from "./api.ts";
import { DownloadError } from "./downloader.ts";
import { t } from "./i18n.ts";
import { KeyStoreError } from "./request-keys.ts";
import { isAbortError } from "./retry.ts";
import { UploadInterruptedError } from "./uploader.ts";

export const DAMAGED = t.damaged;

export function errorMessage(e: unknown): string {
  if (
    e instanceof ApiError ||
    e instanceof DownloadError ||
    e instanceof KeyStoreError ||
    e instanceof UploadInterruptedError
  ) {
    return e.message;
  }
  if (e instanceof DecryptionError) return DAMAGED;
  if (e instanceof FormatError) return t.malformed;
  if (isAbortError(e)) return t.cancelled;
  if (e instanceof Error && e.name === "QuotaExceededError") return t.storageFull;
  return t.unexpected;
}
