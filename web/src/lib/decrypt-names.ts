/**
 * Decrypt file names (metadata) client-side: inbox entries (FK via HPKE from
 * the owner's unlocked key) and share links (FK from the URL fragment).
 *
 * Inbox content comes from anonymous uploaders: names are sanitized by
 * `openMeta` and are only ever shown with `textContent`. Each entry is
 * decrypted independently so one bad entry cannot hide the others.
 *
 * @module
 */

import {
  type FileKeys,
  type FileMeta,
  type OwnerKeyPair,
  b64urlDecode,
  deriveFileKeys,
  openMeta,
  plaintextSize,
  unwrapFileKeyFromRequest,
} from "../crypto/index.ts";
import type { InboxEntry } from "./api.ts";

export interface DecryptedFile {
  /** Subkeys for downloading (non-extractable). */
  readonly keys: FileKeys;
  /** Authenticated, sanitized metadata. `meta.size` equals the blob's plaintext size. */
  readonly meta: FileMeta;
}

/** Open a share's metadata with FK from the fragment. Throws DecryptionError/FormatError. */
export async function openShare(fk: Uint8Array, metaB64: string, cipherSize: number): Promise<DecryptedFile> {
  const keys = await deriveFileKeys(fk);
  const meta = await openMeta(keys.metadata, b64urlDecode(metaB64), plaintextSize(cipherSize));
  return { keys, meta };
}

/** Unwrap FK for an inbox entry and open its metadata. Throws DecryptionError/FormatError. */
export async function openInboxEntry(owner: OwnerKeyPair, e: InboxEntry): Promise<DecryptedFile> {
  const fk = await unwrapFileKeyFromRequest(owner, e.request_id, b64urlDecode(e.wrapped_key));
  try {
    return await openShare(fk, e.meta, e.size);
  } finally {
    fk.fill(0);
  }
}

export type InboxResult =
  | { readonly entry: InboxEntry; readonly ok: true; readonly file: DecryptedFile }
  | { readonly entry: InboxEntry; readonly ok: false; readonly error: unknown };

/** Decrypt many entries with bounded concurrency, preserving order. Never throws per entry. */
export async function decryptInbox(owner: OwnerKeyPair, entries: readonly InboxEntry[], concurrency = 4): Promise<InboxResult[]> {
  const out = new Array<InboxResult>(entries.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let i = next++; i < entries.length; i = next++) {
      const entry = entries[i] as InboxEntry;
      try {
        out[i] = { entry, ok: true, file: await openInboxEntry(owner, entry) };
      } catch (error) {
        out[i] = { entry, ok: false, error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, entries.length)) }, worker));
  return out;
}
