/**
 * Decrypt file names (metadata) client-side: inbox entries (FK via HPKE from
 * the key pair of the request link they were sent through, looked up in this
 * browser's store) and share links (FK from the URL fragment).
 *
 * Inbox content comes from anonymous uploaders: names are sanitized by
 * `openMeta` and are only ever shown with `textContent`. Each entry is
 * decrypted independently so one bad entry cannot hide the others. An entry
 * whose link key is not in this browser is reported as `foreign`, not as a
 * decryption failure: its link was created in another browser.
 *
 * @module
 */

import {
  type FileKeys,
  type FileMeta,
  type RequestKeyPair,
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

/** The key pair of a request link by request ID, if this browser holds it. */
export type KeyLookup = (requestId: string) => RequestKeyPair | undefined;

/** Open a share's metadata with FK from the fragment. Throws DecryptionError/FormatError. */
export async function openShare(fk: Uint8Array, metaB64: string, cipherSize: number): Promise<DecryptedFile> {
  const keys = await deriveFileKeys(fk);
  const meta = await openMeta(keys.metadata, b64urlDecode(metaB64), plaintextSize(cipherSize));
  return { keys, meta };
}

/** Unwrap FK for an inbox entry with its link's key pair and open its metadata. Throws DecryptionError/FormatError. */
export async function openInboxEntry(link: RequestKeyPair, e: InboxEntry): Promise<DecryptedFile> {
  const fk = await unwrapFileKeyFromRequest(link, e.request_id, b64urlDecode(e.wrapped_key));
  try {
    return await openShare(fk, e.meta, e.size);
  } finally {
    fk.fill(0);
  }
}

export type InboxResult =
  | { readonly entry: InboxEntry; readonly kind: "file"; readonly file: DecryptedFile }
  /** No key for its request link in this browser. */
  | { readonly entry: InboxEntry; readonly kind: "foreign" }
  /** The key is here but the entry does not open (damaged or tampered with). */
  | { readonly entry: InboxEntry; readonly kind: "unreadable"; readonly error: unknown };

/** Decrypt many entries with bounded concurrency, preserving order. Never throws per entry. */
export async function decryptInbox(keyFor: KeyLookup, entries: readonly InboxEntry[], concurrency = 4): Promise<InboxResult[]> {
  const out = new Array<InboxResult>(entries.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let i = next++; i < entries.length; i = next++) {
      const entry = entries[i] as InboxEntry;
      const link = keyFor(entry.request_id);
      if (link === undefined) {
        out[i] = { entry, kind: "foreign" };
        continue;
      }
      try {
        out[i] = { entry, kind: "file", file: await openInboxEntry(link, entry) };
      } catch (error) {
        out[i] = { entry, kind: "unreadable", error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, entries.length)) }, worker));
  return out;
}
