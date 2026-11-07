/**
 * The owner's request-link keys, kept in this browser only
 * (ARCHITECTURE.md §3 "Request link keys").
 *
 * - IndexedDB database `dropr` v1, object store `request-keys`, key path
 *   `id` (the request ID); one {@link RequestKeyRecord} per link. The private
 *   key is stored as a non-extractable `CryptoKey` (IndexedDB clones it
 *   without ever exposing its bytes).
 * - The server never sees a key: a link opens only in the browser profile
 *   that created it. Inbox entries and links without a local record belong
 *   to another browser (or to cleared site data).
 * - {@link RequestKeyStore.prune} drops the records of links the server no
 *   longer lists (expired, revoked, deleted elsewhere), whose files are gone.
 *   Records newer than the list are kept: another tab may have just created
 *   the link.
 * - A record is never overwritten: {@link RequestKeyStore.put} fails with
 *   {@link KeyIdTakenError} if the ID is already stored, so a server that
 *   hands out an existing request ID cannot replace that link's key
 *   (audit 2026-11b L-7).
 *
 * The store logic runs over a small {@link KeyBackend} so it is testable in
 * Node, which has no IndexedDB; by default it is IndexedDB. A store is bound
 * to one account ({@link requestKeysFor}): records of other accounts sharing
 * the browser profile are invisible to it and never pruned.
 * Every failure is a {@link KeyStoreError} with a plain-language message.
 *
 * @module
 */

import type { RequestKeyPair } from "../crypto/index.ts";
import { t } from "./i18n.ts";

const DB_NAME = "dropr";
const DB_VERSION = 1;
const STORE = "request-keys";
/** Records created less than this long before a listing are never pruned by it (clock skew, slow responses). */
const PRUNE_GRACE_S = 60;

/** One request link's key pair, as stored. */
export interface RequestKeyRecord extends RequestKeyPair {
  /** Request ID (the key path). */
  readonly id: string;
  /** The owning account (`users.id`); one browser profile may hold several. */
  readonly ownerId: string;
  /** When the record was stored, Unix seconds (this browser's clock). */
  readonly createdAt: number;
}

/** The storage operations the store needs. Values read back are checked, not trusted. */
export interface KeyBackend {
  /** Store a new record; rejects with a `ConstraintError` DOMException if its ID is already stored. */
  add(record: RequestKeyRecord): Promise<void>;
  get(id: string): Promise<unknown>;
  getAll(): Promise<unknown[]>;
  delete(ids: readonly string[]): Promise<void>;
}

/** The key store is unavailable (blocked, private browsing, full) or failed. `message` is safe to show. */
export class KeyStoreError extends Error {
  constructor(cause: unknown, message?: string) {
    const full = cause instanceof Error && cause.name === "QuotaExceededError";
    super(message ?? (full ? t.storageFull : t.keyStoreUnavailable), { cause });
    this.name = "KeyStoreError";
  }
}

/**
 * A key is already stored under this request ID (any account). Nothing was
 * written; the existing record, and the request it belongs to, must be left
 * alone.
 */
export class KeyIdTakenError extends KeyStoreError {
  constructor(cause: unknown) {
    super(cause, t.keyIdTaken);
    this.name = "KeyIdTakenError";
  }
}

/** Current time in Unix seconds. */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isRecord(x: unknown): x is RequestKeyRecord {
  if (typeof x !== "object" || x === null) return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r["id"] === "string" &&
    typeof r["ownerId"] === "string" &&
    r["privateKey"] instanceof CryptoKey &&
    r["publicKey"] instanceof Uint8Array &&
    r["publicKey"].length === 32 &&
    typeof r["createdAt"] === "number"
  );
}

/**
 * The request-link keys of one account. Several accounts may share a browser
 * profile: every read, delete and prune considers only records whose
 * `ownerId` is this store's; other records are invisible and never deleted.
 * A store without an owner (the page did not say who is signed in) fails
 * closed: every operation rejects with a {@link KeyStoreError}.
 */
export class RequestKeyStore {
  /** The signed-in account, or `null` if unknown. */
  readonly ownerId: string | null;
  private readonly openBackend: () => Promise<KeyBackend>;
  private backend: Promise<KeyBackend> | null = null;

  /** `open` is called on first use, and again after any failure. */
  constructor(ownerId: string | null, open: () => Promise<KeyBackend> = openIndexedDb) {
    this.ownerId = ownerId;
    this.openBackend = open;
  }

  private async run<T>(op: (b: KeyBackend) => Promise<T>): Promise<T> {
    if (this.ownerId === null) throw new KeyStoreError(new Error("no owner id on the page"), t.ownerUnknown);
    try {
      return await op(await (this.backend ??= this.openBackend()));
    } catch (e) {
      this.backend = null; // reopen next time (storage allowed again, database closed for an upgrade)
      throw e instanceof KeyStoreError ? e : new KeyStoreError(e);
    }
  }

  private mine(x: unknown): x is RequestKeyRecord {
    return isRecord(x) && x.ownerId === this.ownerId;
  }

  /**
   * Store the key pair of request `id` for this owner. Never overwrites: if
   * any record has this ID, rejects with a {@link KeyIdTakenError}.
   */
  put(id: string, pair: RequestKeyPair, createdAt = nowSeconds()): Promise<void> {
    return this.run(async (b) => {
      const ownerId = this.ownerId as string; // checked by run()
      try {
        await b.add({ id, privateKey: pair.privateKey, publicKey: pair.publicKey, ownerId, createdAt });
      } catch (e) {
        if (e instanceof DOMException && e.name === "ConstraintError") throw new KeyIdTakenError(e);
        throw e;
      }
    });
  }

  /** This owner's record of request `id`, or `null` if this browser has none. */
  get(id: string): Promise<RequestKeyRecord | null> {
    return this.run(async (b) => {
      const r = await b.get(id);
      return this.mine(r) ? r : null;
    });
  }

  /** This owner's records, by request ID. */
  all(): Promise<Map<string, RequestKeyRecord>> {
    return this.run(async (b) => new Map((await b.getAll()).filter((r) => this.mine(r)).map((r) => [r.id, r])));
  }

  /** Delete this owner's record of request `id` (another owner's is left alone). */
  delete(id: string): Promise<void> {
    return this.run(async (b) => {
      if (this.mine(await b.get(id))) await b.delete([id]);
    });
  }

  /**
   * Delete this owner's records whose ID is not in `keepIds` (the server's
   * list of this owner's live links), except those created after
   * `listedAt - 60 s`.
   *
   * @param listedAt - when the list was requested, Unix seconds.
   * @returns this owner's records kept, by request ID.
   */
  prune(keepIds: Iterable<string>, listedAt: number): Promise<Map<string, RequestKeyRecord>> {
    const keep = new Set(keepIds);
    return this.run(async (b) => {
      const kept = new Map<string, RequestKeyRecord>();
      const drop: string[] = [];
      for (const r of await b.getAll()) {
        if (!this.mine(r)) continue;
        if (keep.has(r.id) || r.createdAt > listedAt - PRUNE_GRACE_S) kept.set(r.id, r);
        else drop.push(r.id);
      }
      if (drop.length > 0) await b.delete(drop);
      return kept;
    });
  }
}

/**
 * The signed-in account's store, from `data-owner-id` on the page's `<main>`
 * (owner pages). Without it the store has no owner and refuses everything.
 */
export function requestKeysFor(main: HTMLElement): RequestKeyStore {
  const ownerId = main.dataset["ownerId"]?.trim() ?? "";
  return new RequestKeyStore(ownerId === "" ? null : ownerId);
}

/**
 * Ask the browser not to evict this site's storage (and with it the keys),
 * `navigator.storage.persist()`. Best effort: resolves `false` when refused
 * or unsupported, never throws.
 */
export async function requestPersistence(): Promise<boolean> {
  try {
    const storage = globalThis.navigator?.storage;
    if (storage?.persist === undefined) return false;
    return (await storage.persisted()) || (await storage.persist());
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// IndexedDB backend
// ---------------------------------------------------------------------------

function openIndexedDb(): Promise<KeyBackend> {
  return new Promise((resolve, reject) => {
    if (globalThis.indexedDB === undefined) return reject(new Error("IndexedDB is not available"));
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "id" });
    req.onblocked = () => reject(new Error("IndexedDB upgrade blocked by another tab"));
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      // A newer version opened in another tab: let it upgrade (the store reopens after the failure).
      db.onversionchange = () => db.close();
      resolve(indexedDbBackend(db));
    };
  });
}

function indexedDbBackend(db: IDBDatabase): KeyBackend {
  /** Run `fn` in one transaction; resolve with its request's result once the transaction has committed. */
  const tx = <T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> =>
    new Promise((resolve, reject) => {
      const trans = db.transaction(STORE, mode);
      const req = fn(trans.objectStore(STORE));
      let result: T | undefined;
      if (req !== undefined) req.onsuccess = () => (result = req.result);
      trans.oncomplete = () => resolve(result);
      trans.onabort = () => reject(trans.error ?? new DOMException("Transaction aborted", "AbortError"));
    });
  return {
    // add, not put: an existing ID aborts the transaction with a ConstraintError.
    add: async (record) => void (await tx("readwrite", (s) => s.add(record))),
    get: (id) => tx("readonly", (s) => s.get(id)),
    getAll: async () => (await tx("readonly", (s) => s.getAll())) ?? [],
    delete: async (ids) => {
      await tx("readwrite", (s) => {
        for (const id of ids) s.delete(id);
      });
    },
  };
}
