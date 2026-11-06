/**
 * Streaming, resumable, authenticated download + decryption.
 *
 * Pipeline: `GET /dl/{token}` → length guard → `createDecryptStream` →
 * {@link DownloadSink}. Only plaintext of segments that authenticated is
 * ever written, one segment (64 KiB) at a time, so memory stays constant.
 *
 * **Resume.** If the connection fails (network error, or the body ends
 * early), the download restarts with `Range: bytes=<k·65552>-` where `k` is
 * the number of segments already written to the sink, and a decryptor
 * created with `startSegment: k`. Bytes of a partly received segment are
 * simply fetched again. A segment that was fully received but not yet
 * released (the decryptor holds one block back until it knows whether it is
 * the last) is re-fetched too, so nothing unauthenticated is ever written.
 * Authentication failure is never retried: it means tampering or a wrong key.
 *
 * **Sinks**, in order of preference ({@link openSink}):
 *
 * 1. File System Access (`showSaveFilePicker`, Chromium desktop): writes go
 *    to a swap file that only becomes the real file on `close()`; on error
 *    `writable.abort()` discards it (and an empty file the picker created is
 *    removed when the browser allows it).
 * 2. Service worker (`/sw.js`, scope `/_dl/`): the browser's own download
 *    manager receives the stream. On error the stream is errored and the
 *    browser shows a *failed* download and deletes its partial file; it
 *    cannot show *why* (the page does). Firefox and Safari use this path.
 * 3. Blob in memory, only up to {@link BLOB_LIMIT} (256 MiB), with a notice:
 *    the whole file is decrypted into memory and saved at the end, so
 *    nothing is written on failure.
 *
 * `openSink` must be called directly in the click handler (the file picker
 * needs a user gesture), before any other `await`.
 *
 * @module
 */

import {
  DecryptionError,
  b64urlEncode,
  createDecryptStream,
  plaintextSize,
  segmentCipherOffset,
} from "../crypto/index.ts";
import { Api, ApiError } from "./api.ts";
import { t } from "./i18n.ts";
import { type Progress, RateMeter } from "./progress.ts";
import { abortError, backoffDelay, isAbortError, sleep } from "./retry.ts";
import { DL_SCOPE, type PageToSw, type PortToSw, type SwToPage } from "./swproto.ts";

export type { Progress } from "./progress.ts";

/** Largest file the in-memory Blob fallback accepts. */
export const BLOB_LIMIT = 256 * 1024 * 1024;

/** Where decrypted plaintext goes. `close()` commits; `abort()` must leave no file behind. */
export interface DownloadSink {
  readonly kind: "fs" | "sw" | "blob" | "memory";
  write(chunk: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

/** The download failed for a reason worth showing as is (plain language). */
export class DownloadError extends Error {
  readonly code: "damaged" | "unsupported" | "too_large" | "interrupted" | "sink";
  override readonly cause: unknown;
  constructor(code: DownloadError["code"], message: string, cause?: unknown) {
    super(message);
    this.name = "DownloadError";
    this.code = code;
    this.cause = cause;
  }
}

/** The body ended before the expected number of bytes (connection cut cleanly). */
class TruncatedBodyError extends Error {
  constructor() {
    super("response body ended early");
    this.name = "TruncatedBodyError";
  }
}

/** Wraps errors thrown by the sink so they are not mistaken for network errors. */
class SinkFailure extends Error {
  override readonly cause: unknown;
  constructor(cause: unknown) {
    super("sink failed");
    this.cause = cause;
  }
}

/** Pass bytes through; error with {@link TruncatedBodyError} if fewer than `expected` arrive. */
export function lengthGuard(expected: number): TransformStream<Uint8Array, Uint8Array> {
  let seen = 0;
  return new TransformStream({
    transform(chunk, controller) {
      seen += chunk.length;
      controller.enqueue(chunk);
    },
    flush() {
      if (seen < expected) throw new TruncatedBodyError();
    },
  });
}

export interface DownloadOptions {
  /** Download token from `POST /api/s/{id}/download` or `/api/inbox/{id}/download`. */
  readonly token: string;
  /** Ciphertext size (the API's `size`). */
  readonly cipherSize: number;
  /** CK from `deriveFileKeys(fk).content`. */
  readonly contentKey: CryptoKey;
  readonly sink: DownloadSink;
  readonly api?: Api;
  readonly signal?: AbortSignal;
  readonly onProgress?: (p: Progress) => void;
  /** Consecutive failed attempts without progress before giving up (default 5). */
  readonly maxRetries?: number;
  readonly retryBaseMs?: number;
  readonly retryCapMs?: number;
  /**
   * Called when the token is rejected on a resume (401/403/404/410, e.g.
   * after its 1 h TTL) to obtain a fresh one. Without it such errors are final.
   */
  readonly renewToken?: () => Promise<string>;
  readonly now?: () => number;
  readonly random?: () => number;
}

function isTransient(e: unknown): boolean {
  if (e instanceof ApiError) return e.retryable;
  // fetch body failures surface as TypeError ("network error") in browsers and Node.
  return e instanceof TruncatedBodyError || e instanceof TypeError;
}

const TOKEN_REJECTED = new Set([401, 403, 404, 410]);

/**
 * Download, decrypt and write the whole file to `opts.sink`. On success the
 * sink is closed (file committed); on any failure it is aborted and the
 * error re-thrown (`AbortError` if cancelled, {@link DownloadError} for
 * damage, {@link ApiError} for server/link errors).
 */
export async function downloadToSink(opts: DownloadOptions): Promise<void> {
  const api = opts.api ?? new Api();
  const now = opts.now ?? (() => performance.now());
  const signal = opts.signal;
  const maxRetries = opts.maxRetries ?? 5;
  const plainTotal = plaintextSize(opts.cipherSize);
  const meter = new RateMeter(plainTotal, now());
  let token = opts.token;
  let segments = 0; // segments written to the sink
  let bytes = 0;
  let failures = 0;
  let renewedAt = -1;

  try {
    for (;;) {
      if (signal?.aborted) throw abortError(signal.reason);
      const start = segmentCipherOffset(segments);
      let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>> | null = null;
      try {
        const res = await api.fetchCiphertext(token, start, opts.cipherSize, signal ? { signal } : {});
        if (res.body === null) throw new ApiError(0, "bad_response", t.statusUnexpected("no body"));
        reader = res.body
          .pipeThrough(lengthGuard(opts.cipherSize - start))
          .pipeThrough(createDecryptStream(opts.contentKey, { startSegment: segments }))
          .getReader();
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          const n = r.value.length; // read first: a sink may transfer (detach) the buffer
          try {
            await opts.sink.write(r.value);
          } catch (e) {
            throw new SinkFailure(e);
          }
          segments++;
          bytes += n;
          if (signal?.aborted) throw abortError(signal.reason);
          failures = 0;
          opts.onProgress?.(meter.update(bytes, now()));
        }
        reader = null;
        try {
          await opts.sink.close();
        } catch (e) {
          throw new SinkFailure(e);
        }
        return;
      } catch (e) {
        if (reader !== null) reader.cancel().catch(() => undefined);
        if (signal?.aborted) throw abortError(signal.reason);
        if (e instanceof SinkFailure) {
          if (isAbortError(e.cause)) throw e.cause;
          throw new DownloadError("sink", t.saveFailed, e.cause);
        }
        if (e instanceof DecryptionError) {
          throw new DownloadError("damaged", t.damaged, e);
        }
        if (e instanceof ApiError && TOKEN_REJECTED.has(e.status) && opts.renewToken && renewedAt !== segments && start > 0) {
          renewedAt = segments;
          token = await opts.renewToken();
          continue;
        }
        if (!isTransient(e)) throw e;
        if (++failures > maxRetries) {
          throw new DownloadError("interrupted", t.interrupted, e);
        }
        meter.reset(bytes, now());
        await sleep(
          backoffDelay(failures - 1, {
            baseMs: opts.retryBaseMs ?? 1000,
            capMs: opts.retryCapMs ?? 30_000,
            ...(opts.random ? { random: opts.random } : {}),
          }),
          signal,
        );
      }
    }
  } catch (e) {
    await opts.sink.abort(e).catch(() => undefined);
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Sinks (browser only)
// ---------------------------------------------------------------------------

interface FsWritable {
  write(data: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}
interface FsFileHandle {
  createWritable(): Promise<FsWritable>;
  getFile(): Promise<File>;
  remove?: () => Promise<void>;
}
type SaveFilePicker = (opts: { suggestedName?: string }) => Promise<FsFileHandle>;

function savePicker(): SaveFilePicker | null {
  const g = globalThis as unknown as { showSaveFilePicker?: SaveFilePicker; isSecureContext?: boolean };
  return typeof g.showSaveFilePicker === "function" ? g.showSaveFilePicker.bind(globalThis) : null;
}

/** File System Access sink. Throws `AbortError` if the user dismisses the picker. */
export async function fsSink(picker: SaveFilePicker, name: string): Promise<DownloadSink> {
  const handle = await picker({ suggestedName: name });
  // An empty target is (almost certainly) a file the picker just created; an
  // existing non-empty file is left untouched by abort() thanks to the swap file.
  const createdEmpty = await handle.getFile().then(
    (f) => f.size === 0,
    () => false,
  );
  const writable = await handle.createWritable();
  return {
    kind: "fs",
    write: (c) => writable.write(c),
    close: () => writable.close(),
    async abort(reason) {
      await writable.abort(reason).catch(() => undefined);
      if (createdEmpty && typeof handle.remove === "function") await handle.remove().catch(() => undefined);
    },
  };
}

/** In-memory sink, saved through a Blob URL on close. */
export function blobSink(name: string): DownloadSink {
  let chunks: Uint8Array<ArrayBuffer>[] = [];
  let total = 0;
  return {
    kind: "blob",
    write(c) {
      total += c.length;
      if (total > BLOB_LIMIT) return Promise.reject(new DownloadError("too_large", t.tooLargeForBrowser));
      chunks.push(c);
      return Promise.resolve();
    },
    close() {
      const url = URL.createObjectURL(new Blob(chunks, { type: "application/octet-stream" }));
      chunks = [];
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.rel = "noopener";
      a.hidden = true;
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      return Promise.resolve();
    },
    abort() {
      chunks = [];
      return Promise.resolve();
    },
  };
}

/** Name of the only Trusted Types policy Dropr creates (CSP `trusted-types dropr-sw`). */
export const SW_POLICY = "dropr-sw";
/** URL of the download service worker. */
export const SW_URL = "/sw.js";

type ScriptUrlPolicy = { createScriptURL(input: string): unknown };
export interface TrustedTypesLike {
  createPolicy(name: string, rules: { createScriptURL(input: string): string }): ScriptUrlPolicy;
}

const swPolicies = new WeakMap<TrustedTypesLike, ScriptUrlPolicy>();

/**
 * The service worker script URL, as a `TrustedScriptURL` where Trusted Types
 * are enforced: the CSP has `require-trusted-types-for 'script'`, and
 * `ServiceWorkerContainer.register()` is a TrustedScriptURL sink, so a plain
 * string is rejected (Chromium). The policy accepts exactly {@link SW_URL}.
 * Without Trusted Types support the plain string is returned.
 */
export function serviceWorkerScriptURL(tt: TrustedTypesLike | undefined = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes): string {
  if (tt === undefined || typeof tt.createPolicy !== "function") return SW_URL;
  let policy = swPolicies.get(tt);
  policy ??= tt.createPolicy(SW_POLICY, {
    createScriptURL(input: string): string {
      if (input !== SW_URL) throw new TypeError(`dropr-sw policy: refusing script URL ${input}`);
      return input;
    },
  });
  swPolicies.set(tt, policy);
  // A TrustedScriptURL; typed as string because register() accepts both.
  return policy.createScriptURL(SW_URL) as string;
}

let workerPromise: Promise<ServiceWorker | null> | null = null;

/**
 * Register the download service worker (idempotent). Call on page load so it
 * is active by the time the user clicks Download. Resolves to null where
 * service workers are unavailable (e.g. some private-browsing modes).
 */
export function prepareDownloadWorker(timeoutMs = 10_000): Promise<ServiceWorker | null> {
  workerPromise ??= (async () => {
    if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return null;
    try {
      const reg = await navigator.serviceWorker.register(serviceWorkerScriptURL(), { scope: DL_SCOPE, updateViaCache: "none" });
      const pendingWorker = reg.installing ?? reg.waiting;
      if (reg.active !== null && pendingWorker === null) return reg.active;
      return await new Promise<ServiceWorker | null>((resolve) => {
        const t = setTimeout(() => resolve(reg.active), timeoutMs);
        const sw = pendingWorker ?? reg.active;
        if (sw === null) return resolve(null);
        const check = (): void => {
          if (sw.state === "activated") {
            clearTimeout(t);
            resolve(sw);
          } else if (sw.state === "redundant") {
            clearTimeout(t);
            resolve(reg.active);
          }
        };
        sw.addEventListener("statechange", check);
        check();
      });
    } catch {
      return null;
    }
  })();
  return workerPromise;
}

/** Whether `ReadableStream`s can be transferred with postMessage (Chrome 87+, Firefox 103+, Safari 26.x?). */
export function supportsTransferableStreams(): boolean {
  try {
    const rs = new ReadableStream();
    const mc = new MessageChannel();
    mc.port1.postMessage(rs, [rs as unknown as Transferable]);
    mc.port1.close();
    mc.port2.close();
    return true;
  } catch {
    return false;
  }
}

function randomId(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

function waitFor(port: MessagePort, type: SwToPage["type"], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new DownloadError("unsupported", t.helperTimeout)), timeoutMs);
    const prev = port.onmessage;
    port.onmessage = (ev: MessageEvent<SwToPage>) => {
      if (ev.data.type === type) {
        clearTimeout(timer);
        port.onmessage = prev;
        resolve();
      }
    };
  });
}

/**
 * Service-worker sink: registers a one-shot URL with the worker, navigates
 * to it (the browser starts a normal download) and feeds it plaintext.
 */
export async function swSink(worker: ServiceWorker, name: string, size: number | null): Promise<DownloadSink> {
  const id = randomId();
  const mc = new MessageChannel();
  const port = mc.port1;
  const keepalive = setInterval(() => worker.postMessage({ type: "keepalive" } satisfies PageToSw), 10_000);
  let cancelled = false;
  let finish = (): void => {
    clearInterval(keepalive);
    finish = () => undefined;
  };

  if (supportsTransferableStreams()) {
    const ts = new TransformStream<Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>>(undefined, undefined, { highWaterMark: 16 });
    const ready = waitFor(port, "registered", 5000);
    const msg: PageToSw = { type: "register", id, name, size, stream: ts.readable };
    worker.postMessage(msg, [mc.port2, ts.readable as unknown as Transferable]);
    await ready;
    port.close();
    location.assign(DL_SCOPE + id);
    const writer = ts.writable.getWriter();
    return {
      kind: "sw",
      write: (c) => writer.write(c),
      async close() {
        finish();
        await writer.close();
      },
      async abort(reason) {
        finish();
        await writer.abort(reason).catch(() => undefined);
      },
    };
  }

  // Pull protocol over the port: one chunk per `pull`, so the browser's
  // consumption rate drives us (backpressure).
  let pulls = 0;
  let waiter: (() => void) | null = null;
  const ready = waitFor(port, "registered", 5000);
  worker.postMessage({ type: "register", id, name, size } satisfies PageToSw, [mc.port2]);
  await ready;
  port.onmessage = (ev: MessageEvent<SwToPage>) => {
    if (ev.data.type === "pull") pulls++;
    else if (ev.data.type === "cancel") cancelled = true;
    const w = waiter;
    waiter = null;
    w?.();
  };
  location.assign(DL_SCOPE + id);
  const nextPull = async (): Promise<void> => {
    while (pulls === 0 && !cancelled) await new Promise<void>((r) => (waiter = r));
    if (cancelled) throw abortError(new DOMException("The download was cancelled.", "AbortError"));
    pulls--;
  };
  const send = (m: PortToSw, transfer: Transferable[] = []): void => port.postMessage(m, transfer);
  return {
    kind: "sw",
    async write(c) {
      await nextPull();
      // Copy into an exactly-sized buffer we can transfer.
      const buf = c.byteOffset === 0 && c.byteLength === c.buffer.byteLength ? c.buffer : c.slice().buffer;
      send({ type: "chunk", chunk: buf }, [buf]);
    },
    async close() {
      finish();
      await nextPull();
      send({ type: "end" });
      port.close();
    },
    async abort() {
      finish();
      if (!cancelled) send({ type: "abort" });
      port.close();
    },
  };
}

export interface OpenedSink {
  readonly sink: DownloadSink;
  /** Plain-language notice to show (e.g. the memory fallback warning), or "". */
  readonly notice: string;
}

/**
 * Pick and open the best sink for a file of `plainSize` bytes. Call it
 * first thing in the click handler (user gesture for the file picker).
 *
 * @throws `AbortError` if the user dismisses the save dialog.
 * @throws {DownloadError} `unsupported` if no sink can take a file this large.
 */
export async function openSink(name: string, plainSize: number): Promise<OpenedSink> {
  const picker = savePicker();
  if (picker !== null) {
    try {
      return { sink: await fsSink(picker, name), notice: "" };
    } catch (e) {
      if (isAbortError(e)) throw e; // user dismissed the dialog
      // SecurityError (no gesture), NotAllowedError: fall through to the SW.
    }
  }
  const worker = await prepareDownloadWorker();
  if (worker !== null) {
    try {
      return { sink: await swSink(worker, name, plainSize), notice: "" };
    } catch {
      // fall through
    }
  }
  if (plainSize <= BLOB_LIMIT) {
    return {
      sink: blobSink(name),
      notice: t.inMemoryNotice,
    };
  }
  throw new DownloadError("unsupported", t.noSecureDownload);
}
