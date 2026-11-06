/**
 * Chunked, resumable, encrypted upload engine (ARCHITECTURE.md §3 "Uploads").
 *
 * - The file is read with `Blob.slice()` one 32 MiB part at a time, each part
 *   is encrypted with `encryptPart` (absolute segment indexes, so parts are
 *   independent) and PUT to `/upload/{id}/part/{n}` with the Bearer token.
 * - At most `parallelism` (default 3) parts are in flight. Each worker holds
 *   one plaintext part and its ciphertext at a time, so memory is bounded by
 *   about `parallelism × 2 × 32 MiB` regardless of the file size.
 * - Transient failures (network, timeout, 408, 429, 5xx) are retried with
 *   exponential backoff and jitter. Permanent ones (other 4xx) stop the
 *   upload at once.
 * - When retries are exhausted the upload fails with an
 *   {@link UploadInterruptedError}; calling {@link Uploader.run} again resumes:
 *   it asks the server which parts it already has (`GET /upload/{id}`) and
 *   sends only the others. Re-sending a part is safe: re-encrypting the same
 *   plaintext under the same FK yields byte-identical ciphertext (FORMAT.md
 *   §8.1).
 * - Progress is reported per acknowledged part (bytes, smoothed rate, ETA).
 * - `cancel()` aborts in-flight requests and rejects `run()` with an
 *   `AbortError`.
 *
 * **Resumable state is kept in memory only** (file handle, content key,
 * upload id and token live in this object). Nothing is written to
 * localStorage/IndexedDB:
 *
 * 1. Persisting FK (even wrapped under a non-extractable IndexedDB key) puts
 *    a usable file key on disk for as long as the upload is unfinished, and
 *    any script that later runs on the origin can use it.
 * 2. After a reload the user would have to pick the file again, and the
 *    browser cannot prove it is byte-identical to the original. Resuming
 *    with a *changed* file under the same FK would re-encrypt different
 *    plaintext under the same (key, nonce) pairs, which breaks AES-GCM
 *    (FORMAT.md §8.1: "MUST start a new upload with a new FK").
 *
 * So resumption covers network drops, sleep/wake and server restarts within
 * one page session; a closed tab means starting again (the server garbage-
 * collects the incomplete blob). Pages warn before unload while uploading.
 *
 * @module
 */

import { CIPHER_PART_SIZE, ciphertextSize, encryptPart, partCount, partPlainRange } from "../crypto/index.ts";
import { Api, ApiError } from "./api.ts";
import { type Progress, RateMeter } from "./progress.ts";
import { abortError, backoffDelay, isAbortError, sleep } from "./retry.ts";

export type { Progress } from "./progress.ts";

/** Encrypts one part; injectable for tests. Same contract as `encryptPart`. */
export type PartEncryptor = (
  ck: CryptoKey,
  partIndex: number,
  plaintext: Uint8Array,
  isLastPart: boolean,
) => Promise<Uint8Array<ArrayBuffer>>;

export interface UploaderOptions {
  /** The plaintext file (any Blob). Must not change during the upload. */
  readonly file: Blob;
  /** CK from `deriveFileKeys(fk).content`. */
  readonly contentKey: CryptoKey;
  readonly uploadId: string;
  readonly uploadToken: string;
  /** API client (default: same-origin). */
  readonly api?: Api;
  /** Parts in flight at once (default 3). */
  readonly parallelism?: number;
  /** Retries per request before the upload is reported interrupted (default 5). */
  readonly maxRetries?: number;
  /** Backoff base delay in ms (default 1000). */
  readonly retryBaseMs?: number;
  /** Backoff cap in ms (default 30 000). */
  readonly retryCapMs?: number;
  /** Per-part PUT timeout in ms (default 10 min: 32 MiB on a slow uplink). */
  readonly partTimeoutMs?: number;
  readonly onProgress?: (p: Progress) => void;
  /** Injected for tests. */
  readonly encrypt?: PartEncryptor;
  readonly now?: () => number;
  readonly random?: () => number;
}

/**
 * Retries were exhausted on a transient failure. The upload can be resumed by
 * calling `run()` again (for instance when the browser comes back online).
 */
export class UploadInterruptedError extends Error {
  override readonly cause: unknown;
  constructor(cause: unknown) {
    super(
      cause instanceof ApiError && cause.status !== 0
        ? cause.message
        : "The connection was lost. The upload will continue where it stopped when you retry.",
    );
    this.name = "UploadInterruptedError";
    this.cause = cause;
  }
}

type State = "idle" | "running" | "interrupted" | "done" | "failed" | "cancelled";

export class Uploader {
  readonly cipherSize: number;
  readonly parts: number;

  private readonly o: UploaderOptions;
  private readonly api: Api;
  private readonly encrypt: PartEncryptor;
  private readonly now: () => number;
  private readonly controller = new AbortController();
  private readonly done = new Set<number>();
  private readonly meter: RateMeter;
  private doneBytes = 0;
  private state: State = "idle";
  private runs = 0;

  constructor(opts: UploaderOptions) {
    this.o = opts;
    this.api = opts.api ?? new Api();
    this.encrypt = opts.encrypt ?? encryptPart;
    this.now = opts.now ?? (() => performance.now());
    this.cipherSize = ciphertextSize(opts.file.size);
    this.parts = partCount(this.cipherSize);
    this.meter = new RateMeter(opts.file.size, this.now());
  }

  get status(): State {
    return this.state;
  }

  /** Abort in-flight requests; `run()` rejects with an AbortError. */
  cancel(): void {
    if (this.state === "done") return;
    this.state = "cancelled";
    this.controller.abort();
  }

  /**
   * Upload all missing parts, then finalize. Resolves when the server has
   * accepted the finalize call. Call again after an
   * {@link UploadInterruptedError} to resume.
   */
  async run(): Promise<void> {
    if (this.state === "running") throw new Error("upload already running");
    if (this.state === "done") return;
    if (this.state === "cancelled" || this.controller.signal.aborted) throw abortError();
    if (this.state === "failed") throw new Error("upload failed permanently; start a new one");
    this.state = "running";
    const signal = this.controller.signal;
    try {
      if (this.runs++ > 0) await this.syncWithServer(signal);
      this.meter.reset(this.doneBytes, this.now());
      this.emit();

      const queue: number[] = [];
      for (let n = 0; n < this.parts; n++) if (!this.done.has(n)) queue.push(n);
      // Workers share the queue; the first failure aborts the others.
      const local = new AbortController();
      const both = AbortSignal.any([signal, local.signal]);
      const worker = async (): Promise<void> => {
        for (let n = queue.shift(); n !== undefined; n = queue.shift()) {
          await this.uploadPart(n, both);
        }
      };
      const width = Math.max(1, Math.min(this.o.parallelism ?? 3, queue.length));
      const results = await Promise.allSettled(Array.from({ length: width }, worker).map((p) =>
        p.catch((e: unknown) => {
          local.abort();
          throw e;
        }),
      ));
      const failure = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
      if (failure !== undefined) throw firstRealError(results, failure.reason);

      await this.withRetries(() => this.api.finalizeUpload(this.o.uploadId, this.o.uploadToken, this.parts, { signal }), signal);
      this.state = "done";
    } catch (e) {
      if (signal.aborted) {
        this.state = "cancelled";
        throw abortError();
      }
      if (e instanceof ApiError && e.retryable) {
        this.state = "interrupted";
        throw new UploadInterruptedError(e);
      }
      this.state = "failed";
      throw e;
    }
  }

  /** Resume: the server's list of present parts is authoritative (parts it lost are sent again). */
  private async syncWithServer(signal: AbortSignal): Promise<void> {
    const status = await this.withRetries(() => this.api.uploadStatus(this.o.uploadId, this.o.uploadToken, { signal }), signal);
    this.done.clear();
    this.doneBytes = 0;
    for (const n of new Set(status.parts_present)) {
      if (n < this.parts) {
        this.done.add(n);
        this.doneBytes += this.plainLength(n);
      }
    }
  }

  private plainLength(n: number): number {
    const r = partPlainRange(n, this.o.file.size);
    return r.end - r.start;
  }

  private async uploadPart(n: number, signal: AbortSignal): Promise<void> {
    const range = partPlainRange(n, this.o.file.size);
    let ct: Uint8Array<ArrayBuffer> | null;
    {
      const pt = new Uint8Array(await this.o.file.slice(range.start, range.end).arrayBuffer());
      if (signal.aborted) throw abortError(signal.reason);
      ct = await this.encrypt(this.o.contentKey, n, pt, n === this.parts - 1);
    } // plaintext buffer is unreachable from here on
    if (ct.length > CIPHER_PART_SIZE) throw new Error("part too large"); // cannot happen with encryptPart
    const body = ct;
    await this.withRetries(
      () =>
        this.api.putPart(this.o.uploadId, n, this.o.uploadToken, body, {
          signal,
          timeoutMs: this.o.partTimeoutMs ?? 600_000,
        }),
      signal,
    );
    ct = null;
    this.done.add(n);
    this.doneBytes += range.end - range.start;
    this.emit();
  }

  private async withRetries<T>(fn: () => Promise<T>, signal: AbortSignal): Promise<T> {
    const max = this.o.maxRetries ?? 5;
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (e) {
        if (signal.aborted || isAbortError(e)) throw e;
        if (!(e instanceof ApiError) || !e.retryable || attempt >= max) throw e;
        await sleep(
          backoffDelay(attempt, {
            baseMs: this.o.retryBaseMs ?? 1000,
            capMs: this.o.retryCapMs ?? 30_000,
            ...(this.o.random ? { random: this.o.random } : {}),
          }),
          signal,
        );
      }
    }
  }

  private emit(): void {
    this.o.onProgress?.(this.meter.update(this.doneBytes, this.now()));
  }
}

/** Prefer a real failure over the AbortErrors it caused in sibling workers. */
function firstRealError(results: PromiseSettledResult<void>[], fallback: unknown): unknown {
  for (const r of results) if (r.status === "rejected" && !isAbortError(r.reason)) return r.reason;
  return fallback;
}
