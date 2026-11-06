/**
 * Retry helpers: exponential backoff with full jitter, abortable sleep.
 *
 * @module
 */

export interface BackoffOptions {
  /** First delay in ms (default 500). */
  readonly baseMs?: number;
  /** Maximum delay in ms (default 30 000). */
  readonly capMs?: number;
  /** Random source in [0, 1) (default `Math.random`; injectable for tests). */
  readonly random?: () => number;
}

/**
 * Delay before retry number `attempt` (0-based): uniformly random in
 * `[d/2, d)` with `d = min(cap, base · 2^attempt)` ("equal jitter"), so
 * parallel clients do not retry in lockstep yet the delay still grows.
 */
export function backoffDelay(attempt: number, opts: BackoffOptions = {}): number {
  const base = opts.baseMs ?? 500;
  const cap = opts.capMs ?? 30_000;
  const random = opts.random ?? Math.random;
  const d = Math.min(cap, base * 2 ** Math.min(attempt, 30));
  return d / 2 + random() * (d / 2);
}

/** The `AbortError` DOMException `fetch` uses, so callers can test `err.name === "AbortError"`. */
export function abortError(reason?: unknown): Error {
  if (reason instanceof Error) return reason;
  return new DOMException("The operation was aborted.", "AbortError");
}

export function isAbortError(e: unknown): boolean {
  return e instanceof Error && (e.name === "AbortError" || e.name === "TimeoutError");
}

/** Sleep `ms`, rejecting early with the abort reason if `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal.reason));
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(t);
      reject(abortError(signal?.reason));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
