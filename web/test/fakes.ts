/**
 * In-process fakes for the browser modules: a fake `fetch` routed to
 * handlers (an in-memory Dropr server), fake Blobs and sinks.
 */

import type { FetchFn } from "../src/lib/api.ts";
import type { DownloadSink } from "../src/lib/downloader.ts";

export interface FakeRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Headers;
  readonly body: Uint8Array | null;
  readonly json: unknown;
  readonly signal: AbortSignal | null;
}

export type Handler = (req: FakeRequest) => Response | Promise<Response>;

/** Build a fake fetch from a handler; records every request; honours AbortSignal. */
export function fakeFetch(handler: Handler): FetchFn & { calls: FakeRequest[] } {
  const calls: FakeRequest[] = [];
  const fn = (async (input: string, init: RequestInit = {}) => {
    const signal = init.signal ?? null;
    if (signal?.aborted) throw signal.reason;
    const headers = new Headers(init.headers);
    let body: Uint8Array | null = null;
    let json: unknown = undefined;
    if (typeof init.body === "string") {
      body = new TextEncoder().encode(init.body);
      json = JSON.parse(init.body);
    } else if (init.body instanceof Uint8Array) {
      body = init.body;
    }
    const req: FakeRequest = { method: init.method ?? "GET", path: input, headers, body, json, signal };
    calls.push(req);
    return await new Promise<Response>((resolve, reject) => {
      const onAbort = (): void => reject(signal?.reason);
      signal?.addEventListener("abort", onAbort, { once: true });
      Promise.resolve()
        .then(() => handler(req))
        .then(
          (r) => {
            signal?.removeEventListener("abort", onAbort);
            resolve(r);
          },
          (e: unknown) => {
            signal?.removeEventListener("abort", onAbort);
            reject(e);
          },
        );
    });
  }) as FetchFn & { calls: FakeRequest[] };
  fn.calls = calls;
  return fn;
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function delay(ms: number, signal?: AbortSignal | null): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}

/** A Blob-like of `size` bytes whose slices are cheap (1-byte buffers). For engine tests with fake encryption. */
export function lazyBlob(size: number): Blob {
  return {
    size,
    slice: (start = 0, end = size) => ({
      size: end - start,
      arrayBuffer: async () => new ArrayBuffer(1),
    }),
  } as unknown as Blob;
}

/** Sink collecting chunks in memory. */
export function memorySink(): DownloadSink & { chunks: Uint8Array[]; closed: boolean; aborted: unknown; bytes(): Uint8Array } {
  const s = {
    kind: "memory" as const,
    chunks: [] as Uint8Array[],
    closed: false,
    aborted: undefined as unknown,
    async write(c: Uint8Array) {
      if (s.closed) throw new Error("write after close");
      s.chunks.push(new Uint8Array(c));
    },
    async close() {
      s.closed = true;
    },
    async abort(reason?: unknown) {
      s.aborted = reason ?? true;
      s.chunks = [];
    },
    bytes() {
      const out = new Uint8Array(s.chunks.reduce((n, c) => n + c.length, 0));
      let o = 0;
      for (const c of s.chunks) {
        out.set(c, o);
        o += c.length;
      }
      return out;
    },
  };
  return s;
}

/** Deterministic pseudo-random bytes (fast, non-cryptographic). */
export function pseudoRandom(n: number, seed = 1): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}
