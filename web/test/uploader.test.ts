/**
 * Upload engine against an in-process fake server: real encryption round
 * trip, retries, permanent errors, parallelism and memory bounds, resume,
 * cancellation, finalize, progress.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CIPHER_PART_SIZE,
  PART_SIZE,
  ciphertextSize,
  createDecryptStream,
  deriveFileKeys,
  generateFileKey,
  partCount,
} from "../src/crypto/index.ts";
import { Api, ApiError } from "../src/lib/api.ts";
import type { Progress } from "../src/lib/progress.ts";
import { UploadInterruptedError, Uploader, type UploaderOptions } from "../src/lib/uploader.ts";
import { type FakeRequest, delay, fakeFetch, jsonResponse, lazyBlob, pseudoRandom } from "./fakes.ts";

type Fault = Response | Error | null;

interface ServerOpts {
  readonly delayMs?: number;
  /** Return a fault for this PUT attempt (attempt counts from 1 per part), or null to accept. */
  readonly fault?: (part: number, attempt: number) => Fault;
  readonly finalizeFault?: (attempt: number) => Fault;
}

function uploadServer(parts: number, o: ServerOpts = {}) {
  const stored = new Map<number, Uint8Array>();
  const attempts = new Map<number, number>();
  const s = {
    stored,
    attempts,
    concurrent: 0,
    maxConcurrent: 0,
    finalized: 0,
    finalizeAttempts: 0,
    statusCalls: 0,
    order: [] as number[],
  };
  const handler = async (req: FakeRequest): Promise<Response> => {
    if (req.headers.get("Authorization") !== "Bearer tok") return jsonResponse(401, { error: "unauthorized" });
    let m = /^\/upload\/u1\/part\/(\d+)$/.exec(req.path);
    if (m && req.method === "PUT") {
      const n = Number(m[1]);
      const a = (attempts.get(n) ?? 0) + 1;
      attempts.set(n, a);
      s.concurrent++;
      s.maxConcurrent = Math.max(s.maxConcurrent, s.concurrent);
      try {
        await delay(o.delayMs ?? 1, req.signal);
        const f = o.fault?.(n, a) ?? null;
        if (f instanceof Error) throw f;
        if (f !== null) return f;
        stored.set(n, new Uint8Array(req.body ?? new Uint8Array()));
        s.order.push(n);
        return new Response(null, { status: 204 });
      } finally {
        s.concurrent--;
      }
    }
    if (req.path === "/upload/u1" && req.method === "GET") {
      s.statusCalls++;
      return jsonResponse(200, { parts_present: [...stored.keys()].sort((x, y) => x - y) });
    }
    m = /^\/upload\/u1\/finalize$/.exec(req.path);
    if (m && req.method === "POST") {
      s.finalizeAttempts++;
      const f = o.finalizeFault?.(s.finalizeAttempts) ?? null;
      if (f instanceof Error) throw f;
      if (f !== null) return f;
      const body = req.json as { parts: number };
      if (body.parts !== parts) return jsonResponse(400, { error: "bad_parts" });
      for (let n = 0; n < parts; n++) if (!stored.has(n)) return jsonResponse(409, { error: "missing_part" });
      s.finalized++;
      return jsonResponse(200, {});
    }
    return jsonResponse(404, { error: "not_found" });
  };
  return { s, fetch: fakeFetch(handler) };
}

/** Fake encryption: a tiny tagged buffer per part; tracks how many parts are alive at once. */
function trackingEncrypt() {
  const t = { live: 0, maxLive: 0, calls: [] as number[] };
  const encrypt: UploaderOptions["encrypt"] = async (_ck, n) => {
    t.live++;
    t.maxLive = Math.max(t.maxLive, t.live);
    t.calls.push(n);
    return Uint8Array.of(n & 0xff, n >> 8);
  };
  return { t, encrypt };
}

async function fakeKey(): Promise<CryptoKey> {
  return (await deriveFileKeys(generateFileKey())).content;
}

function base(fetch: ReturnType<typeof fakeFetch>, extra: Partial<UploaderOptions>): Omit<UploaderOptions, "file" | "contentKey"> {
  return {
    uploadId: "u1",
    uploadToken: "tok",
    api: new Api({ fetch }),
    retryBaseMs: 1,
    retryCapMs: 4,
    ...extra,
  };
}

const sizeForParts = (n: number): number => (n - 1) * PART_SIZE + 1234;

describe("Uploader", () => {
  it("uploads real ciphertext that decrypts to the original file, then finalizes", async () => {
    const plain = pseudoRandom(2 * PART_SIZE + 70_001, 7);
    const keys = await deriveFileKeys(generateFileKey());
    const parts = partCount(ciphertextSize(plain.length));
    assert.equal(parts, 3);
    const { s, fetch } = uploadServer(parts);
    const progress: Progress[] = [];
    const up = new Uploader({
      file: new Blob([plain]),
      contentKey: keys.content,
      ...base(fetch, { onProgress: (p) => progress.push(p) }),
    });
    await up.run();
    assert.equal(up.status, "done");
    assert.equal(s.finalized, 1);
    assert.equal(s.stored.size, 3);
    assert.equal(s.stored.get(0)?.length, CIPHER_PART_SIZE);
    // Reassemble and decrypt.
    const ct = new Blob([0, 1, 2].map((n) => s.stored.get(n) as Uint8Array<ArrayBuffer>));
    assert.equal(ct.size, ciphertextSize(plain.length));
    const out = new Uint8Array(await new Response(ct.stream().pipeThrough(createDecryptStream(keys.content))).arrayBuffer());
    assert.equal(Buffer.compare(out, plain), 0);
    // Progress: monotonic, ends at the plaintext size.
    for (let i = 1; i < progress.length; i++) assert.ok((progress[i]?.done ?? 0) >= (progress[i - 1]?.done ?? 0));
    assert.equal(progress.at(-1)?.done, plain.length);
    assert.equal(progress.at(-1)?.total, plain.length);
  });

  it("uploads an empty file as one 16-byte part", async () => {
    const { s, fetch } = uploadServer(1);
    const up = new Uploader({ file: new Blob([]), contentKey: await fakeKey(), ...base(fetch, {}) });
    await up.run();
    assert.equal(s.stored.get(0)?.length, 16);
    assert.equal(s.finalized, 1);
  });

  it("sends the Bearer token and octet-stream bodies to /upload/{id}/part/{n}", async () => {
    const { fetch } = uploadServer(2);
    const { encrypt } = trackingEncrypt();
    await new Uploader({ file: lazyBlob(sizeForParts(2)), contentKey: await fakeKey(), ...base(fetch, { encrypt }) }).run();
    const puts = fetch.calls.filter((c) => c.method === "PUT");
    assert.deepEqual(puts.map((c) => c.path).sort(), ["/upload/u1/part/0", "/upload/u1/part/1"]);
    for (const p of puts) {
      assert.equal(p.headers.get("Authorization"), "Bearer tok");
      assert.equal(p.headers.get("Content-Type"), "application/octet-stream");
    }
    const fin = fetch.calls.find((c) => c.path.endsWith("/finalize"));
    assert.deepEqual(fin?.json, { parts: 2 });
  });

  it("never has more than `parallelism` parts in flight or in memory", async () => {
    for (const parallelism of [1, 3]) {
      const parts = 12;
      const { s, fetch } = uploadServer(parts, { delayMs: 5 });
      const { t, encrypt } = trackingEncrypt();
      // Count a part as alive from encryption until its PUT completes.
      const api = new Api({ fetch });
      const origPut = api.putPart.bind(api);
      api.putPart = async (...args) => {
        try {
          return await origPut(...args);
        } finally {
          t.live--;
        }
      };
      await new Uploader({
        file: lazyBlob(sizeForParts(parts)),
        contentKey: await fakeKey(),
        ...base(fetch, { encrypt, parallelism, api }),
      }).run();
      assert.equal(s.stored.size, parts);
      assert.ok(s.maxConcurrent <= parallelism, `concurrent PUTs ${s.maxConcurrent} > ${parallelism}`);
      assert.ok(t.maxLive <= parallelism, `live parts ${t.maxLive} > ${parallelism}`);
      if (parallelism === 3) assert.equal(s.maxConcurrent, 3, "should actually use the parallelism");
    }
  });

  it("retries network errors and 5xx/429 with backoff, then succeeds", async () => {
    const { s, fetch } = uploadServer(3, {
      fault: (n, a) => {
        if (n === 0 && a <= 2) return new TypeError("fetch failed");
        if (n === 1 && a === 1) return jsonResponse(503, { error: "unavailable" });
        if (n === 2 && a === 1) return jsonResponse(429, { error: "rate_limited" });
        return null;
      },
    });
    const { encrypt } = trackingEncrypt();
    await new Uploader({ file: lazyBlob(sizeForParts(3)), contentKey: await fakeKey(), ...base(fetch, { encrypt }) }).run();
    assert.equal(s.attempts.get(0), 3);
    assert.equal(s.attempts.get(1), 2);
    assert.equal(s.attempts.get(2), 2);
    assert.equal(s.finalized, 1);
  });

  it("retries a failed finalize", async () => {
    const { s, fetch } = uploadServer(1, { finalizeFault: (a) => (a === 1 ? jsonResponse(502, {}) : null) });
    const { encrypt } = trackingEncrypt();
    await new Uploader({ file: lazyBlob(10), contentKey: await fakeKey(), ...base(fetch, { encrypt }) }).run();
    assert.equal(s.finalizeAttempts, 2);
    assert.equal(s.finalized, 1);
  });

  it("stops at once on a permanent 4xx error and does not finalize", async () => {
    const { s, fetch } = uploadServer(4, {
      fault: (n) => (n === 1 ? jsonResponse(413, { error: "too_large", message: "This file is too large." }) : null),
    });
    const { encrypt } = trackingEncrypt();
    const up = new Uploader({ file: lazyBlob(sizeForParts(4)), contentKey: await fakeKey(), ...base(fetch, { encrypt }) });
    await assert.rejects(up.run(), (e: unknown) => e instanceof ApiError && e.status === 413 && e.message === "This file is too large.");
    assert.equal(s.attempts.get(1), 1, "4xx must not be retried");
    assert.equal(s.finalized, 0);
    assert.equal(up.status, "failed");
    await assert.rejects(up.run(), /failed permanently/);
  });

  it("reports an interruption after exhausting retries, then resumes skipping parts the server has", async () => {
    let offline = true;
    const { s, fetch } = uploadServer(5, {
      fault: (n) => (offline && n >= 2 ? new TypeError("network down") : null),
    });
    const { t, encrypt } = trackingEncrypt();
    const up = new Uploader({
      file: lazyBlob(sizeForParts(5)),
      contentKey: await fakeKey(),
      ...base(fetch, { encrypt, parallelism: 1, maxRetries: 2 }),
    });
    await assert.rejects(up.run(), (e: unknown) => e instanceof UploadInterruptedError && e.cause instanceof ApiError);
    assert.equal(up.status, "interrupted");
    assert.deepEqual([...s.stored.keys()].sort(), [0, 1]);
    assert.equal(s.attempts.get(2), 3, "1 try + 2 retries");
    assert.equal(s.finalized, 0);

    offline = false;
    const before = t.calls.length;
    await up.run();
    assert.equal(s.statusCalls, 1, "resume asks the server which parts it has");
    assert.deepEqual(t.calls.slice(before).sort(), [2, 3, 4], "parts 0 and 1 are not re-sent");
    assert.equal(s.attempts.get(0), 1);
    assert.equal(s.finalized, 1);
    assert.equal(up.status, "done");
  });

  it("trusts the server's parts_present on resume (parts it lost are re-sent)", async () => {
    let fail = true;
    const { s, fetch } = uploadServer(3, { fault: (n) => (fail && n === 2 ? jsonResponse(500, {}) : null) });
    const { t, encrypt } = trackingEncrypt();
    const up = new Uploader({
      file: lazyBlob(sizeForParts(3)),
      contentKey: await fakeKey(),
      ...base(fetch, { encrypt, parallelism: 1, maxRetries: 0 }),
    });
    await assert.rejects(up.run(), UploadInterruptedError);
    s.stored.delete(0); // server lost part 0 (e.g. restarted before fsync)
    fail = false;
    const before = t.calls.length;
    await up.run();
    assert.deepEqual(t.calls.slice(before).sort(), [0, 2]);
    assert.equal(s.finalized, 1);
  });

  it("cancel() aborts in-flight requests and rejects with AbortError", async () => {
    const { s, fetch } = uploadServer(6, { delayMs: 50 });
    const { encrypt } = trackingEncrypt();
    const up = new Uploader({ file: lazyBlob(sizeForParts(6)), contentKey: await fakeKey(), ...base(fetch, { encrypt }) });
    const p = up.run();
    await delay(10);
    up.cancel();
    await assert.rejects(p, (e: unknown) => e instanceof Error && e.name === "AbortError");
    assert.equal(up.status, "cancelled");
    assert.equal(s.stored.size, 0);
    assert.equal(s.finalized, 0);
    await assert.rejects(up.run(), (e: unknown) => e instanceof Error && e.name === "AbortError");
  });

  it("cancel() during a backoff sleep stops promptly", async () => {
    const { fetch } = uploadServer(1, { fault: () => jsonResponse(503, {}) });
    const { encrypt } = trackingEncrypt();
    const up = new Uploader({
      file: lazyBlob(10),
      contentKey: await fakeKey(),
      ...base(fetch, { encrypt, retryBaseMs: 10_000, retryCapMs: 10_000 }),
    });
    const p = up.run();
    await delay(20);
    const t0 = Date.now();
    up.cancel();
    await assert.rejects(p, (e: unknown) => e instanceof Error && e.name === "AbortError");
    assert.ok(Date.now() - t0 < 1000);
  });
});
