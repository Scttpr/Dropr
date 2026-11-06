/**
 * Download pipeline against a fake `/dl/{token}` serving real ciphertext with
 * Range support: full download, resume after mid-segment failures (error and
 * clean early close), tampering, token renewal, retry exhaustion, abort.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CIPHER_SEGMENT_SIZE,
  SEGMENT_SIZE,
  deriveFileKeys,
  encryptPart,
  generateFileKey,
} from "../src/crypto/index.ts";
import { Api, ApiError } from "../src/lib/api.ts";
import { DownloadError, SW_POLICY, SW_URL, type TrustedTypesLike, downloadToSink, lengthGuard, serviceWorkerScriptURL } from "../src/lib/downloader.ts";
import { type FakeRequest, fakeFetch, jsonResponse, memorySink, pseudoRandom } from "./fakes.ts";

interface Attempt {
  /** Bytes to send before the fault (relative to the start of this response). */
  readonly cutAfter?: number;
  /** "error" = body stream errors (network); "close" = body ends cleanly early. */
  readonly mode?: "error" | "close";
  /** Respond with this status instead. */
  readonly status?: number;
}

async function fixture(plainLen: number) {
  const plain = pseudoRandom(plainLen, plainLen);
  const keys = await deriveFileKeys(generateFileKey());
  const ct = await encryptPart(keys.content, 0, plain, true);
  return { plain, keys, ct };
}

function body(data: Uint8Array, a: Attempt, chunk = 10_000): ReadableStream<Uint8Array> {
  const limit = a.cutAfter ?? data.length;
  let off = 0;
  return new ReadableStream({
    pull(c) {
      if (off >= limit) {
        if (limit < data.length && a.mode !== "close") c.error(new TypeError("network error"));
        else c.close();
        return;
      }
      const end = Math.min(off + chunk, limit);
      c.enqueue(data.slice(off, end));
      off = end;
    },
  });
}

/** Fake /dl server. `plan[i]` describes the i-th GET; later GETs succeed. */
function dlServer(ct: Uint8Array, plan: Attempt[] = [], validTokens = new Set(["t1"])) {
  const ranges: (number | null)[] = [];
  const tokens: string[] = [];
  const handler = (req: FakeRequest): Response => {
    const m = /^\/dl\/([^/]+)$/.exec(req.path);
    if (!m || req.method !== "GET") return jsonResponse(404, { error: "not_found" });
    const token = decodeURIComponent(m[1] as string);
    tokens.push(token);
    const range = req.headers.get("Range");
    const start = range === null ? null : Number(/^bytes=(\d+)-$/.exec(range)?.[1]);
    ranges.push(start);
    const a = plan[ranges.length - 1] ?? {};
    if (a.status !== undefined) return jsonResponse(a.status, { error: "x" });
    if (!validTokens.has(token)) return jsonResponse(410, { error: "expired" });
    const from = start ?? 0;
    const headers: Record<string, string> = { "Content-Type": "application/octet-stream" };
    if (start !== null) headers["Content-Range"] = `bytes ${from}-${ct.length - 1}/${ct.length}`;
    return new Response(body(ct.subarray(from), a), { status: start === null ? 200 : 206, headers });
  };
  return { ranges, tokens, fetch: fakeFetch(handler) };
}

const fast = { retryBaseMs: 1, retryCapMs: 2 };

describe("downloadToSink", () => {
  it("streams, decrypts and closes the sink", async () => {
    const { plain, keys, ct } = await fixture(5 * SEGMENT_SIZE + 777);
    const srv = dlServer(ct);
    const sink = memorySink();
    const seen: number[] = [];
    await downloadToSink({
      token: "t1",
      cipherSize: ct.length,
      contentKey: keys.content,
      sink,
      api: new Api({ fetch: srv.fetch }),
      onProgress: (p) => seen.push(p.done),
      ...fast,
    });
    assert.equal(sink.closed, true);
    assert.equal(Buffer.compare(sink.bytes(), plain), 0);
    assert.deepEqual(srv.ranges, [null]);
    assert.equal(seen.at(-1), plain.length);
    assert.equal(srv.fetch.calls[0]?.headers.get("Range"), null);
  });

  it("handles an empty file", async () => {
    const { keys, ct } = await fixture(0);
    const srv = dlServer(ct);
    const sink = memorySink();
    await downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: srv.fetch }) });
    assert.equal(sink.closed, true);
    assert.equal(sink.bytes().length, 0);
  });

  it("resumes with a Range request at the last written segment boundary after a mid-segment network error", async () => {
    const { plain, keys, ct } = await fixture(6 * SEGMENT_SIZE + 5);
    // Cut 2.5 segments in: segments 0 and 1 are complete, but the decryptor
    // only releases a segment once it has seen the start of the next one, so
    // exactly 2 segments are written before the failure.
    const cut = 2 * CIPHER_SEGMENT_SIZE + 30_000;
    const srv = dlServer(ct, [{ cutAfter: cut, mode: "error" }, { cutAfter: 3 * CIPHER_SEGMENT_SIZE + 10, mode: "error" }]);
    const sink = memorySink();
    await downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: srv.fetch }), ...fast });
    assert.equal(Buffer.compare(sink.bytes(), plain), 0);
    assert.equal(srv.ranges.length, 3);
    assert.equal(srv.ranges[0], null);
    assert.equal(srv.ranges[1], 2 * CIPHER_SEGMENT_SIZE);
    // Second attempt starts at segment 2 and delivers 3 segments + 10 bytes → segments 2..4 written.
    assert.equal(srv.ranges[2], 5 * CIPHER_SEGMENT_SIZE);
    assert.equal(sink.closed, true);
  });

  it("treats a cleanly truncated body as a network failure and resumes", async () => {
    const { plain, keys, ct } = await fixture(3 * SEGMENT_SIZE + 100);
    const srv = dlServer(ct, [{ cutAfter: CIPHER_SEGMENT_SIZE + 5, mode: "close" }]);
    const sink = memorySink();
    await downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: srv.fetch }), ...fast });
    assert.equal(Buffer.compare(sink.bytes(), plain), 0);
    // Segment 0 was released (5 bytes of segment 1 followed it); resume at segment 1.
    assert.deepEqual(srv.ranges, [null, CIPHER_SEGMENT_SIZE]);
  });

  it("retries 5xx responses", async () => {
    const { plain, keys, ct } = await fixture(SEGMENT_SIZE + 1);
    const srv = dlServer(ct, [{ status: 503 }, { status: 500 }]);
    const sink = memorySink();
    await downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: srv.fetch }), ...fast });
    assert.equal(Buffer.compare(sink.bytes(), plain), 0);
    assert.equal(srv.ranges.length, 3);
  });

  it("aborts the sink and never retries when authentication fails (tampering)", async () => {
    const { keys, ct } = await fixture(4 * SEGMENT_SIZE);
    const bad = new Uint8Array(ct);
    bad[2 * CIPHER_SEGMENT_SIZE + 100] = (bad[2 * CIPHER_SEGMENT_SIZE + 100] ?? 0) ^ 1;
    const srv = dlServer(bad);
    const sink = memorySink();
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: srv.fetch }), ...fast }),
      (e: unknown) => e instanceof DownloadError && e.code === "damaged",
    );
    assert.equal(sink.closed, false);
    assert.ok(sink.aborted !== undefined, "sink must be aborted");
    assert.equal(srv.ranges.length, 1);
  });

  it("rejects a wrong key", async () => {
    const { ct } = await fixture(1000);
    const other = await deriveFileKeys(generateFileKey());
    const sink = memorySink();
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: other.content, sink, api: new Api({ fetch: dlServer(ct).fetch }) }),
      (e: unknown) => e instanceof DownloadError && e.code === "damaged",
    );
    assert.ok(sink.aborted !== undefined);
  });

  it("detects trailing data appended by the server", async () => {
    const { keys, ct } = await fixture(1000);
    const longer = new Uint8Array(ct.length + 20);
    longer.set(ct);
    const sink = memorySink();
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: dlServer(longer).fetch }) }),
      DownloadError,
    );
    assert.equal(sink.closed, false);
  });

  it("renews an expired token when resuming", async () => {
    const { plain, keys, ct } = await fixture(3 * SEGMENT_SIZE + 9);
    const valid = new Set(["t1"]);
    // 1st GET fails mid-way; 2nd (resume) is refused (token expired); 3rd uses the renewed token.
    const srv = dlServer(ct, [{ cutAfter: 2 * CIPHER_SEGMENT_SIZE + 1, mode: "error" }, { status: 410 }], valid);
    const sink = memorySink();
    let renewals = 0;
    await downloadToSink({
      token: "t1",
      cipherSize: ct.length,
      contentKey: keys.content,
      sink,
      api: new Api({ fetch: srv.fetch }),
      renewToken: async () => {
        renewals++;
        valid.add("t2");
        return "t2";
      },
      ...fast,
    });
    assert.equal(renewals, 1);
    assert.deepEqual(srv.tokens, ["t1", "t1", "t2"]);
    assert.deepEqual(srv.ranges, [null, 2 * CIPHER_SEGMENT_SIZE, 2 * CIPHER_SEGMENT_SIZE]);
    assert.equal(Buffer.compare(sink.bytes(), plain), 0);
  });

  it("fails with 410 on the first request without renewing (dead link)", async () => {
    const { keys, ct } = await fixture(10);
    const srv = dlServer(ct, [{ status: 410 }]);
    const sink = memorySink();
    let renewed = false;
    await assert.rejects(
      downloadToSink({
        token: "t1",
        cipherSize: ct.length,
        contentKey: keys.content,
        sink,
        api: new Api({ fetch: srv.fetch }),
        renewToken: async () => {
          renewed = true;
          return "x";
        },
      }),
      (e: unknown) => e instanceof ApiError && e.status === 410,
    );
    assert.equal(renewed, false);
    assert.ok(sink.aborted !== undefined);
  });

  it("gives up after maxRetries consecutive failures without progress", async () => {
    const { keys, ct } = await fixture(SEGMENT_SIZE * 2);
    const srv = dlServer(ct, Array.from({ length: 10 }, () => ({ cutAfter: 100, mode: "error" as const })));
    const sink = memorySink();
    await assert.rejects(
      downloadToSink({
        token: "t1",
        cipherSize: ct.length,
        contentKey: keys.content,
        sink,
        api: new Api({ fetch: srv.fetch }),
        maxRetries: 3,
        ...fast,
      }),
      (e: unknown) => e instanceof DownloadError && e.code === "interrupted",
    );
    assert.equal(srv.ranges.length, 4);
    assert.ok(sink.aborted !== undefined);
  });

  it("rejects a server that ignores the Range header", async () => {
    const { keys, ct } = await fixture(3 * SEGMENT_SIZE);
    const handler = fakeFetch(() => {
      const first = handler.calls.length === 1;
      return new Response(body(ct, first ? { cutAfter: 2 * CIPHER_SEGMENT_SIZE + 3, mode: "error" } : {}), {
        status: 200, // ignores Range
        headers: {},
      });
    });
    const sink = memorySink();
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: handler }), ...fast }),
      (e: unknown) => e instanceof ApiError && e.code === "bad_response",
    );
    assert.ok(sink.aborted !== undefined);
  });

  it("propagates an abort and aborts the sink", async () => {
    const { keys, ct } = await fixture(8 * SEGMENT_SIZE);
    const ctl = new AbortController();
    const srv = dlServer(ct);
    const sink = memorySink();
    const write = sink.write.bind(sink);
    let n = 0;
    sink.write = async (c) => {
      if (++n === 2) ctl.abort();
      await write(c);
    };
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, signal: ctl.signal, api: new Api({ fetch: srv.fetch }) }),
      (e: unknown) => e instanceof Error && e.name === "AbortError",
    );
    assert.ok(sink.aborted !== undefined);
    assert.equal(sink.closed, false);
  });

  it("stops when the sink fails (e.g. disk full) and reports it", async () => {
    const { keys, ct } = await fixture(3 * SEGMENT_SIZE);
    const sink = memorySink();
    sink.write = async () => {
      throw new DOMException("full", "QuotaExceededError");
    };
    await assert.rejects(
      downloadToSink({ token: "t1", cipherSize: ct.length, contentKey: keys.content, sink, api: new Api({ fetch: dlServer(ct).fetch }) }),
      (e: unknown) => e instanceof DownloadError && e.code === "sink",
    );
    assert.ok(sink.aborted !== undefined);
  });
});

describe("lengthGuard", () => {
  it("errors on a short stream and passes a complete one", async () => {
    const run = (n: number, expected: number) =>
      new Response(new Blob([new Uint8Array(n)]).stream().pipeThrough(lengthGuard(expected))).arrayBuffer();
    assert.equal((await run(10, 10)).byteLength, 10);
    await assert.rejects(run(9, 10), /ended early/);
  });
});

describe("serviceWorkerScriptURL (Trusted Types)", () => {
  it("returns the plain URL without Trusted Types", () => {
    assert.equal(serviceWorkerScriptURL(undefined), SW_URL);
  });

  it("creates one dropr-sw policy that only accepts /sw.js", () => {
    const created: string[] = [];
    let rules: { createScriptURL(input: string): string } | null = null;
    const tt: TrustedTypesLike = {
      createPolicy(name, r) {
        created.push(name);
        rules = r;
        return { createScriptURL: (u: string) => ({ trusted: r.createScriptURL(u) }) };
      },
    };
    assert.deepEqual(serviceWorkerScriptURL(tt), { trusted: SW_URL });
    assert.deepEqual(serviceWorkerScriptURL(tt), { trusted: SW_URL });
    assert.deepEqual(created, [SW_POLICY]);
    assert.ok(rules !== null);
    assert.throws(() => rules!.createScriptURL("https://evil.example/sw.js"), TypeError);
    assert.throws(() => rules!.createScriptURL("/sw.js?x"), TypeError);
  });
});
