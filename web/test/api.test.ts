/**
 * API client: request shape (same-origin credentials, headers, bodies),
 * error mapping to plain-language ApiError, timeouts, aborts, response
 * validation, Range checks.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Api, ApiError, errorFromResponse, messageForStatus } from "../src/lib/api.ts";
import { delay, fakeFetch, jsonResponse } from "./fakes.ts";

describe("ApiError mapping", () => {
  it("uses the server's plain-language message and code", async () => {
    const e = await errorFromResponse(jsonResponse(410, { error: "expired", message: "This link has expired." }));
    assert.equal(e.status, 410);
    assert.equal(e.code, "expired");
    assert.equal(e.message, "This link has expired.");
    assert.equal(e.retryable, false);
  });

  it("falls back to a status message for non-JSON, empty or oversized messages", async () => {
    assert.equal((await errorFromResponse(new Response("<html>oops</html>", { status: 502 }))).message, messageForStatus(502));
    assert.equal((await errorFromResponse(new Response(null, { status: 404 }))).code, "http_404");
    const long = await errorFromResponse(jsonResponse(400, { error: "x", message: "y".repeat(1000) }));
    assert.equal(long.message, messageForStatus(400));
    const coded = await errorFromResponse(jsonResponse(410, { error: "exhausted" }));
    assert.equal(coded.message, "This link has reached its download limit.");
  });

  it("flags transient errors as retryable", async () => {
    for (const [status, retry] of [
      [500, true],
      [503, true],
      [429, true],
      [408, true],
      [400, false],
      [401, false],
      [404, false],
      [413, false],
    ] as const) {
      assert.equal((await errorFromResponse(jsonResponse(status, {}))).retryable, retry, String(status));
    }
    assert.equal(new ApiError(0, "network", "x").retryable, true);
    assert.equal(new ApiError(0, "timeout", "x").retryable, true);
    assert.equal(new ApiError(0, "bad_response", "x").retryable, false);
  });

  it("has a plain message for every common status", () => {
    for (const s of [0, 400, 401, 403, 404, 408, 409, 410, 413, 429, 500, 503]) {
      const m = messageForStatus(s);
      assert.ok(m.length > 10 && !/undefined/.test(m), `${s}: ${m}`);
    }
  });
});

describe("Api requests", () => {
  it("sends same-origin JSON with credentials and no-store", async () => {
    const f = fakeFetch(() => jsonResponse(200, { share_id: "s", upload_id: "u", upload_token: "t" }));
    const api = new Api({ fetch: f });
    const r = await api.createShare({ size: 16, parts: 1, meta: "m", expires_in: "7d" });
    assert.deepEqual(r, { share_id: "s", upload_id: "u", upload_token: "t" });
    const c = f.calls[0];
    assert.equal(c?.method, "POST");
    assert.equal(c?.path, "/api/shares");
    assert.equal(c?.headers.get("Content-Type"), "application/json");
    assert.deepEqual(c?.json, { size: 16, parts: 1, meta: "m", expires_in: "7d" });
  });

  it("passes credentials: same-origin, cache: no-store, redirect: error", async () => {
    let init: RequestInit | undefined;
    const api = new Api({
      fetch: async (_u, i) => {
        init = i;
        return jsonResponse(200, []);
      },
    });
    await api.listShares();
    assert.equal(init?.credentials, "same-origin");
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "error");
  });

  it("maps every endpoint to the documented method and path", async () => {
    const f = fakeFetch((req) => {
      if (req.path === "/api/requests" && req.method === "POST") return jsonResponse(200, { request_id: "r" });
      if (req.path.endsWith("/files")) return jsonResponse(200, { upload_id: "u", upload_token: "t" });
      if (req.path.endsWith("/download")) return jsonResponse(200, { token: "t", size: 16, parts: 1, meta: "m" });
      if (req.path.startsWith("/upload/u1") && req.method === "GET") return jsonResponse(200, { parts_present: [0] });
      if (req.method === "GET") return jsonResponse(200, []);
      return new Response(null, { status: 204 });
    });
    const api = new Api({ fetch: f });
    await api.deleteShare("s1");
    await api.listShares();
    await api.shareDownload("s1");
    await api.createRequest({ expires_in: "1d", max_files: 1, max_bytes: 10, single_use: true });
    await api.deleteRequest("r1");
    await api.listRequests();
    await api.createRequestFile("r1", { size: 16, parts: 1, meta: "m", wrapped_key: "k" });
    await api.listInbox();
    await api.inboxDownload("i1");
    await api.deleteInbox("i1");
    await api.putPart("u1", 3, "tok", new Uint8Array(4));
    await api.uploadStatus("u1", "tok");
    await api.finalizeUpload("u1", "tok", 4);
    assert.deepEqual(
      f.calls.map((c) => `${c.method} ${c.path}`),
      [
        "DELETE /api/shares/s1",
        "GET /api/shares",
        "POST /api/s/s1/download",
        "POST /api/requests",
        "DELETE /api/requests/r1",
        "GET /api/requests",
        "POST /api/r/r1/files",
        "GET /api/inbox",
        "POST /api/inbox/i1/download",
        "DELETE /api/inbox/i1",
        "PUT /upload/u1/part/3",
        "GET /upload/u1",
        "POST /upload/u1/finalize",
      ],
    );
    for (const c of f.calls.filter((c) => c.path.startsWith("/upload/"))) assert.equal(c.headers.get("Authorization"), "Bearer tok");
  });

  it("accepts bare arrays and wrapped lists, and validates entries", async () => {
    const share = { id: "a", size: 16, expires_at: 1, max_downloads: null, download_count: 0, created_at: 0 };
    assert.equal((await new Api({ fetch: fakeFetch(() => jsonResponse(200, [share])) }).listShares()).length, 1);
    assert.equal((await new Api({ fetch: fakeFetch(() => jsonResponse(200, { shares: [share] })) }).listShares()).length, 1);
    await assert.rejects(
      new Api({ fetch: fakeFetch(() => jsonResponse(200, [{ ...share, size: "16" }])) }).listShares(),
      (e: unknown) => e instanceof ApiError && e.code === "bad_response",
    );
    await assert.rejects(
      new Api({ fetch: fakeFetch(() => jsonResponse(200, { parts_present: [-1] })) }).uploadStatus("u", "t"),
      (e: unknown) => e instanceof ApiError && e.code === "bad_response",
    );
  });

  it("maps network failures and timeouts to retryable ApiErrors", async () => {
    const down = new Api({
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    await assert.rejects(down.listShares(), (e: unknown) => e instanceof ApiError && e.code === "network" && e.retryable);
    const slow = new Api({ fetch: fakeFetch(async (req) => (await delay(1000, req.signal), jsonResponse(200, []))), timeoutMs: 20 });
    await assert.rejects(slow.listShares(), (e: unknown) => e instanceof ApiError && e.code === "timeout" && e.retryable);
  });

  it("re-throws a caller abort as AbortError, not ApiError", async () => {
    const api = new Api({ fetch: fakeFetch(async (req) => (await delay(1000, req.signal), jsonResponse(200, []))) });
    const ctl = new AbortController();
    const p = api.listShares({ signal: ctl.signal });
    ctl.abort();
    await assert.rejects(p, (e: unknown) => e instanceof Error && e.name === "AbortError");
  });

  it("does not time out a long streamed download body", async () => {
    const api = new Api({
      timeoutMs: 20,
      fetch: fakeFetch(() => {
        let n = 0;
        const body = new ReadableStream<Uint8Array>({
          async pull(c) {
            await delay(15);
            if (n++ === 4) c.close();
            else c.enqueue(new Uint8Array(1));
          },
        });
        return new Response(body, { status: 200 });
      }),
    });
    const res = await api.fetchCiphertext("t", 0, 4);
    assert.equal((await res.arrayBuffer()).byteLength, 4);
  });

  it("checks 206 and Content-Range on ranged downloads", async () => {
    const mk = (status: number, cr: string | null) =>
      new Api({ fetch: fakeFetch(() => new Response("x", { status, headers: cr ? { "Content-Range": cr } : {} })) });
    await mk(206, "bytes 10-99/100").fetchCiphertext("t", 10, 100);
    for (const [s, cr] of [
      [200, null],
      [206, "bytes 0-99/100"],
      [206, "bytes 10-98/100"],
      [206, "bytes 10-99/101"],
      [206, null],
    ] as const) {
      await assert.rejects(mk(s, cr).fetchCiphertext("t", 10, 100), (e: unknown) => e instanceof ApiError && e.code === "bad_response");
    }
    const f = fakeFetch(() => new Response("x", { status: 206, headers: { "Content-Range": "bytes 10-99/100" } }));
    await new Api({ fetch: f }).fetchCiphertext("t", 10, 100);
    assert.equal(f.calls[0]?.headers.get("Range"), "bytes=10-");
  });
});
