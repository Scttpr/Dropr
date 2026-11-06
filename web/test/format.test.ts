/**
 * Formatting, progress metering, backoff, page-level helpers.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  b64urlEncode,
  ciphertextSize,
  deriveFileKeys,
  generateFileKey,
  generateOwnerKeyPair,
  sealMeta,
  toOwnerKeyPair,
  wrapFileKeyForRequest,
} from "../src/crypto/index.ts";
import type { InboxEntry } from "../src/lib/api.ts";
import { decryptInbox, openShare } from "../src/lib/decrypt-names.ts";
import { expiryChoiceText, formatBytes, formatEta, formatExpiry, formatRate, percent } from "../src/lib/format.ts";
import { RateMeter } from "../src/lib/progress.ts";
import { backoffDelay, sleep } from "../src/lib/retry.ts";

describe("format", () => {
  it("formats sizes in binary units", () => {
    assert.equal(formatBytes(0), "0 B");
    assert.equal(formatBytes(1023), "1023 B");
    assert.equal(formatBytes(1024), "1.00 KB");
    assert.equal(formatBytes(1536), "1.50 KB");
    assert.equal(formatBytes(5 * 2 ** 30), "5.00 GB");
    assert.equal(formatBytes(100 * 2 ** 30), "100 GB");
    assert.equal(formatBytes(-1), "–");
    assert.equal(formatRate(0), "–");
    assert.equal(formatRate(12.5 * 2 ** 20), "12.5 MB/s");
  });

  it("formats ETA and expiry in plain language", () => {
    assert.equal(formatEta(Infinity), "");
    assert.equal(formatEta(3), "a few seconds left");
    assert.equal(formatEta(42), "about 40 s left");
    assert.equal(formatEta(600), "about 10 min left");
    assert.equal(formatEta(3600 + 1800), "about 1 h 30 min left");
    const now = 1_000_000_000_000;
    const t = now / 1000;
    assert.equal(formatExpiry(t - 1, now), "Expired");
    assert.equal(formatExpiry(t + 30, now), "Expires in 1 minute");
    // Same table as internal/web/format_test.go (rounding up).
    const table: [number, string][] = [
      [1, "Expires in 1 minute"], [600, "Expires in 10 minutes"], [601, "Expires in 11 minutes"],
      [3599, "Expires in 1 hour"], [3600, "Expires in 1 hour"], [3601, "Expires in 2 hours"],
      [3 * 3600 - 5, "Expires in 3 hours"], [86_399, "Expires in 1 day"], [86_400, "Expires in 1 day"],
      [86_401, "Expires in 2 days"], [6 * 86_400 + 100, "Expires in 7 days"], [7 * 86_400 - 3, "Expires in 7 days"],
    ];
    for (const [d, want] of table) assert.equal(formatExpiry(t + d, now), want, `+${d}s`);
    assert.equal(expiryChoiceText("7d"), "Expires in 7 days");
    assert.equal(percent(5, 10), 50);
    assert.equal(percent(0, 0), 100);
  });
});

describe("RateMeter", () => {
  it("measures rate and ETA, and resets after a pause", () => {
    const m = new RateMeter(1000, 0);
    assert.equal(m.update(0, 0).eta, Infinity);
    const p = m.update(100, 1000);
    assert.equal(p.rate, 100);
    assert.equal(p.eta, 9);
    const q = m.update(300, 2000);
    assert.ok(q.rate > 100 && q.rate < 200);
    m.reset(300, 10_000);
    assert.equal(m.snapshot(300).rate, 0);
    assert.equal(m.update(1000, 11_000).eta, 0);
  });
});

describe("retry", () => {
  it("backs off exponentially with jitter in [d/2, d)", () => {
    assert.equal(backoffDelay(0, { baseMs: 100, random: () => 0 }), 50);
    assert.equal(backoffDelay(3, { baseMs: 100, random: () => 0.999999 }) < 800, true);
    assert.equal(backoffDelay(3, { baseMs: 100, random: () => 0 }), 400);
    assert.equal(backoffDelay(50, { baseMs: 100, capMs: 1000, random: () => 0 }), 500);
  });

  it("sleep is abortable", async () => {
    const c = new AbortController();
    const p = sleep(10_000, c.signal);
    c.abort();
    await assert.rejects(p, (e: unknown) => e instanceof Error && e.name === "AbortError");
  });
});

describe("decrypt-names", () => {
  it("opens share metadata and checks the size against the blob", async () => {
    const fk = generateFileKey();
    const keys = await deriveFileKeys(fk);
    const meta = b64urlEncode(await sealMeta(keys.metadata, { name: "a/b.txt", type: "text/plain", size: 5 }));
    const out = await openShare(fk, meta, ciphertextSize(5));
    assert.equal(out.meta.name, "a_b.txt");
    await assert.rejects(openShare(fk, meta, ciphertextSize(6)));
  });

  it("decrypts inbox entries independently; a bad one does not hide the others", async () => {
    const owner = await generateOwnerKeyPair();
    const kp = await toOwnerKeyPair(owner);
    const entry = async (id: string, requestId: string, name: string): Promise<InboxEntry> => {
      const fk = generateFileKey();
      const keys = await deriveFileKeys(fk);
      return {
        id,
        request_id: requestId,
        size: ciphertextSize(3),
        created_at: 1,
        meta: b64urlEncode(await sealMeta(keys.metadata, { name, type: "", size: 3 })),
        wrapped_key: b64urlEncode(await wrapFileKeyForRequest(owner.publicKey, requestId, fk)),
      };
    };
    const R1 = "AAAAAAAAAAAAAAAAAAAAAA";
    const R2 = "BBBBBBBBBBBBBBBBBBBBBA";
    const good = await entry("e1", R1, "one.pdf");
    const moved = { ...(await entry("e2", R1, "two.pdf")), request_id: R2 }; // server moved it to another request
    const third = await entry("e3", R2, "three.pdf");
    const res = await decryptInbox(kp, [good, moved, third], 2);
    assert.deepEqual(
      res.map((r) => (r.ok ? r.file.meta.name : "ERR")),
      ["one.pdf", "ERR", "three.pdf"],
    );
  });
});
