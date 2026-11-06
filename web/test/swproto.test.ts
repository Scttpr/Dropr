/**
 * Service-worker helpers: download ids, message validation, file-name
 * sanitization and Content-Disposition encoding (RFC 6266 / RFC 8187).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DL_SCOPE,
  asciiFallback,
  contentDisposition,
  downloadHeaders,
  downloadIdFromPath,
  encodeRfc8187,
  parseRegister,
  safeDownloadName,
} from "../src/lib/swproto.ts";

const ID = "AAAAAAAAAAAAAAAAAAAAAA";

describe("swproto: ids and messages", () => {
  it("extracts only well-formed ids under the scope", () => {
    assert.equal(DL_SCOPE, "/_dl/");
    assert.equal(downloadIdFromPath(`/_dl/${ID}`), ID);
    assert.equal(downloadIdFromPath(`/_dl/${ID}/x`), null);
    assert.equal(downloadIdFromPath(`/_dl/short`), null);
    assert.equal(downloadIdFromPath(`/dl/${ID}`), null);
    assert.equal(downloadIdFromPath(`/_dl/${ID.slice(1)}+`), null);
  });

  it("validates register messages", () => {
    assert.deepEqual(parseRegister({ type: "register", id: ID, name: "a.txt", size: 3 }), { id: ID, name: "a.txt", size: 3, stream: null });
    assert.equal(parseRegister({ type: "register", id: ID, name: "a", size: null })?.size, null);
    const rs = new ReadableStream();
    assert.equal(parseRegister({ type: "register", id: ID, name: "a", size: 1, stream: rs })?.stream, rs);
    for (const bad of [
      null,
      "x",
      { type: "keepalive" },
      { type: "register", id: "bad", name: "a", size: 1 },
      { type: "register", id: ID, name: 5, size: 1 },
      { type: "register", id: ID, name: "a", size: -1 },
      { type: "register", id: ID, name: "a", size: 1.5 },
      { type: "register", id: ID, name: "a", size: 1, stream: {} },
    ]) {
      assert.equal(parseRegister(bad), null, JSON.stringify(bad));
    }
  });
});

describe("swproto: Content-Disposition", () => {
  it("encodes RFC 8187 value-chars", () => {
    assert.equal(encodeRfc8187("a b.txt"), "a%20b.txt");
    assert.equal(encodeRfc8187("é"), "%C3%A9");
    assert.equal(encodeRfc8187("it's (1)*"), "it%27s%20%281%29%2A");
    assert.equal(encodeRfc8187("😀"), "%F0%9F%98%80");
    // Only attr-char survive unencoded.
    assert.match(encodeRfc8187("!#$&+-.^_`|~AZaz09"), /^[A-Za-z0-9!#$&+\-.^_`|~%]*$/);
  });

  it("produces an ASCII fallback without quotes, backslashes or percent", () => {
    assert.equal(asciiFallback('ré"sumé\\%.pdf'), "r__sum___.pdf");
    assert.equal(asciiFallback("日本"), "__");
    assert.equal(asciiFallback("   "), "download");
  });

  it("builds both filename and filename* parameters", () => {
    assert.equal(contentDisposition("report.pdf"), `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`);
    assert.equal(contentDisposition("Résumé 2026.pdf"), `attachment; filename="R_sum_ 2026.pdf"; filename*=UTF-8''R%C3%A9sum%C3%A9%202026.pdf`);
  });

  it("cannot be used for header injection or path traversal", () => {
    const cd = contentDisposition('evil\r\nSet-Cookie: a=b; x="../../etc/passwd"');
    assert.doesNotMatch(cd, /[\r\n]/);
    assert.equal((cd.match(/"/g) ?? []).length, 2, "only the two delimiting quotes");
    assert.doesNotMatch(cd, /\.\.\//);
    assert.doesNotMatch(safeDownloadName("../../etc/passwd"), /\//);
  });

  it("sanitizes names like the crypto core", () => {
    assert.equal(safeDownloadName("a‮txt.exe"), "atxt.exe"); // bidi override removed
    assert.equal(safeDownloadName("a.pdf\u3164\u2003\u2003\u2003.exe"), "a.pdf .exe"); // audit I-4
    assert.equal(safeDownloadName("con:tent?.txt"), "con_tent_.txt");
    assert.equal(safeDownloadName("name. . ."), "name");
    assert.equal(safeDownloadName(""), "download");
    assert.equal(safeDownloadName(".."), "download");
    assert.equal(safeDownloadName("\uD800x"), "�x");
    assert.equal(safeDownloadName("é"), "é"); // NFC
  });

  it("sets safe response headers", () => {
    const h = new Headers(downloadHeaders("a.bin", 42));
    assert.equal(h.get("Content-Type"), "application/octet-stream");
    assert.equal(h.get("X-Content-Type-Options"), "nosniff");
    assert.match(h.get("Content-Security-Policy") ?? "", /^default-src 'none'/);
    assert.equal(h.get("Content-Length"), "42");
    assert.match(h.get("Content-Disposition") ?? "", /^attachment;/);
    assert.equal(new Headers(downloadHeaders("a", null)).get("Content-Length"), null);
  });
});
