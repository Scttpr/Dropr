/**
 * Localization: language parsing, French formatting (identical to the Go
 * side), API error translation by code, and catalog hygiene.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { errorFromResponse, messageForStatus } from "../src/lib/api.ts";
import { expiryChoiceText, formatBytes, formatDate, formatEta, formatExpiry, formatPercent } from "../src/lib/format.ts";
import { localeFor, parseLang } from "../src/lib/i18n.ts";
import { en } from "../src/lib/locales/en.ts";
import { fr } from "../src/lib/locales/fr.ts";
import { jsonResponse } from "./fakes.ts";

const FR = localeFor("fr");
const NBSP = "\u00a0";

describe("i18n", () => {
  it("parses language tags", () => {
    assert.equal(parseLang("fr"), "fr");
    assert.equal(parseLang("fr-CA"), "fr");
    assert.equal(parseLang("EN-gb"), "en");
    assert.equal(parseLang("de"), "en");
    assert.equal(parseLang(""), "en");
    assert.equal(parseLang(undefined), "en");
  });

  it("picks the visitor's regional variant for Intl", () => {
    assert.equal(localeFor("fr", ["en-US", "fr-CA", "fr"]).tag, "fr-CA");
    assert.equal(localeFor("fr", ["de-DE"]).tag, "fr");
    assert.equal(localeFor("en", ["fr-FR", "en-GB"]).tag, "en-GB");
  });

  it("formats French sizes like FormatBytesIn (internal/web/format.go)", () => {
    assert.equal(formatBytes(0, FR), `0${NBSP}o`);
    assert.equal(formatBytes(1536, FR), `1,50${NBSP}Ko`);
    assert.equal(formatBytes(10 * 1024, FR), `10,0${NBSP}Ko`);
    assert.equal(formatBytes(5 * 2 ** 30, FR), `5,00${NBSP}Go`);
    assert.equal(formatBytes(73_400_320, FR), `70,0${NBSP}Mo`);
  });

  it("formats French expiry like FormatExpiryIn, with French plurals", () => {
    const now = 1_000_000_000;
    const t = now / 1000;
    for (const [d, want] of [
      [-5, "Expiré"],
      [30, "Expire dans 1 minute"],
      [600, "Expire dans 10 minutes"],
      [3600, "Expire dans 1 heure"],
      [3601, "Expire dans 2 heures"],
      [86_400, "Expire dans 1 jour"],
      [7 * 86_400, "Expire dans 7 jours"],
    ] as const) {
      assert.equal(formatExpiry(t + d, now, FR), want, `+${d}s`);
    }
    assert.equal(expiryChoiceText("30d", FR), "Expire dans 30 jours");
  });

  it("keeps French wording identical to the server catalog", () => {
    const goSrc = readFileSync(new URL("../../internal/i18n/fr.go", import.meta.url), "utf8");
    const go = (msgid: string): string => {
      const m = new RegExp(`^\\s*${JSON.stringify(msgid).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\s*("(?:[^"\\\\]|\\\\.)*"),`, "m").exec(goSrc);
      assert.ok(m?.[1], `missing ${msgid} in fr.go`);
      return (JSON.parse(m[1]) as string).replace("%d", "§");
    };
    assert.equal(fr.expired, go("Expired"));
    assert.equal(fr.expiresInMinutes(1), go("Expires in 1 minute"));
    assert.equal(fr.expiresInHours(1), go("Expires in 1 hour"));
    assert.equal(fr.expiresInDays(1), go("Expires in 1 day"));
    assert.equal(fr.expiresInMinutes(5).replace("5", "§"), go("Expires in %d minutes"));
    assert.equal(fr.expiresInHours(5).replace("5", "§"), go("Expires in %d hours"));
    assert.equal(fr.expiresInDays(5).replace("5", "§"), go("Expires in %d days"));
    assert.equal(fr.statusExpired, go("This link has expired."));
    assert.equal(fr.statusExhausted, go("This link has reached its download limit."));
  });

  it("formats French durations, percentages and dates", () => {
    assert.equal(formatEta(3, FR), "encore quelques secondes");
    assert.equal(formatEta(600, FR), `encore environ 10${NBSP}min`);
    assert.match(formatPercent(42, FR), /^42[\u00a0\u202f]%$/);
    assert.match(formatDate(1_700_000_000, FR), /2023/);
  });

  it("translates API errors by code, never showing the English server message", async () => {
    const e = await errorFromResponse(jsonResponse(410, { error: "expired", message: "This link has expired." }), FR);
    assert.equal(e.message, "Ce lien a expiré.");
    assert.equal(e.code, "expired");
    const unknown = await errorFromResponse(jsonResponse(409, { error: "brand_new", message: "Some new English text." }), FR);
    assert.equal(unknown.message, messageForStatus(409, "brand_new", FR));
    assert.equal(unknown.message, fr.statusConflict);
    const proto = await errorFromResponse(jsonResponse(400, { error: "toString", message: "x" }), FR);
    assert.equal(proto.message, fr.statusBadRequest);
  });

  it("translates every API error code the server can send", () => {
    const codes = new Set<string>();
    for (const file of ["internal/server/api.go", "internal/httpx/problem.go", "internal/httpx/streams.go"]) {
      const src = readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
      for (const m of src.matchAll(/Errorf\(\s*http\.Status\w+,\s*"([a-z_]+)"/g)) codes.add(m[1] as string);
    }
    assert.ok(codes.size > 20, "scanner found too few codes");
    for (const code of codes) assert.ok(Object.hasOwn(fr.apiCodes, code), `fr.apiCodes lacks ${code}`);
  });

  it("has the same plain-string keys in every catalog, none left in English", () => {
    for (const [k, v] of Object.entries(en)) {
      const f = (fr as Record<string, unknown>)[k];
      assert.equal(typeof f, typeof v, k);
      if (typeof v === "string" && v.length > 12) assert.notEqual(f, v, `${k} is not translated`);
    }
  });
});
