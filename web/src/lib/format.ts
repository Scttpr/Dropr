/**
 * Pure formatting helpers for the pages (sizes, rates, durations, expiry).
 * No DOM access: unit-tested in Node. Each takes a {@link Locale} (default:
 * the page's).
 *
 * @module
 */

import { type Locale, locale } from "./i18n.ts";

/**
 * Human-readable byte size in binary units labelled KB/MB/GB ("1.5 GB";
 * French "1,50 Go"), matching the server config (`5GB` = 5 GiB) and
 * FormatBytesIn in internal/web/format.go.
 */
export function formatBytes(n: number, { t }: Locale = locale): string {
  if (!Number.isFinite(n) || n < 0) return "–";
  const units = t.byteUnits;
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits).replace(".", t.decimalSeparator)}${t.unitSpace}${units[u]}`;
}

/** Transfer rate ("12.3 MB/s"). */
export function formatRate(bytesPerSecond: number, loc: Locale = locale): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return "–";
  return `${formatBytes(bytesPerSecond, loc)}/s`;
}

/** Remaining time in plain language ("about 3 min left"); empty string if unknown. */
export function formatEta(seconds: number, { t }: Locale = locale): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  if (seconds < 5) return t.etaFewSeconds;
  if (seconds < 60) return t.etaSeconds(Math.round(seconds / 5) * 5);
  if (seconds < 3600) return t.etaMinutes(Math.round(seconds / 60));
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m === 0 || h >= 10 ? t.etaHours(h) : t.etaHoursMinutes(h, m);
}

/**
 * "Expires in 7 days" / "Expires in 3 hours" / "Expired", for a Unix-seconds
 * timestamp. Rounds up to the largest unit that fits (minutes below an hour,
 * hours below a day, days otherwise), so a fresh 7-day link reads "7 days".
 * Same rule as FormatExpiryIn in internal/web/format.go.
 */
export function formatExpiry(expiresAt: number, nowMs: number = Date.now(), { t }: Locale = locale): string {
  const s = expiresAt - Math.floor(nowMs / 1000);
  if (s <= 0) return t.expired;
  const m = Math.ceil(s / 60);
  if (m < 60) return t.expiresInMinutes(m);
  const h = Math.ceil(s / 3600);
  if (h < 24) return t.expiresInHours(h);
  return t.expiresInDays(Math.ceil(s / 86_400));
}

/** "Expires in 7 days" for an `expires_in` choice ("1h" | "1d" | "7d" | "30d"). */
export function expiryChoiceText(choice: string, { t }: Locale = locale): string {
  switch (choice) {
    case "1h":
      return t.expiresInHours(1);
    case "1d":
      return t.expiresInDays(1);
    case "7d":
      return t.expiresInDays(7);
    case "30d":
      return t.expiresInDays(30);
    default:
      return "";
  }
}

/** Locale date+time for a Unix-seconds timestamp. */
export function formatDate(unixSeconds: number, { tag }: Locale = locale): string {
  return new Date(unixSeconds * 1000).toLocaleString(tag, { dateStyle: "medium", timeStyle: "short" });
}

/** A number with the locale's digit grouping ("1,234,567"; French "1 234 567"). */
export function formatInteger(n: number, { tag }: Locale = locale): string {
  return n.toLocaleString(tag);
}

/** A whole percentage in the locale's style ("42%"; French "42 %"). */
export function formatPercent(pc: number, { tag }: Locale = locale): string {
  return new Intl.NumberFormat(tag, { style: "percent" }).format(pc / 100);
}

/** Whole-percent progress, clamped to 0..100 (0 bytes total counts as done). */
export function percent(done: number, total: number): number {
  if (total <= 0) return 100;
  return Math.min(100, Math.max(0, Math.floor((done / total) * 100)));
}
