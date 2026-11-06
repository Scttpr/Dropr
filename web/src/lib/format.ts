/**
 * Pure formatting helpers for the pages (sizes, rates, durations, expiry).
 * No DOM access: unit-tested in Node.
 *
 * @module
 */

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** Human-readable byte size in binary units labelled KB/MB/GB ("1.5 GB"), matching the server config (`5GB` = 5 GiB). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "–";
  let v = n;
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${UNITS[u]}`;
}

/** Transfer rate ("12.3 MB/s"). */
export function formatRate(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return "–";
  return `${formatBytes(bytesPerSecond)}/s`;
}

/** Remaining time in plain language ("about 3 min left"); empty string if unknown. */
export function formatEta(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  if (seconds < 5) return "a few seconds left";
  if (seconds < 60) return `about ${Math.round(seconds / 5) * 5} s left`;
  if (seconds < 3600) return `about ${Math.round(seconds / 60)} min left`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m === 0 || h >= 10 ? `about ${h} h left` : `about ${h} h ${m} min left`;
}

/**
 * "Expires in 7 days" / "Expires in 3 hours" / "Expired", for a Unix-seconds
 * timestamp. Rounds up to the largest unit that fits (minutes below an hour,
 * hours below a day, days otherwise), so a fresh 7-day link reads "7 days".
 * Same rule as FormatExpiry in internal/web/format.go.
 */
export function formatExpiry(expiresAt: number, nowMs: number = Date.now()): string {
  const s = expiresAt - Math.floor(nowMs / 1000);
  if (s <= 0) return "Expired";
  const plural = (n: number, w: string): string => `${n} ${w}${n === 1 ? "" : "s"}`;
  const m = Math.ceil(s / 60);
  if (m < 60) return `Expires in ${plural(m, "minute")}`;
  const h = Math.ceil(s / 3600);
  if (h < 24) return `Expires in ${plural(h, "hour")}`;
  return `Expires in ${plural(Math.ceil(s / 86_400), "day")}`;
}

const EXPIRY_TEXT: Readonly<Record<string, string>> = {
  "1h": "Expires in 1 hour",
  "1d": "Expires in 1 day",
  "7d": "Expires in 7 days",
  "30d": "Expires in 30 days",
};

/** "Expires in 7 days" for an `expires_in` choice ("1h" | "1d" | "7d" | "30d"). */
export function expiryChoiceText(choice: string): string {
  return EXPIRY_TEXT[choice] ?? "";
}

/** Locale date+time for a Unix-seconds timestamp. */
export function formatDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Whole-percent progress, clamped to 0..100 (0 bytes total counts as done). */
export function percent(done: number, total: number): number {
  if (total <= 0) return 100;
  return Math.min(100, Math.max(0, Math.floor((done / total) * 100)));
}
