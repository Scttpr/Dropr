/**
 * Protocol and pure helpers shared by the download service worker (`sw.ts`)
 * and the page side (`downloader.ts`). Compiles under both the DOM and the
 * WebWorker libs: no DOM- or worker-only APIs here.
 *
 * Flow (page → SW):
 *
 * 1. The page registers `/sw.js` with scope `/_dl/` (so the worker never
 *    sees any other request: everything else bypasses it by construction).
 * 2. The page picks a random id and posts `{type: "register", id, name, size,
 *    stream?}` to the active worker with a `MessagePort` in the transfer
 *    list. `stream` is a transferred `ReadableStream` when the browser
 *    supports transferable streams; otherwise chunks are pumped over the
 *    port with a pull protocol (backpressure: one chunk per `pull`).
 * 3. The SW answers `{type: "registered"}` on the port; the page then
 *    navigates to `/_dl/<id>`. The SW's fetch handler answers that one
 *    navigation with a streamed `attachment` response and forgets the id.
 *
 * @module
 */

/** Path prefix (and SW scope) for streamed downloads. */
export const DL_SCOPE = "/_dl/";

/** Unclaimed registrations expire after this many ms. */
export const REGISTRATION_TTL_MS = 60_000;

/** Page → SW (via `ServiceWorker.postMessage`). */
export type PageToSw =
  | { readonly type: "register"; readonly id: string; readonly name: string; readonly size: number | null; readonly stream?: ReadableStream<Uint8Array> }
  | { readonly type: "keepalive" };

/** SW → page, on the registration's port. */
export type SwToPage = { readonly type: "registered" } | { readonly type: "pull" } | { readonly type: "cancel" };

/** Page → SW, on the registration's port (pull protocol only). */
export type PortToSw =
  | { readonly type: "chunk"; readonly chunk: ArrayBuffer }
  | { readonly type: "end" }
  | { readonly type: "abort" };

/** Download ids: 22-char base64url (128 random bits). */
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

export function isValidId(id: unknown): id is string {
  return typeof id === "string" && ID_RE.test(id);
}

/** The download id for a URL path under {@link DL_SCOPE}, or null. */
export function downloadIdFromPath(pathname: string): string | null {
  if (!pathname.startsWith(DL_SCOPE)) return null;
  const id = pathname.slice(DL_SCOPE.length);
  return isValidId(id) ? id : null;
}

/** Validate an untrusted `register` message (shape only). */
export function parseRegister(
  data: unknown,
): { id: string; name: string; size: number | null; stream: ReadableStream<Uint8Array> | null } | null {
  if (typeof data !== "object" || data === null) return null;
  const d = data as Record<string, unknown>;
  if (d["type"] !== "register" || !isValidId(d["id"]) || typeof d["name"] !== "string") return null;
  const size = d["size"];
  if (size !== null && !(typeof size === "number" && Number.isSafeInteger(size) && size >= 0)) return null;
  const stream = d["stream"];
  if (stream !== undefined && !(stream instanceof ReadableStream)) return null;
  return { id: d["id"], name: d["name"], size, stream: stream ?? null };
}

// ---------------------------------------------------------------------------
// Content-Disposition
// ---------------------------------------------------------------------------

const FALLBACK = "download";

/**
 * Make a (possibly untrusted) name safe for a response header and for the
 * file system: removes controls (CR/LF in particular), bidi/invisible
 * characters, replaces path separators and Windows-reserved characters, and
 * trims dots/whitespace. The crypto core already sanitizes names
 * (`sanitizeFileName`); this is defence in depth in the worker.
 */
export function safeDownloadName(name: string): string {
  let s = name
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD")
    .normalize("NFC")
    .replace(/(?![\u200C\u200D\uFE00-\uFE0F\u{E0020}-\u{E007F}])[\p{Cc}\p{Default_Ignorable_Code_Point}\u061C\u2028\u2029\u2800]/gu, "")
    .replace(/\p{Zs}+/gu, " ")
    .replace(/[/\\:*?"<>|]/g, "_")
    .trim()
    .replace(/[.\s]+$/, "");
  if (s.length > 255) s = Array.from(s).slice(0, 200).join("");
  return s === "" || s === "." || s === ".." ? FALLBACK : s;
}

/** RFC 8187 `value-chars` encoding: everything but `attr-char` is percent-encoded (UTF-8). */
export function encodeRfc8187(s: string): string {
  return encodeURIComponent(s).replace(/['()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** ASCII-only fallback for old clients: non-ASCII, `%`, `"`, `\` and `;` become `_`. */
export function asciiFallback(name: string): string {
  const s = name.replace(/[^\x20-\x7E]/g, "_").replace(/["\\%;]/g, "_");
  return s.trim() === "" ? FALLBACK : s;
}

/** `attachment; filename="<ascii>"; filename*=UTF-8''<pct-encoded>` for a sanitized name. */
export function contentDisposition(name: string): string {
  const safe = safeDownloadName(name);
  return `attachment; filename="${asciiFallback(safe)}"; filename*=UTF-8''${encodeRfc8187(safe)}`;
}

/** Headers of the streamed download response. */
export function downloadHeaders(name: string, size: number | null): [string, string][] {
  const h: [string, string][] = [
    ["Content-Type", "application/octet-stream"],
    ["Content-Disposition", contentDisposition(name)],
    ["Content-Security-Policy", "default-src 'none'; sandbox"],
    ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "no-referrer"],
    ["Cache-Control", "no-store"],
  ];
  // A length lets the browser show progress and mark a short stream as failed.
  if (size !== null) h.push(["Content-Length", String(size)]);
  return h;
}
