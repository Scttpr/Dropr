/**
 * Typed wrappers for every JSON/HTTP endpoint of docs/ARCHITECTURE.md §3.
 *
 * - Same-origin only, `credentials: "same-origin"`, `cache: "no-store"`.
 * - Every call takes an optional `AbortSignal` and has a timeout.
 * - Failures become {@link ApiError} with a plain-language `message`: the
 *   server's `{"error", "message"}` body when present (shown with
 *   `textContent`, never parsed as HTML), else a message derived from the
 *   status. Network failures and timeouts are `ApiError`s too (status 0) and
 *   are flagged `retryable`. A caller-initiated abort is re-thrown as the
 *   original `AbortError`, not wrapped.
 * - Responses are shape-checked: a malformed body is an `ApiError`
 *   (`bad_response`) rather than `undefined` flowing into crypto code.
 *
 * Sizes: every `size` exchanged with the server is the **ciphertext** size
 * (FORMAT.md §4.3); the plaintext size is `plaintextSize(size)`.
 *
 * @module
 */

import { isAbortError } from "./retry.ts";

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export type ExpiresIn = "1h" | "1d" | "7d" | "30d";
export const EXPIRY_CHOICES: readonly ExpiresIn[] = ["1h", "1d", "7d", "30d"];

/** An API call failed. `message` is safe to show to the user (plain text). */
export class ApiError extends Error {
  /** HTTP status; 0 for network failure or timeout. */
  readonly status: number;
  /** Server error code, or `network` / `timeout` / `bad_response`. */
  readonly code: string;
  /** Worth retrying automatically (network, timeout, 408, 429, 5xx). */
  readonly retryable: boolean;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryable = code === "network" || code === "timeout" || status === 408 || status === 429 || status >= 500;
  }
}

/** Plain-language fallback for a status when the server sent no usable message. */
export function messageForStatus(status: number, code = ""): string {
  switch (code) {
    case "expired":
      return "This link has expired.";
    case "exhausted":
      return "This link has reached its download limit.";
    case "revoked":
      return "This link has been revoked by its owner.";
    case "locked":
      return "Unlock your inbox with your passkey first.";
    case "quota_exceeded":
      return "There is not enough storage space left for this file.";
    case "too_large":
      return "This file is too large.";
  }
  if (status === 0) return "Could not reach the server. Check your connection and try again.";
  if (status === 400 || status === 422) return "The request was not accepted. Please reload the page and try again.";
  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return "You are not allowed to do this.";
  if (status === 404) return "This link does not exist or has been revoked.";
  if (status === 408) return "The server took too long to respond. Please try again.";
  if (status === 409) return "This was changed in the meantime. Please reload the page.";
  if (status === 410) return "This link has expired or is no longer available.";
  if (status === 413) return "This file is too large.";
  if (status === 429) return "Too many attempts. Please wait a moment and try again.";
  if (status >= 500) return "The server had a problem. Please try again in a moment.";
  return `Unexpected response from the server (${status}).`;
}

const MAX_SERVER_MESSAGE = 300;

/** Build an ApiError from a non-2xx response (reads the body). */
export async function errorFromResponse(res: Response): Promise<ApiError> {
  let code = "";
  let message = "";
  try {
    const text = await res.text();
    const body: unknown = text === "" ? null : JSON.parse(text);
    if (isObject(body)) {
      if (typeof body["error"] === "string") code = body["error"].slice(0, 64);
      if (typeof body["message"] === "string") message = body["message"].trim();
    }
  } catch {
    // not JSON: fall back to the status message
  }
  if (message === "" || message.length > MAX_SERVER_MESSAGE) message = messageForStatus(res.status, code);
  return new ApiError(res.status, code === "" ? `http_${res.status}` : code, message);
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

export interface ShareCreated {
  readonly share_id: string;
  readonly upload_id: string;
  readonly upload_token: string;
}
export interface UploadCreated {
  readonly upload_id: string;
  readonly upload_token: string;
}
export interface ShareDownload {
  readonly token: string;
  /** Ciphertext size. */
  readonly size: number;
  readonly parts: number;
  /** Sealed metadata, base64url. */
  readonly meta: string;
}
export interface ShareSummary {
  readonly id: string;
  readonly size: number;
  readonly expires_at: number;
  readonly max_downloads: number | null;
  readonly download_count: number;
  readonly created_at: number;
}
export interface RequestSummary {
  readonly id: string;
  readonly expires_at: number;
  readonly max_files: number;
  readonly max_bytes: number;
  readonly single_use: boolean;
  readonly files_received: number;
  readonly bytes_received: number;
  readonly created_at: number;
}
export interface InboxEntry {
  readonly id: string;
  readonly request_id: string;
  /** Ciphertext size. */
  readonly size: number;
  readonly created_at: number;
  /** Sealed metadata, base64url. */
  readonly meta: string;
  /** HPKE `enc ‖ ct`, base64url (80 bytes decoded). */
  readonly wrapped_key: string;
}
export interface PasskeySummary {
  readonly id: string;
  readonly created_at: number;
  readonly last_used_at: number | null;
}
/** What a passkey assertion is for (ARCHITECTURE.md §3 "Passkeys"). */
export type UnlockPurpose = { readonly kind: "unlock" } | { readonly kind: "add" } | { readonly kind: "delete"; readonly passkeyId: string };

export interface UnlockResult {
  /** base64url `iv ‖ GCM(...)`. */
  readonly wrapped_privkey: string;
  readonly credential_id: string;
  /** Optional: the WebAuthn user handle (base64url), used if the authenticator omits it. */
  readonly user_handle?: string;
}
export interface UploadStatus {
  readonly parts_present: readonly number[];
}

export interface NewShare {
  readonly size: number;
  readonly parts: number;
  readonly meta: string;
  readonly expires_in: ExpiresIn;
  readonly max_downloads?: number;
}
export interface NewRequest {
  readonly expires_in: ExpiresIn;
  readonly max_files: number;
  readonly max_bytes: number;
  readonly single_use: boolean;
  readonly label_meta?: string;
}
export interface NewRequestFile {
  readonly size: number;
  readonly parts: number;
  readonly meta: string;
  readonly wrapped_key: string;
}

// ---------------------------------------------------------------------------
// Shape checks (throw ApiError "bad_response")
// ---------------------------------------------------------------------------

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function bad(what: string): ApiError {
  return new ApiError(0, "bad_response", `Unexpected response from the server (${what}).`);
}

function obj(x: unknown, what: string): Record<string, unknown> {
  if (!isObject(x)) throw bad(what);
  return x;
}
function str(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  if (typeof v !== "string") throw bad(k);
  return v;
}
function int(o: Record<string, unknown>, k: string): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw bad(k);
  return v;
}
function intOrNull(o: Record<string, unknown>, k: string): number | null {
  return o[k] === null || o[k] === undefined ? null : int(o, k);
}
function bool(o: Record<string, unknown>, k: string): boolean {
  const v = o[k];
  if (typeof v !== "boolean") throw bad(k);
  return v;
}
/** Accept a bare JSON array or an object wrapping it under `key` (e.g. `{"shares": [...]}`). */
function list(x: unknown, key: string): unknown[] {
  if (Array.isArray(x)) return x;
  if (isObject(x) && Array.isArray(x[key])) return x[key] as unknown[];
  throw bad(key);
}

export function parseShareSummary(x: unknown): ShareSummary {
  const o = obj(x, "share");
  return {
    id: str(o, "id"),
    size: int(o, "size"),
    expires_at: int(o, "expires_at"),
    max_downloads: intOrNull(o, "max_downloads"),
    download_count: int(o, "download_count"),
    created_at: int(o, "created_at"),
  };
}
export function parseRequestSummary(x: unknown): RequestSummary {
  const o = obj(x, "request");
  return {
    id: str(o, "id"),
    expires_at: int(o, "expires_at"),
    max_files: int(o, "max_files"),
    max_bytes: int(o, "max_bytes"),
    single_use: bool(o, "single_use"),
    files_received: int(o, "files_received"),
    bytes_received: o["bytes_received"] === undefined ? 0 : int(o, "bytes_received"),
    created_at: int(o, "created_at"),
  };
}
export function parseInboxEntry(x: unknown): InboxEntry {
  const o = obj(x, "inbox entry");
  return {
    id: str(o, "id"),
    request_id: str(o, "request_id"),
    size: int(o, "size"),
    created_at: int(o, "created_at"),
    meta: str(o, "meta"),
    wrapped_key: str(o, "wrapped_key"),
  };
}

/**
 * Map a thrown fetch/body error: caller abort → re-thrown as is; our timer →
 * ApiError("timeout"); anything else (TypeError: network) → ApiError("network").
 */
export function mapThrown(e: unknown, user: AbortSignal | undefined, timer: AbortSignal | undefined): unknown {
  if (user?.aborted) return e;
  if (timer?.aborted || (e instanceof Error && e.name === "TimeoutError")) {
    return new ApiError(0, "timeout", "The server took too long to respond. Please try again.");
  }
  if (e instanceof ApiError || isAbortError(e)) return e;
  return new ApiError(0, "network", messageForStatus(0));
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface ApiOptions {
  /** `fetch` implementation (default: the global one). Injected by tests. */
  readonly fetch?: FetchFn;
  /** URL prefix (default `""`: same origin). */
  readonly base?: string;
  /** Timeout for JSON calls in ms (default 30 s). */
  readonly timeoutMs?: number;
}

export interface CallOptions {
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number;
}

interface RequestSpec extends CallOptions {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
  readonly json?: unknown;
  readonly body?: Uint8Array<ArrayBuffer>;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
}

const seg = (s: string): string => encodeURIComponent(s);

export class Api {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(opts: ApiOptions = {}) {
    this.fetchFn = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.base = opts.base ?? "";
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /**
   * Low-level request: resolves with the successful `Response` (2xx), throws
   * ApiError otherwise. The timeout runs until `done()` is called; callers
   * call it once the body is consumed, or right after the headers for streamed
   * downloads so a long body is not cut off.
   */
  async raw(spec: RequestSpec): Promise<{ res: Response; done: () => void }> {
    const headers: Record<string, string> = { ...spec.headers };
    let body: BodyInit | undefined;
    if (spec.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(spec.json);
    } else if (spec.body !== undefined) {
      headers["Content-Type"] = "application/octet-stream";
      body = spec.body;
    }
    if (spec.bearer !== undefined) headers["Authorization"] = `Bearer ${spec.bearer}`;
    if (spec.json !== undefined || spec.method === "GET") headers["Accept"] = "application/json";

    const timer = new AbortController();
    const t = setTimeout(
      () => timer.abort(new DOMException("The server took too long to respond.", "TimeoutError")),
      spec.timeoutMs ?? this.timeoutMs,
    );
    const done = (): void => clearTimeout(t);
    const signal = spec.signal ? AbortSignal.any([spec.signal, timer.signal]) : timer.signal;
    let res: Response;
    try {
      const init: RequestInit = {
        method: spec.method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal,
      };
      if (body !== undefined) init.body = body;
      res = await this.fetchFn(this.base + spec.path, init);
    } catch (e) {
      done();
      throw mapThrown(e, spec.signal, timer.signal);
    }
    if (!res.ok) {
      try {
        throw await errorFromResponse(res);
      } finally {
        done();
      }
    }
    return { res, done };
  }

  private async json(spec: RequestSpec): Promise<unknown> {
    const { res, done } = await this.raw(spec);
    let text: string;
    try {
      text = await res.text();
    } catch (e) {
      throw mapThrown(e, spec.signal, undefined);
    } finally {
      done();
    }
    if (text === "") return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw bad("not JSON");
    }
  }

  // --- Passkeys ------------------------------------------------------------

  /**
   * WebAuthn creation options as produced by go-webauthn (`{publicKey: {...}}`)
   * plus `confirm.challenge`, the server challenge the new credential asserts
   * over right after `create()` (required for the account's first passkey).
   * Once the account has a passkey, the session needs an "add" grant
   * ({@link unlockBegin} with purpose "add"), else 403 `reauth_required`.
   */
  registerBegin(o: CallOptions = {}): Promise<unknown> {
    return this.json({ ...o, method: "POST", path: "/api/passkeys/register/begin", json: {} });
  }
  async registerFinish(
    body: { credential: unknown; wrapped_privkey: string; pubkey: string; confirm?: unknown },
    o: CallOptions = {},
  ): Promise<void> {
    await this.json({ ...o, method: "POST", path: "/api/passkeys/register/finish", json: body });
  }
  /**
   * WebAuthn assertion options as produced by go-webauthn: `{publicKey: {...}}`.
   * `purpose` "add" or "delete" (with the passkey ID) makes the assertion
   * leave a single-use, 5-minute grant for that action on the session.
   */
  unlockBegin(o: CallOptions & { readonly purpose?: UnlockPurpose } = {}): Promise<unknown> {
    const { purpose: p, ...call } = o;
    const json = p === undefined ? {} : p.kind === "delete" ? { purpose: "delete", passkey_id: p.passkeyId } : { purpose: p.kind };
    return this.json({ ...call, method: "POST", path: "/api/passkeys/unlock/begin", json });
  }
  async unlockFinish(body: { credential: unknown }, o: CallOptions = {}): Promise<UnlockResult> {
    const r = obj(await this.json({ ...o, method: "POST", path: "/api/passkeys/unlock/finish", json: body }), "unlock");
    const out: UnlockResult = { wrapped_privkey: str(r, "wrapped_privkey"), credential_id: str(r, "credential_id") };
    return typeof r["user_handle"] === "string" ? { ...out, user_handle: r["user_handle"] } : out;
  }
  async listPasskeys(o: CallOptions = {}): Promise<PasskeySummary[]> {
    const x = await this.json({ ...o, method: "GET", path: "/api/passkeys" });
    return list(x, "passkeys").map((p) => {
      const r = obj(p, "passkey");
      return { id: str(r, "id"), created_at: int(r, "created_at"), last_used_at: intOrNull(r, "last_used_at") };
    });
  }
  async deletePasskey(id: string, o: CallOptions = {}): Promise<void> {
    await this.json({ ...o, method: "DELETE", path: `/api/passkeys/${seg(id)}` });
  }

  // --- Shares --------------------------------------------------------------

  async createShare(body: NewShare, o: CallOptions = {}): Promise<ShareCreated> {
    const r = obj(await this.json({ ...o, method: "POST", path: "/api/shares", json: body }), "share");
    return { share_id: str(r, "share_id"), upload_id: str(r, "upload_id"), upload_token: str(r, "upload_token") };
  }
  async deleteShare(id: string, o: CallOptions = {}): Promise<void> {
    await this.json({ ...o, method: "DELETE", path: `/api/shares/${seg(id)}` });
  }
  async listShares(o: CallOptions = {}): Promise<ShareSummary[]> {
    return list(await this.json({ ...o, method: "GET", path: "/api/shares" }), "shares").map(parseShareSummary);
  }
  /** Recipient side (no session): download token + metadata. 404/410 for dead links. */
  async shareDownload(id: string, o: CallOptions = {}): Promise<ShareDownload> {
    const r = obj(await this.json({ ...o, method: "POST", path: `/api/s/${seg(id)}/download`, json: {} }), "download");
    return { token: str(r, "token"), size: int(r, "size"), parts: int(r, "parts"), meta: str(r, "meta") };
  }

  // --- Requests ------------------------------------------------------------

  async createRequest(body: NewRequest, o: CallOptions = {}): Promise<{ request_id: string }> {
    const r = obj(await this.json({ ...o, method: "POST", path: "/api/requests", json: body }), "request");
    return { request_id: str(r, "request_id") };
  }
  async deleteRequest(id: string, o: CallOptions = {}): Promise<void> {
    await this.json({ ...o, method: "DELETE", path: `/api/requests/${seg(id)}` });
  }
  async listRequests(o: CallOptions = {}): Promise<RequestSummary[]> {
    return list(await this.json({ ...o, method: "GET", path: "/api/requests" }), "requests").map(parseRequestSummary);
  }
  /** Uploader side (no session). */
  async createRequestFile(requestId: string, body: NewRequestFile, o: CallOptions = {}): Promise<UploadCreated> {
    const r = obj(await this.json({ ...o, method: "POST", path: `/api/r/${seg(requestId)}/files`, json: body }), "file");
    return { upload_id: str(r, "upload_id"), upload_token: str(r, "upload_token") };
  }

  // --- Inbox ---------------------------------------------------------------

  async listInbox(o: CallOptions = {}): Promise<InboxEntry[]> {
    return list(await this.json({ ...o, method: "GET", path: "/api/inbox" }), "inbox").map(parseInboxEntry);
  }
  async inboxDownload(id: string, o: CallOptions = {}): Promise<{ token: string }> {
    const r = obj(await this.json({ ...o, method: "POST", path: `/api/inbox/${seg(id)}/download`, json: {} }), "download");
    return { token: str(r, "token") };
  }
  async deleteInbox(id: string, o: CallOptions = {}): Promise<void> {
    await this.json({ ...o, method: "DELETE", path: `/api/inbox/${seg(id)}` });
  }

  // --- Uploads ---------------------------------------------------------------

  async putPart(
    uploadId: string,
    n: number,
    token: string,
    body: Uint8Array<ArrayBuffer>,
    o: CallOptions = {},
  ): Promise<void> {
    const { res, done } = await this.raw({
      ...o,
      method: "PUT",
      path: `/upload/${seg(uploadId)}/part/${n}`,
      body,
      bearer: token,
    });
    done();
    await res.body?.cancel().catch(() => undefined); // nothing useful in the body
  }
  async uploadStatus(uploadId: string, token: string, o: CallOptions = {}): Promise<UploadStatus> {
    const r = obj(await this.json({ ...o, method: "GET", path: `/upload/${seg(uploadId)}`, bearer: token }), "status");
    const present = r["parts_present"];
    if (!Array.isArray(present) || !present.every((n) => Number.isSafeInteger(n) && (n as number) >= 0)) {
      throw bad("parts_present");
    }
    return { parts_present: present as number[] };
  }
  async finalizeUpload(uploadId: string, token: string, parts: number, o: CallOptions = {}): Promise<void> {
    await this.json({ ...o, method: "POST", path: `/upload/${seg(uploadId)}/finalize`, json: { parts }, bearer: token });
  }

  // --- Downloads -------------------------------------------------------------

  /**
   * Start `GET /dl/{token}`, optionally from byte `start` (Range). Resolves
   * once headers arrive (the timeout covers headers only); the caller reads
   * the body. Validates 200 vs 206 and `Content-Range` so a misbehaving
   * server cannot make the decryptor start at the wrong segment.
   */
  async fetchCiphertext(token: string, start: number, cipherSize: number, o: CallOptions = {}): Promise<Response> {
    const headers: Record<string, string> = {};
    if (start > 0) headers["Range"] = `bytes=${start}-`;
    const { res, done } = await this.raw({ ...o, method: "GET", path: `/dl/${seg(token)}`, headers });
    done(); // headers arrived: the body may legitimately take hours
    if (start === 0 && res.status !== 200) throw bad(`status ${res.status}`);
    if (start > 0) {
      const cr = res.headers.get("Content-Range");
      const m = cr === null ? null : /^bytes (\d+)-(\d+)\/(\d+)$/.exec(cr);
      if (
        res.status !== 206 ||
        m === null ||
        Number(m[1]) !== start ||
        Number(m[2]) !== cipherSize - 1 ||
        Number(m[3]) !== cipherSize
      ) {
        await res.body?.cancel();
        throw bad("range");
      }
    }
    return res;
  }
}

/** Default client for the pages (same origin, global fetch). */
export const api = new Api();
