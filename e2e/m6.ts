/**
 * Milestone 6 (hardening) test helpers, layered on fixtures.ts without
 * changing it:
 *
 * - `dropr` is overridden by a configurable server (`droprConfig` worker
 *   option: max_file_size, revalidate_every, …) that also exposes its data
 *   directory, so tests can inspect blobs on disk and edit the SQLite
 *   database directly (e.g. move `expires_at` into the past). There is no
 *   test backdoor in the production code: time travel is done on the DB.
 * - Every spec file that calls `test.use({ droprConfig: … })` gets its own
 *   worker, hence its own fresh server, owner and authenticators.
 * - `alice` is the worker's owner after sign-in and two passkeys.
 */

import { type Browser, type BrowserContext, type Page, chromium } from "@playwright/test";
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { type Dropr, KEYCLOAK, Owner, type TestFile, USERS, expect, logConsole, test as base } from "./fixtures.ts";

export { anonymousPage, downloadVia, expect, makeFile, sha256File, type TestFile, USERS } from "./fixtures.ts";
export { Owner };

export const ROOT = resolve(import.meta.dirname, "..");
export const LOGIN_LABEL = "Sign in with Keycloak (e2e)";
export const MiB = 1024 * 1024;

export const M6_USERS = {
  alice: USERS.alice,
  bob: { username: "bob", password: "bob-dev-password", name: "Bob Example" },
  mallory: { username: "mallory", password: "mallory-dev-password", name: "Mallory" },
} as const;
type User = (typeof M6_USERS)[keyof typeof M6_USERS];

// ---------------------------------------------------------------------------
// Keycloak admin
// ---------------------------------------------------------------------------

export async function kcAdmin(): Promise<Record<string, string>> {
  const tok = await fetch(`${KEYCLOAK}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" }),
  });
  if (!tok.ok) throw new Error(`Keycloak admin login failed: ${tok.status}`);
  const { access_token } = (await tok.json()) as { access_token: string };
  return { authorization: `Bearer ${access_token}`, "content-type": "application/json" };
}

async function setRedirectUri(origin: string, add: boolean): Promise<void> {
  const headers = await kcAdmin();
  const list = (await (await fetch(`${KEYCLOAK}/admin/realms/dropr/clients?clientId=dropr`, { headers })).json()) as { id: string }[];
  const url = `${KEYCLOAK}/admin/realms/dropr/clients/${list[0]!.id}`;
  const rep = (await (await fetch(url, { headers })).json()) as Record<string, unknown>;
  const uri = `${origin}/auth/callback`;
  const uris = ((rep["redirectUris"] as string[] | undefined) ?? []).filter((u) => u !== uri);
  if (add) uris.push(uri);
  const res = await fetch(url, { method: "PUT", headers, body: JSON.stringify({ ...rep, redirectUris: uris }) });
  if (!res.ok) throw new Error(`Keycloak client update failed: ${res.status} ${await res.text()}`);
}

/** Add or remove the realm role Dropr.User for a Keycloak user. */
export async function setRealmRole(username: string, granted: boolean, role = "Dropr.User"): Promise<void> {
  const headers = await kcAdmin();
  const users = (await (await fetch(`${KEYCLOAK}/admin/realms/dropr/users?exact=true&username=${username}`, { headers })).json()) as { id: string }[];
  const uid = users[0]?.id;
  if (uid === undefined) throw new Error(`Keycloak user ${username} not found`);
  const roleRep = await (await fetch(`${KEYCLOAK}/admin/realms/dropr/roles/${encodeURIComponent(role)}`, { headers })).json();
  const res = await fetch(`${KEYCLOAK}/admin/realms/dropr/users/${uid}/role-mappings/realm`, {
    method: granted ? "POST" : "DELETE",
    headers,
    body: JSON.stringify([roleRep]),
  });
  if (!res.ok) throw new Error(`Keycloak role mapping failed: ${res.status} ${await res.text()}`);
}

// ---------------------------------------------------------------------------
// Configurable Dropr server
// ---------------------------------------------------------------------------

export interface DroprConfig {
  /** limits.max_file_size (binary units). */
  readonly maxFileSize?: string;
  readonly userQuota?: string;
  /** oidc.revalidate_every (1m..1h). */
  readonly revalidateEvery?: string;
}

export interface DroprX extends Dropr {
  readonly port: number;
  readonly dir: string;
  readonly dataDir: string;
  readonly dbPath: string;
  readonly pid: number;
}

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      s.close(() => (typeof a === "object" && a !== null ? ok(a.port) : fail(new Error("no port"))));
    });
  });
}

export async function startDroprX(c: DroprConfig = {}): Promise<{ dropr: DroprX; stop: () => Promise<void> }> {
  const port = await freePort();
  const origin = `http://localhost:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "dropr-e2e-m6-"));
  const dataDir = join(dir, "data");
  writeFileSync(join(dir, "refresh_key"), randomBytes(32).toString("base64") + "\n", { mode: 0o600 });
  const cfg = join(dir, "dropr.toml");
  writeFileSync(
    cfg,
    `mode = "dev"
tls = "proxy"
listen = "127.0.0.1:${port}"
public_url = "${origin}"
data_dir = "${dataDir}"
refresh_key_file = "${join(dir, "refresh_key")}"
login_label = "${LOGIN_LABEL}"
log_level = "debug"

[limits]
max_file_size = "${c.maxFileSize ?? "1GB"}"
user_quota = "${c.userQuota ?? "10GB"}"
default_expiry = "7d"

[oidc]
issuer = "${KEYCLOAK}/realms/dropr"
client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "${join(ROOT, "deploy/dev/client_secret")}"
scopes = ["openid", "profile"]
role_claim = "realm_access.roles"
required_role = "Dropr.User"
display_claim = "name"
revalidate_every = "${c.revalidateEvery ?? "15m"}"
`,
  );
  await setRedirectUri(origin, true);
  const logFile = join(dir, "dropr.log");
  const log = openSync(logFile, "a");
  const proc: ChildProcess = spawn(join(ROOT, "bin/dropr"), ["serve", "--config", cfg], { stdio: ["ignore", log, log] });
  const exited = new Promise<void>((ok) => proc.once("exit", () => ok()));
  const deadline = Date.now() + 20_000;
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`dropr exited (${proc.exitCode}):\n${readFileSync(logFile, "utf8")}`);
    const r = await fetch(`http://127.0.0.1:${port}/healthz`).catch(() => null);
    if (r?.ok) break;
    if (Date.now() > deadline) throw new Error(`dropr did not start:\n${readFileSync(logFile, "utf8")}`);
    await new Promise((ok) => setTimeout(ok, 200));
  }
  return {
    dropr: { origin, logFile, port, dir, dataDir, dbPath: join(dataDir, "dropr.db"), pid: proc.pid! },
    async stop() {
      proc.kill("SIGTERM");
      await Promise.race([exited, new Promise((ok) => setTimeout(ok, 10_000))]);
      closeSync(log);
      await setRedirectUri(origin, false).catch(() => undefined);
      if (process.env["E2E_KEEP"] !== "1") rmSync(dir, { recursive: true, force: true });
      else console.log(`kept ${dir}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Direct database access (the server runs SQLite in WAL mode)
// ---------------------------------------------------------------------------

export function withDB<T>(d: DroprX, f: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(d.dbPath, { timeout: 10_000 });
  try {
    return f(db);
  } finally {
    db.close();
  }
}

export function sqlGet<T = Record<string, unknown>>(d: DroprX, sql: string, ...params: (string | number | null)[]): T | undefined {
  return withDB(d, (db) => db.prepare(sql).get(...params) as T | undefined);
}

export function sqlAll<T = Record<string, unknown>>(d: DroprX, sql: string, ...params: (string | number | null)[]): T[] {
  return withDB(d, (db) => db.prepare(sql).all(...params) as T[]);
}

export function sqlRun(d: DroprX, sql: string, ...params: (string | number | null)[]): number {
  return withDB(d, (db) => Number(db.prepare(sql).run(...params).changes));
}

/** On-disk directory of a blob (ARCHITECTURE.md §3 Storage). */
export function blobDir(d: DroprX, blobId: string): string {
  return join(d.dataDir, "blobs", blobId.slice(0, 2), blobId.slice(2, 4), blobId);
}

export function blobExists(d: DroprX, blobId: string): boolean {
  return existsSync(blobDir(d, blobId));
}

/** Link id from a share or request URL. */
export function linkId(url: string): string {
  const m = /\/[sr]\/([A-Za-z0-9_-]{22})/.exec(url);
  if (m === null) throw new Error(`not a link: ${url}`);
  return m[1]!;
}

// ---------------------------------------------------------------------------
// Owner helpers
// ---------------------------------------------------------------------------

export async function login(page: Page, origin: string, user: User): Promise<void> {
  await page.goto(origin + "/");
  await page.getByRole("link", { name: LOGIN_LABEL }).click();
  await page.waitForURL(`${KEYCLOAK}/**`);
  await page.locator("#username").fill(user.username);
  await page.locator("#password").fill(user.password);
  await page.locator("#kc-login").click();
}

/** Sign in and register two passkeys (as in the smoke test). */
export async function setupOwner(owner: Owner, user: User): Promise<void> {
  const p = owner.page;
  // Before /setup loads, so the page offers (and recommends) "This computer".
  const first = await owner.addAuthenticator();
  await login(p, owner.dropr.origin, user);
  await p.waitForURL(owner.dropr.origin + "/setup");
  await expect(p.locator(".who")).toHaveText(user.name);
  const register = p.locator("#setup-register");
  await expect(register).toHaveText("Create my first passkey");
  await p.locator("#setup-where-device").check();
  await register.click();
  await expect(register).toHaveText("Create my spare passkey");
  const second = await owner.addAuthenticator("usb");
  await owner.only(second);
  await p.locator("#setup-where-security-key").check();
  await register.click();
  await p.waitForURL(owner.dropr.origin + "/");
  await owner.only(first);
}

/** A second owner (own Chromium context and authenticators). */
export async function newOwner(browser: Browser, dropr: Dropr, label: string): Promise<Owner> {
  const context = await browser.newContext({ acceptDownloads: true });
  await context.grantPermissions(["clipboard-write"], { origin: dropr.origin });
  const page = await context.newPage();
  logConsole(page, label);
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  return new Owner(dropr, context, page, cdp);
}

export interface ShareOptions {
  readonly expiresIn?: "1h" | "1d" | "7d" | "30d";
  readonly maxDownloads?: number;
}

/** Share a file from the dashboard; returns the share link. */
export async function shareFile(owner: Owner, file: TestFile, o: ShareOptions = {}): Promise<string> {
  const p = owner.page;
  await p.goto(owner.dropr.origin + "/");
  await expect(p.locator("#share-form")).toBeVisible();
  if (o.expiresIn !== undefined) await p.locator("#expires-in").selectOption(o.expiresIn);
  if (o.maxDownloads !== undefined) await p.locator("#max-downloads").fill(String(o.maxDownloads));
  await p.locator("#file-input").setInputFiles(file.path);
  await expect(p.locator("#share-result")).toBeVisible({ timeout: 120_000 });
  return p.locator("#share-link").inputValue();
}

/** Create a request link from the dashboard (unlocks the session). */
export async function createRequest(owner: Owner, maxFiles = 10): Promise<string> {
  const p = owner.page;
  await p.goto(owner.dropr.origin + "/");
  await expect(p.locator("#request-form")).toBeVisible();
  await p.locator("#request-max-files").fill(String(maxFiles));
  await p.locator("#request-create").click();
  await expect(p.locator("#request-result")).toBeVisible();
  return p.locator("#request-link").inputValue();
}

/** Upload files through a request link in a fresh anonymous context. */
export async function sendViaRequest(browser: Browser, link: string, files: string[], label = "sender"): Promise<void> {
  const context = await browser.newContext();
  const page = await context.newPage();
  logConsole(page, label);
  await page.goto(link);
  await page.locator("#file-input").setInputFiles(files);
  await expect(page.locator("#upload-done")).toBeVisible({ timeout: 180_000 });
  await context.close();
}

/** JSON fetch from inside a page (same origin, the page's cookies). */
export async function pageFetch(page: Page, path: string, init: { method?: string; body?: unknown } = {}): Promise<{ status: number; json: unknown }> {
  return page.evaluate(
    async ({ path, method, body }) => {
      const res = await fetch(path, {
        method: method ?? "GET",
        headers: body === undefined ? {} : { "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await res.text();
      let json: unknown = null;
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
      return { status: res.status, json };
    },
    { path, method: init.method, body: init.body },
  );
}

/** Downloads a page starts, collected (to assert none, or only failed ones, were saved). */
export function collectDownloads(page: Page): { list: import("@playwright/test").Download[] } {
  const out = { list: [] as import("@playwright/test").Download[] };
  page.on("download", (d) => out.list.push(d));
  return out;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface M6Worker {
  droprConfig: DroprConfig;
  dropr: DroprX;
  alice: Owner;
}

export const test = base.extend<object, M6Worker>({
  droprConfig: [{}, { scope: "worker", option: true }],
  dropr: [
    async ({ droprConfig }, use) => {
      const { dropr, stop } = await startDroprX(droprConfig);
      try {
        await use(dropr);
      } finally {
        await stop();
      }
    },
    { scope: "worker" },
  ],
  alice: [
    async ({ owner }, use) => {
      await setupOwner(owner, M6_USERS.alice);
      await use(owner);
    },
    { scope: "worker" },
  ],
});

/** Chromium for owner-only specs when the project browser is another one. */
export async function chromiumBrowser(browser: Browser, browserName: string): Promise<{ b: Browser; close: () => Promise<void> }> {
  if (browserName === "chromium") return { b: browser, close: async () => undefined };
  const b = await chromium.launch();
  return { b, close: () => b.close() };
}

export type { BrowserContext, Page };

/** A real (not same-document) navigation, even when only the fragment would differ. */
export async function gotoFresh(page: Page, url: string): Promise<import("@playwright/test").Response | null> {
  await page.goto("about:blank");
  return page.goto(url);
}
