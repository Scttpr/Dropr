/**
 * Test fixtures: a Dropr server per worker (fresh data directory, free port,
 * dev mode against the dev Keycloak) and an owner browser context in
 * Chromium. Request link keys live in that context's IndexedDB, so the
 * owner's request links can only be opened from `owner.context`.
 */

import { type Browser, type BrowserContext, type ConsoleMessage, type Locator, type Page, test as base, chromium, expect } from "@playwright/test";
import { type ChildProcess, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, createReadStream, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const KEYCLOAK = process.env["KEYCLOAK_URL"] ?? "http://localhost:8180";
const ROOT = resolve(import.meta.dirname, "..");
const LOGIN_LABEL = "Sign in with Keycloak (e2e)";

export const USERS = {
  alice: { username: "alice", password: "alice-dev-password", name: "Alice Example" },
} as const;

// ---------------------------------------------------------------------------
// Keycloak: register this run's redirect URI on the dev client
// ---------------------------------------------------------------------------

async function kcClient(): Promise<{ url: string; headers: Record<string, string>; rep: Record<string, unknown> }> {
  const tok = await fetch(`${KEYCLOAK}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" }),
  });
  if (!tok.ok) throw new Error(`Keycloak admin login failed: ${tok.status}`);
  const { access_token } = (await tok.json()) as { access_token: string };
  const headers = { authorization: `Bearer ${access_token}`, "content-type": "application/json" };
  const list = (await (await fetch(`${KEYCLOAK}/admin/realms/dropr/clients?clientId=dropr`, { headers })).json()) as { id: string }[];
  const id = list[0]?.id;
  if (id === undefined) throw new Error("Keycloak client 'dropr' not found");
  const url = `${KEYCLOAK}/admin/realms/dropr/clients/${id}`;
  const rep = (await (await fetch(url, { headers })).json()) as Record<string, unknown>;
  return { url, headers, rep };
}

async function setRedirectUri(origin: string, add: boolean): Promise<void> {
  const { url, headers, rep } = await kcClient();
  const uri = `${origin}/auth/callback`;
  const uris = ((rep["redirectUris"] as string[] | undefined) ?? []).filter((u) => u !== uri);
  if (add) uris.push(uri);
  const res = await fetch(url, { method: "PUT", headers, body: JSON.stringify({ ...rep, redirectUris: uris }) });
  if (!res.ok) throw new Error(`Keycloak client update failed: ${res.status} ${await res.text()}`);
}

// ---------------------------------------------------------------------------
// Dropr server
// ---------------------------------------------------------------------------

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

export interface Dropr {
  readonly origin: string;
  readonly logFile: string;
}

async function startDropr(): Promise<{ dropr: Dropr; stop: () => Promise<void> }> {
  const port = await freePort();
  // "localhost", not 127.0.0.1: browsers treat http://localhost as a secure
  // context (WebCrypto, IndexedDB keys, service workers, __Host- cookies).
  const origin = `http://localhost:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "dropr-e2e-"));
  writeFileSync(join(dir, "refresh_key"), randomBytes(32).toString("base64") + "\n", { mode: 0o600 });
  const cfg = join(dir, "dropr.toml");
  writeFileSync(
    cfg,
    `mode = "dev"
tls = "proxy"
listen = "127.0.0.1:${port}"
public_url = "${origin}"
data_dir = "${join(dir, "data")}"
refresh_key_file = "${join(dir, "refresh_key")}"
login_label = "${LOGIN_LABEL}"
log_level = "debug"

[limits]
max_file_size = "1GB"
user_quota = "10GB"
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
    dropr: { origin, logFile },
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
// Files and hashes
// ---------------------------------------------------------------------------

export async function sha256File(path: string): Promise<string> {
  const h = createHash("sha256");
  for await (const chunk of createReadStream(path)) h.update(chunk as Buffer);
  return h.digest("hex");
}

export interface TestFile {
  readonly name: string;
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

/** A file of random bytes (written in 1 MiB chunks). */
export async function makeFile(dir: string, name: string, size: number): Promise<TestFile> {
  const path = join(dir, name);
  const fd = openSync(path, "w");
  for (let left = size; left > 0; ) {
    const n = Math.min(left, 1 << 20);
    writeSync(fd, randomBytes(n));
    left -= n;
  }
  closeSync(fd);
  return { name, path, size, sha256: await sha256File(path) };
}

/** Click and wait for the browser download it starts; returns the downloaded file's hash and name. */
export async function downloadVia(page: Page, trigger: Locator): Promise<{ name: string; sha256: string }> {
  const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 120_000 }), trigger.click()]);
  const failure = await dl.failure();
  if (failure !== null) throw new Error(`download failed: ${failure}`);
  const path = await dl.path();
  return { name: dl.suggestedFilename(), sha256: await sha256File(path) };
}

/** Server-rendered dead pages (errors, 403) load no page module: prefs.js, on every page, is the only script. */
export async function expectNoPageModule(page: Page): Promise<void> {
  await expect(page.locator("script")).toHaveCount(1);
  await expect(page.locator("script")).toHaveAttribute("src", /^\/assets\/prefs-[^/]+\.js$/);
}

/** Forward page errors and warnings to the test output (minus header noise). */
export function logConsole(page: Page, label: string): void {
  page.on("console", (m: ConsoleMessage) => {
    const t = m.type();
    const noise = m.text().includes("Permissions-Policy");
    if ((t === "error" || t === "warning") && !noise) console.log(`[${label} ${t}] ${m.text()}`);
  });
  page.on("pageerror", (e) => console.log(`[${label} pageerror] ${e.message}`));
}

// ---------------------------------------------------------------------------
// Request link keys (IndexedDB "dropr", store "request-keys", ARCHITECTURE.md §3)
// ---------------------------------------------------------------------------

/**
 * IDs of the request link keys stored in the page's origin. Does not create
 * the database if it does not exist yet (returns []).
 */
export async function requestKeyIds(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const dbs = await indexedDB.databases();
    if (!dbs.some((d) => d.name === "dropr")) return [];
    const db = await new Promise<IDBDatabase>((ok, fail) => {
      const r = indexedDB.open("dropr");
      r.onsuccess = () => ok(r.result);
      r.onerror = () => fail(r.error);
    });
    try {
      if (!db.objectStoreNames.contains("request-keys")) return [];
      const keys = await new Promise<IDBValidKey[]>((ok, fail) => {
        const r = db.transaction("request-keys").objectStore("request-keys").getAllKeys();
        r.onsuccess = () => ok(r.result);
        r.onerror = () => fail(r.error);
      });
      return keys.map(String);
    } finally {
      db.close();
    }
  });
}

/**
 * Rewrite the `createdAt` (Unix seconds) of a stored record, e.g. to age it
 * past the 60 s prune grace period. Throws if there is no such record.
 */
export async function setRequestKeyCreatedAt(page: Page, id: string, createdAt: number): Promise<void> {
  await page.evaluate(
    async ({ id, createdAt }) => {
      const db = await new Promise<IDBDatabase>((ok, fail) => {
        const r = indexedDB.open("dropr");
        r.onsuccess = () => ok(r.result);
        r.onerror = () => fail(r.error);
      });
      try {
        const tx = db.transaction("request-keys", "readwrite");
        const store = tx.objectStore("request-keys");
        const rec = await new Promise<Record<string, unknown> | undefined>((ok, fail) => {
          const r = store.get(id);
          r.onsuccess = () => ok(r.result as Record<string, unknown> | undefined);
          r.onerror = () => fail(r.error);
        });
        if (rec === undefined) throw new Error(`no request key record ${id}`);
        store.put({ ...rec, createdAt });
        await new Promise<void>((ok, fail) => {
          tx.oncomplete = () => ok();
          tx.onerror = () => fail(tx.error);
        });
      } finally {
        db.close();
      }
    },
    { id, createdAt },
  );
}

/**
 * Store a well-formed record (fresh non-extractable X25519 key) as if another
 * account had created request link `id` in this browser profile. Opens the
 * database at version 1 and creates the store if no page did so yet.
 */
export async function injectRequestKey(page: Page, rec: { id: string; ownerId: string; createdAt: number }): Promise<void> {
  await page.evaluate(async ({ id, ownerId, createdAt }) => {
    const kp = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const db = await new Promise<IDBDatabase>((ok, fail) => {
      const r = indexedDB.open("dropr", 1);
      r.onupgradeneeded = () => {
        if (!r.result.objectStoreNames.contains("request-keys")) r.result.createObjectStore("request-keys", { keyPath: "id" });
      };
      r.onsuccess = () => ok(r.result);
      r.onerror = () => fail(r.error);
    });
    try {
      const tx = db.transaction("request-keys", "readwrite");
      tx.objectStore("request-keys").put({ id, privateKey: kp.privateKey, publicKey, ownerId, createdAt });
      await new Promise<void>((ok, fail) => {
        tx.oncomplete = () => ok();
        tx.onerror = () => fail(tx.error);
      });
    } finally {
      db.close();
    }
  }, rec);
}

/** Request ID of a request link URL. */
export function requestIdOf(link: string): string {
  const m = /\/r\/([A-Za-z0-9_-]{22})(?:#|$)/.exec(link);
  if (m === null) throw new Error(`not a request link: ${link}`);
  return m[1]!;
}

// ---------------------------------------------------------------------------
// Owner (one browser context = one browser profile)
// ---------------------------------------------------------------------------

export class Owner {
  constructor(
    readonly dropr: Dropr,
    readonly context: BrowserContext,
    readonly page: Page,
  ) {}

  /** Sign in through Keycloak; there is no setup step, so this lands on the dashboard. */
  async login(user: { readonly username: string; readonly password: string; readonly name: string }): Promise<void> {
    const p = this.page;
    await p.goto(this.dropr.origin + "/");
    await p.getByRole("link", { name: LOGIN_LABEL }).click();
    await p.waitForURL(`${KEYCLOAK}/**`);
    await p.locator("#username").fill(user.username);
    await p.locator("#password").fill(user.password);
    await p.locator("#kc-login").click();
    await p.waitForURL(this.dropr.origin + "/");
    await expect(p.locator(".who")).toHaveText(user.name);
  }
}

/** A new owner browser context (a separate "browser profile": its own cookies and IndexedDB). */
export async function newOwnerContext(browser: Browser, dropr: Dropr, label: string): Promise<Owner> {
  const context = await browser.newContext({ acceptDownloads: true });
  await context.grantPermissions(["clipboard-write"], { origin: dropr.origin });
  const page = await context.newPage();
  logConsole(page, label);
  return new Owner(dropr, context, page);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface WorkerFixtures {
  dropr: Dropr;
  ownerBrowser: Browser;
  owner: Owner;
  filesDir: string;
}

export const test = base.extend<object, WorkerFixtures>({
  dropr: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      const { dropr, stop } = await startDropr();
      try {
        await use(dropr);
      } finally {
        await stop();
      }
    },
    { scope: "worker" },
  ],
  // Owner pages run in Chromium (the clipboard-write permission grant is
  // Chromium-only); the anonymous side runs in each project's browser.
  ownerBrowser: [
    async ({ browserName, browser }, use) => {
      if (browserName === "chromium") return use(browser);
      const b = await chromium.launch();
      try {
        await use(b);
      } finally {
        await b.close();
      }
    },
    { scope: "worker" },
  ],
  owner: [
    async ({ ownerBrowser, dropr }, use) => {
      const owner = await newOwnerContext(ownerBrowser, dropr, "owner");
      await use(owner);
      await owner.context.close();
    },
    { scope: "worker" },
  ],
  filesDir: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      const dir = mkdtempSync(join(tmpdir(), "dropr-e2e-files-"));
      try {
        await use(dir);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
    { scope: "worker" },
  ],
});

export { expect };

/**
 * A fresh anonymous recipient page in the project's browser. In Chromium the
 * File System Access picker is shadowed so the download goes through the
 * service worker (the path Firefox and Safari use) and Playwright sees it.
 */
export async function anonymousPage(browser: Browser, label: string): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ acceptDownloads: true });
  await context.addInitScript(() => {
    // The picker lives on Window.prototype; shadow it on the instance.
    Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true });
  });
  const page = await context.newPage();
  logConsole(page, label);
  return { context, page };
}
