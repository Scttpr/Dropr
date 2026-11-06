/**
 * Test fixtures: a Dropr server per worker (fresh data directory, free port,
 * dev mode against the dev Keycloak) and a signed-in owner in Chromium with
 * CDP virtual authenticators (ctap2, resident keys, UV, PRF).
 */

import { type Browser, type BrowserContext, type CDPSession, type ConsoleMessage, type Locator, type Page, test as base, chromium, expect } from "@playwright/test";
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
  // context (WebAuthn, service workers, __Host- cookies).
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
// Owner (Chromium + virtual authenticators)
// ---------------------------------------------------------------------------

export class Owner {
  readonly authenticators: string[] = [];
  constructor(
    readonly dropr: Dropr,
    readonly context: BrowserContext,
    readonly page: Page,
    readonly cdp: CDPSession,
  ) {}

  /**
   * Add an authenticator with PRF that answers prompts automatically:
   * "internal" is a platform authenticator (Chrome allows one per
   * environment), "usb" a security key.
   */
  async addAuthenticator(transport: "internal" | "usb" = "internal"): Promise<string> {
    const { authenticatorId } = await this.cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport,
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
      },
    });
    this.authenticators.push(authenticatorId);
    return authenticatorId;
  }

  /** Make only `id` respond to WebAuthn prompts. */
  async only(id: string): Promise<void> {
    for (const a of this.authenticators) {
      await this.cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: a, enabled: a === id });
    }
  }

  async credentials(id: string): Promise<number> {
    const { credentials } = await this.cdp.send("WebAuthn.getCredentials", { authenticatorId: id });
    return credentials.length;
  }

  async login(user: (typeof USERS)[keyof typeof USERS]): Promise<void> {
    const p = this.page;
    await p.goto(this.dropr.origin + "/");
    await p.getByRole("link", { name: LOGIN_LABEL }).click();
    await p.waitForURL(`${KEYCLOAK}/**`);
    await p.locator("#username").fill(user.username);
    await p.locator("#password").fill(user.password);
    await p.locator("#kc-login").click();
    await p.waitForURL(this.dropr.origin + "/setup");
    await expect(p.locator(".who")).toHaveText(user.name);
  }
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
      const context = await ownerBrowser.newContext({ acceptDownloads: true });
      await context.grantPermissions(["clipboard-write"], { origin: dropr.origin });
      const page = await context.newPage();
      logConsole(page, "owner");
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable", { enableUI: false });
      await use(new Owner(dropr, context, page, cdp));
      await context.close();
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
