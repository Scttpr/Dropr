/**
 * Soak / performance test (not part of `make e2e`; run with `make soak`).
 *
 * Streams a large generated file through the real HTTP API of a fresh
 * Dropr instance, using the browser crypto modules (web/src/crypto, loaded
 * with Node's type stripping) exactly as the pages do:
 *
 *   sign in at Keycloak (plain HTTP) → POST /api/shares → encrypt 32 MiB
 *   parts on the fly (3 in flight) → PUT /upload/{id}/part/{n} → finalize →
 *   POST /api/s/{id}/download → GET /dl/{token} streamed through
 *   createDecryptStream → SHA-256 compared with the generated plaintext.
 *
 * Nothing is buffered beyond a few parts: the plaintext is a deterministic
 * AES-CTR keystream generated per part, so memory stays bounded whatever the
 * size. Reports throughput and the peak RSS (VmHWM) of node and dropr.
 *
 * Environment:
 *   SOAK_SIZE   plaintext size, e.g. "2GiB" (default), "100GiB", or bytes
 *   SOAK_DIR    work directory for the server's data (default
 *               ~/.cache/dropr-soak; NOT /tmp, which is often tmpfs/RAM).
 *               100 GiB needs ~101 GiB free there plus 1 GiB headroom.
 *   SOAK_KEEP=1 keep the work directory
 *   KEYCLOAK_URL (default http://localhost:8180; `make keycloak-up`)
 *
 * 100 GB path: `SOAK_SIZE=100GiB make soak` (≈3200 parts). Dropr's
 * max_file_size cap is 100 GiB, so that is the largest valid file.
 */

import { spawn } from "node:child_process";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import {

  PART_SIZE,
  b64urlEncode,
  ciphertextSize,
  createDecryptStream,
  deriveFileKeys,
  encryptPart,
  generateFileKey,
  partCount,
  sealMeta,
} from "../../web/src/crypto/index.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const KEYCLOAK = process.env["KEYCLOAK_URL"] ?? "http://localhost:8180";
const PARALLEL = 3;

function parseSize(s: string): number {
  const m = /^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB|TiB|KB|MB|GB|TB)?$/i.exec(s.trim());
  if (m === null) throw new Error(`bad SOAK_SIZE ${s}`);
  const mult: Record<string, number> = { b: 1, kib: 2 ** 10, mib: 2 ** 20, gib: 2 ** 30, tib: 2 ** 40, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12 };
  return Math.floor(Number(m[1]) * mult[(m[2] ?? "b").toLowerCase()]!);
}

const SIZE = parseSize(process.env["SOAK_SIZE"] ?? "2GiB");
const fmt = (n: number): string => `${(n / 2 ** 20).toFixed(1)} MiB`;

// --- peak memory ---------------------------------------------------------
function vm(pid: number | "self", key: "VmHWM" | "VmRSS"): number {
  const m = new RegExp(`^${key}:\\s+(\\d+) kB`, "m").exec(readFileSync(`/proc/${pid}/status`, "utf8"));
  return m === null ? 0 : Number(m[1]) * 1024;
}

// --- deterministic plaintext ---------------------------------------------
const genKey = randomBytes(16);
function plainPart(n: number, len: number): Uint8Array {
  const iv = Buffer.alloc(16);
  iv.writeUInt32BE(n, 12); // a counter block per part, far apart (32 MiB = 2^21 blocks < 2^32)
  iv.writeUInt32BE(n, 4);
  const c = createCipheriv("aes-128-ctr", genKey, iv);
  return new Uint8Array(c.update(Buffer.alloc(len)));
}

// --- cookies ----------------------------------------------------------------
class Jar {
  private readonly c = new Map<string, string>();
  take(res: Response): void {
    for (const sc of res.headers.getSetCookie()) {
      const [kv] = sc.split(";");
      const i = kv!.indexOf("=");
      const name = kv!.slice(0, i).trim();
      const value = kv!.slice(i + 1).trim();
      if (/max-age=0/i.test(sc) || value === "") this.c.delete(name);
      else this.c.set(name, value);
    }
  }
  header(): string {
    return [...this.c].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function kcHeaders(): Promise<Record<string, string>> {
  const tok = await fetch(`${KEYCLOAK}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" }),
  });
  const { access_token } = (await tok.json()) as { access_token: string };
  return { authorization: `Bearer ${access_token}`, "content-type": "application/json" };
}

async function setRedirect(origin: string, add: boolean): Promise<void> {
  const headers = await kcHeaders();
  const [client] = (await (await fetch(`${KEYCLOAK}/admin/realms/dropr/clients?clientId=dropr`, { headers })).json()) as { id: string }[];
  const url = `${KEYCLOAK}/admin/realms/dropr/clients/${client!.id}`;
  const rep = (await (await fetch(url, { headers })).json()) as { redirectUris?: string[] };
  const uri = `${origin}/auth/callback`;
  const uris = (rep.redirectUris ?? []).filter((u) => u !== uri);
  if (add) uris.push(uri);
  await fetch(url, { method: "PUT", headers, body: JSON.stringify({ ...rep, redirectUris: uris }) });
}

/** Authorization-code login through Keycloak's HTML form, without a browser. */
async function login(origin: string): Promise<Jar> {
  const app = new Jar();
  const kc = new Jar();
  let r = await fetch(origin + "/auth/login", { redirect: "manual" });
  app.take(r);
  r = await fetch(r.headers.get("location")!, { redirect: "manual" });
  kc.take(r);
  const html = await r.text();
  const action = /<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"/.exec(html)?.[1]?.replaceAll("&amp;", "&");
  if (action === undefined) throw new Error("Keycloak login form not found");
  r = await fetch(action, {
    method: "POST",
    redirect: "manual",
    headers: { cookie: kc.header(), "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: "alice", password: "alice-dev-password", credentialId: "" }),
  });
  const cb = r.headers.get("location");
  if (cb === null || !cb.startsWith(origin + "/auth/callback")) throw new Error(`unexpected login redirect ${r.status} ${cb}`);
  r = await fetch(cb, { redirect: "manual", headers: { cookie: app.header() } });
  app.take(r);
  if (!app.header().includes("__Host-dropr_session=")) throw new Error(`no session after callback (${r.status})`);
  return app;
}

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => ok(p));
    });
  });
}

async function main(): Promise<void> {
  const base = process.env["SOAK_DIR"] ?? join(homedir(), ".cache", "dropr-soak");
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, "run-"));
  const port = await freePort();
  const origin = `http://localhost:${port}`;
  writeFileSync(join(dir, "refresh_key"), randomBytes(32).toString("base64"), { mode: 0o600 });
  writeFileSync(
    join(dir, "dropr.toml"),
    `mode = "dev"
tls = "proxy"
listen = "127.0.0.1:${port}"
public_url = "${origin}"
data_dir = "${join(dir, "data")}"
refresh_key_file = "${join(dir, "refresh_key")}"
log_level = "warn"
[limits]
max_file_size = "100GB"
user_quota = "200GB"
default_expiry = "1d"
disk_headroom = "1GB"
[oidc]
issuer = "${KEYCLOAK}/realms/dropr"
client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "${join(ROOT, "deploy/dev/client_secret")}"
scopes = ["openid", "profile"]
role_claim = "realm_access.roles"
required_role = "Dropr.User"
`,
  );
  await setRedirect(origin, true);
  const proc = spawn(join(ROOT, "bin/dropr"), ["serve", "--config", join(dir, "dropr.toml")], { stdio: ["ignore", "inherit", "inherit"] });
  const pid = proc.pid!;
  let peakNode = 0;
  const sampler = setInterval(() => (peakNode = Math.max(peakNode, process.memoryUsage().rss)), 250);
  try {
    for (let i = 0; ; i++) {
      if ((await fetch(origin + "/healthz").catch(() => null))?.ok) break;
      if (i > 100) throw new Error("dropr did not start");
      await new Promise((ok) => setTimeout(ok, 200));
    }
    const jar = await login(origin);
    const H = { cookie: jar.header(), origin, "content-type": "application/json" };

    const fk = generateFileKey();
    const keys = await deriveFileKeys(fk);
    const size = ciphertextSize(SIZE);
    const parts = partCount(size);
    const meta = await sealMeta(keys.metadata, { name: "soak.bin", type: "application/octet-stream", size: SIZE });
    const cr = await fetch(origin + "/api/shares", {
      method: "POST",
      headers: H,
      body: JSON.stringify({ size, parts, meta: b64urlEncode(meta), expires_in: "1d" }),
    });
    if (cr.status !== 201) throw new Error(`create share: ${cr.status} ${await cr.text()}`);
    const { share_id, upload_id, upload_token } = (await cr.json()) as { share_id: string; upload_id: string; upload_token: string };
    console.log(`soak: ${fmt(SIZE)} plaintext, ${parts} parts, share ${share_id}`);

    // Upload: parts are generated and hashed in order, encrypted and sent with PARALLEL in flight.
    const upHash = createHash("sha256");
    const t0 = performance.now();
    let next = 0;
    let hashed = 0;
    const plains = new Map<number, Uint8Array>();
    const flushHash = (): void => {
      while (plains.has(hashed)) {
        upHash.update(plains.get(hashed)!);
        plains.delete(hashed++);
      }
    };
    const worker = async (): Promise<void> => {
      for (let n = next++; n < parts; n = next++) {
        const len = Math.min(PART_SIZE, SIZE - n * PART_SIZE);
        const pt = plainPart(n, Math.max(0, len));
        const ct = await encryptPart(keys.content, n, pt, n === parts - 1);
        plains.set(n, pt);
        flushHash();
        for (let attempt = 0; ; attempt++) {
          const r = await fetch(`${origin}/upload/${upload_id}/part/${n}`, {
            method: "PUT",
            headers: { authorization: `Bearer ${upload_token}`, origin, "content-type": "application/octet-stream" },
            body: ct,
          }).catch((e: unknown) => e as Error);
          if (!(r instanceof Error) && r.status === 204) break;
          if (attempt >= 5) throw new Error(`part ${n}: ${r instanceof Error ? r.message : r.status}`);
          await new Promise((ok) => setTimeout(ok, 1000 * 2 ** attempt));
        }
        if (n % 32 === 0) process.stdout.write(`\r  up ${n + 1}/${parts}  node rss ${fmt(process.memoryUsage().rss)}  dropr rss ${fmt(vm(pid, "VmRSS"))}   `);
      }
    };
    await Promise.all(Array.from({ length: Math.min(PARALLEL, parts) }, worker));
    flushHash();
    const fin = await fetch(`${origin}/upload/${upload_id}/finalize`, {
      method: "POST",
      headers: { authorization: `Bearer ${upload_token}`, origin, "content-type": "application/json" },
      body: JSON.stringify({ parts }),
    });
    if (!fin.ok) throw new Error(`finalize: ${fin.status} ${await fin.text()}`);
    const tUp = (performance.now() - t0) / 1000;
    const upDigest = upHash.digest("hex");
    console.log(`\n  upload: ${tUp.toFixed(1)} s, ${(SIZE / 2 ** 20 / tUp).toFixed(1)} MiB/s (plaintext; ciphertext ${fmt(size)})`);

    // Download + decrypt, streamed.
    const tk = await fetch(`${origin}/api/s/${share_id}/download`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: "{}" });
    const { token } = (await tk.json()) as { token: string };
    const t1 = performance.now();
    const res = await fetch(`${origin}/dl/${token}`);
    if (res.status !== 200 || res.body === null) throw new Error(`download: ${res.status}`);
    const dnHash = createHash("sha256");
    let got = 0;
    let tick = 0;
    const reader = res.body.pipeThrough(createDecryptStream(keys.content)).getReader();
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      dnHash.update(r.value);
      got += r.value.length;
      if (++tick % 4096 === 0) process.stdout.write(`\r  down ${fmt(got)}  node rss ${fmt(process.memoryUsage().rss)}  dropr rss ${fmt(vm(pid, "VmRSS"))}   `);
    }
    const tDn = (performance.now() - t1) / 1000;
    const dnDigest = dnHash.digest("hex");
    console.log(`\n  download+decrypt: ${tDn.toFixed(1)} s, ${(SIZE / 2 ** 20 / tDn).toFixed(1)} MiB/s`);
    if (got !== SIZE || dnDigest !== upDigest) throw new Error(`MISMATCH: got ${got} bytes, ${dnDigest} != ${upDigest}`);
    console.log(`  sha256 ok: ${upDigest}`);
    console.log(`  peak RSS: node ${fmt(Math.max(peakNode, vm("self", "VmHWM")))}, dropr ${fmt(vm(pid, "VmHWM"))}`);
    await fetch(`${origin}/api/shares/${share_id}`, { method: "DELETE", headers: H });
  } finally {
    clearInterval(sampler);
    proc.kill("SIGTERM");
    await setRedirect(origin, false).catch(() => undefined);
    if (process.env["SOAK_KEEP"] !== "1") rmSync(dir, { recursive: true, force: true });
    else console.log(`kept ${dir}`);
  }
}

await main();
