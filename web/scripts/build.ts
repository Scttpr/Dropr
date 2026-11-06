/**
 * Bundle the browser entry points with esbuild.
 *
 * - Page entries: every top-level `src/*.ts` file except `sw.ts` (one per
 *   page: dashboard, setup, inbox, links, share, request). Library code
 *   (`src/crypto/`, `src/lib/`) is bundled into each entry; no code splitting,
 *   so each page loads exactly one same-origin script. ESM, content-hashed
 *   names `<name>-<hash>.js`, served from `/assets/`.
 * - Service worker: `src/sw.ts` → `sw.js`, **fixed name** (the server serves
 *   it at `/sw.js`; a SW URL must be stable across releases for updates to be
 *   picked up), **classic script** (IIFE) rather than a module worker so it
 *   registers in every browser without `type: "module"`.
 * - Output: `../internal/web/static/` (override with `--outdir <dir>`). No
 *   sourcemaps, no legal comments: deterministic output for reproducible
 *   builds and published asset hashes.
 * - `manifest.json` maps logical names to files, e.g.
 *   `{"dashboard.js": "dashboard-5HQ2RZ3M.js", "sw.js": "sw.js"}`; the Go
 *   server resolves asset URLs (and `/sw.js`) through it. Files listed in a
 *   previous manifest are removed first; nothing else in the output directory
 *   is touched.
 * - `--dev`: unminified with inline sourcemaps.
 */

import { build, type BuildOptions } from "esbuild";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { gzipSync } from "node:zlib";

const { values } = parseArgs({
  options: { outdir: { type: "string" }, dev: { type: "boolean", default: false } },
});
const root = resolve(import.meta.dirname, "..");
const outdir = resolve(root, values.outdir ?? "../internal/web/static");
const dev = values.dev === true;

const srcDir = join(root, "src");
const SW = "sw.ts";
const tsFiles = readdirSync(srcDir, { withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".d.ts"))
  .map((e) => e.name)
  .sort();
const pageEntries = tsFiles.filter((n) => n !== SW).map((n) => join(srcDir, n));
const hasSw = tsFiles.includes(SW);

mkdirSync(outdir, { recursive: true });
const manifestPath = join(outdir, "manifest.json");
if (existsSync(manifestPath)) {
  const old = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, string>;
  for (const file of Object.values(old)) {
    if (file === basename(file)) rmSync(join(outdir, file), { force: true });
  }
}

const common: BuildOptions = {
  bundle: true,
  platform: "browser",
  // Browsers with WebCrypto X25519 (required by the crypto core).
  target: ["chrome133", "firefox130", "safari17.4"],
  minify: !dev,
  sourcemap: dev ? "inline" : false,
  legalComments: "none",
  charset: "utf8",
  metafile: true,
  logLevel: "warning",
};

const manifest: Record<string, string> = {};
if (pageEntries.length > 0) {
  const result = await build({ ...common, entryPoints: pageEntries, outdir, format: "esm", entryNames: "[name]-[hash]" });
  for (const [out, meta] of Object.entries(result.metafile?.outputs ?? {})) {
    if (meta.entryPoint === undefined) continue;
    manifest[basename(meta.entryPoint).replace(/\.ts$/, ".js")] = basename(out);
  }
}
if (hasSw) {
  await build({ ...common, entryPoints: [join(srcDir, SW)], outfile: join(outdir, "sw.js"), format: "iife" });
  manifest["sw.js"] = "sw.js";
}

const sorted = Object.fromEntries(Object.entries(manifest).sort(([a], [b]) => a.localeCompare(b)));
writeFileSync(manifestPath, JSON.stringify(sorted, null, 2) + "\n");

for (const [name, file] of Object.entries(sorted)) {
  const path = join(outdir, file);
  const raw = statSync(path).size;
  const gz = gzipSync(readFileSync(path), { level: 9 }).length;
  console.log(`  ${name.padEnd(14)} ${file.padEnd(28)} ${(raw / 1024).toFixed(1).padStart(6)} KiB  (${(gz / 1024).toFixed(1)} KiB gzip)`);
}
console.log(`wrote ${manifestPath} (${Object.keys(sorted).length} entries)`);
