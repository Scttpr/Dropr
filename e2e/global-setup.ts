import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { KEYCLOAK } from "./fixtures.ts";

/** Build bin/dropr with embedded browser bundles (skip with E2E_SKIP_BUILD=1) and check Keycloak. */
export default async function globalSetup(): Promise<void> {
  const root = resolve(import.meta.dirname, "..");
  if (process.env["E2E_SKIP_BUILD"] !== "1") {
    execFileSync("make", ["build"], { cwd: root, stdio: "inherit" });
  }
  if (!existsSync(resolve(root, "bin/dropr"))) throw new Error("bin/dropr missing: run `make build`");
  const res = await fetch(`${KEYCLOAK}/realms/dropr/.well-known/openid-configuration`).catch(() => null);
  if (res === null || !res.ok) throw new Error(`Keycloak is not reachable on ${KEYCLOAK}: run \`make keycloak-up\``);
}
