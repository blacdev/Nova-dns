/**
 * Tests run against a real PostgreSQL. With TEST_DATABASE_URL set, that server is used;
 * otherwise a throwaway cluster is started here (initdb from PATH or
 * /usr/lib/postgresql/<v>/bin) on a free port, and removed afterwards.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { chownSync, existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

function pgBin(): string {
  const which = spawnSync("sh", ["-c", "command -v initdb"], { encoding: "utf8" }).stdout.trim();
  if (which) return join(which, "..");
  const base = "/usr/lib/postgresql";
  if (existsSync(base)) {
    const v = readdirSync(base).sort((a, b) => Number(b) - Number(a))[0];
    if (v && existsSync(join(base, v, "bin", "initdb"))) return join(base, v, "bin");
  }
  throw new Error("No PostgreSQL found: install it, or set TEST_DATABASE_URL.");
}

const freePort = () =>
  new Promise<number>((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });

import type { TestProject } from "vitest/node";

declare module "vitest" {
  export interface ProvidedContext {
    dbUrl: string;
  }
}

export default async function setup(project: TestProject) {
  if (process.env.TEST_DATABASE_URL) {
    project.provide("dbUrl", process.env.TEST_DATABASE_URL);
    return () => undefined;
  }
  const bin = pgBin();
  const dir = mkdtempSync(join(tmpdir(), "nova-dns-pg-"));
  const port = await freePort();
  // PostgreSQL will not run as root: use "nobody" then.
  const root = process.getuid?.() === 0;
  const as = (cmd: string, args: string[]) =>
    root ? execFileSync("runuser", ["-u", "nobody", "--", cmd, ...args], { stdio: "pipe" }) : execFileSync(cmd, args, { stdio: "pipe" });
  if (root) chownSync(dir, 65534, 65534);
  as(join(bin, "initdb"), ["-D", join(dir, "data"), "-U", "postgres", "--auth=trust", "-E", "UTF8"]);
  as(join(bin, "pg_ctl"), ["-D", join(dir, "data"), "-o", `-p ${port} -k ${dir} -c listen_addresses=127.0.0.1 -c fsync=off`, "-w", "-l", join(dir, "log"), "start"]);
  project.provide("dbUrl", `postgres://postgres@127.0.0.1:${port}/postgres`);
  return () => {
    try {
      as(join(bin, "pg_ctl"), ["-D", join(dir, "data"), "-m", "immediate", "stop"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}
