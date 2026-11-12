/** A fresh database per test file, migrated; and a platform wired to the memory DNS provider. */

import { randomBytes } from "node:crypto";
import pg from "pg";
import { inject } from "vitest";
import { connect, migrate, type Db } from "../src/db/db.js";
import type { Config } from "../src/config.js";
import { DnsManager } from "../src/dns/dns.js";
import { MemoryProvider } from "../src/dns/providers.js";
import { Metrics, type Deps } from "../src/api/studio.js";
import { ALL_PERMISSIONS } from "../src/lib/rbac.js";
import { encrypt } from "../src/lib/secrets.js";

export async function freshDb(): Promise<Db> {
  const base = inject("dbUrl");
  const name = `t_${randomBytes(6).toString("hex")}`;
  const admin = new pg.Client({ connectionString: base });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const db = connect(base.replace(/\/[^/]*$/, `/${name}`));
  await migrate(db);
  return db;
}

export function testConfig(over: Partial<Config> = {}): Config {
  return {
    rootDomain: "example.test", databaseUrl: "", dnsProvider: "memory", challTestSrvUrl: "",
    cloudflareApiToken: "", cloudflareZoneId: "", acmeDirectoryUrl: "", acmeEmail: "ops@example.test", acmeCaBundle: "",
    turnSharedSecret: "turn-secret", turnSharedSecretPrevious: "", turnHost: "turn.example.test", turnUsageToken: "usage-token",
    edgeIp: "", edgeHost: "edge.example.test:443", edgeToken: "edge-token",
    sessionSecret: "session-secret", smtpUrl: "", mailFrom: "Nova <no-reply@example.test>", trustedProxies: ["127.0.0.1"],
    apiPort: 0, dashboardPort: 0, dashboardUrl: "http://app.example.test", subdomainLimit: 1, certWeeklyLimit: 50,
    adminEmails: [], allowPrivateProbe: true, dnsCheckResolver: "",
    ...over,
  };
}

export function platform(db: Db, over: Partial<Config> = {}) {
  const config = testConfig(over);
  const provider = new MemoryProvider();
  const dns = new DnsManager(db, provider, config.rootDomain, async () => undefined);
  const deps: Deps = { db, dns, config, metrics: new Metrics() };
  return { config, provider, dns, deps };
}

/** The authenticator secret every admin made by `person` has (admins need two-step sign-in). */
export const STAFF_TOTP = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/** A verified person, straight into the database. An admin gets every permission unless told otherwise, and two-step sign-in. */
export async function person(db: Db, email = `p${randomBytes(3).toString("hex")}@example.test`, role = "user", permissions: string[] = role === "admin" ? ALL_PERMISSIONS : []): Promise<number> {
  const totp = role === "user" ? null : encrypt(testConfig().sessionSecret, STAFF_TOTP);
  const r = await db.query<{ id: number }>(
    "INSERT INTO users (email, password_hash, role, permissions, email_verified_at, totp_secret_enc) VALUES ($1, 'x', $2, $3, now(), $4) RETURNING id", [email, role, permissions, totp]);
  return r.rows[0].id;
}
