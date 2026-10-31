/**
 * Certificates end to end against Pebble (Let's Encrypt's test CA) and its challenge DNS
 * server. Skipped when they are not installed:
 *   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
 *   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
 */

import { spawn, type ChildProcess } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import acme from "acme-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Issuer } from "../src/acme/issuer.js";
import { buildApi } from "../src/api/app.js";
import { Metrics } from "../src/api/studio.js";
import type { Db } from "../src/db/db.js";
import { DnsManager } from "../src/dns/dns.js";
import { ChallTestSrvProvider } from "../src/dns/providers.js";
import * as subs from "../src/lib/subdomains.js";
import { freshDb, person, testConfig } from "./helpers.js";

const BIN = process.env.PEBBLE_BIN ?? join(homedir(), "go", "bin");
const MOD = join(homedir(), "go", "pkg", "mod", "github.com", "letsencrypt", "pebble");
const pebbleSrc = process.env.PEBBLE_SRC ?? (existsSync(MOD) ? readdirSync(MOD).filter((d) => d.startsWith("v2@")).map((d) => join(MOD, d)).sort().pop() : undefined);
const available = existsSync(join(BIN, "pebble")) && existsSync(join(BIN, "pebble-challtestsrv")) && !!pebbleSrc;

const freePort = () => new Promise<number>((resolve) => {
  const s = createServer();
  s.listen(0, "127.0.0.1", () => {
    const p = (s.address() as { port: number }).port;
    s.close(() => resolve(p));
  });
});

async function waitFor(url: string, ca?: string) {
  const https = await import("node:https");
  for (let i = 0; i < 100; i++) {
    const ok = await new Promise<boolean>((resolve) => {
      const req = https.get(url, { ca, timeout: 1000 }, (res) => { res.resume(); resolve(true); });
      req.on("error", () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not come up`);
}

describe.skipIf(!available)("certificates from Pebble, by DNS-01", () => {
  const procs: ChildProcess[] = [];
  let db: Db;
  let issuer: Issuer;
  let dns: DnsManager;
  let api: ReturnType<typeof buildApi>;
  let config: ReturnType<typeof testConfig>;

  beforeAll(async () => {
    const [dnsPort, mgmt, acmePort, pebbleMgmt] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
    procs.push(spawn(join(BIN, "pebble-challtestsrv"), ["-dnsserver", `127.0.0.1:${dnsPort}`, "-management", `127.0.0.1:${mgmt}`,
      "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""], { stdio: "ignore" }));
    const dir = mkdtempSync(join(tmpdir(), "pebble-"));
    writeFileSync(join(dir, "config.json"), JSON.stringify({ pebble: {
      listenAddress: `127.0.0.1:${acmePort}`, managementListenAddress: `127.0.0.1:${pebbleMgmt}`,
      certificate: join(pebbleSrc!, "test/certs/localhost/cert.pem"), privateKey: join(pebbleSrc!, "test/certs/localhost/key.pem"),
      httpPort: 5002, tlsPort: 5001, ocspResponderURL: "", externalAccountBindingRequired: false,
      keyAlgorithm: "ecdsa", profiles: { default: { description: "default", validityPeriod: 7776000 } },
    } }));
    procs.push(spawn(join(BIN, "pebble"), ["-config", join(dir, "config.json"), "-dnsserver", `127.0.0.1:${dnsPort}`],
      { stdio: "ignore", env: { ...process.env, PEBBLE_VA_NOSLEEP: "1", PEBBLE_WFE_NONCEREJECT: "0", PEBBLE_AUTHZREUSE: "0" } }));
    const ca = readFileSync(join(pebbleSrc!, "test/certs/pebble.minica.pem"), "utf8");
    await waitFor(`https://127.0.0.1:${acmePort}/dir`, ca);
    for (let i = 0; i < 100; i++) {
      const up = await fetch(`http://127.0.0.1:${mgmt}/clear-txt`, { method: "POST", body: JSON.stringify({ host: "x." }) }).then(() => true, () => false);
      if (up) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    db = await freshDb();
    config = testConfig({ acmeDirectoryUrl: `https://127.0.0.1:${acmePort}/dir`, acmeCaBundle: ca, dnsCheckResolver: `127.0.0.1:${dnsPort}` });
    dns = new DnsManager(db, new ChallTestSrvProvider(`http://127.0.0.1:${mgmt}`), config.rootDomain, async () => undefined);
    issuer = new Issuer({ db, dns, config });
    api = buildApi({ db, dns, config, metrics: new Metrics() });
  }, 60_000);

  afterAll(async () => {
    await api?.close();
    await db?.end();
    for (const p of procs) p.kill();
  });

  async function station(label: string) {
    const owner = await person(db);
    const { id, accessCode } = await subs.claim({ db, dns, rootDomain: config.rootDomain, limit: 1 }, { id: owner, ip: null }, label);
    const reg = await api.inject({ method: "POST", url: "/v1/studio/register", payload: { hostname: label, access_code: accessCode, install_id: "i" }, remoteAddress: `192.0.2.${id}` });
    return { id, owner, token: reg.json().studio_token as string };
  }

  const auth = (token: string) => ({ authorization: `Bearer ${token}` });

  it("issues a certificate for the studio's CSR, keeps no key, and cleans up the challenge", async () => {
    const s = await station("kfm");
    const [key, csr] = await acme.crypto.createCsr({ commonName: "kfm.example.test", altNames: ["kfm.example.test"] }, await acme.crypto.createPrivateEcdsaKey("P-256"));
    expect((await api.inject({ method: "POST", url: "/v1/cert/csr", payload: { csr_pem: csr.toString() }, headers: auth(s.token) })).statusCode).toBe(202);
    expect(await issuer.runOne()).toBe(true);
    const got = (await api.inject({ method: "GET", url: "/v1/cert", headers: auth(s.token) })).json();
    expect(got.status).toBe("issued");
    const cert = new X509Certificate(got.cert_pem);
    expect(cert.subjectAltName).toBe("DNS:kfm.example.test");
    expect(cert.checkPrivateKey((await import("node:crypto")).createPrivateKey(key))).toBe(true);
    expect(got.chain_pem).toContain("BEGIN CERTIFICATE");
    expect(Date.parse(got.expires_at)).toBeGreaterThan(Date.now() + 80 * 86400_000);
    expect(got.serial).toMatch(/^[0-9a-f]+$/);
    // The platform never had the key: only the CSR and the certificate are stored.
    const stored = JSON.stringify((await db.query("SELECT * FROM certificates")).rows);
    expect(stored).not.toContain("PRIVATE KEY");
    // Renewal info (ARI) from the CA.
    expect((await db.query("SELECT ari_renewal_after FROM certificates WHERE status = 'issued'")).rows[0].ari_renewal_after).toBeInstanceOf(Date);
  });

  it("renews with the stored CSR at the CA's window, replacing the old one (ARI)", async () => {
    await db.query("UPDATE certificates SET ari_renewal_after = now() - interval '1 minute' WHERE status = 'issued'");
    expect(await issuer.queueRenewals()).toBe(1);
    expect(await issuer.queueRenewals()).toBe(0); // not twice
    expect(await issuer.runOne()).toBe(true);
    const rows = (await db.query("SELECT status, renews_id FROM certificates ORDER BY id")).rows;
    expect(rows.map((r) => r.status)).toEqual(["superseded", "issued"]);
    expect(rows[1].renews_id).toBeTruthy();
  });

  it("queues new certificates (does not fail them) near the weekly limit", async () => {
    const s = await station("busyfm");
    const tight = new Issuer({ db, dns, config: { ...config, certWeeklyLimit: 3 } });
    const [, csr] = await acme.crypto.createCsr({ commonName: "busyfm.example.test" });
    await api.inject({ method: "POST", url: "/v1/cert/csr", payload: { csr_pem: csr.toString() }, headers: auth(s.token) });
    expect(await tight.runOne()).toBe(true);
    const row = (await db.query("SELECT status, error, next_attempt_at FROM certificates WHERE fqdn = 'busyfm.example.test'")).rows[0];
    expect(row.status).toBe("pending");
    expect(row.error).toContain("weekly");
    expect(row.next_attempt_at.getTime()).toBeGreaterThan(Date.now() + 6 * 86400_000);
  });

  it("revokes a deleted station's certificate", async () => {
    const kfm = (await db.query("SELECT id, user_id FROM subdomains WHERE label = 'kfm'")).rows[0];
    await subs.remove({ db, dns, rootDomain: config.rootDomain, limit: 1 }, { id: kfm.user_id, ip: null }, kfm.id);
    expect(await issuer.revokeQueued()).toBe(1);
    const q = (await db.query("SELECT done_at, error FROM revoke_queue")).rows[0];
    expect(q.error).toBeNull();
    expect(q.done_at).toBeInstanceOf(Date);
  });
});
