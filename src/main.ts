/**
 * One program, several roles: `node dist/main.js <migrate | api | dashboard | worker | all | turn-usage>`.
 * Docker Compose runs api, dashboard and worker as separate services; `all` is for
 * development on one machine.
 */

import { readFileSync } from "node:fs";
import { buildApi } from "./api/app.js";
import { Metrics } from "./api/studio.js";
import { Issuer } from "./acme/issuer.js";
import { loadConfig, type Config } from "./config.js";
import { buildDashboard } from "./dashboard/app.js";
import { connect, migrate, type Db } from "./db/db.js";
import { DnsManager, type DnsProvider } from "./dns/dns.js";
import { ChallTestSrvProvider, CloudflareProvider, MemoryProvider } from "./dns/providers.js";
import { makeMailer } from "./lib/mail.js";
import { startWorker } from "./worker/jobs.js";

export function providerFor(c: Config): DnsProvider {
  if (c.dnsProvider === "cloudflare") return new CloudflareProvider(c.cloudflareApiToken, c.cloudflareZoneId);
  if (c.dnsProvider === "challtestsrv") return new ChallTestSrvProvider(c.challTestSrvUrl);
  return new MemoryProvider();
}

async function main() {
  const role = process.argv[2] ?? "all";
  if (role === "turn-usage") {
    // On the coturn host: no database, only the API's address and the usage token.
    const { keepTurnCert, ship } = await import("./turn/shipper.js");
    const need = (n: string) => process.env[n] || (() => { throw new Error(`${n} is not set`); })();
    ship({ logFile: process.env.TURN_LOG_FILE ?? "/var/log/coturn/turn.log", apiBase: need("API_BASE"), token: need("TURN_USAGE_TOKEN") });
    if (process.env.TURN_CERT_DIR) {
      keepTurnCert({ apiBase: need("API_BASE"), token: need("TURN_USAGE_TOKEN"), dir: process.env.TURN_CERT_DIR,
        reloadPid: process.env.TURN_RELOAD_PID ? Number(process.env.TURN_RELOAD_PID) : undefined });
    }
    console.log("shipping TURN usage");
    return;
  }
  const config = loadConfig();
  if (config.acmeCaBundle && !config.acmeCaBundle.includes("BEGIN")) config.acmeCaBundle = readFileSync(config.acmeCaBundle, "utf8");
  const db: Db = connect(config.databaseUrl);
  const applied = await migrate(db);
  if (applied.length) console.log(`migrations applied: ${applied.join(", ")}`);
  if (role === "migrate") return db.end();

  const dns = new DnsManager(db, providerFor(config), config.rootDomain);
  const mail = makeMailer(config.smtpUrl, config.mailFrom);
  const stops: (() => Promise<unknown>)[] = [];

  if (role === "api" || role === "all") {
    const api = buildApi({ db, dns, config, metrics: new Metrics() });
    await api.listen({ host: "0.0.0.0", port: config.apiPort });
    console.log(`api on :${config.apiPort}`);
    stops.push(() => api.close());
  }
  if (role === "dashboard" || role === "all") {
    const dash = buildDashboard({ db, dns, config, mail });
    await dash.listen({ host: "0.0.0.0", port: config.dashboardPort });
    console.log(`dashboard on :${config.dashboardPort}`);
    stops.push(() => dash.close());
  }
  if (role === "worker" || role === "all") {
    const locks = connect(config.databaseUrl, 16); // one per job and the listener
    const worker = await startWorker({ db, dns, mail, config, locks, issuer: new Issuer({ db, dns, config }) });
    console.log("worker running");
    stops.push(async () => {
      await worker.stop();
      await locks.end();
    });
  }
  if (!stops.length) throw new Error(`unknown role ${role}: use migrate, api, dashboard, worker or all`);

  const shutdown = async () => {
    for (const stop of stops) await stop().catch(() => undefined);
    await db.end();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((e) => {
  console.error((e as Error).message);
  process.exit(1);
});
