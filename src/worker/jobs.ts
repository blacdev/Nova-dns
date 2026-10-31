/**
 * Background jobs (spec section 8), each on its own timer; one failing never stops the
 * others. A Postgres advisory lock per job keeps two workers from running it at once.
 *
 * | job          | every   | what                                                          |
 * | ------------ | ------- | ------------------------------------------------------------- |
 * | certificates | 15 s    | issue pending certificates (also woken by NOTIFY cert_queue)  |
 * | renewals     | 1 h     | queue renewals (ARI window, else 30 days left)                |
 * | renewal-info | 1 day   | ask the CA again when to renew                                |
 * | revocations  | 5 min   | revoke deleted stations' certificates                         |
 * | dns-retry    | 1 min   | retry DNS records a provider failure left pending             |
 * | offline      | 1 min   | studios silent for 10 minutes are offline (DNS untouched)     |
 * | cooldowns    | 1 h     | release names whose cooldown has passed                       |
 * | tokens       | 1 h     | drop expired or revoked tokens, sessions and email links      |
 * | prune        | 1 day   | audit, usage and operations rows past their retention         |
 * | alert        | 1 day   | email admins the DNS/ACME failures not yet reported           |
 */

import type { Db } from "../db/db.js";
import { opsEvent } from "../lib/audit.js";
import type { Mailer } from "../lib/mail.js";
import type { Issuer } from "../acme/issuer.js";
import type { DnsManager } from "../dns/dns.js";
import type { Config } from "../config.js";

export const OFFLINE_AFTER_MINUTES = 10;

export interface JobDeps {
  db: Db;
  issuer: Issuer;
  dns: DnsManager;
  mail: Mailer;
  config: Config;
  retention?: { auditDays: number; usageDays: number; opsDays: number };
}

export async function markOffline(db: Db): Promise<number> {
  const r = await db.query(`UPDATE studios SET online = false WHERE online AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(mins => $1))`, [OFFLINE_AFTER_MINUTES]);
  return r.rowCount ?? 0;
}

export async function releaseCooldowns(db: Db): Promise<number> {
  return (await db.query("DELETE FROM name_cooldowns WHERE available_after <= now()")).rowCount ?? 0;
}

export async function expireTokens(db: Db): Promise<number> {
  let n = (await db.query("DELETE FROM studio_tokens WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'")).rowCount ?? 0;
  n += (await db.query("DELETE FROM sessions WHERE expires_at < now()")).rowCount ?? 0;
  n += (await db.query("DELETE FROM email_tokens WHERE expires_at < now() - interval '1 day'")).rowCount ?? 0;
  n += (await db.query("DELETE FROM rate_limits WHERE window_start < now() - interval '1 day'")).rowCount ?? 0;
  return n;
}

export async function prune(db: Db, keep = { auditDays: 730, usageDays: 400, opsDays: 90 }): Promise<void> {
  await db.query("DELETE FROM audit_log WHERE created_at < now() - make_interval(days => $1)", [keep.auditDays]);
  await db.query("DELETE FROM turn_usage WHERE day < current_date - $1::int", [keep.usageDays]);
  await db.query("DELETE FROM ops_events WHERE created_at < now() - make_interval(days => $1)", [keep.opsDays]);
  await db.query("DELETE FROM revoke_queue WHERE created_at < now() - interval '90 days'");
}

/** One email to every admin listing the DNS and ACME failures not yet reported. */
export async function dailyAlert(d: JobDeps): Promise<number> {
  const events = await d.db.query<{ id: number; kind: string; target: string | null; message: string; created_at: Date }>(
    "SELECT id, kind, target, message, created_at FROM ops_events WHERE level = 'error' AND alerted_at IS NULL AND kind IN ('dns', 'acme') ORDER BY created_at");
  if (!events.rowCount) return 0;
  const admins = new Set([...d.config.adminEmails,
    ...(await d.db.query<{ email: string }>("SELECT email FROM users WHERE role = 'admin' AND status = 'active'")).rows.map((r) => r.email.toLowerCase())]);
  const text = [`${events.rowCount} DNS/certificate problem(s) since the last report:`, "",
    ...events.rows.map((e) => `${e.created_at.toISOString()}  ${e.kind.toUpperCase()}  ${e.target ?? "-"}  ${e.message}`),
    "", `Details: ${d.config.dashboardUrl}/admin/operations`].join("\n");
  for (const to of admins) await d.mail({ to, subject: `[${d.config.rootDomain}] ${events.rowCount} DNS/ACME problem(s)`, text });
  await d.db.query("UPDATE ops_events SET alerted_at = now() WHERE id = ANY($1)", [events.rows.map((e) => e.id)]);
  return events.rowCount ?? 0;
}

interface Job {
  name: string;
  everyMs: number;
  run: () => Promise<unknown>;
}

const LOCK_BASE = 7466100;

export function jobsFor(d: JobDeps): Job[] {
  return [
    { name: "certificates", everyMs: 15_000, run: async () => { while (await d.issuer.runOne()); } },
    { name: "renewals", everyMs: 3600_000, run: () => d.issuer.queueRenewals() },
    { name: "renewal-info", everyMs: 86400_000, run: () => d.issuer.refreshRenewalInfo() },
    { name: "revocations", everyMs: 300_000, run: () => d.issuer.revokeQueued() },
    { name: "dns-retry", everyMs: 60_000, run: () => d.dns.retryPending() },
    { name: "offline", everyMs: 60_000, run: () => markOffline(d.db) },
    { name: "cooldowns", everyMs: 3600_000, run: () => releaseCooldowns(d.db) },
    { name: "tokens", everyMs: 3600_000, run: () => expireTokens(d.db) },
    { name: "prune", everyMs: 86400_000, run: () => prune(d.db, d.retention) },
    { name: "alert", everyMs: 86400_000, run: () => dailyAlert(d) },
  ];
}

/** Run every job on its timer until `stop()`. Certificates also wake on NOTIFY cert_queue. */
export async function startWorker(d: JobDeps): Promise<{ stop: () => Promise<void>; wake: (name: string) => void }> {
  const jobs = jobsFor(d);
  const timers = new Map<string, NodeJS.Timeout>();
  const running = new Set<string>();
  let stopped = false;

  const run = async (job: Job, index: number) => {
    if (stopped || running.has(job.name)) return;
    running.add(job.name);
    const client = await d.db.connect().catch(() => null);
    try {
      if (!client) return;
      const locked = (await client.query<{ ok: boolean }>("SELECT pg_try_advisory_lock($1) AS ok", [LOCK_BASE + index])).rows[0].ok;
      if (!locked) return; // another worker has it
      try {
        await job.run();
      } finally {
        await client.query("SELECT pg_advisory_unlock($1)", [LOCK_BASE + index]);
      }
    } catch (e) {
      await opsEvent(d.db, "job", `${job.name}: ${(e as Error).message}`).catch(() => undefined);
    } finally {
      client?.release();
      running.delete(job.name);
    }
  };

  jobs.forEach((job, i) => {
    void run(job, i);
    timers.set(job.name, setInterval(() => void run(job, i), job.everyMs));
  });

  const listener = await d.db.connect();
  await listener.query("LISTEN cert_queue");
  listener.on("notification", () => void run(jobs[0], 0));

  return {
    wake: (name) => {
      const i = jobs.findIndex((j) => j.name === name);
      if (i >= 0) void run(jobs[i], i);
    },
    stop: async () => {
      stopped = true;
      for (const t of timers.values()) clearInterval(t);
      await listener.query("UNLISTEN *").catch(() => undefined);
      listener.release();
      while (running.size) await new Promise((r) => setTimeout(r, 50));
    },
  };
}
