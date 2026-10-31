/**
 * What can be done to a station's subdomain (spec sections 1 and 2), shared by the
 * customer and admin dashboards. Database changes happen in one transaction; DNS
 * changes follow it (a provider failure is logged and retried, never half-applied in
 * the database). Every action lands in the audit log.
 */

import type { Db, Queryable } from "../db/db.js";
import { transaction } from "../db/db.js";
import type { DnsManager } from "../dns/dns.js";
import { audit } from "./audit.js";
import { checkName, coolDown, fqdnOf } from "./names.js";
import { canonicalCode, hashSecret, newAccessCode } from "./secrets.js";

export class SubdomainError extends Error {}

export interface Ctx {
  db: Db;
  dns: DnsManager;
  rootDomain: string;
  limit: number;
}

export interface Actor {
  id: number;
  ip: string | null;
  admin?: boolean;
}

const isUnique = (e: unknown) => (e as { code?: string })?.code === "23505";

/** Claim a name: the subdomain, its studio and its access code (returned once, never kept). */
export async function claim(c: Ctx, actor: Actor, label: string): Promise<{ id: number; accessCode: string }> {
  const code = newAccessCode();
  const hash = await hashSecret(canonicalCode(code));
  try {
    const id = await transaction(c.db, async (tx) => {
      // One claim at a time per person, so the plan limit cannot be raced either.
      const me = await tx.query<{ status: string; email_verified_at: Date | null }>("SELECT status, email_verified_at FROM users WHERE id = $1 FOR UPDATE", [actor.id]);
      if (!me.rows[0] || me.rows[0].status !== "active") throw new SubdomainError("Your account is suspended.");
      if (!me.rows[0].email_verified_at) throw new SubdomainError("Verify your email address first.");
      const n = Number((await tx.query("SELECT count(*) AS n FROM subdomains WHERE user_id = $1", [actor.id])).rows[0].n);
      if (n >= c.limit) throw new SubdomainError(`Your plan allows ${c.limit} subdomain${c.limit === 1 ? "" : "s"}.`);
      const check = await checkName(tx, label);
      if (check.state !== "available") throw new SubdomainError(check.message);
      const sub = await tx.query<{ id: number }>("INSERT INTO subdomains (label, user_id) VALUES ($1, $2) RETURNING id", [label, actor.id]);
      await tx.query("INSERT INTO studios (subdomain_id, access_code_hash) VALUES ($1, $2)", [sub.rows[0].id, hash]);
      await audit(tx, { actor: actor.id, action: "subdomain.create", target: label, ip: actor.ip });
      return sub.rows[0].id;
    });
    return { id, accessCode: code };
  } catch (e) {
    // Two people pressed Claim at once: the unique index let exactly one through.
    if (isUnique(e)) throw new SubdomainError("Someone already has this name.");
    throw e;
  }
}

interface SubRow {
  id: number;
  label: string;
  user_id: number;
  status: string;
  studio_id: string;
  last_ip: string | null;
}

async function load(q: Queryable, id: number, lock = false): Promise<SubRow> {
  const r = await q.query<SubRow>(
    `SELECT s.id, s.label, s.user_id, s.status, st.id AS studio_id, st.last_ip
       FROM subdomains s JOIN studios st ON st.subdomain_id = s.id WHERE s.id = $1 ${lock ? "FOR UPDATE OF s" : ""}`, [id]);
  if (!r.rows[0]) throw new SubdomainError("No such subdomain.");
  return r.rows[0];
}

function mine(s: SubRow, actor: Actor) {
  if (!actor.admin && s.user_id !== actor.id) throw new SubdomainError("No such subdomain.");
}

/** Rename: the old name cools down for 30 days; the studio learns the new one on its next heartbeat. */
export async function rename(c: Ctx, actor: Actor, id: number, label: string): Promise<{ from: string; to: string }> {
  let before: SubRow;
  try {
    before = await transaction(c.db, async (tx) => {
      const s = await load(tx, id, true);
      mine(s, actor);
      if (s.label === label) throw new SubdomainError("That is already its name.");
      const check = await checkName(tx, label);
      if (check.state !== "available") throw new SubdomainError(check.message);
      await tx.query("UPDATE subdomains SET label = $2, updated_at = now() WHERE id = $1", [id, label]);
      await coolDown(tx, s.label);
      // The old name's certificate is of no use now; the studio asks for a new one.
      await tx.query("UPDATE certificates SET status = 'superseded' WHERE subdomain_id = $1 AND status IN ('pending', 'issued')", [id]);
      await audit(tx, { actor: actor.id, action: "subdomain.rename", target: label, ip: actor.ip, metadata: { from: s.label, to: label, admin: !!actor.admin } });
      return s;
    });
  } catch (e) {
    if (isUnique(e)) throw new SubdomainError("Someone already has this name.");
    throw e;
  }
  await c.dns.removeName(fqdnOf(before.label, c.rootDomain)).catch(() => undefined);
  if (before.last_ip && before.status === "active") await c.dns.pointAt(fqdnOf(label, c.rootDomain), before.last_ip).catch(() => undefined);
  return { from: before.label, to: label };
}

/** A new access code; the old one and every studio token stop working at once. */
export async function regenerate(c: Ctx, actor: Actor, id: number): Promise<string> {
  const code = newAccessCode();
  const hash = await hashSecret(canonicalCode(code));
  await transaction(c.db, async (tx) => {
    const s = await load(tx, id, true);
    mine(s, actor);
    await tx.query("UPDATE studios SET access_code_hash = $2 WHERE id = $1", [s.studio_id, hash]);
    await tx.query("UPDATE studio_tokens SET revoked_at = now() WHERE studio_id = $1 AND revoked_at IS NULL", [s.studio_id]);
    await audit(tx, { actor: actor.id, action: "subdomain.regenerate_code", target: s.label, ip: actor.ip });
  });
  return code;
}

/** Delete: DNS removed, tokens gone, certificates revoked, the name cools down for 30 days. */
export async function remove(c: Ctx, actor: Actor, id: number): Promise<string> {
  const s = await transaction(c.db, async (tx) => {
    const s = await load(tx, id, true);
    mine(s, actor);
    await tx.query(
      `INSERT INTO revoke_queue (fqdn, cert_pem) SELECT fqdn, cert_pem FROM certificates
        WHERE subdomain_id = $1 AND status = 'issued' AND cert_pem IS NOT NULL AND expires_at > now()`, [id]);
    await tx.query("DELETE FROM subdomains WHERE id = $1", [id]); // studios, tokens, certificates follow
    await coolDown(tx, s.label);
    await audit(tx, { actor: actor.id, action: "subdomain.delete", target: s.label, ip: actor.ip, metadata: { admin: !!actor.admin } });
    return s;
  });
  await c.dns.removeName(fqdnOf(s.label, c.rootDomain)).catch(() => undefined);
  return s.label;
}

/** Suspend or restore a subdomain: its DNS record goes (or comes back), the API answers 403 meanwhile. */
export async function setSuspended(c: Ctx, actor: Actor, id: number, suspended: boolean): Promise<void> {
  const s = await transaction(c.db, async (tx) => {
    const s = await load(tx, id, true);
    await tx.query("UPDATE subdomains SET status = $2, updated_at = now() WHERE id = $1", [id, suspended ? "suspended" : "active"]);
    await audit(tx, { actor: actor.id, action: suspended ? "subdomain.suspend" : "subdomain.unsuspend", target: s.label, ip: actor.ip });
    return s;
  });
  const fqdn = fqdnOf(s.label, c.rootDomain);
  if (suspended) await c.dns.removeName(fqdn);
  else if (s.last_ip) await c.dns.pointAt(fqdn, s.last_ip);
}

/** Suspend or restore a person: every one of their stations follows. */
export async function setUserSuspended(c: Ctx, actor: Actor, userId: number, suspended: boolean): Promise<void> {
  const subs = await transaction(c.db, async (tx) => {
    const u = await tx.query<{ email: string }>("UPDATE users SET status = $2 WHERE id = $1 RETURNING email", [userId, suspended ? "suspended" : "active"]);
    if (!u.rows[0]) throw new SubdomainError("No such user.");
    if (suspended) await tx.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    await audit(tx, { actor: actor.id, action: suspended ? "user.suspend" : "user.unsuspend", target: u.rows[0].email, ip: actor.ip });
    return (await tx.query<{ label: string; status: string; last_ip: string | null }>(
      "SELECT s.label, s.status, st.last_ip FROM subdomains s JOIN studios st ON st.subdomain_id = s.id WHERE s.user_id = $1", [userId])).rows;
  });
  for (const s of subs) {
    const fqdn = fqdnOf(s.label, c.rootDomain);
    if (suspended) await c.dns.removeName(fqdn).catch(() => undefined);
    else if (s.status === "active" && s.last_ip) await c.dns.pointAt(fqdn, s.last_ip).catch(() => undefined);
  }
}

/** Admin: free a name now (a cooldown or a reservation ends). */
export async function forceRelease(db: Db, actor: Actor, label: string): Promise<void> {
  await db.query("DELETE FROM name_cooldowns WHERE label = $1", [label]);
  await audit(db, { actor: actor.id, action: "name.force_release", target: label, ip: actor.ip });
}
