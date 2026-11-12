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
import { allowance, stationWord } from "./plans.js";
import { canonicalCode, hashSecret, newAccessCode } from "./secrets.js";

export class SubdomainError extends Error {}

export interface Ctx {
  db: Db;
  dns: DnsManager;
  rootDomain: string;
  /** SUBDOMAIN_LIMIT: the limit when no plan applies (see plans.ts). */
  limit: number;
  /** The tunnel's edge (EDGE_IP), when it runs: a station reached through it is pointed there. */
  edgeIp?: string;
}

/** Where a station's name should point: the edge for one that comes in through it, else the station. */
function target(c: Ctx, s: { last_ip: string | null; via?: string | null }): string | null {
  return s.via === "tunnel" && c.edgeIp ? c.edgeIp : s.last_ip;
}

export interface Actor {
  id: number;
  ip: string | null;
  /** May manage any station (the `stations.manage` permission). */
  admin?: boolean;
}

function staffOnly(actor: Actor) {
  if (!actor.admin) throw new SubdomainError("Not allowed.");
}

const isUnique = (e: unknown) => (e as { code?: string })?.code === "23505";

/**
 * Claim a name: the subdomain, its studio and its access code (returned once, never kept).
 * With `ownerId`, an admin claims it for that person (their email need not be confirmed;
 * their plan's limit still applies).
 */
export async function claim(c: Ctx, actor: Actor, label: string, ownerId = actor.id): Promise<{ id: number; accessCode: string }> {
  const forOther = ownerId !== actor.id;
  if (forOther) staffOnly(actor);
  const code = newAccessCode();
  const hash = await hashSecret(canonicalCode(code));
  try {
    const id = await transaction(c.db, async (tx) => {
      // One claim at a time per person, so the plan limit cannot be raced either.
      const me = await tx.query<{ status: string; email: string; email_verified_at: Date | null }>("SELECT status, email, email_verified_at FROM users WHERE id = $1 FOR UPDATE", [ownerId]);
      const owner = me.rows[0];
      if (!owner) throw new SubdomainError("No such person.");
      if (owner.status !== "active") throw new SubdomainError(forOther ? `${owner.email} is suspended.` : "Your account is suspended.");
      if (!forOther && !owner.email_verified_at) throw new SubdomainError("Verify your email address first.");
      const n = Number((await tx.query("SELECT count(*) AS n FROM subdomains WHERE user_id = $1", [ownerId])).rows[0].n);
      const a = await allowance(tx, ownerId, c.limit);
      if (n >= a.limit) {
        throw new SubdomainError(forOther
          ? `${owner.email} may have ${stationWord(a.limit)} and has ${n}. Raise their limit or change their plan first.`
          : `Your plan allows ${stationWord(a.limit)}.`);
      }
      const check = await checkName(tx, label);
      if (check.state !== "available") throw new SubdomainError(check.message);
      const sub = await tx.query<{ id: number }>("INSERT INTO subdomains (label, user_id) VALUES ($1, $2) RETURNING id", [label, ownerId]);
      await tx.query("INSERT INTO studios (subdomain_id, access_code_hash) VALUES ($1, $2)", [sub.rows[0].id, hash]);
      await audit(tx, { actor: actor.id, action: "subdomain.create", target: label, ip: actor.ip, metadata: forOther ? { owner: owner.email, admin: true } : {} });
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
  via: string;
}

async function load(q: Queryable, id: number, lock = false): Promise<SubRow> {
  const r = await q.query<SubRow>(
    `SELECT s.id, s.label, s.user_id, s.status, st.id AS studio_id, st.last_ip, st.via
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
  const to = target(c, before);
  if (to && before.status === "active") await c.dns.pointAt(fqdnOf(label, c.rootDomain), to).catch(() => undefined);
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
  staffOnly(actor);
  const s = await transaction(c.db, async (tx) => {
    const s = await load(tx, id, true);
    await tx.query("UPDATE subdomains SET status = $2, updated_at = now() WHERE id = $1", [id, suspended ? "suspended" : "active"]);
    await audit(tx, { actor: actor.id, action: suspended ? "subdomain.suspend" : "subdomain.unsuspend", target: s.label, ip: actor.ip });
    return s;
  });
  const fqdn = fqdnOf(s.label, c.rootDomain);
  if (suspended) await c.dns.removeName(fqdn);
  else if (target(c, s)) await c.dns.pointAt(fqdn, target(c, s)!);
}

/** Suspend or restore a person: every one of their stations follows. */
export async function setUserSuspended(c: Ctx, actor: Actor, userId: number, suspended: boolean): Promise<void> {
  const subs = await transaction(c.db, async (tx) => {
    const u = await tx.query<{ email: string }>("UPDATE users SET status = $2 WHERE id = $1 RETURNING email", [userId, suspended ? "suspended" : "active"]);
    if (!u.rows[0]) throw new SubdomainError("No such user.");
    if (suspended) await tx.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    await audit(tx, { actor: actor.id, action: suspended ? "user.suspend" : "user.unsuspend", target: u.rows[0].email, ip: actor.ip });
    return (await tx.query<{ label: string; status: string; last_ip: string | null; via: string }>(
      "SELECT s.label, s.status, st.last_ip, st.via FROM subdomains s JOIN studios st ON st.subdomain_id = s.id WHERE s.user_id = $1", [userId])).rows;
  });
  for (const s of subs) {
    const fqdn = fqdnOf(s.label, c.rootDomain);
    if (suspended) await c.dns.removeName(fqdn).catch(() => undefined);
    else if (s.status === "active" && target(c, s)) await c.dns.pointAt(fqdn, target(c, s)!).catch(() => undefined);
  }
}

/**
 * Admin: give a station to someone else. Its access code is replaced (the old owner knows
 * it) and every studio sign-in ends; the new code is returned, once, for the new owner.
 * The new owner's limit applies.
 */
export async function transfer(c: Ctx, actor: Actor, id: number, toEmail: string): Promise<{ label: string; to: string; accessCode: string }> {
  staffOnly(actor);
  const code = newAccessCode();
  const hash = await hashSecret(canonicalCode(code));
  return transaction(c.db, async (tx) => {
    const s = await load(tx, id, true);
    const to = (await tx.query<{ id: number; email: string; status: string }>("SELECT id, email, status FROM users WHERE lower(email) = lower($1) FOR UPDATE", [toEmail.trim()])).rows[0];
    if (!to) throw new SubdomainError(`There is no account for ${toEmail.trim() || "that email"}.`);
    if (to.id === s.user_id) throw new SubdomainError(`${to.email} has it already.`);
    if (to.status !== "active") throw new SubdomainError(`${to.email} is suspended.`);
    const n = Number((await tx.query("SELECT count(*) AS n FROM subdomains WHERE user_id = $1", [to.id])).rows[0].n);
    const a = await allowance(tx, to.id, c.limit);
    if (n >= a.limit) throw new SubdomainError(`${to.email} may have ${stationWord(a.limit)} and has ${n}. Raise their limit or change their plan first.`);
    const from = (await tx.query<{ email: string }>("SELECT email FROM users WHERE id = $1", [s.user_id])).rows[0]?.email;
    await tx.query("UPDATE subdomains SET user_id = $2, updated_at = now() WHERE id = $1", [id, to.id]);
    await tx.query("UPDATE studios SET access_code_hash = $2 WHERE id = $1", [s.studio_id, hash]);
    await tx.query("UPDATE studio_tokens SET revoked_at = now() WHERE studio_id = $1 AND revoked_at IS NULL", [s.studio_id]);
    await audit(tx, { actor: actor.id, action: "subdomain.transfer", target: s.label, ip: actor.ip, metadata: { from, to: to.email } });
    return { label: s.label, to: to.email, accessCode: code };
  });
}

/** Delete a person: each of their stations is deleted as an owner's delete would (DNS, certificates, cooldown), then the account. */
export async function removeUser(c: Ctx, actor: Actor, userId: number): Promise<string> {
  const ids = (await c.db.query<{ id: number }>("SELECT id FROM subdomains WHERE user_id = $1", [userId])).rows.map((r) => r.id);
  for (const id of ids) await remove(c, { ...actor, admin: true }, id);
  return transaction(c.db, async (tx) => {
    const u = await tx.query<{ email: string }>("DELETE FROM users WHERE id = $1 RETURNING email", [userId]);
    if (!u.rows[0]) throw new SubdomainError("No such person.");
    await audit(tx, { actor: actor.id, action: "user.delete", target: u.rows[0].email, ip: actor.ip, metadata: { stations: ids.length } });
    return u.rows[0].email;
  });
}

/** Admin: free a name now (a cooldown or a reservation ends). */
export async function forceRelease(db: Db, actor: Actor, label: string): Promise<void> {
  await db.query("DELETE FROM name_cooldowns WHERE label = $1", [label]);
  await audit(db, { actor: actor.id, action: "name.force_release", target: label, ip: actor.ip });
}
