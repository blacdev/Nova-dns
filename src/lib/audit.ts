/**
 * The audit log (every create / rename / delete / regenerate / suspend, with who, from
 * where and when) and the operations log (DNS, ACME and probe problems, shown to
 * admins and sent in the daily alert). Nothing secret is ever written to either.
 */

import type { Queryable } from "../db/db.js";

export async function audit(db: Queryable, entry: { actor: number | null; action: string; target?: string; ip?: string | null; metadata?: Record<string, unknown> }) {
  await db.query("INSERT INTO audit_log (actor_user_id, action, target, ip, metadata) VALUES ($1, $2, $3, $4, $5)", [
    entry.actor, entry.action, entry.target ?? null, entry.ip ?? null, JSON.stringify(entry.metadata ?? {}),
  ]);
}

export type OpsKind = "dns" | "acme" | "probe" | "mail" | "job";

export async function opsEvent(db: Queryable, kind: OpsKind, message: string, target?: string, level: "info" | "error" = "error") {
  await db.query("INSERT INTO ops_events (kind, level, target, message) VALUES ($1, $2, $3, $4)", [kind, level, target ?? null, message.slice(0, 2000)]);
  if (level === "error") console.error(`[${kind}] ${target ?? ""} ${message}`);
}
