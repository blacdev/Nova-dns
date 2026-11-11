/**
 * How many stations a person may have: their own override if an admin set one, else
 * their plan's limit, else the default plan's, else SUBDOMAIN_LIMIT from .env.
 */

import type { Queryable } from "../db/db.js";

export interface Allowance {
  limit: number;
  /** The plan's name ("" when none applies). */
  plan: string;
  /** Whether the limit is this person's own (an admin's override), not their plan's. */
  custom: boolean;
}

export async function allowance(q: Queryable, userId: number, fallback: number): Promise<Allowance> {
  const r = await q.query<{ override: number | null; own: number | null; own_name: string | null; def: number | null; def_name: string | null }>(
    `SELECT u.station_limit_override AS override, p.station_limit AS own, p.name AS own_name, dp.station_limit AS def, dp.name AS def_name
       FROM users u LEFT JOIN plans p ON p.id = u.plan_id LEFT JOIN plans dp ON dp.is_default
      WHERE u.id = $1`, [userId]);
  const row = r.rows[0];
  const plan = row?.own_name ?? row?.def_name ?? "";
  if (row?.override !== null && row?.override !== undefined) return { limit: row.override, plan, custom: true };
  return { limit: row?.own ?? row?.def ?? fallback, plan, custom: false };
}

export const stationWord = (n: number) => `${n} station${n === 1 ? "" : "s"}`;
