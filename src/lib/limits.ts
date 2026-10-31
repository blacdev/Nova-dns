/**
 * Rate limits shared by every API and dashboard process: fixed windows counted in
 * Postgres (`rate_limits`), one row per key. `hit` counts this attempt and says
 * whether it is still within the limit.
 */

import type { Queryable } from "../db/db.js";

export interface Limit {
  max: number;
  seconds: number;
}

export const LIMITS = {
  register: { max: 10, seconds: 600 },          // per IP and per hostname (spec 3.1)
  probe: { max: 1, seconds: 10 },               // per studio (spec 3.4)
  nameCheck: { max: 60, seconds: 60 },          // per IP: no scraping names (spec 9)
  login: { max: 10, seconds: 600 },             // per IP and per email
  signup: { max: 5, seconds: 3600 },            // per IP
  mail: { max: 5, seconds: 3600 },              // per email: verification / reset links
  totp: { max: 10, seconds: 600 },              // per user
} satisfies Record<string, Limit>;

export async function hit(db: Queryable, key: string, limit: Limit): Promise<{ ok: boolean; retryAfter: number }> {
  const r = await db.query<{ count: number; window_start: Date }>(
    `INSERT INTO rate_limits (key, window_start, count) VALUES ($1, now(), 1)
     ON CONFLICT (key) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start < now() - make_interval(secs => $2) THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start < now() - make_interval(secs => $2) THEN now() ELSE rate_limits.window_start END
     RETURNING count, window_start`,
    [key, limit.seconds],
  );
  const row = r.rows[0];
  const left = Math.max(1, Math.ceil(limit.seconds - (Date.now() - row.window_start.getTime()) / 1000));
  return { ok: row.count <= limit.max, retryAfter: left };
}

/** Clear a key (a successful sign-in forgets the failures before it). */
export async function forget(db: Queryable, key: string): Promise<void> {
  await db.query("DELETE FROM rate_limits WHERE key = $1", [key]);
}
