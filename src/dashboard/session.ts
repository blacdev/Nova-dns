/**
 * Dashboard sign-in: a random token in an HttpOnly, SameSite cookie (only its SHA-256 is
 * kept; `__Host-` prefixed over HTTPS, so no subdomain can set or read it).
 *
 * - Idle timeout: 12 hours for station owners, 2 hours for admins.
 * - Absolute lifetime: 7 days, however active; then sign in again.
 * - Sudo mode: sensitive changes (settings, payment keys, roles, deleting people) need the
 *   password, and the two-step code, confirmed again within the last 10 minutes.
 *
 * CSRF: signed-in forms carry the session's own token; forms before sign-in use a
 * double-submit cookie. Every POST must also come from this site (Origin).
 */

import type { FastifyReply, FastifyRequest } from "fastify";
import type { Db } from "../db/db.js";
import type { Role } from "../lib/rbac.js";
import { newToken, sameString, tokenHash } from "../lib/secrets.js";

export const IDLE_HOURS = 12;
export const STAFF_IDLE_HOURS = 2;
export const MAX_DAYS = 7;
export const SUDO_MINUTES = 10;

/** Cookie names: `__Host-` over HTTPS (Secure, path /, no Domain), plain over HTTP (development). */
export const cookieNames = (secure: boolean) => (secure ? { sid: "__Host-nova_sid", pre: "__Host-nova_csrf" } : { sid: "nova_sid", pre: "nova_csrf" });

export interface SessionUser {
  id: number;
  email: string;
  role: Role;
  /** What this admin may do (see rbac.ts); empty for everyone else. */
  permissions: string[];
  verified: boolean;
  totp: boolean;
}

export interface Session {
  id: number;
  tokenHash: string;
  csrf: string;
  needsTotp: boolean;
  pendingTotpEnc: string | null;
  /** Identity confirmed again recently (sudo mode). */
  elevated: boolean;
  elevatedUntil: Date | null;
  user: SessionUser;
}

export async function loadSession(db: Db, token: string | undefined): Promise<Session | null> {
  if (!token || token.length > 100) return null;
  const r = await db.query(
    `UPDATE sessions s SET last_seen_at = now(),
            expires_at = least(now() + make_interval(hours => CASE WHEN u.role = 'user' THEN $2::int ELSE $3::int END), s.created_at + make_interval(days => $4::int))
       FROM users u WHERE s.token_hash = $1 AND u.id = s.user_id AND s.expires_at > now() AND u.status = 'active'
     RETURNING s.id, s.token_hash, s.csrf, s.needs_totp, s.pending_totp_enc, s.elevated_until, s.elevated_until > now() AS elevated,
               u.id AS user_id, u.email, u.role, u.permissions, u.email_verified_at, u.totp_secret_enc IS NOT NULL AS totp`,
    [tokenHash(token), IDLE_HOURS, STAFF_IDLE_HOURS, MAX_DAYS]);
  const row = r.rows[0];
  if (!row) return null;
  return {
    id: row.id, tokenHash: row.token_hash, csrf: row.csrf, needsTotp: row.needs_totp, pendingTotpEnc: row.pending_totp_enc,
    elevated: !!row.elevated, elevatedUntil: row.elevated_until,
    user: { id: row.user_id, email: row.email, role: row.role, permissions: row.permissions ?? [], verified: !!row.email_verified_at, totp: !!row.totp },
  };
}

export async function startSession(db: Db, reply: FastifyReply, userId: number, needsTotp: boolean, ip: string, secure: boolean, userAgent = "") {
  const token = newToken();
  // Signing in with the password (and code) counts as a fresh confirmation.
  await db.query(
    `INSERT INTO sessions (token_hash, user_id, csrf, needs_totp, expires_at, ip, user_agent, elevated_until)
     VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5), $6, $7, CASE WHEN $4 THEN NULL ELSE now() + make_interval(mins => $8) END)`,
    [tokenHash(token), userId, newToken(), needsTotp, IDLE_HOURS, ip, userAgent.slice(0, 300), SUDO_MINUTES]);
  reply.setCookie(cookieNames(secure).sid, token, { path: "/", httpOnly: true, sameSite: "lax", secure, maxAge: MAX_DAYS * 86400 });
}

export async function endSession(db: Db, reply: FastifyReply, s: Session | null, secure = false) {
  if (s) await db.query("DELETE FROM sessions WHERE token_hash = $1", [s.tokenHash]);
  reply.clearCookie(cookieNames(secure).sid, { path: "/", secure });
}

/** Sudo mode on for this session, for SUDO_MINUTES. */
export async function elevate(db: Db, s: Session) {
  await db.query("UPDATE sessions SET elevated_until = now() + make_interval(mins => $2) WHERE token_hash = $1", [s.tokenHash, SUDO_MINUTES]);
}

/** The token a form before sign-in carries (set in a cookie the first time). */
export function preToken(req: FastifyRequest, reply: FastifyReply, secure: boolean): string {
  const name = cookieNames(secure).pre;
  const have = req.cookies[name];
  if (have && /^[\w-]{43}$/.test(have)) return have;
  const t = newToken();
  reply.setCookie(name, t, { path: "/", httpOnly: true, sameSite: "strict", secure });
  return t;
}

/** Whether a POST's form token is right, and it came from this site. */
export function csrfOk(req: FastifyRequest, session: Session | null, host: string, secure = false): boolean {
  const origin = req.headers.origin ?? req.headers.referer;
  if (origin) {
    try {
      if (new URL(origin).host !== host) return false;
    } catch {
      return false;
    }
  }
  const given = String((req.body as Record<string, unknown> | undefined)?._csrf ?? "");
  if (!given) return false;
  if (session) return sameString(given, session.csrf);
  const pre = req.cookies[cookieNames(secure).pre];
  return !!pre && sameString(given, pre);
}
