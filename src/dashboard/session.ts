/**
 * Dashboard sign-in: a random token in an HttpOnly cookie (only its SHA-256 is kept),
 * 12 hours idle. CSRF: signed-in forms carry the session's own token; forms before
 * sign-in use a double-submit cookie. Every POST must also come from this site (Origin).
 */

import type { FastifyReply, FastifyRequest } from "fastify";
import type { Db } from "../db/db.js";
import type { Role } from "../lib/rbac.js";
import { newToken, sameString, tokenHash } from "../lib/secrets.js";

export const COOKIE = "nova_sid";
export const PRE_COOKIE = "nova_csrf";
export const IDLE_HOURS = 12;

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
  tokenHash: string;
  csrf: string;
  needsTotp: boolean;
  pendingTotpEnc: string | null;
  user: SessionUser;
}

export async function loadSession(db: Db, token: string | undefined): Promise<Session | null> {
  if (!token) return null;
  const r = await db.query(
    `UPDATE sessions s SET expires_at = now() + make_interval(hours => $2)
       FROM users u WHERE s.token_hash = $1 AND u.id = s.user_id AND s.expires_at > now() AND u.status = 'active'
     RETURNING s.token_hash, s.csrf, s.needs_totp, s.pending_totp_enc, u.id, u.email, u.role, u.permissions, u.email_verified_at, u.totp_secret_enc`,
    [tokenHash(token), IDLE_HOURS]);
  const row = r.rows[0];
  if (!row) return null;
  return {
    tokenHash: row.token_hash, csrf: row.csrf, needsTotp: row.needs_totp, pendingTotpEnc: row.pending_totp_enc,
    user: { id: row.id, email: row.email, role: row.role, permissions: row.permissions ?? [], verified: !!row.email_verified_at, totp: !!row.totp_secret_enc },
  };
}

export async function startSession(db: Db, reply: FastifyReply, userId: number, needsTotp: boolean, ip: string, secure: boolean) {
  const token = newToken();
  await db.query("INSERT INTO sessions (token_hash, user_id, csrf, needs_totp, expires_at, ip) VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5), $6)",
    [tokenHash(token), userId, newToken(), needsTotp, IDLE_HOURS, ip]);
  reply.setCookie(COOKIE, token, { path: "/", httpOnly: true, sameSite: "lax", secure, maxAge: IDLE_HOURS * 3600 });
}

export async function endSession(db: Db, reply: FastifyReply, s: Session | null) {
  if (s) await db.query("DELETE FROM sessions WHERE token_hash = $1", [s.tokenHash]);
  reply.clearCookie(COOKIE, { path: "/" });
}

/** The token a form before sign-in carries (set in a cookie the first time). */
export function preToken(req: FastifyRequest, reply: FastifyReply, secure: boolean): string {
  const have = req.cookies[PRE_COOKIE];
  if (have && /^[\w-]{43}$/.test(have)) return have;
  const t = newToken();
  reply.setCookie(PRE_COOKIE, t, { path: "/", httpOnly: true, sameSite: "strict", secure });
  return t;
}

/** Whether a POST's form token is right, and it came from this site. */
export function csrfOk(req: FastifyRequest, session: Session | null, host: string): boolean {
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
  const pre = req.cookies[PRE_COOKIE];
  return !!pre && sameString(given, pre);
}
