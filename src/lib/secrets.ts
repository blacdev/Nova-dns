/**
 * Codes, tokens and secrets.
 *
 * - Access codes: 24 random Crockford base32 characters, shown once as
 *   XXXX-XXXX-XXXX-XXXX-XXXX-XXXX; only an Argon2id hash is kept. Typing is forgiving
 *   (case, hyphens, spaces; O->0, I/L->1), as Crockford intends.
 * - Studio and session tokens: 256 random bits; only their SHA-256 is kept (they are
 *   random, so a fast hash is enough, and lookups stay indexed).
 * - Passwords: Argon2id. Compared through argon2.verify (constant time).
 * - TOTP secrets: AES-256-GCM with a key derived from SESSION_SECRET.
 * - TOTP itself: RFC 6238 (SHA-1, 6 digits, 30 s, one step either side).
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function newAccessCode(): string {
  const bytes = randomBytes(24);
  const chars = [...bytes].map((b) => CROCKFORD[b & 31]).join("");
  return chars.match(/.{4}/g)!.join("-");
}

/** The code as it is hashed: upper case, no separators, Crockford's look-alikes mapped. */
export function canonicalCode(input: string): string {
  return String(input ?? "")
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

const ARGON = { type: argon2.argon2id as 2, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const hashSecret = (plain: string) => argon2.hash(plain, ARGON);

export async function verifySecret(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

/** A hash to compare against when there is no real one, so a miss takes as long as a hit. */
let dummy: Promise<string> | null = null;
export const dummyHash = () => (dummy ??= hashSecret("no-such-account-placeholder"));

export const newToken = () => randomBytes(32).toString("base64url");
export const tokenHash = (token: string) => createHash("sha256").update(token).digest("hex");

export function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---------------------------------------------------------------- encryption at rest

const keyOf = (secret: string) => createHash("sha256").update(`nova-dns:totp:${secret}`).digest();

export function encrypt(secret: string, plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", keyOf(secret), iv);
  const body = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]).toString("base64");
}

export function decrypt(secret: string, enc: string): string {
  const raw = Buffer.from(enc, "base64");
  const d = createDecipheriv("aes-256-gcm", keyOf(secret), raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8");
}

// ---------------------------------------------------------------- TOTP (RFC 6238)

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newTotpSecret(): string {
  return [...randomBytes(20)].map((b) => B32[b & 31]).join("");
}

function base32Decode(s: string): Buffer {
  let bits = "";
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const v = B32.indexOf(ch);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

export function totpAt(secret: string, at = Date.now(), step = 30): string {
  const counter = Math.floor(at / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const off = mac[mac.length - 1] & 0xf;
  const n = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

export function verifyTotp(secret: string, code: string, at = Date.now()): boolean {
  const given = String(code ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(given)) return false;
  return [-1, 0, 1].some((d) => sameString(totpAt(secret, at + d * 30_000), given));
}

export const totpUri = (secret: string, account: string, issuer: string) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

// ---------------------------------------------------------------- TURN (coturn REST API scheme)

/** username = "<unix expiry>:<studio id>", credential = base64(HMAC-SHA1(secret, username)). */
export function turnCredential(secret: string, studioId: string, ttlSeconds: number, now = Date.now()) {
  const username = `${Math.floor(now / 1000) + ttlSeconds}:${studioId}`;
  const credential = createHmac("sha1", secret).update(username).digest("base64");
  return { username, credential };
}
