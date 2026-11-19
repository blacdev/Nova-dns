/**
 * Platform settings an admin can change in the dashboard (Admin > Settings) instead of in
 * .env. A value saved there wins; without one, .env's is used. Secret values (API token,
 * the SMTP password) are encrypted with SESSION_SECRET's key and never shown
 * again, only their last characters.
 *
 * The api, dashboard and worker are separate processes: a save sends a NOTIFY and each
 * process reloads (with a poll every minute in case a notification is missed), so a new
 * token takes effect without a restart.
 *
 * Not here, on purpose: DATABASE_URL (needed to reach the settings), SESSION_SECRET (the
 * key that encrypts them), ROOT_DOMAIN, ports and proxies (Caddy and Docker depend on
 * them), and TURN's shared secrets (coturn's host must change with them).
 */

import pg from "pg";
import type { Config } from "../config.js";
import type { Db, Queryable } from "../db/db.js";
import type { DnsManager } from "../dns/dns.js";
import { providerFor } from "../dns/providers.js";
import { smtpOf } from "../config.js";
import { isSmtpSecurity, makeMailer, parseSmtpUrl, type SwitchableMailer } from "./mail.js";
import { decrypt, encrypt } from "./secrets.js";

export const LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
export const LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

type Key = "dnsProvider" | "cloudflareApiToken" | "cloudflareZoneId" | "smtpHost" | "smtpPort" | "smtpSecurity" | "smtpUser" | "smtpPassword" | "mailFrom"
  | "acmeEmail" | "acmeDirectoryUrl" | "certWeeklyLimit";

/** The single SMTP address saved by earlier versions; read (split into the parts) until the email settings are saved again. */
export const LEGACY_SMTP_URL = "smtpUrl";

interface Spec {
  env: string;
  secret: boolean;
  /** The value as stored, or an error message. */
  check: (v: string) => string | { error: string };
}

const nonEmpty = (what: string) => (v: string) => (v.trim() ? v.trim() : { error: `${what} cannot be empty.` });

export const SETTINGS: Record<Key, Spec> = {
  dnsProvider: { env: "DNS_PROVIDER", secret: false, check: (v) => (v === "cloudflare" || v === "memory" ? v : { error: "Choose Cloudflare or none." }) },
  cloudflareApiToken: { env: "CLOUDFLARE_API_TOKEN", secret: true, check: (v) => (/^[\w-]{20,}$/.test(v.trim()) ? v.trim() : { error: "That does not look like a Cloudflare API token." }) },
  cloudflareZoneId: { env: "CLOUDFLARE_ZONE_ID", secret: false, check: (v) => (/^[0-9a-f]{32}$/.test(v.trim()) ? v.trim() : { error: "A Zone ID is 32 letters and digits (0-9, a-f)." }) },
  smtpHost: {
    env: "SMTP_HOST", secret: false,
    check: (v) => (/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(v.trim()) ? v.trim().toLowerCase() : { error: "The host is a server name like smtp.example.com (no smtp:// in front, no port)." }),
  },
  smtpPort: { env: "SMTP_PORT", secret: false, check: (v) => (/^\d{1,5}$/.test(v.trim()) && Number(v) >= 1 && Number(v) <= 65535 ? String(Number(v)) : { error: "The port is a number from 1 to 65535 (usually 465 or 587)." }) },
  smtpSecurity: { env: "SMTP_SECURITY", secret: false, check: (v) => (isSmtpSecurity(v) ? v : { error: "Choose SSL/TLS, STARTTLS or None." }) },
  smtpUser: { env: "SMTP_USER", secret: false, check: (v) => (v.trim().length <= 254 ? v.trim() : { error: "The username is too long." }) },
  smtpPassword: { env: "SMTP_PASSWORD", secret: true, check: (v) => (v.length <= 500 ? v : { error: "The password is too long." }) },
  mailFrom: { env: "MAIL_FROM", secret: false, check: nonEmpty("The sender") },
  acmeEmail: { env: "ACME_EMAIL", secret: false, check: (v) => (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.trim()) ? v.trim() : { error: "That is not an email address." }) },
  acmeDirectoryUrl: { env: "ACME_DIRECTORY_URL", secret: false, check: (v) => (v === LE_PRODUCTION || v === LE_STAGING ? v : { error: "Choose staging or production." }) },
  certWeeklyLimit: { env: "CERT_WEEKLY_LIMIT", secret: false, check: (v) => (/^\d{1,5}$/.test(v.trim()) && Number(v) > 0 ? v.trim() : { error: "The weekly limit is a whole number above 0." }) },
};

export type SettingKey = Key;
export const isSettingKey = (k: string): k is Key => k in SETTINGS;

/** What a secret looks like on the page: enough to recognise it, never enough to use it. */
export function masked(key: Key, value: string): string {
  if (!value) return "";
  return value.length > 8 ? `••••${value.slice(-4)}` : "••••";
}

export interface Stored {
  key: Key;
  value: string;
  secret: boolean;
  updated_at: Date;
  updated_by: string | null;
}

/** The settings saved in the dashboard, decrypted. A value that no longer decrypts (SESSION_SECRET changed) is left out. */
export async function readSettings(q: Queryable, sessionSecret: string): Promise<Stored[]> {
  const rows = (await q.query<{ key: string; value: string; secret: boolean; updated_at: Date; updated_by: string | null }>(
    "SELECT s.key, s.value, s.secret, s.updated_at, u.email AS updated_by FROM settings s LEFT JOIN users u ON u.id = s.updated_by")).rows;
  const out: Stored[] = [];
  for (const r of rows) {
    if (!isSettingKey(r.key) && r.key !== LEGACY_SMTP_URL) continue;
    try {
      out.push({ ...r, key: r.key as Key, value: r.secret ? decrypt(sessionSecret, r.value) : r.value });
    } catch {
      // Encrypted with an earlier SESSION_SECRET: .env's value applies until it is saved again.
    }
  }
  return out;
}

export async function saveSetting(q: Queryable, sessionSecret: string, actor: number, key: Key, value: string) {
  const secret = SETTINGS[key].secret;
  await q.query(
    `INSERT INTO settings (key, value, secret, updated_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = EXCLUDED.secret, updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [key, secret ? encrypt(sessionSecret, value) : value, secret, actor]);
}

export async function clearSetting(q: Queryable, key: Key) {
  await q.query("DELETE FROM settings WHERE key = $1", [key]);
}

/** Tell every process to reload. */
export async function announce(q: Queryable) {
  await q.query("SELECT pg_notify('nova_settings', '')");
}

function toConfig(stored: Stored[], base: Config): Partial<Config> {
  const o: Partial<Config> = {};
  // An address saved by an earlier version first; the separate settings win over it.
  const legacy = stored.find((s) => (s.key as string) === LEGACY_SMTP_URL);
  const parsed = legacy ? parseSmtpUrl(legacy.value) : null;
  if (parsed) Object.assign(o, { smtpHost: parsed.host, smtpPort: parsed.port, smtpSecurity: parsed.security, smtpUser: parsed.user, smtpPassword: parsed.password });
  for (const s of stored) {
    if ((s.key as string) === LEGACY_SMTP_URL) continue;
    if (s.key === "certWeeklyLimit") o.certWeeklyLimit = Number(s.value);
    else if (s.key === "smtpPort") o.smtpPort = Number(s.value);
    else if (s.key === "smtpSecurity") o.smtpSecurity = s.value as Config["smtpSecurity"];
    else if (s.key === "dnsProvider") {
      // The end-to-end test provider is chosen in .env only, and stays.
      if (base.dnsProvider !== "challtestsrv") o.dnsProvider = s.value as Config["dnsProvider"];
    } else if (s.key === "acmeDirectoryUrl") {
      // A custom directory in .env (Pebble in tests) is not overridden by the staging/production choice.
      if (!base.acmeDirectoryUrl || base.acmeDirectoryUrl === LE_PRODUCTION || base.acmeDirectoryUrl === LE_STAGING) o.acmeDirectoryUrl = s.value;
    } else (o as Record<string, unknown>)[s.key] = s.value;
  }
  return o;
}

/**
 * The process's one Config object, kept up to date: .env's values with the saved settings
 * on top. Everything holds the same object, so a reload is seen everywhere; the DNS
 * provider and the mail transport are rebuilt when their settings change.
 */
export class LiveConfig {
  readonly base: Config;
  private dnsKey: string;
  private mailKey: string;

  constructor(readonly config: Config, private db: Db, private parts: { dns?: DnsManager; mail?: SwitchableMailer } = {}) {
    this.base = { ...config };
    this.dnsKey = this.keyOf("dns");
    this.mailKey = this.keyOf("mail");
  }

  private keyOf(part: "dns" | "mail") {
    const c = this.config;
    return part === "dns" ? [c.dnsProvider, c.cloudflareApiToken, c.cloudflareZoneId].join("\n") : [c.smtpHost, c.smtpPort, c.smtpSecurity, c.smtpUser, c.smtpPassword, c.mailFrom].join("\n");
  }

  /** Where each value comes from now: a saved setting, or .env. */
  async stored(): Promise<Stored[]> {
    return readSettings(this.db, this.base.sessionSecret);
  }

  async reload(): Promise<void> {
    const over = toConfig(await this.stored(), this.base);
    Object.assign(this.config, this.base, over);
    const dnsKey = this.keyOf("dns");
    if (dnsKey !== this.dnsKey) {
      this.dnsKey = dnsKey;
      this.parts.dns?.setProvider(providerFor(this.config));
    }
    const mailKey = this.keyOf("mail");
    if (mailKey !== this.mailKey) {
      this.mailKey = mailKey;
      this.parts.mail?.set(makeMailer(smtpOf(this.config), this.config.mailFrom));
    }
  }
}

/** Reload on every NOTIFY, and once a minute anyway. Returns a stop function. */
export function watchSettings(databaseUrl: string, live: LiveConfig, pollMs = 60_000): () => Promise<void> {
  let client: pg.Client | null = null;
  let stopped = false;
  let retry: NodeJS.Timeout | null = null;
  const reload = () => live.reload().catch((e) => console.error("settings reload failed:", (e as Error).message));
  const listen = async () => {
    if (stopped) return;
    const c = new pg.Client({ connectionString: databaseUrl });
    c.on("notification", () => void reload());
    c.on("error", () => {
      client = null;
      void c.end().catch(() => undefined);
      if (!stopped) retry = setTimeout(() => void listen(), 5_000);
    });
    try {
      await c.connect();
      await c.query("LISTEN nova_settings");
      client = c;
      void reload(); // anything saved while not listening
    } catch {
      void c.end().catch(() => undefined);
      if (!stopped) retry = setTimeout(() => void listen(), 5_000);
    }
  };
  void listen();
  const poll = setInterval(() => void reload(), pollMs);
  poll.unref();
  return async () => {
    stopped = true;
    clearInterval(poll);
    if (retry) clearTimeout(retry);
    await client?.end().catch(() => undefined);
  };
}
