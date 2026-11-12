/**
 * Certificates from the studios' own CSRs (spec section 5). One platform ACME account;
 * DNS-01 through the DNS manager; never a wildcard (the CSR may name only the station).
 *
 * - **Queue**: `certificates` rows in `pending`, oldest first, taken with SKIP LOCKED so
 *   several workers never take the same one.
 * - **Weekly limit**: Let's Encrypt allows 50 new certificates per registered domain per
 *   7 days. New ones wait (they are not failed) once the count reaches the limit less a
 *   margin, and the admin page shows it. Renewals carry ACME's `replaces` (ARI), which
 *   Let's Encrypt exempts from that limit.
 * - **Renewal**: the stored CSR is used again (the studio's key never changes hands), at
 *   the start of the CA's suggested window (ARI), else with 30 days left.
 * - Issued names appear in public Certificate Transparency logs.
 */

import https from "node:https";
import { X509Certificate } from "node:crypto";
import { Resolver } from "node:dns/promises";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import type { Db } from "../db/db.js";
import type { DnsManager, PlatformLabel } from "../dns/dns.js";
import { opsEvent } from "../lib/audit.js";
import { decrypt, encrypt } from "../lib/secrets.js";
import type { Config } from "../config.js";

export const RENEW_DAYS = 30;
const LIMIT_MARGIN = 2;
const MAX_ATTEMPTS = 3;

export interface IssuerDeps {
  db: Db;
  dns: DnsManager;
  config: Config;
  /** Waits for the challenge TXT to be visible (replaced in tests). */
  waitForTxt?: (name: string, value: string) => Promise<void>;
}

let caConfigured = false;
function trustCa(bundle: string) {
  if (caConfigured || !bundle) return;
  acme.axios.defaults.httpsAgent = new https.Agent({ ca: bundle });
  caConfigured = true;
}

export class Issuer {
  private client: acme.Client | null = null;
  /** The directory `client` is for: switching staging/production in the settings makes a new one. */
  private clientUrl = "";
  private renewalInfoUrl: string | null | undefined;

  constructor(private d: IssuerDeps) {
    trustCa(d.config.acmeCaBundle);
  }

  /** The platform's ACME account, made once and kept (encrypted). */
  async account(): Promise<acme.Client> {
    const url = this.d.config.acmeDirectoryUrl;
    if (this.client && this.clientUrl === url) return this.client;
    this.renewalInfoUrl = undefined;
    const row = (await this.d.db.query<{ key_enc: string; account_url: string | null }>("SELECT key_enc, account_url FROM acme_account WHERE directory_url = $1", [url])).rows[0];
    let key: Buffer;
    if (row) key = Buffer.from(decrypt(this.d.config.sessionSecret, row.key_enc));
    else {
      key = await acme.crypto.createPrivateEcdsaKey("P-256");
      await this.d.db.query("INSERT INTO acme_account (directory_url, key_enc) VALUES ($1, $2) ON CONFLICT DO NOTHING", [url, encrypt(this.d.config.sessionSecret, key.toString())]);
    }
    const client = new acme.Client({ directoryUrl: url, accountKey: key, accountUrl: row?.account_url ?? undefined });
    if (!row?.account_url) {
      await client.createAccount({ termsOfServiceAgreed: true, contact: [`mailto:${this.d.config.acmeEmail}`] });
      await this.d.db.query("UPDATE acme_account SET account_url = $2 WHERE directory_url = $1", [url, client.getAccountUrl()]);
    }
    this.client = client;
    this.clientUrl = url;
    return client;
  }

  /** New (non-renewal) certificates issued in the last 7 days. */
  async issuedThisWeek(): Promise<number> {
    return Number((await this.d.db.query("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")).rows[0].n);
  }

  /** Take one pending certificate and see it through. False when there was none ready. */
  async runOne(): Promise<boolean> {
    const job = await this.take();
    if (!job) return false;
    try {
      if (!job.renews_id && (await this.issuedThisWeek()) >= this.d.config.certWeeklyLimit - LIMIT_MARGIN) {
        // Near the CA's weekly limit: wait for the oldest of the week to drop out.
        const oldest = (await this.d.db.query<{ t: Date }>("SELECT min(issued_at) AS t FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")).rows[0].t;
        const after = new Date((oldest?.getTime() ?? Date.now()) + 7 * 86400_000 + 60_000);
        await this.d.db.query("UPDATE certificates SET next_attempt_at = $2, error = 'queued: weekly certificate limit' WHERE id = $1", [job.id, after]);
        await opsEvent(this.d.db, "acme", `weekly limit near: ${job.fqdn} waits until ${after.toISOString()}`, job.fqdn, "info");
        return true;
      }
      await this.issue(job);
    } catch (e) {
      const message = (e as Error).message ?? String(e);
      const attempts = job.attempts + 1;
      const failed = attempts >= MAX_ATTEMPTS;
      await this.d.db.query(
        "UPDATE certificates SET attempts = $2, status = $3, error = $4, next_attempt_at = now() + make_interval(mins => $5) WHERE id = $1",
        [job.id, attempts, failed ? "failed" : "pending", message.slice(0, 1000), 5 * 2 ** attempts]);
      await opsEvent(this.d.db, "acme", `${failed ? "failed" : "will retry"}: ${message}`, job.fqdn);
    }
    return true;
  }

  private async take() {
    const r = await this.d.db.query<{ id: number; subdomain_id: number; fqdn: string; csr_pem: string; attempts: number; renews_id: number | null }>(
      `UPDATE certificates SET next_attempt_at = now() + interval '10 minutes'
        WHERE id = (SELECT id FROM certificates WHERE status = 'pending' AND next_attempt_at <= now()
                     ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id, subdomain_id, fqdn, csr_pem, attempts, renews_id`);
    return r.rows[0] ?? null;
  }

  /** One ACME order by DNS-01 for `fqdn` from `csr`; the full chain PEM. */
  private async order(fqdn: string, csr: string, challenge: { set: (v: string) => Promise<void>; clear: (v: string) => Promise<void> }, replaces?: string): Promise<string> {
    const client = await this.account();
    const orderData: Record<string, unknown> = { identifiers: [{ type: "dns", value: fqdn }] };
    if (replaces) orderData.replaces = replaces;
    const order = await client.createOrder(orderData as unknown as Parameters<acme.Client["createOrder"]>[0]);
    const auths = await client.getAuthorizations(order);
    const set: string[] = [];
    try {
      for (const auth of auths) {
        if (auth.status === "valid") continue;
        const ch = auth.challenges.find((c) => c.type === "dns-01");
        if (!ch) throw new Error("the CA offered no DNS-01 challenge");
        const value = await client.getChallengeKeyAuthorization(ch);
        await challenge.set(value);
        set.push(value);
        await (this.d.waitForTxt ?? ((n, v) => waitForTxt(n, v, this.d.config.dnsCheckResolver)))(`_acme-challenge.${fqdn}`, value);
        await client.completeChallenge(ch);
        await client.waitForValidStatus(ch);
      }
      return await client.getCertificate(await client.finalizeOrder(order, csr));
    } finally {
      for (const v of set) await challenge.clear(v);
    }
  }

  private async issue(job: { id: number; subdomain_id: number; fqdn: string; csr_pem: string; renews_id: number | null }) {
    let replaces: string | undefined;
    if (job.renews_id) {
      const before = (await this.d.db.query<{ cert_pem: string }>("SELECT cert_pem FROM certificates WHERE id = $1", [job.renews_id])).rows[0];
      if (before?.cert_pem && (await this.renewalInfoBase())) replaces = certId(before.cert_pem);
    }
    {
      const pem = await this.order(job.fqdn, job.csr_pem, {
        set: (v) => this.d.dns.setChallenge(job.fqdn, v), clear: (v) => this.d.dns.clearChallenge(job.fqdn, v),
      }, replaces);
      const [leaf, ...chain] = splitPem(pem);
      const cert = new X509Certificate(leaf);
      const renewAfter = await this.renewalWindow(leaf).catch(() => null);
      await this.d.db.query(
        `UPDATE certificates SET status = 'issued', cert_pem = $2, chain_pem = $3, serial = $4, issued_at = now(),
                expires_at = $5, ari_renewal_after = $6, error = NULL WHERE id = $1`,
        [job.id, leaf, chain.join(""), cert.serialNumber.toLowerCase(), new Date(cert.validTo), renewAfter]);
      await this.d.db.query("UPDATE certificates SET status = 'superseded' WHERE subdomain_id = $1 AND status = 'issued' AND id <> $2", [job.subdomain_id, job.id]);
      await opsEvent(this.d.db, "acme", `issued, until ${cert.validTo}`, job.fqdn, "info");
    }
  }

  // ---------------------------------------------------------------- the platform's own (turn.<root>)

  /** Keep a certificate for turn.<root> (coturn's TLS), renewed with 30 days left. */
  async ensurePlatformCert(label: PlatformLabel = "turn"): Promise<boolean> {
    const fqdn = `${label}.${this.d.config.rootDomain}`;
    const row = (await this.d.db.query<{ key_enc: string; expires_at: Date | null }>("SELECT key_enc, expires_at FROM platform_certs WHERE name = $1", [label])).rows[0];
    if (row?.expires_at && row.expires_at.getTime() - Date.now() > RENEW_DAYS * 86400_000) return false;
    let key: string;
    if (row) key = decrypt(this.d.config.sessionSecret, row.key_enc);
    else {
      key = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
      await this.d.db.query("INSERT INTO platform_certs (name, key_enc) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING", [label, encrypt(this.d.config.sessionSecret, key)]);
    }
    const [, csr] = await acme.crypto.createCsr({ commonName: fqdn, altNames: [fqdn] }, key);
    try {
      const pem = await this.order(fqdn, csr.toString(), {
        set: (v) => this.d.dns.setPlatformChallenge(label, v), clear: (v) => this.d.dns.clearPlatformChallenge(label, v),
      });
      const leaf = splitPem(pem)[0];
      await this.d.db.query("UPDATE platform_certs SET cert_pem = $2, expires_at = $3, error = NULL, updated_at = now() WHERE name = $1",
        [label, pem, new Date(new X509Certificate(leaf).validTo)]);
      await opsEvent(this.d.db, "acme", "issued (platform)", fqdn, "info");
      return true;
    } catch (e) {
      await this.d.db.query("UPDATE platform_certs SET error = $2, updated_at = now() WHERE name = $1", [label, (e as Error).message.slice(0, 500)]);
      await opsEvent(this.d.db, "acme", `platform certificate failed: ${(e as Error).message}`, fqdn);
      throw e;
    }
  }

  // ---------------------------------------------------------------- ARI (RFC 9773)

  private async renewalInfoBase(): Promise<string | null> {
    if (this.renewalInfoUrl !== undefined) return this.renewalInfoUrl;
    try {
      const dir = (await acme.axios.get(this.d.config.acmeDirectoryUrl)).data as { renewalInfo?: string };
      this.renewalInfoUrl = dir.renewalInfo ?? null;
    } catch {
      this.renewalInfoUrl = null;
    }
    return this.renewalInfoUrl;
  }

  /** When the CA suggests renewing (the start of its window), or null without ARI. */
  async renewalWindow(certPem: string): Promise<Date | null> {
    const base = await this.renewalInfoBase();
    if (!base) return null;
    const res = await acme.axios.get(`${base.replace(/\/$/, "")}/${certId(certPem)}`);
    const start = (res.data as { suggestedWindow?: { start?: string } }).suggestedWindow?.start;
    return start ? new Date(start) : null;
  }

  /** Queue renewals: at the ARI window, else 30 days before expiry, with the stored CSR. */
  async queueRenewals(): Promise<number> {
    const due = await this.d.db.query<{ id: number; subdomain_id: number; fqdn: string; csr_pem: string }>(
      `SELECT c.id, c.subdomain_id, c.fqdn, c.csr_pem FROM certificates c JOIN subdomains s ON s.id = c.subdomain_id
        WHERE c.status = 'issued' AND s.status = 'active' AND c.fqdn = s.label || '.' || $1
          AND (c.ari_renewal_after <= now() OR c.expires_at < now() + make_interval(days => $2))
          AND NOT EXISTS (SELECT 1 FROM certificates p WHERE p.subdomain_id = c.subdomain_id AND p.status = 'pending')`,
      [this.d.config.rootDomain, RENEW_DAYS]);
    for (const c of due.rows) {
      await this.d.db.query("INSERT INTO certificates (subdomain_id, fqdn, status, csr_pem, renews_id) VALUES ($1, $2, 'pending', $3, $4)",
        [c.subdomain_id, c.fqdn, c.csr_pem, c.id]);
    }
    return due.rowCount ?? 0;
  }

  /** Ask the CA again when to renew (its window can move, e.g. after an incident). */
  async refreshRenewalInfo(): Promise<void> {
    if (!(await this.renewalInfoBase())) return;
    const rows = await this.d.db.query<{ id: number; cert_pem: string }>("SELECT id, cert_pem FROM certificates WHERE status = 'issued' AND cert_pem IS NOT NULL");
    for (const r of rows.rows) {
      const at = await this.renewalWindow(r.cert_pem).catch(() => null);
      if (at) await this.d.db.query("UPDATE certificates SET ari_renewal_after = $2 WHERE id = $1", [r.id, at]);
    }
  }

  /** Revoke a deleted station's certificates. */
  async revokeQueued(): Promise<number> {
    const rows = await this.d.db.query<{ id: number; fqdn: string; cert_pem: string }>("SELECT id, fqdn, cert_pem FROM revoke_queue WHERE done_at IS NULL AND error IS NULL LIMIT 20");
    if (!rows.rowCount) return 0;
    const client = await this.account();
    for (const r of rows.rows) {
      try {
        await client.revokeCertificate(r.cert_pem, { reason: 4 }); // superseded
        await this.d.db.query("UPDATE revoke_queue SET done_at = now() WHERE id = $1", [r.id]);
      } catch (e) {
        await this.d.db.query("UPDATE revoke_queue SET error = $2 WHERE id = $1", [r.id, (e as Error).message.slice(0, 500)]);
        await opsEvent(this.d.db, "acme", `revocation failed: ${(e as Error).message}`, r.fqdn);
      }
    }
    return rows.rowCount ?? 0;
  }
}

export function splitPem(pem: string): string[] {
  return (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\s*/g) ?? []).map((p) => p.trim() + "\n");
}

/** ARI's certificate identifier: base64url(authority key id) "." base64url(serial). */
export function certId(certPem: string): string {
  const cert = new x509.X509Certificate(certPem);
  const aki = cert.getExtension(x509.AuthorityKeyIdentifierExtension);
  if (!aki?.keyId) throw new Error("the certificate has no authority key identifier");
  const b64u = (buf: Buffer) => buf.toString("base64url");
  let serial = Buffer.from(cert.serialNumber.length % 2 ? `0${cert.serialNumber}` : cert.serialNumber, "hex");
  if (serial[0] & 0x80) serial = Buffer.concat([Buffer.from([0]), serial]); // DER INTEGER stays positive
  return `${b64u(Buffer.from(aki.keyId, "hex"))}.${b64u(serial)}`;
}

/** Wait (up to 3 minutes) until a resolver sees the challenge TXT record. */
export async function waitForTxt(name: string, value: string, server = "", timeoutMs = 180_000): Promise<void> {
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  if (server) resolver.setServers([server]);
  else resolver.setServers(["1.1.1.1", "8.8.8.8"]);
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const found = await resolver.resolveTxt(name).catch(() => [] as string[][]);
    if (found.some((parts) => parts.join("") === value)) return;
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error(`the challenge record ${name} did not appear in time`);
}
