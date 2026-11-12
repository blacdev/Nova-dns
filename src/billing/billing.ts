/**
 * Billing: an on/off switch, the one provider that takes payments, each provider's keys
 * (encrypted), and payments for plans.
 *
 * A plan bought here lasts one period (a month or a year) from the payment, or from the
 * end of the time already paid for when the same plan is renewed early. When it runs out
 * the person is back on the default plan (their stations stay; they cannot add more
 * beyond the default plan's limit). An admin can still assign any plan by hand, with no end.
 *
 * Money is only ever counted as paid after the provider's own API says so, for the exact
 * amount and currency asked: the return from checkout and every webhook (whose signature
 * is checked first) only trigger that check. Each payment is fulfilled once, under a row
 * lock, however many times it is confirmed.
 */

import { randomBytes } from "node:crypto";
import type { Db, Queryable } from "../db/db.js";
import { transaction } from "../db/db.js";
import { audit, opsEvent } from "../lib/audit.js";
import type { Mailer } from "../lib/mail.js";
import { decrypt, encrypt } from "../lib/secrets.js";
import { checkKey, formatMoney, gateway, isLive, isProvider, PROVIDER_INFO, PROVIDERS, type Gateway, type ProviderId } from "./gateways.js";

export interface BillingDeps {
  db: Db;
  config: { sessionSecret: string; dashboardUrl: string; rootDomain: string };
  mail?: Mailer;
  /** Tests replace the network. */
  fetch?: typeof fetch;
}

export class BillingError extends Error {}

export interface ProviderState {
  id: ProviderId;
  configured: boolean;
  live: boolean;
  keyHint: string;
  webhookHint: string;
  needsWebhookSecret: boolean;
  updatedAt: Date | null;
  updatedBy: string | null;
}

export interface BillingState {
  enabled: boolean;
  provider: ProviderId | null;
  providers: Record<ProviderId, ProviderState>;
  /** Payments can be taken now: on, a provider chosen, and its keys set. */
  ready: boolean;
}

const hint = (v: string) => (v ? `••••${v.slice(-4)}` : "");

async function creds(q: Queryable, secret: string, p: ProviderId) {
  const r = (await q.query<{ secret_key_enc: string | null; webhook_secret_enc: string | null; updated_at: Date; updated_by: string | null }>(
    "SELECT pp.secret_key_enc, pp.webhook_secret_enc, pp.updated_at, u.email AS updated_by FROM payment_providers pp LEFT JOIN users u ON u.id = pp.updated_by WHERE provider = $1", [p])).rows[0];
  const open = (v: string | null | undefined) => {
    if (!v) return "";
    try {
      return decrypt(secret, v);
    } catch {
      return ""; // encrypted under an earlier SESSION_SECRET: set it again
    }
  };
  return { secretKey: open(r?.secret_key_enc), webhookSecret: open(r?.webhook_secret_enc), updatedAt: r?.updated_at ?? null, updatedBy: r?.updated_by ?? null };
}

export async function billingState(q: Queryable, secret: string): Promise<BillingState> {
  const b = (await q.query<{ enabled: boolean; provider: string | null }>("SELECT enabled, provider FROM billing")).rows[0] ?? { enabled: false, provider: null };
  const providers = {} as Record<ProviderId, ProviderState>;
  for (const id of PROVIDERS) {
    const c = await creds(q, secret, id);
    const needsWebhookSecret = PROVIDER_INFO[id].webhookLabel !== null;
    providers[id] = {
      id, configured: !!c.secretKey && (!needsWebhookSecret || !!c.webhookSecret), live: isLive(id, c.secretKey),
      keyHint: hint(c.secretKey), webhookHint: hint(c.webhookSecret), needsWebhookSecret, updatedAt: c.updatedAt, updatedBy: c.updatedBy,
    };
  }
  const provider = isProvider(b.provider) ? b.provider : null;
  return { enabled: b.enabled, provider, providers, ready: b.enabled && !!provider && providers[provider].configured };
}

/** Just the switch, for every page's menu (cheap). */
export async function billingOn(q: Queryable): Promise<boolean> {
  return !!(await q.query("SELECT 1 FROM billing WHERE enabled AND provider IS NOT NULL")).rowCount;
}

export async function gatewayFor(d: BillingDeps, p: ProviderId): Promise<Gateway | null> {
  const c = await creds(d.db, d.config.sessionSecret, p);
  return c.secretKey ? gateway(p, c, d.fetch) : null;
}

// ---------------------------------------------------------------- admin changes

export async function saveCredentials(d: BillingDeps, actor: { id: number; ip: string | null }, p: ProviderId, secretKey: string, webhookSecret: string) {
  const enc = (v: string) => (v ? encrypt(d.config.sessionSecret, v) : null);
  await d.db.query(
    `INSERT INTO payment_providers (provider, secret_key_enc, webhook_secret_enc, updated_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (provider) DO UPDATE SET secret_key_enc = coalesce(EXCLUDED.secret_key_enc, payment_providers.secret_key_enc),
       webhook_secret_enc = coalesce(EXCLUDED.webhook_secret_enc, payment_providers.webhook_secret_enc), updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [p, enc(secretKey), enc(webhookSecret), actor.id]);
  await audit(d.db, { actor: actor.id, action: "billing.credentials", target: p, ip: actor.ip,
    metadata: { secret_key: secretKey ? (isLive(p, secretKey) ? "live key set" : "test key set") : "unchanged", webhook_secret: webhookSecret ? "set" : "unchanged" } });
}

export async function removeCredentials(d: BillingDeps, actor: { id: number; ip: string | null }, p: ProviderId) {
  const b = await billingState(d.db, d.config.sessionSecret);
  if (b.enabled && b.provider === p) throw new BillingError(`${PROVIDER_INFO[p].name} takes payments now. Turn payments off or choose another provider first.`);
  await d.db.query("DELETE FROM payment_providers WHERE provider = $1", [p]);
  await audit(d.db, { actor: actor.id, action: "billing.credentials_removed", target: p, ip: actor.ip });
}

export async function chooseProvider(d: BillingDeps, actor: { id: number; ip: string | null }, p: ProviderId) {
  const b = await billingState(d.db, d.config.sessionSecret);
  if (b.enabled && !b.providers[p].configured) throw new BillingError(`Set ${PROVIDER_INFO[p].name}'s keys before it takes payments.`);
  await d.db.query("UPDATE billing SET provider = $1, updated_by = $2, updated_at = now()", [p, actor.id]);
  await audit(d.db, { actor: actor.id, action: "billing.provider", target: p, ip: actor.ip });
}

export async function setEnabled(d: BillingDeps, actor: { id: number; ip: string | null }, on: boolean) {
  if (on) {
    const b = await billingState(d.db, d.config.sessionSecret);
    if (!b.provider) throw new BillingError("Choose a payment provider first.");
    if (!b.providers[b.provider].configured) throw new BillingError(`Set ${PROVIDER_INFO[b.provider].name}'s keys first.`);
    const priced = Number((await d.db.query("SELECT count(*) AS n FROM plans WHERE price_minor IS NOT NULL")).rows[0].n);
    if (!priced) throw new BillingError("No plan has a price yet. Give at least one plan a price (Plans), then turn payments on.");
  }
  await d.db.query("UPDATE billing SET enabled = $1, updated_by = $2, updated_at = now()", [on, actor.id]);
  await audit(d.db, { actor: actor.id, action: on ? "billing.on" : "billing.off", ip: actor.ip });
}

// ---------------------------------------------------------------- buying a plan

export interface PlanForSale {
  id: number;
  name: string;
  description: string | null;
  station_limit: number;
  price_minor: number;
  currency: string;
  period: "month" | "year";
}

export async function plansForSale(q: Queryable): Promise<PlanForSale[]> {
  return (await q.query<PlanForSale>(
    "SELECT id, name, description, station_limit, price_minor, currency, period FROM plans WHERE price_minor IS NOT NULL ORDER BY price_minor, station_limit")).rows;
}

/** Start paying for a plan: a payment row, then the provider's checkout page to send the person to. */
export async function startCheckout(d: BillingDeps, user: { id: number; email: string; ip: string | null }, planId: number): Promise<{ url: string; reference: string }> {
  const b = await billingState(d.db, d.config.sessionSecret);
  if (!b.ready || !b.provider) throw new BillingError("Payments are not available right now.");
  const plan = (await plansForSale(d.db)).find((p) => p.id === planId);
  if (!plan) throw new BillingError("That plan cannot be bought.");
  const gw = await gatewayFor(d, b.provider);
  if (!gw) throw new BillingError("Payments are not available right now.");
  const c = await creds(d.db, d.config.sessionSecret, b.provider);
  const reference = `nova_${randomBytes(12).toString("hex")}`;
  await d.db.query(
    `INSERT INTO payments (reference, user_id, email, plan_id, plan_name, period, provider, live, amount_minor, currency)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [reference, user.id, user.email, plan.id, plan.name, plan.period, b.provider, isLive(b.provider, c.secretKey), plan.price_minor, plan.currency]);
  try {
    const out = await gw.checkout({
      reference, email: user.email, amountMinor: plan.price_minor, currency: plan.currency,
      description: `${plan.name} plan, 1 ${plan.period} · ${d.config.rootDomain}`,
      returnUrl: `${d.config.dashboardUrl}/billing/return?ref=${reference}`,
      cancelUrl: `${d.config.dashboardUrl}/billing?cancelled=${reference}`,
    });
    await d.db.query("UPDATE payments SET provider_ref = $2, updated_at = now() WHERE reference = $1", [reference, out.providerRef]);
    await audit(d.db, { actor: user.id, action: "billing.checkout", target: reference, ip: user.ip, metadata: { plan: plan.name, amount: formatMoney(plan.price_minor, plan.currency), provider: b.provider } });
    return { url: out.url, reference };
  } catch (e) {
    await d.db.query("UPDATE payments SET status = 'failed', error = $2, updated_at = now() WHERE reference = $1", [reference, (e as Error).message.slice(0, 500)]);
    await opsEvent(d.db, "job", `checkout ${b.provider}: ${(e as Error).message}`, reference).catch(() => undefined);
    throw new BillingError("The payment page could not be opened. Try again in a moment.");
  }
}

export interface PaymentRow {
  id: number;
  reference: string;
  user_id: number | null;
  email: string;
  plan_id: number | null;
  plan_name: string;
  period: "month" | "year";
  provider: ProviderId;
  live: boolean;
  amount_minor: number;
  currency: string;
  status: "pending" | "paid" | "failed" | "abandoned";
  provider_ref: string | null;
  error: string | null;
  paid_at: Date | null;
  period_end: Date | null;
  created_at: Date;
}

/**
 * Ask the provider about a payment and act on the answer. Safe to call any number of
 * times, from anywhere (the return page, a webhook, the worker): a payment is fulfilled once.
 */
export async function confirm(d: BillingDeps, reference: string): Promise<PaymentRow | null> {
  const p = (await d.db.query<PaymentRow>("SELECT * FROM payments WHERE reference = $1", [reference])).rows[0];
  if (!p) return null;
  if (p.status === "paid") return p;
  const gw = await gatewayFor(d, p.provider);
  if (!gw) return p;
  const v = await gw.verify({ reference: p.reference, providerRef: p.provider_ref });
  return transaction(d.db, async (tx) => {
    const now = (await tx.query<PaymentRow>("SELECT * FROM payments WHERE id = $1 FOR UPDATE", [p.id])).rows[0];
    if (now.status === "paid") return now;
    if (v.state === "pending") return now;
    if (v.state === "failed") {
      await tx.query("UPDATE payments SET status = 'failed', error = $2, updated_at = now() WHERE id = $1", [p.id, v.detail ?? "The provider says the payment failed."]);
      return { ...now, status: "failed" };
    }
    // Paid: but for exactly what was asked?
    if (v.amountMinor !== Number(now.amount_minor) || v.currency !== now.currency) {
      const why = `Paid ${v.amountMinor} ${v.currency}, expected ${now.amount_minor} ${now.currency}.`;
      await tx.query("UPDATE payments SET status = 'failed', error = $2, updated_at = now() WHERE id = $1", [p.id, why]);
      await opsEvent(tx, "job", `payment amount mismatch: ${why}`, reference);
      return { ...now, status: "failed" };
    }
    let periodEnd: Date | null = null;
    if (now.user_id && now.plan_id) {
      const u = (await tx.query<{ plan_id: number | null; plan_expires_at: Date | null }>("SELECT plan_id, plan_expires_at FROM users WHERE id = $1 FOR UPDATE", [now.user_id])).rows[0];
      if (u) {
        // Renewing early adds to the time left; anything else starts now.
        const from = u.plan_id === now.plan_id && u.plan_expires_at && u.plan_expires_at > new Date() ? u.plan_expires_at : new Date();
        const r = await tx.query<{ end: Date }>(`SELECT $1::timestamptz + interval '1 ${now.period === "year" ? "year" : "month"}' AS end`, [from]);
        periodEnd = r.rows[0].end;
        await tx.query("UPDATE users SET plan_id = $2, plan_expires_at = $3, plan_reminded_at = NULL WHERE id = $1", [now.user_id, now.plan_id, periodEnd]);
      }
    }
    await tx.query("UPDATE payments SET status = 'paid', paid_at = now(), period_end = $2, provider_ref = coalesce($3, provider_ref), error = NULL, updated_at = now() WHERE id = $1",
      [p.id, periodEnd, v.providerRef ?? null]);
    await audit(tx, { actor: now.user_id, action: "billing.paid", target: now.reference, metadata: { plan: now.plan_name, amount: formatMoney(Number(now.amount_minor), now.currency), provider: now.provider, until: periodEnd } });
    return { ...now, status: "paid", period_end: periodEnd, paid_at: new Date() };
  });
}

/** A webhook: check the signature, handle each event once, then confirm the payment it is about. */
export async function handleWebhook(d: BillingDeps, provider: string, raw: string, headers: Record<string, string | string[] | undefined>): Promise<"ok" | "duplicate" | "ignored"> {
  if (!isProvider(provider)) throw new BillingError("No such provider.");
  const gw = await gatewayFor(d, provider);
  if (!gw) throw new BillingError("This provider is not set up.");
  const ev = gw.webhook(raw, headers); // throws BadSignature
  if (ev.eventId) {
    const fresh = await d.db.query("INSERT INTO webhook_events (provider, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [provider, ev.eventId.slice(0, 200)]);
    if (!fresh.rowCount) return "duplicate";
  }
  if (!ev.reference) return "ignored";
  const known = await d.db.query("SELECT 1 FROM payments WHERE reference = $1 AND provider = $2", [ev.reference, provider]);
  if (!known.rowCount) return "ignored";
  await confirm(d, ev.reference);
  return "ok";
}

/** Can these keys be used? One harmless call to the provider. */
export async function testProvider(d: BillingDeps, p: ProviderId): Promise<string> {
  const gw = await gatewayFor(d, p);
  if (!gw) throw new BillingError(`No ${PROVIDER_INFO[p].name} key is set.`);
  await gw.test();
  const c = await creds(d.db, d.config.sessionSecret, p);
  return `${PROVIDER_INFO[p].name} accepted the ${isLive(p, c.secretKey) ? "live" : "test"} key.`;
}

export { checkKey };

// ---------------------------------------------------------------- upkeep (the worker)

/** Payments left pending: ask again (a webhook may have been missed); give up after a day. */
export async function recheckPending(d: BillingDeps): Promise<number> {
  await d.db.query("UPDATE payments SET status = 'abandoned', updated_at = now() WHERE status = 'pending' AND created_at < now() - interval '1 day'");
  const rows = (await d.db.query<{ reference: string }>(
    "SELECT reference FROM payments WHERE status = 'pending' AND created_at < now() - interval '2 minutes' ORDER BY created_at LIMIT 50")).rows;
  for (const r of rows) await confirm(d, r.reference).catch((e) => opsEvent(d.db, "job", `payment recheck: ${(e as Error).message}`, r.reference));
  return rows.length;
}

/** Email people whose paid plan ends within 3 days, once per period. */
export async function remindExpiring(d: BillingDeps): Promise<number> {
  if (!d.mail || !(await billingOn(d.db))) return 0;
  const rows = (await d.db.query<{ id: number; email: string; plan: string; ends: Date }>(
    `SELECT u.id, u.email, p.name AS plan, u.plan_expires_at AS ends FROM users u JOIN plans p ON p.id = u.plan_id
      WHERE u.status = 'active' AND u.plan_expires_at BETWEEN now() AND now() + interval '3 days' AND u.plan_reminded_at IS NULL`)).rows;
  for (const r of rows) {
    await d.mail({ to: r.email, subject: `Your ${r.plan} plan ends soon`,
      text: `Your ${r.plan} plan on ${d.config.rootDomain} ends on ${r.ends.toISOString().slice(0, 10)}. Renew it here to keep its station limit:\n\n${d.config.dashboardUrl}/billing\n` }).catch(() => undefined);
    await d.db.query("UPDATE users SET plan_reminded_at = now() WHERE id = $1", [r.id]);
  }
  return rows.length;
}
