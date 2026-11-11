/**
 * Payment providers behind one interface. Each takes people to the provider's own hosted
 * checkout (no card details ever touch this platform), confirms a payment by asking the
 * provider's API (a redirect back is never trusted on its own), and checks the signature
 * of the provider's webhooks.
 *
 * - Stripe: Checkout Sessions; webhooks signed HMAC-SHA256 with the endpoint's signing secret.
 * - Paystack: Transaction initialize/verify; webhooks signed HMAC-SHA512 with the secret key.
 * - Flutterwave (v3): Standard payments; webhooks carry the "secret hash" set in its dashboard.
 *
 * Amounts are kept in the currency's smallest unit (cents, kobo).
 */

import { createHmac } from "node:crypto";
import { sameString } from "../lib/secrets.js";

export type ProviderId = "stripe" | "paystack" | "flutterwave";
export const PROVIDERS: ProviderId[] = ["stripe", "paystack", "flutterwave"];
export const isProvider = (v: unknown): v is ProviderId => PROVIDERS.includes(v as ProviderId);

export interface ProviderInfo {
  name: string;
  blurb: string;
  keyLabel: string;
  keyHelp: string;
  /** null: the provider signs webhooks with the secret key itself (Paystack). */
  webhookLabel: string | null;
  webhookHelp: string;
  events: string;
  dashboard: string;
}

export const PROVIDER_INFO: Record<ProviderId, ProviderInfo> = {
  stripe: {
    name: "Stripe", blurb: "Cards, wallets and local methods in 40+ countries.",
    keyLabel: "Secret key", keyHelp: "Developers > API keys. Starts with sk_test_ or sk_live_ (or a restricted key, rk_).",
    webhookLabel: "Webhook signing secret", webhookHelp: "Developers > Webhooks > your endpoint > Signing secret. Starts with whsec_.",
    events: "checkout.session.completed, checkout.session.async_payment_succeeded, checkout.session.async_payment_failed, checkout.session.expired",
    dashboard: "https://dashboard.stripe.com",
  },
  paystack: {
    name: "Paystack", blurb: "Cards, bank transfer and USSD in Nigeria, Ghana, Kenya and South Africa.",
    keyLabel: "Secret key", keyHelp: "Settings > API Keys & Webhooks. Starts with sk_test_ or sk_live_.",
    webhookLabel: null, webhookHelp: "Paystack signs webhooks with the secret key, so there is nothing more to paste.",
    events: "charge.success (Paystack sends every event to the URL)",
    dashboard: "https://dashboard.paystack.com",
  },
  flutterwave: {
    name: "Flutterwave", blurb: "Cards, mobile money and bank transfer across Africa.",
    keyLabel: "Secret key", keyHelp: "Settings > API Keys. Starts with FLWSECK_TEST- or FLWSECK-.",
    webhookLabel: "Secret hash", webhookHelp: "Settings > Webhooks > Secret hash: choose a long random value there and paste the same here.",
    events: "Successful and failed charges (tick them under Settings > Webhooks)",
    dashboard: "https://app.flutterwave.com",
  },
};

export interface Credentials {
  secretKey: string;
  webhookSecret: string;
}

/** The key's own shape, and whether it is a live key. An error message when it is not one. */
export function checkKey(p: ProviderId, key: string): { live: boolean } | { error: string } {
  const k = key.trim();
  if (p === "stripe") {
    const m = /^(sk|rk)_(test|live)_[A-Za-z0-9]{10,}$/.exec(k);
    return m ? { live: m[2] === "live" } : { error: "A Stripe secret key starts with sk_test_, sk_live_, rk_test_ or rk_live_." };
  }
  if (p === "paystack") {
    const m = /^sk_(test|live)_[A-Za-z0-9]{20,}$/.exec(k);
    return m ? { live: m[1] === "live" } : { error: "A Paystack secret key starts with sk_test_ or sk_live_." };
  }
  const m = /^FLWSECK(_TEST)?-[A-Za-z0-9]{16,}(-X)?$/.exec(k);
  return m ? { live: !m[1] } : { error: "A Flutterwave secret key starts with FLWSECK_TEST- or FLWSECK-." };
}

export function checkWebhookSecret(p: ProviderId, secret: string): string | null {
  const s = secret.trim();
  if (p === "stripe") return /^whsec_[A-Za-z0-9+/=]{16,}$/.test(s) ? null : "A Stripe signing secret starts with whsec_.";
  if (p === "flutterwave") return s.length >= 16 && s.length <= 200 && !/\s/.test(s) ? null : "Use a secret hash of 16 characters or more, without spaces.";
  return null;
}

export const isLive = (p: ProviderId, key: string) => {
  const c = checkKey(p, key);
  return "live" in c && c.live;
};

// ---------------------------------------------------------------- currencies

/** Currencies without a minor unit (Stripe's list); every other has two decimals here. */
const ZERO_DECIMAL = new Set(["BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"]);
export const exponent = (currency: string) => (ZERO_DECIMAL.has(currency.toUpperCase()) ? 0 : 2);

/** "19.99" in USD -> 1999; null when it is not a price. */
export function toMinor(text: string, currency: string): number | null {
  const e = exponent(currency);
  const m = (e ? /^(\d{1,9})(?:\.(\d{1,2}))?$/ : /^(\d{1,12})$/).exec(text.trim().replace(/,/g, ""));
  if (!m) return null;
  const v = Number(m[1]) * 10 ** e + (e ? Number((m[2] ?? "").padEnd(2, "0") || 0) : 0);
  return v > 0 && Number.isSafeInteger(v) ? v : null;
}

export function formatMoney(minor: number, currency: string): string {
  const e = exponent(currency);
  try {
    return new Intl.NumberFormat("en", { style: "currency", currency, currencyDisplay: "narrowSymbol", minimumFractionDigits: e, maximumFractionDigits: e }).format(minor / 10 ** e);
  } catch {
    return `${(minor / 10 ** e).toFixed(e)} ${currency}`;
  }
}

// ---------------------------------------------------------------- the interface

export interface CheckoutRequest {
  reference: string;
  email: string;
  amountMinor: number;
  currency: string;
  description: string;
  /** Where the provider sends the person back (the reference is in it already). */
  returnUrl: string;
  cancelUrl: string;
}

export interface Verification {
  state: "paid" | "pending" | "failed";
  amountMinor: number | null;
  currency: string | null;
  providerRef?: string | null;
  detail?: string;
}

export class GatewayError extends Error {}
export class BadSignature extends Error {}

export interface Gateway {
  id: ProviderId;
  /** A hosted checkout page to send the person to. */
  checkout(c: CheckoutRequest): Promise<{ url: string; providerRef: string | null }>;
  /** What the provider says about this payment. */
  verify(p: { reference: string; providerRef: string | null }): Promise<Verification>;
  /** Check a webhook's signature (throws BadSignature); the event's id and the payment reference it is about. */
  webhook(raw: string, headers: Record<string, string | string[] | undefined>, now?: number): { eventId: string; reference: string | null };
  /** One harmless authenticated call: do the keys work? */
  test(): Promise<void>;
}

type Fetch = typeof fetch;
const header = (h: Record<string, string | string[] | undefined>, name: string) => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] ?? "" : v ?? "";
};

async function call(fetchFn: Fetch, provider: string, url: string, init: RequestInit): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(20_000) });
  } catch (e) {
    throw new GatewayError(`${provider} could not be reached (${(e as Error).message}).`);
  }
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const err = json.error as { message?: string } | undefined;
    const msg = err?.message ?? (json.message as string | undefined) ?? `HTTP ${res.status}`;
    throw new GatewayError(res.status === 401 || res.status === 403 ? `${provider} refused the key (${msg}).` : `${provider}: ${msg}`);
  }
  return json;
}

/** Only an https page on the provider's own domain is a place to send people. */
function checkoutUrl(url: unknown, hosts: RegExp, provider: string): string {
  try {
    const u = new URL(String(url));
    if (u.protocol === "https:" && hosts.test(u.hostname)) return u.toString();
  } catch {
    // fall through
  }
  throw new GatewayError(`${provider} returned an unexpected checkout address.`);
}

// ---------------------------------------------------------------- Stripe

export class StripeGateway implements Gateway {
  readonly id = "stripe" as const;
  constructor(private c: Credentials, private fetchFn: Fetch = fetch, private base = "https://api.stripe.com") {}

  private req(method: string, path: string, form?: Record<string, string>, idempotencyKey?: string) {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.c.secretKey}`, "Stripe-Version": "2024-06-20" };
    if (form) headers["Content-Type"] = "application/x-www-form-urlencoded";
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    return call(this.fetchFn, "Stripe", `${this.base}${path}`, { method, headers, body: form ? new URLSearchParams(form).toString() : undefined });
  }

  async checkout(c: CheckoutRequest) {
    const s = await this.req("POST", "/v1/checkout/sessions", {
      mode: "payment",
      success_url: c.returnUrl,
      cancel_url: c.cancelUrl,
      customer_email: c.email,
      client_reference_id: c.reference,
      "metadata[reference]": c.reference,
      "payment_intent_data[metadata][reference]": c.reference,
      "line_items[0][quantity]": "1",
      "line_items[0][price_data][currency]": c.currency.toLowerCase(),
      "line_items[0][price_data][unit_amount]": String(c.amountMinor),
      "line_items[0][price_data][product_data][name]": c.description,
    }, c.reference);
    return { url: checkoutUrl(s.url, /^checkout\.stripe\.com$/, "Stripe"), providerRef: String(s.id ?? "") || null };
  }

  async verify(p: { reference: string; providerRef: string | null }): Promise<Verification> {
    if (!p.providerRef) return { state: "pending", amountMinor: null, currency: null, detail: "No Stripe session yet." };
    const s = await this.req("GET", `/v1/checkout/sessions/${encodeURIComponent(p.providerRef)}`);
    if (s.client_reference_id !== p.reference) return { state: "failed", amountMinor: null, currency: null, detail: "The Stripe session is for another payment." };
    const state = s.payment_status === "paid" || s.payment_status === "no_payment_required" ? "paid" : s.status === "expired" ? "failed" : "pending";
    return { state, amountMinor: Number(s.amount_total ?? NaN), currency: String(s.currency ?? "").toUpperCase(), providerRef: p.providerRef };
  }

  webhook(raw: string, headers: Record<string, string | string[] | undefined>, now = Date.now()) {
    if (!this.c.webhookSecret) throw new BadSignature("No signing secret is set.");
    const parts = header(headers, "stripe-signature").split(",").map((x) => x.trim().split("="));
    const t = parts.find(([k]) => k === "t")?.[1] ?? "";
    const sigs = parts.filter(([k]) => k === "v1").map(([, v]) => v ?? "");
    if (!/^\d+$/.test(t) || !sigs.length) throw new BadSignature("No signature.");
    if (Math.abs(now / 1000 - Number(t)) > 300) throw new BadSignature("The signature is too old.");
    const want = createHmac("sha256", this.c.webhookSecret).update(`${t}.${raw}`).digest("hex");
    if (!sigs.some((s) => sameString(s, want))) throw new BadSignature("The signature does not match.");
    const ev = JSON.parse(raw) as { id?: string; type?: string; data?: { object?: { client_reference_id?: string; metadata?: { reference?: string } } } };
    const o = ev.data?.object;
    const reference = String(ev.type ?? "").startsWith("checkout.session.") ? o?.client_reference_id ?? o?.metadata?.reference ?? null : null;
    return { eventId: String(ev.id ?? ""), reference };
  }

  async test() {
    await this.req("GET", "/v1/balance");
  }
}

// ---------------------------------------------------------------- Paystack

export class PaystackGateway implements Gateway {
  readonly id = "paystack" as const;
  constructor(private c: Credentials, private fetchFn: Fetch = fetch, private base = "https://api.paystack.co") {}

  private req(method: string, path: string, body?: unknown) {
    return call(this.fetchFn, "Paystack", `${this.base}${path}`, {
      method, headers: { Authorization: `Bearer ${this.c.secretKey}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  async checkout(c: CheckoutRequest) {
    const r = await this.req("POST", "/transaction/initialize", {
      email: c.email, amount: c.amountMinor, currency: c.currency, reference: c.reference, callback_url: c.returnUrl,
      metadata: { reference: c.reference, cancel_action: c.cancelUrl, custom_fields: [{ display_name: "Plan", variable_name: "plan", value: c.description }] },
    });
    const data = (r.data ?? {}) as { authorization_url?: string; reference?: string };
    return { url: checkoutUrl(data.authorization_url, /^checkout\.paystack\.com$/, "Paystack"), providerRef: data.reference ?? c.reference };
  }

  async verify(p: { reference: string }): Promise<Verification> {
    let r: Record<string, unknown>;
    try {
      r = await this.req("GET", `/transaction/verify/${encodeURIComponent(p.reference)}`);
    } catch (e) {
      // Not started on Paystack's side yet (the person never reached the page).
      if (/not found/i.test((e as Error).message)) return { state: "pending", amountMinor: null, currency: null, detail: "Not found at Paystack yet." };
      throw e;
    }
    const d = (r.data ?? {}) as { status?: string; amount?: number; currency?: string; reference?: string; id?: number };
    if (d.reference !== p.reference) return { state: "failed", amountMinor: null, currency: null, detail: "Paystack answered about another payment." };
    const state = d.status === "success" ? "paid" : d.status === "failed" || d.status === "reversed" ? "failed" : "pending";
    return { state, amountMinor: Number(d.amount ?? NaN), currency: String(d.currency ?? "").toUpperCase(), providerRef: d.id ? String(d.id) : null };
  }

  webhook(raw: string, headers: Record<string, string | string[] | undefined>) {
    const given = header(headers, "x-paystack-signature");
    const want = createHmac("sha512", this.c.secretKey).update(raw).digest("hex");
    if (!given || !sameString(given, want)) throw new BadSignature("The signature does not match.");
    const ev = JSON.parse(raw) as { event?: string; data?: { id?: number; reference?: string } };
    return { eventId: `${ev.event ?? "event"}:${ev.data?.id ?? ev.data?.reference ?? ""}`, reference: ev.event?.startsWith("charge.") ? ev.data?.reference ?? null : null };
  }

  async test() {
    await this.req("GET", "/balance");
  }
}

// ---------------------------------------------------------------- Flutterwave

export class FlutterwaveGateway implements Gateway {
  readonly id = "flutterwave" as const;
  constructor(private c: Credentials, private fetchFn: Fetch = fetch, private base = "https://api.flutterwave.com") {}

  private req(method: string, path: string, body?: unknown) {
    return call(this.fetchFn, "Flutterwave", `${this.base}${path}`, {
      method, headers: { Authorization: `Bearer ${this.c.secretKey}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  async checkout(c: CheckoutRequest) {
    const e = exponent(c.currency);
    const r = await this.req("POST", "/v3/payments", {
      tx_ref: c.reference, amount: c.amountMinor / 10 ** e, currency: c.currency, redirect_url: c.returnUrl,
      customer: { email: c.email }, customizations: { title: c.description }, meta: { reference: c.reference },
    });
    const data = (r.data ?? {}) as { link?: string };
    return { url: checkoutUrl(data.link, /(^|\.)flutterwave\.com$/, "Flutterwave"), providerRef: null };
  }

  async verify(p: { reference: string }): Promise<Verification> {
    let r: Record<string, unknown>;
    try {
      r = await this.req("GET", `/v3/transactions/verify_by_reference?tx_ref=${encodeURIComponent(p.reference)}`);
    } catch (e) {
      if (/no transaction/i.test((e as Error).message)) return { state: "pending", amountMinor: null, currency: null, detail: "Not found at Flutterwave yet." };
      throw e;
    }
    const d = (r.data ?? {}) as { status?: string; amount?: number; currency?: string; tx_ref?: string; id?: number };
    if (d.tx_ref !== p.reference) return { state: "failed", amountMinor: null, currency: null, detail: "Flutterwave answered about another payment." };
    const cur = String(d.currency ?? "").toUpperCase();
    const state = d.status === "successful" ? "paid" : d.status === "failed" ? "failed" : "pending";
    return { state, amountMinor: Math.round(Number(d.amount ?? NaN) * 10 ** exponent(cur || "USD")), currency: cur, providerRef: d.id ? String(d.id) : null };
  }

  webhook(raw: string, headers: Record<string, string | string[] | undefined>) {
    const given = header(headers, "verif-hash");
    if (!this.c.webhookSecret || !given || !sameString(given, this.c.webhookSecret)) throw new BadSignature("The secret hash does not match.");
    const ev = JSON.parse(raw) as { event?: string; data?: { id?: number; tx_ref?: string } };
    return { eventId: `${ev.event ?? "event"}:${ev.data?.id ?? ev.data?.tx_ref ?? ""}`, reference: ev.data?.tx_ref ?? null };
  }

  async test() {
    await this.req("GET", "/v3/balances");
  }
}

export function gateway(p: ProviderId, c: Credentials, fetchFn: Fetch = fetch): Gateway {
  if (p === "stripe") return new StripeGateway(c, fetchFn);
  if (p === "paystack") return new PaystackGateway(c, fetchFn);
  return new FlutterwaveGateway(c, fetchFn);
}
