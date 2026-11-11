/** Payments: provider keys and signatures, the on/off switch, checkout, confirmation, webhooks, expiry. */

import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { LightMyRequestResponse } from "fastify";
import { buildApi } from "../src/api/app.js";
import { BadSignature, checkKey, formatMoney, FlutterwaveGateway, PaystackGateway, StripeGateway, toMinor } from "../src/billing/gateways.js";
import { allowance } from "../src/lib/plans.js";
import { buildDashboard } from "../src/dashboard/app.js";
import type { Db } from "../src/db/db.js";
import { totpAt } from "../src/lib/secrets.js";
import { freshDb, platform } from "./helpers.js";

const PAYSTACK_KEY = `sk_test_${"a".repeat(40)}`;
const STRIPE_KEY = `sk_test_${"b".repeat(30)}`;
const STRIPE_WHSEC = `whsec_${"c".repeat(32)}`;

describe("gateways", () => {
  it("know each provider's key shapes, and which are live", () => {
    expect(checkKey("stripe", STRIPE_KEY)).toEqual({ live: false });
    expect(checkKey("stripe", `sk_live_${"x".repeat(24)}`)).toEqual({ live: true });
    expect(checkKey("paystack", "pk_test_abc")).toHaveProperty("error");
    expect(checkKey("flutterwave", `FLWSECK_TEST-${"d".repeat(32)}-X`)).toEqual({ live: false });
    expect(checkKey("flutterwave", `FLWSECK-${"d".repeat(32)}-X`)).toEqual({ live: true });
  });

  it("count money in the smallest unit", () => {
    expect(toMinor("19.99", "USD")).toBe(1999);
    expect(toMinor("5000", "NGN")).toBe(500000);
    expect(toMinor("19.5", "USD")).toBe(1950);
    expect(toMinor("1500", "JPY")).toBe(1500);
    expect(toMinor("1.5", "JPY")).toBeNull();
    expect(toMinor("-1", "USD")).toBeNull();
    expect(formatMoney(1999, "USD")).toBe("$19.99");
  });

  it("check Stripe's signature, and its age", () => {
    const g = new StripeGateway({ secretKey: STRIPE_KEY, webhookSecret: STRIPE_WHSEC });
    const body = JSON.stringify({ id: "evt_1", type: "checkout.session.completed", data: { object: { client_reference_id: "nova_ref" } } });
    const t = Math.floor(Date.now() / 1000);
    const sig = createHmac("sha256", STRIPE_WHSEC).update(`${t}.${body}`).digest("hex");
    expect(g.webhook(body, { "stripe-signature": `t=${t},v1=${sig}` })).toEqual({ eventId: "evt_1", reference: "nova_ref" });
    expect(() => g.webhook(body, { "stripe-signature": `t=${t},v1=${"0".repeat(64)}` })).toThrow(BadSignature);
    expect(() => g.webhook(body.replace("nova_ref", "nova_other"), { "stripe-signature": `t=${t},v1=${sig}` })).toThrow(BadSignature);
    expect(() => g.webhook(body, { "stripe-signature": `t=${t},v1=${sig}` }, (t + 600) * 1000)).toThrow(/too old/);
  });

  it("check Paystack's and Flutterwave's signatures", () => {
    const body = JSON.stringify({ event: "charge.success", data: { id: 7, reference: "nova_ref" } });
    const ps = new PaystackGateway({ secretKey: PAYSTACK_KEY, webhookSecret: "" });
    expect(ps.webhook(body, { "x-paystack-signature": createHmac("sha512", PAYSTACK_KEY).update(body).digest("hex") }).reference).toBe("nova_ref");
    expect(() => ps.webhook(body, { "x-paystack-signature": "nope" })).toThrow(BadSignature);
    const fw = new FlutterwaveGateway({ secretKey: `FLWSECK_TEST-${"d".repeat(32)}-X`, webhookSecret: "a-long-secret-hash-value" });
    expect(fw.webhook(JSON.stringify({ event: "charge.completed", data: { id: 9, tx_ref: "nova_ref" } }), { "verif-hash": "a-long-secret-hash-value" }).reference).toBe("nova_ref");
    expect(() => fw.webhook("{}", { "verif-hash": "wrong" })).toThrow(BadSignature);
  });
});

// ---------------------------------------------------------------- end to end, with a fake provider

/** The providers' APIs, as far as these tests need them. `paid` maps a reference to what Paystack says was paid. */
const fake = {
  paid: new Map<string, { amount: number; currency: string }>(),
  stripePaid: new Set<string>(),
  calls: [] as string[],
};
const fakeFetch: typeof fetch = async (input, init) => {
  const url = String(input);
  fake.calls.push(`${init?.method ?? "GET"} ${url}`);
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const auth = String((init?.headers as Record<string, string>)?.Authorization ?? "");
  if (url.startsWith("https://api.paystack.co")) {
    if (auth !== `Bearer ${PAYSTACK_KEY}`) return json(401, { status: false, message: "Invalid key" });
    if (url.endsWith("/balance")) return json(200, { status: true, data: [] });
    if (url.endsWith("/transaction/initialize")) {
      const b = JSON.parse(String(init?.body));
      return json(200, { status: true, data: { authorization_url: `https://checkout.paystack.com/${b.reference}`, reference: b.reference } });
    }
    const ref = decodeURIComponent(url.split("/transaction/verify/")[1] ?? "");
    const p = fake.paid.get(ref);
    return json(200, { status: true, data: { reference: ref, status: p ? "success" : "abandoned", amount: p?.amount ?? 0, currency: p?.currency ?? "NGN", id: 99 } });
  }
  if (url.startsWith("https://api.stripe.com")) {
    if (url.endsWith("/v1/checkout/sessions")) {
      const b = new URLSearchParams(String(init?.body));
      return json(200, { id: `cs_${b.get("client_reference_id")}`, url: "https://checkout.stripe.com/c/pay/cs_x" });
    }
    const id = decodeURIComponent(url.split("/v1/checkout/sessions/")[1] ?? "");
    const ref = id.replace(/^cs_/, "");
    return json(200, { id, client_reference_id: ref, payment_status: fake.stripePaid.has(ref) ? "paid" : "unpaid", status: "open", amount_total: 1999, currency: "usd" });
  }
  return json(404, {});
};

let db: Db;
let app: ReturnType<typeof buildDashboard>;
let api: ReturnType<typeof buildApi>;
const PW = "correct horse battery";

beforeAll(async () => {
  db = await freshDb();
  const p = platform(db, { dashboardUrl: "http://app.example.test" });
  app = buildDashboard({ db, dns: p.dns, config: p.config, mail: async () => undefined, fetch: fakeFetch });
  api = buildApi({ ...p.deps, fetch: fakeFetch });
});
afterAll(async () => {
  await app.close();
  await api.close();
  await db.end();
});

class Browser {
  cookies = new Map<string, string>();
  constructor(public ip: string) {}
  private keep(r: LightMyRequestResponse) {
    for (const c of r.cookies) {
      if (c.value === "" || (c.maxAge !== undefined && c.maxAge <= 0)) this.cookies.delete(c.name);
      else this.cookies.set(c.name, c.value);
    }
    return r;
  }
  private get cookie() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async get(url: string) {
    return this.keep(await app.inject({ method: "GET", url, headers: { cookie: this.cookie }, remoteAddress: this.ip }));
  }
  async post(url: string, form: Record<string, string>, from = url) {
    const page = await this.get(from);
    const body = new URLSearchParams({ _csrf: /name="_csrf" value="([^"]+)"/.exec(page.body)?.[1] ?? "", ...form });
    return this.keep(await app.inject({ method: "POST", url, payload: body.toString(),
      headers: { cookie: this.cookie, "content-type": "application/x-www-form-urlencoded", origin: "http://app.example.test" }, remoteAddress: this.ip }));
  }
  async flash(url: string) {
    const t = /class="flash \w+" role="status">[\s\S]*?<span>([^<]*)</.exec((await this.get(url)).body)?.[1] ?? "";
    return t.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  }
}

const boss = new Browser("192.0.2.1");
const buyer = new Browser("192.0.2.2");
const webhook = (provider: string, body: string, headers: Record<string, string>) =>
  api.inject({ method: "POST", url: `/v1/billing/webhook/${provider}`, payload: body, headers: { "content-type": "application/json", ...headers } });
const paystackSig = (body: string) => createHmac("sha512", PAYSTACK_KEY).update(body).digest("hex");

describe("payments", () => {
  it("are off until a provider, its keys and a priced plan are ready, and nothing else needs them", async () => {
    await boss.post("/signup", { email: "boss@example.test", password: PW }, "/signup");
    await boss.post("/account/totp/start", {}, "/account");
    const secret = /Key: <code>([A-Z2-7]+)</.exec((await boss.get("/account")).body)![1];
    await boss.post("/account/totp/confirm", { code: totpAt(secret) }, "/account");
    await buyer.post("/signup", { email: "buyer@example.test", password: PW }, "/signup");
    await db.query("UPDATE users SET email_verified_at = now()");

    // Off: owners see no Billing, and claiming works as ever.
    expect((await buyer.get("/billing")).statusCode).toBe(404);
    expect((await buyer.get("/")).body).not.toContain('href="/billing"');
    await buyer.post("/stations", { label: "first" }, "/stations/new");
    expect((await db.query("SELECT 1 FROM subdomains WHERE label = 'first'")).rowCount).toBe(1);

    await boss.post("/admin/billing/switch", { on: "1" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Choose a payment provider first");
    await boss.post("/admin/billing/provider", { provider: "paystack" }, "/admin/billing");
    await boss.post("/admin/billing/switch", { on: "1" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Set Paystack's keys first");
    await boss.post("/admin/billing/keys/paystack", { secretKey: "sk_live_short" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("starts with sk_test_ or sk_live_");
    await boss.post("/admin/billing/keys/paystack", { secretKey: PAYSTACK_KEY }, "/admin/billing");
    await boss.post("/admin/billing/test/paystack", {}, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Paystack accepted the test key");
    await boss.post("/admin/billing/switch", { on: "1" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("No plan has a price yet");

    await boss.post("/admin/plans", { name: "Free", limit: "1", default: "1" }, "/admin/plans/new");
    await boss.post("/admin/plans", { name: "Pro", limit: "5", price: "5000", currency: "NGN", period: "month" }, "/admin/plans/new");
    await boss.post("/admin/billing/switch", { on: "1" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Payments are on");

    // The key is encrypted and never shown again.
    expect(JSON.stringify((await db.query("SELECT * FROM payment_providers")).rows)).not.toContain(PAYSTACK_KEY);
    expect((await boss.get("/admin/billing")).body).not.toContain(PAYSTACK_KEY);
    expect(JSON.stringify((await db.query("SELECT metadata FROM audit_log")).rows)).not.toContain(PAYSTACK_KEY);
  });

  let ref = "";
  it("send the buyer to the provider's checkout, and count nothing as paid until the provider says so", async () => {
    const page = await buyer.get("/billing");
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("₦5,000.00");
    expect(page.body).toContain("Test mode");
    const pro = (await db.query("SELECT id FROM plans WHERE name = 'Pro'")).rows[0].id;
    const r = await buyer.post("/billing/checkout", { plan: String(pro) }, "/billing");
    expect(r.body).toMatch(/href="https:\/\/checkout\.paystack\.com\/nova_[0-9a-f]{24}" data-autoredirect/);
    ref = /checkout\.paystack\.com\/(nova_[0-9a-f]+)/.exec(r.body)![1];
    expect((await db.query("SELECT status, amount_minor, currency FROM payments WHERE reference = $1", [ref])).rows[0]).toEqual({ status: "pending", amount_minor: 500000, currency: "NGN" });

    // Coming back before paying (or a forged return) changes nothing.
    expect((await buyer.get(`/billing/return?ref=${ref}`)).body).toContain("Confirming your payment");
    expect((await db.query("SELECT plan_id FROM users WHERE email = 'buyer@example.test'")).rows[0].plan_id).toBeNull();
  });

  it("take a webhook only with the right signature, confirm with the provider, and fulfil once", async () => {
    const body = JSON.stringify({ event: "charge.success", data: { id: 501, reference: ref } });
    expect((await webhook("paystack", body, { "x-paystack-signature": "forged" })).statusCode).toBe(400);
    expect((await webhook("nobody", body, {})).statusCode).toBe(404);

    // Signed, but Paystack has not seen the money: still pending.
    expect((await webhook("paystack", body, { "x-paystack-signature": paystackSig(body) })).statusCode).toBe(200);
    expect((await db.query("SELECT status FROM payments WHERE reference = $1", [ref])).rows[0].status).toBe("pending");

    fake.paid.set(ref, { amount: 500000, currency: "NGN" });
    const again = JSON.stringify({ event: "charge.success", data: { id: 502, reference: ref } });
    const r = await webhook("paystack", again, { "x-paystack-signature": paystackSig(again) });
    expect(r.json().result).toBe("ok");
    const pay = (await db.query("SELECT status, period_end FROM payments WHERE reference = $1", [ref])).rows[0];
    expect(pay.status).toBe("paid");
    const days = (new Date(pay.period_end).getTime() - Date.now()) / 86400_000;
    expect(days).toBeGreaterThan(27);
    expect(days).toBeLessThan(32);
    const uid = (await db.query("SELECT id FROM users WHERE email = 'buyer@example.test'")).rows[0].id;
    expect((await allowance(db, uid, 1)).limit).toBe(5);

    // The same event again is ignored; the return page shows the result.
    expect((await webhook("paystack", again, { "x-paystack-signature": paystackSig(again) })).json().result).toBe("duplicate");
    expect((await buyer.get(`/billing/return?ref=${ref}`)).body).toContain("Payment received");
    expect((await db.query("SELECT count(*)::int AS n FROM audit_log WHERE action = 'billing.paid'")).rows[0].n).toBe(1);
  });

  it("refuse a payment for less than the price", async () => {
    const pro = (await db.query("SELECT id FROM plans WHERE name = 'Pro'")).rows[0].id;
    const r = await buyer.post("/billing/checkout", { plan: String(pro) }, "/billing");
    const ref2 = /checkout\.paystack\.com\/(nova_[0-9a-f]+)/.exec(r.body)![1];
    fake.paid.set(ref2, { amount: 100, currency: "NGN" });
    const body = JSON.stringify({ event: "charge.success", data: { id: 777, reference: ref2 } });
    await webhook("paystack", body, { "x-paystack-signature": paystackSig(body) });
    const row = (await db.query("SELECT status, error FROM payments WHERE reference = $1", [ref2])).rows[0];
    expect(row.status).toBe("failed");
    expect(row.error).toContain("expected 500000 NGN");
  });

  it("switch provider: Stripe's checkout and its signed webhook", async () => {
    await boss.post("/admin/billing/keys/stripe", { secretKey: STRIPE_KEY }, "/admin/billing");
    await boss.post("/admin/billing/provider", { provider: "stripe" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Set Stripe's keys");
    await boss.post("/admin/billing/keys/stripe", { webhookSecret: STRIPE_WHSEC }, "/admin/billing");
    await boss.post("/admin/billing/provider", { provider: "stripe" }, "/admin/billing");
    expect(await boss.flash("/admin/billing")).toContain("Stripe takes new payments");

    await boss.post("/admin/plans", { name: "Intl", limit: "3", price: "19.99", currency: "USD", period: "year" }, "/admin/plans/new");
    const intl = (await db.query("SELECT id FROM plans WHERE name = 'Intl'")).rows[0].id;
    const r = await buyer.post("/billing/checkout", { plan: String(intl) }, "/billing");
    expect(r.body).toContain("https://checkout.stripe.com/c/pay/cs_x");
    const sref = (await db.query("SELECT reference FROM payments WHERE provider = 'stripe'")).rows[0].reference;
    fake.stripePaid.add(sref);
    const body = JSON.stringify({ id: "evt_9", type: "checkout.session.completed", data: { object: { client_reference_id: sref } } });
    const t = Math.floor(Date.now() / 1000);
    const sig = createHmac("sha256", STRIPE_WHSEC).update(`${t}.${body}`).digest("hex");
    expect((await webhook("stripe", body, { "stripe-signature": `t=${t},v1=${sig}` })).json().result).toBe("ok");
    expect((await db.query("SELECT status FROM payments WHERE reference = $1", [sref])).rows[0].status).toBe("paid");
  });

  it("end with the period, back to the default plan", async () => {
    const uid = (await db.query("SELECT id FROM users WHERE email = 'buyer@example.test'")).rows[0].id;
    await db.query("UPDATE users SET plan_expires_at = now() - interval '1 day' WHERE id = $1", [uid]);
    const a = await allowance(db, uid, 1);
    expect(a.limit).toBe(1);
    expect(a.lapsed).toBe("Intl");
    expect((await buyer.get("/")).body).toContain("Your Intl plan has ended");
  });

  it("turn off without touching anything else", async () => {
    await boss.post("/admin/billing/switch", { on: "0" }, "/admin/billing");
    expect((await buyer.get("/billing")).statusCode).toBe(404);
    expect((await buyer.get("/")).statusCode).toBe(200);
  });
});
