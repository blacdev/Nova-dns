/**
 * Admin > Payments: the on/off switch, which provider takes payments (Stripe, Paystack or
 * Flutterwave), each provider's keys, a connection test, the webhook address to give the
 * provider, and every payment.
 *
 * Off by default, and nothing else depends on it: with payments off, admins assign plans
 * by hand. Turning them on needs a provider with its keys and at least one priced plan.
 * Every change needs the `billing.manage` permission, two-step sign-in and sudo mode;
 * keys are encrypted and never shown again.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { billingState, BillingError, chooseProvider, confirm, removeCredentials, saveCredentials, setEnabled, testProvider } from "../billing/billing.js";
import { checkKey, checkWebhookSecret, formatMoney, GatewayError, isProvider, PROVIDER_INFO, PROVIDERS, type ProviderId } from "../billing/gateways.js";
import { hit } from "../lib/limits.js";
import { adminGuard } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { paymentBadge } from "./app.js";
import { badge, csrfField, emptyState, field, formSection, html, icon, pageHead, panel, when } from "./html.js";
import type { Session } from "./session.js";

export function billingAdminRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);
  const deps = () => h.billingDeps();
  const webhookUrl = (p: ProviderId) => `https://api.${d.config.rootDomain}/v1/billing/webhook/${p}`;

  /** A change: the permission, two-step sign-in, and sudo mode. */
  const change = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return null;
    return h.requireSudo(req, reply, s, "/admin/billing") ? s : null;
  };
  const actor = (s: Session, req: FastifyRequest) => ({ id: s.user.id, ip: req.ip });

  app.get("/admin/billing", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const b = await billingState(d.db, d.config.sessionSecret);
    const status = String((req.query as Record<string, string>).status ?? "");
    const payments = (await d.db.query(
      `SELECT id, reference, email, user_id, plan_name, amount_minor, currency, status, provider, live, error, created_at, paid_at
         FROM payments WHERE $1 = '' OR status = $1 ORDER BY created_at DESC LIMIT 100`, [["paid", "pending", "failed", "abandoned"].includes(status) ? status : ""])).rows;
    const priced = Number((await d.db.query("SELECT count(*) AS n FROM plans WHERE price_minor IS NOT NULL")).rows[0].n);
    const active = b.provider;
    const modeBadge = (p: ProviderId) => (!b.providers[p].configured ? badge("neutral", "Not set up") : b.providers[p].live ? badge("ok", "Live keys") : badge("warn", "Test keys"));

    const providerPanel = (p: ProviderId) => {
      const info = PROVIDER_INFO[p];
      const st = b.providers[p];
      const body = html`
        ${formSection("Keys", html`From your <a href="${info.dashboard}" target="_blank" rel="noreferrer">${info.name} dashboard</a>. A test key takes test payments; a live key takes real ones.`, html`
          ${field({ id: `${p}-key`, label: info.keyLabel, help: info.keyHelp, control: html`<input id="${p}-key" type="password" name="secretKey" autocomplete="off" placeholder="${st.keyHint ? `Unchanged (${st.keyHint})` : "Paste the key"}">` })}
          ${info.webhookLabel ? field({ id: `${p}-wh`, label: info.webhookLabel, help: info.webhookHelp, control: html`<input id="${p}-wh" type="password" name="webhookSecret" autocomplete="off" placeholder="${st.webhookHint ? `Unchanged (${st.webhookHint})` : "Paste the secret"}">` }) : html`<p class="help">${info.webhookHelp}</p>`}`)}
        ${formSection("Webhook", `Add this address in ${info.name}'s dashboard so payments are confirmed even if someone closes the page before coming back.`, html`
          ${field({ id: `${p}-url`, label: "Webhook URL", control: html`<div class="copyline"><code>${webhookUrl(p)}</code><button type="button" class="sm" data-copy="${webhookUrl(p)}">${icon("copy", 14)} Copy</button></div>` })}
          ${field({ id: `${p}-events`, label: "Events", control: html`<p class="small" style="margin:0">${info.events}</p>` })}`)}
        ${st.updatedAt ? html`<p class="dim small" style="margin:12px 0 0">Keys last changed ${when(st.updatedAt)}${st.updatedBy ? ` by ${st.updatedBy}` : ""}.</p>` : ""}`;
      const foot = html`${st.keyHint ? html`<button class="ghost danger" form="remove-${p}">Remove keys</button><span class="spacer"></span><button class="ghost" form="test-${p}">Test connection</button>` : ""}<button class="primary">Save ${info.name} keys</button>`;
      return html`<form id="test-${p}" method="post" action="/admin/billing/test/${p}">${csrfField(s.csrf)}</form>
        <form id="remove-${p}" method="post" action="/admin/billing/keys/${p}/remove" data-confirm="Remove ${info.name}'s keys from the platform?">${csrfField(s.csrf)}</form>
        <form method="post" action="/admin/billing/keys/${p}" id="provider-${p}">${csrfField(s.csrf)}${panel({ title: `${info.name}${p === active ? " · selected" : ""}`, sub: info.blurb, actions: modeBadge(p) }, body, foot)}</form>`;
    };

    return h.render(req, reply, "Payments", html`${pageHead({ title: "Payments", sub: "Let station owners buy plans. Off by default: with payments off, you assign plans by hand.",
        meta: html`${b.enabled ? badge("ok", "Payments on") : badge("neutral", "Payments off")}${active ? html`<span>Provider: <b>${PROVIDER_INFO[active].name}</b></span>` : ""}${active && b.providers[active].configured && !b.providers[active].live ? badge("warn", "Test mode") : ""}` })}
      ${!s.elevated ? html`<div class="callout warn">${icon("lock")}<div><b>Changes need your identity confirmed</b><p>You can look around; saving asks for your password and code first.</p></div><a class="btn sm" href="/sudo?next=%2Fadmin%2Fbilling" style="margin-left:auto">Confirm now</a></div>` : ""}

      ${panel({ title: "Accept payments", sub: "When on, owners see Billing and can buy any plan that has a price." }, html`<div class="switch-row">
        <div><b>${b.enabled ? "Payments are on" : "Payments are off"}</b><p class="dim small" style="margin:2px 0 0">${b.enabled
          ? `People pay through ${active ? PROVIDER_INFO[active].name : "the selected provider"}. Turning off hides Billing; plans already paid for keep running.`
          : !active ? "Choose a provider and add its keys first." : !b.providers[active].configured ? `Add ${PROVIDER_INFO[active].name}'s keys first.` : !priced ? "Give at least one plan a price first (Plans)." : "Ready to turn on."}</p></div>
        <form method="post" action="/admin/billing/switch"${b.enabled ? html` data-confirm="Turn payments off? Owners will no longer see Billing."` : ""}>${csrfField(s.csrf)}<input type="hidden" name="on" value="${b.enabled ? "0" : "1"}">
          <button class="${b.enabled ? "danger" : "primary"}">${b.enabled ? "Turn payments off" : "Turn payments on"}</button></form></div>`)}

      <form method="post" action="/admin/billing/provider">${csrfField(s.csrf)}${panel({ title: "Payment provider", sub: "The one provider that takes new payments. Each keeps its own keys, so you can switch back and forth." }, html`
        <div class="options">${PROVIDERS.map((p) => html`<label class="option"><input type="radio" name="provider" value="${p}"${p === active ? " checked" : ""}>
          ${modeBadge(p)}<b>${PROVIDER_INFO[p].name}</b><span>${PROVIDER_INFO[p].blurb}</span></label>`)}</div>`,
        html`<button class="primary">Use selected provider</button>`)}</form>

      ${[...(active ? [active] : []), ...PROVIDERS.filter((p) => p !== active)].map(providerPanel)}

      ${panel({ title: "Payments", flush: true, actions: html`<form method="get" class="row tight"><select name="status" aria-label="Status" style="width:auto">
          ${[["", "All"], ["paid", "Paid"], ["pending", "Pending"], ["failed", "Failed"], ["abandoned", "Abandoned"]].map(([v, t]) => html`<option value="${v}"${status === v ? " selected" : ""}>${t}</option>`)}</select><button class="sm">Filter</button></form>` },
        payments.length ? html`<div class="table-wrap"><table><tr><th>Date</th><th>Customer</th><th>Plan</th><th class="num">Amount</th><th>Status</th><th class="wide-only">Provider</th><th class="wide-only">Reference</th><th class="actions"></th></tr>${payments.map((p) => html`<tr>
          <td style="white-space:nowrap">${when(p.created_at)}</td><td>${p.user_id ? html`<a href="/admin/users/${p.user_id}">${p.email}</a>` : p.email}</td><td>${p.plan_name}</td>
          <td class="num">${formatMoney(Number(p.amount_minor), p.currency)}</td><td>${paymentBadge(p.status)}${p.live ? "" : html` ${badge("warn", "Test")}`}${p.error ? html`<span class="sub bad">${p.error}</span>` : ""}</td>
          <td class="wide-only">${PROVIDER_INFO[p.provider as ProviderId]?.name ?? p.provider}</td><td class="wide-only"><code>${p.reference}</code></td>
          <td class="actions">${p.status === "pending" || p.status === "abandoned" ? html`<form method="post" action="/admin/billing/payments/${p.id}/recheck">${csrfField(s.csrf)}<button class="sm">Check again</button></form>` : ""}</td></tr>`)}</table></div>`
        : emptyState("No payments yet", b.enabled ? "Payments will appear here as people buy plans." : "Turn payments on to let people buy plans."))}`, h.takeFlash(req, reply));
  });

  const fail = (reply: FastifyReply, e: unknown, to = "/admin/billing") => {
    if (e instanceof BillingError || e instanceof GatewayError) return h.back(reply, to, { kind: "bad", text: e.message });
    throw e;
  };

  app.post("/admin/billing/switch", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const on = h.form(req).on === "1";
    try {
      await setEnabled(deps(), actor(s, req), on);
    } catch (e) {
      return fail(reply, e);
    }
    return h.back(reply, "/admin/billing", { kind: "ok", text: on ? "Payments are on. Owners now see Billing." : "Payments are off. Plans already paid for keep running." });
  });

  app.post("/admin/billing/provider", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const p = h.form(req).provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "Choose a provider." });
    try {
      await chooseProvider(deps(), actor(s, req), p);
    } catch (e) {
      return fail(reply, e);
    }
    return h.back(reply, `/admin/billing#provider-${p}`, { kind: "ok", text: `${PROVIDER_INFO[p].name} takes new payments.` });
  });

  app.post("/admin/billing/keys/:provider", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const p = (req.params as { provider: string }).provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "No such provider." });
    const f = h.form(req);
    const key = String(f.secretKey ?? "").trim();
    const wh = String(f.webhookSecret ?? "").trim();
    const back = `/admin/billing#provider-${p}`;
    if (!key && !wh) return h.back(reply, back, { kind: "ok", text: "Nothing changed." });
    if (key) {
      const k = checkKey(p, key);
      if ("error" in k) return h.back(reply, back, { kind: "bad", text: k.error });
    }
    if (wh) {
      const bad = checkWebhookSecret(p, wh);
      if (bad) return h.back(reply, back, { kind: "bad", text: bad });
    }
    const st = (await billingState(d.db, d.config.sessionSecret)).providers[p];
    if (!key && !st.keyHint) return h.back(reply, back, { kind: "bad", text: `Add the ${PROVIDER_INFO[p].keyLabel.toLowerCase()} too.` });
    await saveCredentials(deps(), actor(s, req), p, key, PROVIDER_INFO[p].webhookLabel ? wh : "");
    const now = (await billingState(d.db, d.config.sessionSecret)).providers[p];
    const missing = now.needsWebhookSecret && !now.webhookHint ? ` Add the ${PROVIDER_INFO[p].webhookLabel?.toLowerCase()} to finish.` : " Use Test connection to check them.";
    return h.back(reply, back, { kind: "ok", text: `${PROVIDER_INFO[p].name} keys saved (${now.live ? "live" : "test"}).${missing}` });
  });

  app.post("/admin/billing/keys/:provider/remove", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const p = (req.params as { provider: string }).provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "No such provider." });
    try {
      await removeCredentials(deps(), actor(s, req), p);
    } catch (e) {
      return fail(reply, e);
    }
    return h.back(reply, "/admin/billing", { kind: "ok", text: `${PROVIDER_INFO[p].name}'s keys are removed.` });
  });

  app.post("/admin/billing/test/:provider", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const p = (req.params as { provider: string }).provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "No such provider." });
    if (!(await hit(d.db, `billing-test:${s.user.id}`, { max: 20, seconds: 600 })).ok) return h.back(reply, "/admin/billing", { kind: "bad", text: "Too many tests; wait a few minutes." });
    try {
      const text = await testProvider(deps(), p);
      return h.back(reply, `/admin/billing#provider-${p}`, { kind: "ok", text });
    } catch (e) {
      return fail(reply, e, `/admin/billing#provider-${p}`);
    }
  });

  app.post("/admin/billing/payments/:id/recheck", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const id = Number((req.params as { id: string }).id);
    const ref = (await d.db.query<{ reference: string }>("SELECT reference FROM payments WHERE id = $1", [Number.isSafeInteger(id) ? id : -1])).rows[0]?.reference;
    if (!ref) return h.back(reply, "/admin/billing", { kind: "bad", text: "No such payment." });
    try {
      // An abandoned payment may still have gone through: ask once more.
      await d.db.query("UPDATE payments SET status = 'pending' WHERE id = $1 AND status = 'abandoned'", [id]);
      const p = await confirm(deps(), ref);
      return h.back(reply, "/admin/billing", { kind: "ok", text: `${ref}: ${p?.status ?? "unknown"}.` });
    } catch (e) {
      return fail(reply, e);
    }
  });
}
