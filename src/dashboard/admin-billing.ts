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
import { badge, csrfField, day, emptyState, facts, field, html, icon, pageHead, panel, raw, when } from "./html.js";
import { dateParam, filterBar, like, menu, menuLink, menuPost, pageOf, paged, pager, table, tabs } from "./ui.js";
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

  const billingTabs = async (current: "setup" | "payments") => {
    const n = Number((await d.db.query("SELECT count(*) AS n FROM payments")).rows[0].n);
    return tabs([
      { href: "/admin/billing", label: "Setup", current: current === "setup" },
      { href: "/admin/billing/payments", label: "Payments", count: n, current: current === "payments" },
    ], "Payments");
  };

  /** Admin > Payments > Setup: on/off, the provider, and that provider's keys, in one card. */
  app.get("/admin/billing", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const b = await billingState(d.db, d.config.sessionSecret);
    const priced = Number((await d.db.query("SELECT count(*) AS n FROM plans WHERE price_minor IS NOT NULL")).rows[0].n);
    const active = b.provider;
    const shown = (isProvider((req.query as Record<string, string>).p) ? (req.query as Record<string, string>).p : active ?? PROVIDERS[0]) as ProviderId;
    const modeBadge = (p: ProviderId) => (!b.providers[p].configured ? badge("neutral", "Not set up") : b.providers[p].live ? badge("ok", "Live keys") : badge("warn", "Test keys"));
    const blocker = !active ? "Choose a provider and save its keys first." : !b.providers[active].configured ? `Save ${PROVIDER_INFO[active].name}'s keys first.` : !priced ? html`Give at least one plan a price first (<a href="/admin/plans">Plans</a>).` : "";
    const fs = h.takeForm(req, reply).for("billing-setup");

    const pane = (p: ProviderId) => {
      const info = PROVIDER_INFO[p];
      const st = b.providers[p];
      return html`<div class="pp" data-p="${p}">
        <div class="row tight" style="justify-content:space-between;margin-bottom:14px"><div><b>${info.name}</b> ${modeBadge(p)}${p === active ? html` ${badge("accent", "Takes payments")}` : ""}</div>
          <a class="small" href="${info.dashboard}" target="_blank" rel="noreferrer">Open the ${info.name} dashboard ${icon("ext", 13)}</a></div>
        <div class="form-grid">
          ${field({ id: `${p}-key`, label: info.keyLabel, help: info.keyHelp, error: fs.e(`key_${p}`), control: html`<input id="${p}-key" type="password" name="key_${p}" autocomplete="off" placeholder="${st.keyHint ? `Unchanged (${st.keyHint})` : "Paste the key"}">` })}
          ${info.webhookLabel ? field({ id: `${p}-wh`, label: info.webhookLabel, help: info.webhookHelp, error: fs.e(`webhook_${p}`), control: html`<input id="${p}-wh" type="password" name="webhook_${p}" autocomplete="off" placeholder="${st.webhookHint ? `Unchanged (${st.webhookHint})` : "Paste the secret"}">` }) : html`<div class="field"><span class="label">Webhook secret</span><p class="help" style="margin:0">${info.webhookHelp}</p></div>`}</div>
        ${field({ id: `${p}-url`, label: "Webhook URL", help: html`Add it in ${info.name}'s dashboard, with these events: ${info.events}`, control: html`<div class="copyline"><code>${webhookUrl(p)}</code><button type="button" class="sm" data-copy="${webhookUrl(p)}">${icon("copy", 14)} Copy</button></div>` })}
        <div class="line-actions">${st.keyHint ? html`<button class="sm" formaction="/admin/billing/test/${p}" formnovalidate>${icon("activity", 15)} Test connection</button>
          <button class="sm ghost danger" formaction="/admin/billing/keys/${p}/remove" formnovalidate data-confirm="${info.name}'s keys are deleted from the platform. Payments already made are not affected." data-confirm-title="Remove ${info.name}'s keys?" data-confirm-ok="Remove keys">Remove keys</button>` : ""}
          ${st.updatedAt ? html`<span class="dim small">Keys changed ${when(st.updatedAt)}${st.updatedBy ? ` by ${st.updatedBy}` : ""}.</span>` : ""}</div></div>`;
    };

    return h.render(req, reply, "Payments", html`${pageHead({ title: "Payments", sub: "Let station owners buy plans. With payments off, you assign plans by hand." })}
      ${await billingTabs("setup")}
      ${!s.elevated ? html`<div class="callout warn">${icon("lock")}<div><b>Changes need your identity confirmed</b><p>You can look around; saving asks for your password and code first.</p></div><a class="btn sm" href="/sudo?next=%2Fadmin%2Fbilling" style="margin-left:auto">Confirm now</a></div>` : ""}
      <form id="switch" method="post" action="/admin/billing/switch"${b.enabled ? html` data-confirm="Owners will no longer see Billing. Plans already paid for keep running." data-confirm-title="Turn payments off?" data-danger` : ""}>${csrfField(s.csrf)}<input type="hidden" name="on" value="${b.enabled ? "0" : "1"}"></form>
      <style>${PROVIDERS.map((p) => `#billing-setup:has(input[name=provider][value=${p}]:checked) .pp[data-p=${p}]{display:block}`).join("")}</style>
      <form method="post" action="/admin/billing/setup" id="billing-setup"${active ? html` data-confirm="New payments will go through the provider you selected. Payments already made stay where they are, and ${PROVIDER_INFO[active].name}'s keys are kept." data-confirm-title="Switch the payment provider?" data-confirm-ok="Switch provider" data-confirm-unless="provider=${active}"` : ""}>${csrfField(s.csrf)}
      ${panel({ title: b.enabled ? "Payments are on" : "Payments are off",
        sub: b.enabled ? `Owners see Billing and pay through ${active ? PROVIDER_INFO[active].name : "the selected provider"}.` : blocker || "Ready: turn payments on to show Billing to owners.",
        actions: html`${active && b.providers[active].configured && !b.providers[active].live ? badge("warn", "Test mode") : ""}
          <button form="switch" class="${b.enabled ? "danger" : "primary"}"${!b.enabled && blocker ? raw(" disabled") : ""}>${b.enabled ? "Turn payments off" : "Turn payments on"}</button>` }, html`
        <div class="psplit">
          <div><span class="label" id="provider-label">Provider</span>
            <div class="options stack" role="radiogroup" aria-labelledby="provider-label">${PROVIDERS.map((p) => html`<label class="option"><input type="radio" name="provider" value="${p}"${p === shown ? " checked" : ""}>
              ${modeBadge(p)}<b>${PROVIDER_INFO[p].name}</b><span>${PROVIDER_INFO[p].blurb}</span></label>`)}</div></div>
          <div>${PROVIDERS.map(pane)}</div>
        </div>`, html`<span class="dim small spacer">The provider selected here takes new payments once saved.</span><button class="primary">Save</button>`)}
      </form>`, h.takeFlash(req, reply));
  });

  /** Admin > Payments > Payments: every payment, with filters and pages. */
  app.get("/admin/billing/payments", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const b = await billingState(d.db, d.config.sessionSecret);
    const query = req.query as Record<string, string>;
    const status = ["paid", "pending", "failed", "abandoned"].includes(query.status) ? query.status : "";
    const search = String(query.q ?? "").trim().toLowerCase().slice(0, 100);
    const pg = pageOf(query);
    const { rows: payments, total } = await paged<{ id: number; reference: string; email: string; user_id: number | null; plan_name: string; amount_minor: string; currency: string; status: string; provider: string; live: boolean; error: string | null; created_at: Date; paid_at: Date | null }>(d.db,
      `SELECT id, reference, email, user_id, plan_name, amount_minor, currency, status, provider, live, error, created_at, paid_at FROM payments
        WHERE ($1 = '' OR status = $1) AND ($2 = '' OR lower(email) LIKE '%' || $2 || '%' OR lower(reference) LIKE '%' || $2 || '%' OR lower(plan_name) LIKE '%' || $2 || '%')
          AND ($3 = '' OR created_at >= NULLIF($3, '')::date) AND ($4 = '' OR created_at < NULLIF($4, '')::date + 1)
        ORDER BY created_at DESC`, [status, like(search), dateParam(query.from), dateParam(query.to)], pg);
    const filtered = status || search || query.from || query.to;
    return h.render(req, reply, "Payments", html`${pageHead({ title: "Payments", sub: "Let station owners buy plans. With payments off, you assign plans by hand." })}
      ${await billingTabs("payments")}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/billing/payments", query, search: { placeholder: "Search email, reference or plan" }, dates: true,
          chips: { name: "status", label: "Status", options: [["", "All"], ["paid", "Paid"], ["pending", "Pending"], ["failed", "Failed"], ["abandoned", "Abandoned"]] } })}
        ${payments.length ? table(["Date", "Customer", "Plan", { text: "Amount", cls: "num" }, "Status", { text: "Provider", cls: "wide-only" }, { text: "Reference", cls: "wide-only" }, { text: "", cls: "actions" }], payments.map((p) => html`<tr>
          <td style="white-space:nowrap"><a href="/admin/billing/payments/${p.id}">${when(p.created_at)}</a></td><td>${p.user_id ? html`<a href="/admin/users/${p.user_id}">${p.email}</a>` : p.email}</td><td>${p.plan_name}</td>
          <td class="num">${formatMoney(Number(p.amount_minor), p.currency)}</td><td>${paymentBadge(p.status)}${p.live ? "" : html` ${badge("warn", "Test")}`}${p.error ? html`<span class="sub bad">${p.error}</span>` : ""}</td>
          <td class="wide-only">${PROVIDER_INFO[p.provider as ProviderId]?.name ?? p.provider}</td><td class="wide-only"><code>${p.reference}</code></td>
          <td class="actions">${menu([menuLink(`/admin/billing/payments/${p.id}`, "Details", "info"),
            p.status === "pending" || p.status === "abandoned" ? menuPost(`/admin/billing/payments/${p.id}/recheck`, "Check again with the provider", s.csrf, { ic: "activity" }) : ""], { aria: `Actions for ${p.reference}` })}</td></tr>`))
        : emptyState(filtered ? "Nothing found" : "No payments yet", filtered ? "No payment matches these filters." : b.enabled ? "Payments will appear here as people buy plans." : "Turn payments on (Setup) to let people buy plans.")}
        ${pager("/admin/billing/payments", query, pg, total, "payments")}`)}`, h.takeFlash(req, reply));
  });

  /** Setup's one form: the provider to use and (optionally) its keys. */
  app.post("/admin/billing/setup", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const f = h.form(req);
    const p = f.provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "Choose a provider." });
    const here = `/admin/billing?p=${p}`;
    const key = String(f[`key_${p}`] ?? "").trim();
    const wh = PROVIDER_INFO[p].webhookLabel ? String(f[`webhook_${p}`] ?? "").trim() : "";
    const bad = (field: string, text: string) => h.back(reply, here, { kind: "bad", text }, { form: "billing-setup", values: { provider: p }, errors: { [field]: text } });
    if (key) {
      const k = checkKey(p, key);
      if ("error" in k) return bad(`key_${p}`, k.error);
    }
    if (wh) {
      const w = checkWebhookSecret(p, wh);
      if (w) return bad(`webhook_${p}`, w);
    }
    const before = await billingState(d.db, d.config.sessionSecret);
    const done: string[] = [];
    if (key || wh) {
      if (!key && !before.providers[p].keyHint) return bad(`key_${p}`, `Add the ${PROVIDER_INFO[p].keyLabel.toLowerCase()} too.`);
      await saveCredentials(deps(), actor(s, req), p, key, wh);
      done.push(`${PROVIDER_INFO[p].name}'s keys saved`);
    }
    if (before.provider !== p) {
      try {
        await chooseProvider(deps(), actor(s, req), p);
      } catch (e) {
        return fail(reply, e, here);
      }
      done.push(`${PROVIDER_INFO[p].name} takes new payments`);
    }
    if (!done.length) return h.back(reply, here, { kind: "ok", text: "Nothing changed." });
    const now = (await billingState(d.db, d.config.sessionSecret)).providers[p];
    const next = now.needsWebhookSecret && !now.webhookHint ? ` Add the ${PROVIDER_INFO[p].webhookLabel?.toLowerCase()} to finish.` : now.keyHint && key ? " Use Test connection to check them." : "";
    return h.back(reply, here, { kind: "ok", text: `${done.join("; ")}.${next}` });
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
    return h.back(reply, `/admin/billing?p=${p}`, { kind: "ok", text: `${PROVIDER_INFO[p].name} takes new payments.` });
  });

  app.post("/admin/billing/keys/:provider", async (req, reply) => {
    const s = change(req, reply);
    if (!s) return reply;
    const p = (req.params as { provider: string }).provider;
    if (!isProvider(p)) return h.back(reply, "/admin/billing", { kind: "bad", text: "No such provider." });
    const f = h.form(req);
    const key = String(f.secretKey ?? "").trim();
    const wh = String(f.webhookSecret ?? "").trim();
    const back = `/admin/billing?p=${p}`;
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
      return h.back(reply, `/admin/billing?p=${p}`, { kind: "ok", text });
    } catch (e) {
      return fail(reply, e, `/admin/billing?p=${p}`);
    }
  });

  app.get("/admin/billing/payments/:id", async (req, reply) => {
    const s = admin(req, reply, "billing.manage");
    if (!s) return reply;
    const id = Number((req.params as { id: string }).id);
    const p = (await d.db.query<{ id: number; reference: string; user_id: number | null; email: string; plan_id: number | null; plan_name: string; period: string; provider: string; live: boolean; amount_minor: string; currency: string; status: string; provider_ref: string | null; error: string | null; paid_at: Date | null; period_end: Date | null; created_at: Date; updated_at: Date }>(
      "SELECT * FROM payments WHERE id = $1", [Number.isSafeInteger(id) ? id : -1])).rows[0];
    if (!p) return h.render(req, reply, "Not found", html`${pageHead({ title: "No such payment", back: { href: "/admin/billing/payments", text: "Payments" } })}`, null, 404);
    const recheck = p.status === "pending" || p.status === "abandoned";
    return h.render(req, reply, p.reference, html`${pageHead({ title: `${formatMoney(Number(p.amount_minor), p.currency)} · ${p.plan_name}`, back: { href: "/admin/billing/payments", text: "Payments" },
        meta: html`${paymentBadge(p.status)}${p.live ? "" : badge("warn", "Test")}<span>Reference <code>${p.reference}</code></span>`,
        actions: recheck ? html`<form method="post" action="/admin/billing/payments/${p.id}/recheck">${csrfField(s.csrf)}<input type="hidden" name="back" value="/admin/billing/payments/${p.id}"><button>${icon("activity", 16)} Check again with the provider</button></form>` : "" })}
      ${p.error ? html`<div class="callout bad">${icon("alert")}<div><b>The provider said</b><p>${p.error}</p></div></div>` : ""}
      ${panel({ title: "Payment" }, facts([
        ["Customer", p.user_id ? html`<a href="/admin/users/${p.user_id}">${p.email}</a>` : html`${p.email} <span class="dim">(account deleted)</span>`],
        ["Plan", html`${p.plan_id ? html`<a href="/admin/plans/${p.plan_id}">${p.plan_name}</a>` : p.plan_name} <span class="dim">· 1 ${p.period}</span>`],
        ["Amount", formatMoney(Number(p.amount_minor), p.currency)],
        ["Status", paymentBadge(p.status)],
        ["Provider", html`${PROVIDER_INFO[p.provider as ProviderId]?.name ?? p.provider} ${p.live ? badge("ok", "Live") : badge("warn", "Test")}`],
        ["Provider's reference", p.provider_ref ? html`<code>${p.provider_ref}</code>` : "—"],
        ["Started", when(p.created_at)],
        ["Paid", when(p.paid_at)],
        ["Covers until", day(p.period_end)],
        ["Last change", when(p.updated_at)],
      ]))}`, h.takeFlash(req, reply));
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
      const to = h.form(req).back === `/admin/billing/payments/${id}` ? `/admin/billing/payments/${id}` : "/admin/billing/payments";
      return h.back(reply, to, { kind: "ok", text: `${ref}: ${p?.status ?? "unknown"}.` });
    } catch (e) {
      return fail(reply, e);
    }
  });
}
