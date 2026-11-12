/**
 * The admin console (spec section 2): the overview, every station (search, create for
 * someone, suspend), reserved and blocked names, certificates against the CA's weekly
 * limit, TURN usage, the audit log, DNS/ACME events and the setup checks. People, roles
 * and plans are in admin-people.ts; settings in admin-settings.ts; payments in
 * admin-billing.ts.
 *
 * Every admin route goes through `adminGuard`: signed in, an admin, two-step sign-in on,
 * and holding the page's permission (rbac.ts).
 */

import { Resolver } from "node:dns/promises";
import { readFileSync } from "node:fs";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { billingState } from "../billing/billing.js";
import { formatMoney, PROVIDER_INFO } from "../billing/gateways.js";
import type { DnsCheckStep } from "../dns/dns.js";
import { audit } from "../lib/audit.js";
import { formError, fqdnOf, normaliseLabel } from "../lib/names.js";
import { can, isStaff, type Permission } from "../lib/rbac.js";
import { LE_PRODUCTION } from "../lib/settings.js";
import * as subs from "../lib/subdomains.js";
import type { DashDeps, Helpers } from "./app.js";
import { statusChip } from "./app.js";
import { badge, bytes, csrfField, emptyState, field, html, icon, pageHead, panel, when, type Html } from "./html.js";
import { headings, markdown } from "./markdown.js";
import type { Session } from "./session.js";

/** docs/cloudflare-setup.md, with the guide's example domain replaced by this platform's, beside its contents. */
function cloudflareGuide(rootDomain: string): Html {
  try {
    const text = readFileSync(new URL("../../docs/cloudflare-setup.md", import.meta.url), "utf8").replaceAll("yourdomain.com", rootDomain);
    return html`<div class="guide"><nav class="toc" aria-label="In this guide"><b>In this guide</b>${headings(text).map((h) => html`<a href="#${h.id}">${h.text}</a>`)}</nav>
      <div class="card doc" id="guide">${markdown(text)}</div></div>`;
  } catch {
    return panel({}, html`<p class="dim">The guide (docs/cloudflare-setup.md) is not on this machine. It is in the project's repository.</p>`);
  }
}

/** A and AAAA records as the public internet sees them (not this machine's own resolver). */
async function publicLookup(name: string): Promise<string[]> {
  const r = new Resolver({ timeout: 3000, tries: 1 });
  r.setServers(["1.1.1.1", "8.8.8.8"]);
  const found = await Promise.all([r.resolve4(name).catch(() => [] as string[]), r.resolve6(name).catch(() => [] as string[])]);
  return found.flat();
}

const mark = (ok: boolean | null) => (ok === true ? html`<span class="ok">✓</span>` : ok === false ? html`<span class="bad">✗</span>` : html`<span class="dim">?</span>`);

/**
 * The check at the top of every admin route: signed in, an admin (else "Not found", as if
 * the page did not exist), two-step sign-in on, and holding `perm` (else "Not allowed").
 */
export function adminGuard(h: Helpers) {
  return (req: FastifyRequest, reply: FastifyReply, perm: Permission | null = null): Session | null => {
    const s = h.signedIn(req, reply);
    if (!s) return null;
    if (!isStaff(s.user)) {
      void h.render(req, reply, "Not found", html`${pageHead({ title: "Page not found" })}`, null, 404);
      return null;
    }
    if (!s.user.totp) {
      void h.render(req, reply, "Two-step sign-in required", html`${pageHead({ title: "Two-step sign-in required", sub: "The admin console holds people's data and the platform's credentials, so every admin signs in with a second step." })}
        <div style="max-width:620px">${panel({}, html`<div class="empty"><div class="empty-ic">${icon("lock", 22)}</div><h3>Turn on two-step sign-in to continue</h3>
          <p>It takes a minute with any authenticator app.</p><a class="btn primary" href="/account">Set it up</a></div>`)}</div>`, null, req.method === "GET" ? 200 : 403);
      return null;
    }
    if (perm && !can(s.user, perm)) {
      void h.render(req, reply, "Not allowed", html`${pageHead({ title: "Not allowed" })}${panel({}, html`<p class="dim" style="margin:0">Your account may not open this page. The super admin decides what each admin may do.</p>`)}`, null, 403);
      return null;
    }
    return s;
  };
}

export function adminRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);
  const q = (req: FastifyRequest) => String((req.query as Record<string, string>).q ?? "").trim().toLowerCase().slice(0, 100);
  const search = (req: FastifyRequest, placeholder: string) =>
    html`<div class="toolbar"><form method="get"><input type="search" name="q" value="${q(req)}" placeholder="${placeholder}" aria-label="Search"><button>Search</button></form></div>`;
  const none = html`<div class="card-body"><p class="dim" style="margin:0">None.</p></div>`;
  const unfinished = () => [
    d.config.dnsProvider === "memory" ? "station names are not published (no DNS provider)" : "",
    d.config.dnsProvider !== "challtestsrv" && d.config.acmeDirectoryUrl !== LE_PRODUCTION ? "certificates are test certificates (Let's Encrypt staging)" : "",
    d.config.smtpUrl ? "" : "no email is sent",
  ].filter(Boolean);

  // ------------------------------------------------------------------ overview

  app.get("/admin", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const n = async (sql: string) => Number((await d.db.query(sql)).rows[0].n);
    const todo = can(s.user, "settings.manage") ? unfinished() : [];
    const tiles: Html[] = [];
    if (can(s.user, "users.view")) tiles.push(html`<a class="stat" href="/admin/users"><span>People</span><b>${await n("SELECT count(*) AS n FROM users")}</b><small>${await n("SELECT count(*) AS n FROM users WHERE created_at > now() - interval '30 days'")} new in 30 days</small></a>`);
    if (can(s.user, "stations.view")) tiles.push(html`<a class="stat" href="/admin/stations"><span>Stations</span><b>${await n("SELECT count(*) AS n FROM subdomains")}</b><small>${await n("SELECT count(*) AS n FROM studios WHERE online")} online · ${await n("SELECT count(*) AS n FROM subdomains WHERE status = 'suspended'")} suspended</small></a>`);
    if (can(s.user, "logs.view")) {
      tiles.push(html`<a class="stat" href="/admin/certificates"><span>New certificates, 7 days</span><b>${await n("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")} <span>of ${d.config.certWeeklyLimit}</span></b><small>Let's Encrypt's weekly limit</small></a>`);
      tiles.push(html`<a class="stat" href="/admin/operations"><span>Problems, 24 hours</span><b>${await n("SELECT count(*) AS n FROM ops_events WHERE level = 'error' AND created_at > now() - interval '1 day'")}</b><small>DNS, certificates, jobs</small></a>`);
    }
    if (can(s.user, "billing.manage")) {
      const b = await billingState(d.db, d.config.sessionSecret);
      const rev = (await d.db.query<{ currency: string; total: string }>("SELECT currency, sum(amount_minor)::bigint AS total FROM payments WHERE status = 'paid' AND live AND paid_at > now() - interval '30 days' GROUP BY currency ORDER BY total DESC")).rows;
      tiles.push(html`<a class="stat" href="/admin/billing"><span>Revenue, 30 days</span><b>${rev.length ? rev.map((r) => formatMoney(Number(r.total), r.currency)).join(" · ") : "—"}</b><small>${b.enabled && b.provider ? `Payments on · ${PROVIDER_INFO[b.provider].name}` : "Payments off"}</small></a>`);
    }
    const recent = can(s.user, "logs.view") ? (await d.db.query(
      "SELECT a.created_at, a.action, a.target, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id ORDER BY a.created_at DESC LIMIT 8")).rows : [];
    return h.render(req, reply, "Overview", html`${pageHead({ title: "Overview", sub: s.user.role === "superadmin" ? "You are the super admin: you may do everything, and decide what other admins may do." : "What is happening on the platform." })}
      ${todo.length ? html`<div class="callout warn">${icon("alert")}<div><b>Setup is not finished</b><p>${todo.join("; ")}.</p></div><a class="btn sm" href="/admin/settings" style="margin-left:auto">Open settings</a></div>` : ""}
      ${tiles.length ? html`<div class="stats">${tiles}</div>` : ""}
      ${recent.length ? panel({ title: "Recent activity", flush: true, actions: html`<a class="btn sm" href="/admin/audit">Full audit log</a>` }, html`<div class="table-wrap"><table><tr><th>When</th><th>Who</th><th>Action</th><th>On</th></tr>${recent.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.email ?? "—"}</td><td><code>${r.action}</code></td><td>${r.target ?? ""}</td></tr>`)}</table></div>`) : ""}`, h.takeFlash(req, reply));
  });

  // ------------------------------------------------------------------ setup checks

  const setupPage = (req: FastifyRequest, reply: FastifyReply, s: Session, tested?: { dns: DnsCheckStep[] | null; names: { name: string; found: string[] }[] }) => {
    const c = d.config;
    const cloudflare = c.dnsProvider === "cloudflare";
    const production = c.acmeDirectoryUrl === LE_PRODUCTION;
    const failed = tested?.dns?.some((x) => x.ok === false);
    const row = (name: string, state: Html, text: Html | string) => html`<li><div class="row tight" style="justify-content:space-between"><b>${name}</b>${state}</div><p class="dim small" style="margin:4px 0 0">${text}</p></li>`;
    return h.render(req, reply, "Setup checks", html`${pageHead({ title: "Setup checks", sub: "Whether the platform is ready, and a step-by-step Cloudflare guide.",
        actions: html`<form method="post" action="/admin/setup/check">${csrfField(s.csrf)}<button class="primary">${cloudflare ? "Test the Cloudflare connection" : "Check the platform's addresses"}</button></form>` })}
      ${panel({ title: "Status", sub: cloudflare ? "The test adds and removes one TXT record, and looks up the platform's own addresses." : "The check looks up the platform's own addresses." }, html`<ul class="checks">
        ${row("Domain", badge("neutral", c.rootDomain), "Stations get names under this domain.")}
        ${row("DNS provider", cloudflare ? badge("ok", "Cloudflare") : badge("bad", c.dnsProvider), cloudflare ? "Station names are published at Cloudflare." : html`Station names are not published on the internet and their certificates fail. Set up Cloudflare with the guide below, then add the token in <a href="/admin/settings">Settings</a>.`)}
        ${row("Certificates", production ? badge("ok", "Let's Encrypt, production") : badge("warn", "test certificates"), production ? "Browsers trust the certificates." : html`Browsers warn about test certificates. Once a station works, choose production in <a href="/admin/settings">Settings</a>.`)}
        ${row("Email", c.smtpUrl ? badge("ok", "Sending") : badge("bad", "Not sending"), c.smtpUrl ? `As ${c.mailFrom}.` : html`Confirmation and reset links are only written to the dashboard's log. Add an SMTP address in <a href="/admin/settings">Settings</a>.`)}
      </ul>`)}
      ${tested ? panel({ title: tested.dns ? (failed ? "Cloudflare: something needs fixing" : "Cloudflare: working") : "The platform's addresses", id: "result" }, html`
        ${tested.dns ? html`<ul class="checks">${tested.dns.map((x) => html`<li>${mark(x.ok)} <b>${x.name}</b><br><span class="${x.ok === false ? "bad" : "dim"}">${x.detail}</span></li>`)}</ul><h3 style="margin:20px 0 4px;font-size:14px">The platform's addresses</h3>` : ""}
        <ul class="checks">${tested.names.map((x) => html`<li>${mark(x.found.length > 0)} <b>${x.name}</b><br><span class="${x.found.length ? "dim" : "bad"}">${x.found.length
          ? `Points to ${x.found.join(", ")}. Check that this is the right machine's public address.`
          : "Not found on the internet. Add this record at your DNS provider (the guide's step 6); a new record can take a few minutes to show."}</span></li>`)}</ul>`) : ""}
      ${cloudflareGuide(c.rootDomain)}`, h.takeFlash(req, reply));
  };

  app.get("/admin/setup", async (req, reply) => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return reply;
    return setupPage(req, reply, s);
  });
  app.post("/admin/setup/check", async (req, reply) => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return reply;
    const lookup = d.lookup ?? publicLookup;
    const wanted = [`api.${d.config.rootDomain}`, `app.${d.config.rootDomain}`, d.config.turnHost];
    const [dns, names] = await Promise.all([
      d.dns.check().catch((e): DnsCheckStep[] => [{ name: "Reach the DNS provider", ok: false, detail: (e as Error).message }]),
      Promise.all(wanted.map(async (name) => ({ name, found: await lookup(name).catch(() => [] as string[]) }))),
    ]);
    await audit(d.db, { actor: s.user.id, action: "setup.check", target: d.dns.providerName, ip: req.ip });
    return setupPage(req, reply, s, { dns, names });
  });

  // ------------------------------------------------------------------ stations

  app.get("/admin/stations", async (req, reply) => {
    const s = admin(req, reply, "stations.view");
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT sd.id, sd.label, sd.status, sd.user_id, u.email, st.last_ip, st.last_port, st.last_seen_at, st.app_version
         FROM subdomains sd JOIN users u ON u.id = sd.user_id JOIN studios st ON st.subdomain_id = sd.id
        WHERE $1 = '' OR sd.label LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%'
        ORDER BY sd.label LIMIT 200`, [q(req)])).rows;
    const manage = can(s.user, "stations.manage");
    return h.render(req, reply, "All stations", html`${pageHead({ title: "All stations", sub: "Every station address on the platform." })}
      ${manage ? panel({ title: "Create a station for someone", sub: "The owner's plan limit applies. Their access code is shown once, on the next page." }, html`
        <form method="post" action="/admin/stations">${csrfField(s.csrf)}<div class="form-grid">
          ${field({ id: "new-owner", label: "Owner's email", control: html`<input id="new-owner" name="email" type="email" required autocomplete="off" placeholder="owner@example.com">` })}
          ${field({ id: "new-label", label: "Name", control: html`<div class="input-group"><input id="new-label" name="label" required maxlength="63" autocomplete="off" placeholder="kfm"><span class="addon">.${d.config.rootDomain}</span></div>` })}</div>
          <div class="row"><button class="primary">${icon("plus", 16)} Create station</button></div></form>`) : ""}
      ${panel({ flush: true }, html`${search(req, "Search by name or owner")}
        ${rows.length ? html`<div class="table-wrap"><table><tr><th>Address</th><th>Owner</th><th>Status</th><th class="wide-only">Last address</th><th>Last seen</th><th class="wide-only">Nova</th><th class="actions"></th></tr>${rows.map((r) => html`<tr>
        <td><a href="/stations/${r.id}"><b>${fqdnOf(r.label, d.config.rootDomain)}</b></a></td>
        <td>${can(s.user, "users.view") ? html`<a href="/admin/users/${r.user_id}">${r.email}</a>` : r.email}</td><td>${statusChip(r.status, r.last_seen_at)}</td>
        <td class="wide-only">${r.last_ip ?? "—"}${r.last_port ? `:${r.last_port}` : ""}</td><td>${when(r.last_seen_at)}</td><td class="wide-only">${r.app_version ?? "—"}</td>
        <td class="actions">${manage ? html`<form class="inline" method="post" action="/admin/stations/${r.id}/${r.status === "active" ? "suspend" : "unsuspend"}" data-confirm="${r.status === "active" ? "Suspend" : "Restore"} ${r.label}?">${csrfField(s.csrf)}<button class="${r.status === "active" ? "danger" : ""}">${r.status === "active" ? "Suspend" : "Restore"}</button></form>` : ""}
          <a class="btn sm" href="/stations/${r.id}">Open</a></td>
      </tr>`)}</table></div>` : emptyState("No stations", q(req) ? "Nothing matches that search." : "No station has been claimed yet.")}`)}`, h.takeFlash(req, reply));
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    app.post(`/admin/stations/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply, "stations.manage");
      if (!s) return reply;
      const to = /^\/stations\/\d+$/.test(h.form(req).back ?? "") ? h.form(req).back : "/admin/stations";
      try {
        await subs.setSuspended(h.ctx(), h.actor(s, req), Number((req.params as { id: string }).id), on);
      } catch (e) {
        if (e instanceof subs.SubdomainError) return h.back(reply, to, { kind: "bad", text: e.message });
        throw e;
      }
      return h.back(reply, to, { kind: "ok", text: on ? "Suspended: its DNS record is gone and the API answers 403." : "Restored." });
    });
  }
  app.post("/admin/stations", async (req, reply) => {
    const s = admin(req, reply, "stations.manage");
    if (!s) return reply;
    const f = h.form(req);
    const owner = (await d.db.query<{ id: number }>("SELECT id FROM users WHERE lower(email) = lower($1)", [String(f.email ?? "").trim()])).rows[0];
    if (!owner) return h.back(reply, "/admin/stations", { kind: "bad", text: `There is no account for ${String(f.email ?? "").trim() || "that email"}. Add the person first (People).` });
    const label = normaliseLabel(f.label, d.config.rootDomain);
    try {
      const { accessCode } = await subs.claim(h.ctx(), h.actor(s, req), label, owner.id);
      return h.codeOnce(req, reply, label, accessCode, `${fqdnOf(label, d.config.rootDomain)} is created`);
    } catch (e) {
      if (e instanceof subs.SubdomainError) return h.back(reply, f.back === "user" ? `/admin/users/${owner.id}` : "/admin/stations", { kind: "bad", text: e.message });
      throw e;
    }
  });

  // ------------------------------------------------------------------ names

  app.get("/admin/names", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const names = (await d.db.query("SELECT label, kind, reason, created_at FROM reserved_names ORDER BY kind, label")).rows;
    const cooling = (await d.db.query("SELECT label, available_after FROM name_cooldowns WHERE available_after > now() ORDER BY available_after")).rows;
    return h.render(req, reply, "Names", html`${pageHead({ title: "Names", sub: "Names nobody may claim, and names waiting 30 days after a rename or delete." })}
      ${panel({ title: "Reserve or block a name", sub: "Existing stations keep their names." }, html`<form method="post" action="/admin/names">${csrfField(s.csrf)}<div class="form-grid">
        ${field({ id: "n-label", label: "Name", control: html`<input id="n-label" name="label" required maxlength="63" autocomplete="off">` })}
        ${field({ id: "n-kind", label: "Kind", control: html`<select id="n-kind" name="kind"><option value="blocked">Blocked (not allowed)</option><option value="reserved">Reserved (the platform's)</option></select>` })}
        ${field({ id: "n-reason", label: "Reason (optional)", control: html`<input id="n-reason" name="reason" maxlength="200">` })}</div>
        <div class="row"><button class="primary">Add name</button></div></form>`)}
      ${panel({ title: "Reserved and blocked", flush: true }, html`<div class="table-wrap"><table><tr><th>Name</th><th>Kind</th><th>Reason</th><th class="actions"></th></tr>${names.map((n) => html`<tr><td><b>${n.label}</b></td><td>${n.kind === "blocked" ? badge("bad", "Blocked") : badge("neutral", "Reserved")}</td><td class="dim">${n.reason ?? ""}</td>
        <td class="actions"><form class="inline" method="post" action="/admin/names/remove" data-confirm="Remove ${n.label} from the list?">${csrfField(s.csrf)}<input type="hidden" name="label" value="${n.label}"><button>Remove</button></form></td></tr>`)}</table></div>`)}
      ${panel({ title: "Cooling down", flush: true }, cooling.length ? html`<div class="table-wrap"><table><tr><th>Name</th><th>Free again</th><th class="actions"></th></tr>${cooling.map((c) => html`<tr><td><b>${c.label}</b></td><td>${when(c.available_after)}</td>
        <td class="actions"><form class="inline" method="post" action="/admin/names/release" data-confirm="Release ${c.label} now?">${csrfField(s.csrf)}<input type="hidden" name="label" value="${c.label}"><button>Release now</button></form></td></tr>`)}</table></div>` : none)}`,
    h.takeFlash(req, reply));
  });
  app.post("/admin/names", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const f = h.form(req);
    const label = String(f.label ?? "").trim().toLowerCase();
    if (!label || label.length > 63 || !/^[a-z0-9-]+$/.test(label)) return h.back(reply, "/admin/names", { kind: "bad", text: "Letters, digits and hyphens only." });
    const kind = f.kind === "reserved" ? "reserved" : "blocked";
    await d.db.query("INSERT INTO reserved_names (label, kind, reason, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (label) DO UPDATE SET kind = EXCLUDED.kind, reason = EXCLUDED.reason",
      [label, kind, String(f.reason ?? "").slice(0, 200) || null, s.user.id]);
    await audit(d.db, { actor: s.user.id, action: `name.${kind}`, target: label, ip: req.ip });
    return h.back(reply, "/admin/names", { kind: "ok", text: `${label} is ${kind}. Existing stations keep their names.` });
  });
  app.post("/admin/names/remove", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const label = String(h.form(req).label ?? "");
    await d.db.query("DELETE FROM reserved_names WHERE label = $1", [label]);
    await audit(d.db, { actor: s.user.id, action: "name.unreserve", target: label, ip: req.ip });
    return h.back(reply, "/admin/names", { kind: "ok", text: formError(label) ? `${label} removed.` : `${label} can be claimed.` });
  });
  app.post("/admin/names/release", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const label = String(h.form(req).label ?? "");
    await subs.forceRelease(d.db, h.actor(s, req), label);
    return h.back(reply, "/admin/names", { kind: "ok", text: `${label} is free now.` });
  });

  // ------------------------------------------------------------------ certificates

  app.get("/admin/certificates", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const week = Number((await d.db.query("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")).rows[0].n);
    const renewals = Number((await d.db.query("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NOT NULL")).rows[0].n);
    const queued = (await d.db.query("SELECT fqdn, created_at, next_attempt_at, error FROM certificates WHERE status = 'pending' ORDER BY created_at")).rows;
    const failed = (await d.db.query("SELECT fqdn, created_at, error FROM certificates WHERE status = 'failed' AND created_at > now() - interval '30 days' ORDER BY created_at DESC LIMIT 50")).rows;
    const upcoming = (await d.db.query(
      "SELECT fqdn, expires_at, ari_renewal_after FROM certificates WHERE status = 'issued' ORDER BY coalesce(ari_renewal_after, expires_at - interval '30 days') LIMIT 50")).rows;
    const near = week >= d.config.certWeeklyLimit - 5;
    return h.render(req, reply, "Certificates", html`${pageHead({ title: "Certificates", sub: "Station certificates from Let's Encrypt, issued by the worker over DNS-01." })}
      <div class="stats"><div class="stat"><span>New, last 7 days</span><b>${week} <span>of ${d.config.certWeeklyLimit}</span></b><small>${near ? "Near the limit: new ones wait in the queue." : "Let's Encrypt's limit per registered domain"}</small></div>
        <div class="stat"><span>Renewals, last 7 days</span><b>${renewals}</b><small>Exempt from the limit (ARI)</small></div>
        <div class="stat"><span>Waiting</span><b>${queued.length}</b></div><div class="stat"><span>Failed, 30 days</span><b>${failed.length}</b></div></div>
      ${near ? html`<div class="callout warn">${icon("alert")}<div><b>Near the weekly limit</b><p>Consider asking Let's Encrypt for a higher limit, or Public Suffix List inclusion.</p></div></div>` : ""}
      ${panel({ title: "Waiting", flush: true }, queued.length ? html`<div class="table-wrap"><table><tr><th>Name</th><th>Asked</th><th>Next try</th><th>Note</th></tr>${queued.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td>${when(c.next_attempt_at)}</td><td class="dim">${c.error ?? ""}</td></tr>`)}</table></div>` : none)}
      ${panel({ title: "Failed, 30 days", flush: true }, failed.length ? html`<div class="table-wrap"><table><tr><th>Name</th><th>When</th><th>Error</th></tr>${failed.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td class="bad">${c.error ?? ""}</td></tr>`)}</table></div>` : none)}
      ${panel({ title: "Upcoming renewals", flush: true }, upcoming.length ? html`<div class="table-wrap"><table><tr><th>Name</th><th>Renew from</th><th>Expires</th></tr>${upcoming.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.ari_renewal_after ?? new Date(new Date(c.expires_at).getTime() - 30 * 86400_000))}${c.ari_renewal_after ? html` ${badge("info", "ARI")}` : ""}</td><td>${when(c.expires_at)}</td></tr>`)}</table></div>` : none)}`);
  });

  // ------------------------------------------------------------------ TURN usage

  app.get("/admin/turn", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT sd.label, sum(t.bytes_relayed)::bigint AS b, sum(t.sessions)::int AS n
         FROM turn_usage t JOIN studios st ON st.id = t.studio_id JOIN subdomains sd ON sd.id = st.subdomain_id
        WHERE t.day >= current_date - 30 GROUP BY sd.label ORDER BY b DESC LIMIT 100`)).rows;
    return h.render(req, reply, "Audio relay", html`${pageHead({ title: "Audio relay", sub: "Audio relayed by TURN in the last 30 days, for stations whose presenters could not connect directly. Largest first." })}
      ${panel({ flush: true }, rows.length ? html`<div class="table-wrap"><table><tr><th>Station</th><th class="num">Relayed</th><th class="num">Sessions</th></tr>${rows.map((r) => html`<tr><td>${r.label}</td><td class="num">${bytes(Number(r.b))}</td><td class="num">${r.n}</td></tr>`)}</table></div>` : emptyState("Nothing relayed", "Every presenter connected directly."))}`);
  });

  // ------------------------------------------------------------------ logs

  app.get("/admin/audit", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT a.created_at, a.action, a.target, a.ip, a.metadata, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
        WHERE $1 = '' OR a.action LIKE '%' || $1 || '%' OR a.target LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%'
        ORDER BY a.created_at DESC LIMIT 300`, [q(req)])).rows;
    return h.render(req, reply, "Audit log", html`${pageHead({ title: "Audit log", sub: "Every change, who made it and from where. Secrets are never written here." })}
      ${panel({ flush: true }, html`${search(req, "Search action, name or person")}<div class="table-wrap"><table><tr><th>When</th><th>Who</th><th>Action</th><th>On</th><th class="wide-only">From</th><th class="wide-only">Details</th></tr>${rows.map((r) => html`<tr>
        <td style="white-space:nowrap">${when(r.created_at)}</td><td>${r.email ?? "—"}</td><td><code>${r.action}</code></td><td>${r.target ?? ""}</td><td class="wide-only">${r.ip ?? ""}</td>
        <td class="wide-only dim small">${Object.keys(r.metadata ?? {}).length ? JSON.stringify(r.metadata) : ""}</td></tr>`)}</table></div>`)}`);
  });

  app.get("/admin/operations", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const rows = (await d.db.query("SELECT created_at, kind, level, target, message FROM ops_events ORDER BY created_at DESC LIMIT 300")).rows;
    return h.render(req, reply, "DNS & ACME events", html`${pageHead({ title: "DNS & ACME events", sub: "Problems with DNS, certificates, probes and background jobs. Admins get a daily email of new errors." })}
      ${panel({ flush: true }, rows.length ? html`<div class="table-wrap"><table><tr><th>When</th><th>Kind</th><th>Name</th><th>Message</th></tr>${rows.map((r) => html`<tr>
        <td style="white-space:nowrap">${when(r.created_at)}</td><td>${r.level === "error" ? badge("bad", r.kind) : badge("neutral", r.kind)}</td><td>${r.target ?? ""}</td><td class="${r.level === "error" ? "bad" : "dim"}">${r.message}</td></tr>`)}</table></div>` : emptyState("No events", "Nothing has gone wrong."))}`);
  });
}
