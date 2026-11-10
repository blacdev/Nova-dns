/**
 * The admin dashboard (spec section 2): people and stations (search, suspend), reserved
 * and blocked names, certificates against the CA's weekly limit, TURN usage, the audit
 * log and DNS/ACME problems. Role `admin` only.
 */

import { Resolver } from "node:dns/promises";
import { readFileSync } from "node:fs";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { DnsCheckStep } from "../dns/dns.js";
import { audit } from "../lib/audit.js";
import { formError, fqdnOf } from "../lib/names.js";
import * as subs from "../lib/subdomains.js";
import type { DashDeps, Helpers } from "./app.js";
import { statusChip } from "./app.js";
import { bytes, csrfField, html, raw, when, type Html } from "./html.js";
import { headings, markdown } from "./markdown.js";
import type { Session } from "./session.js";

const LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";

/** docs/cloudflare-setup.md, with the guide's example domain replaced by this platform's, beside its contents. */
function cloudflareGuide(rootDomain: string): Html {
  try {
    const text = readFileSync(new URL("../../docs/cloudflare-setup.md", import.meta.url), "utf8").replaceAll("yourdomain.com", rootDomain);
    return html`<div class="guide"><nav class="toc" aria-label="In this guide"><b>In this guide</b>${headings(text).map((h) => html`<a href="#${h.id}">${h.text}</a>`)}</nav>
      <div class="card doc" id="guide">${markdown(text)}</div></div>`;
  } catch {
    return html`<div class="card"><p class="dim">The guide (docs/cloudflare-setup.md) is not on this machine. It is in the project's repository.</p></div>`;
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

export function adminRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = h.signedIn(req, reply);
    if (!s) return null;
    if (s.user.role !== "admin") {
      void h.render(req, reply, "Not found", html`<div class="card"><h1>Not found</h1></div>`, null, 404);
      return null;
    }
    return s;
  };
  const q = (req: FastifyRequest) => String((req.query as Record<string, string>).q ?? "").trim().toLowerCase();
  const TABS: [string, string][] = [["/admin", "Overview"], ["/admin/users", "People"], ["/admin/stations", "Stations"], ["/admin/names", "Names"],
    ["/admin/certificates", "Certificates"], ["/admin/turn", "Audio relay"], ["/admin/audit", "Audit log"], ["/admin/operations", "DNS / ACME problems"], ["/admin/setup", "Setup"]];
  /** The tab bar above every admin page, with the page being shown marked. */
  const tabs = (req: FastifyRequest) => {
    const path = req.url.split("?")[0];
    const here = TABS.filter(([href]) => path === href || path.startsWith(`${href}/`)).sort((x, y) => y[0].length - x[0].length)[0]?.[0];
    return html`<nav class="tabs" aria-label="Admin">${TABS.map(([href, text]) => html`<a href="${href}"${href === here ? raw(' aria-current="page"') : ""}>${text}</a>`)}</nav>`;
  };
  const unfinished = () => [
    d.config.dnsProvider === "memory" ? "station names are not published (no DNS provider)" : "",
    d.config.dnsProvider !== "challtestsrv" && d.config.acmeDirectoryUrl !== LE_PRODUCTION ? "certificates are test certificates (Let's Encrypt staging)" : "",
    d.config.smtpUrl ? "" : "no email is sent",
  ].filter(Boolean);

  app.get("/admin", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const n = async (sql: string) => Number((await d.db.query(sql)).rows[0].n);
    const todo = unfinished();
    return h.render(req, reply, "Admin", html`${tabs(req)}
      ${todo.length ? html`<div class="card notice"><b>Setup is not finished:</b> ${todo.join("; ")}. <a href="/admin/setup">Open Setup</a></div>` : ""}
      <div class="stats">
        <a class="stat" href="/admin/users"><b>${await n("SELECT count(*) AS n FROM users")}</b><span>People</span></a>
        <a class="stat" href="/admin/stations"><b>${await n("SELECT count(*) AS n FROM subdomains")}</b><span>Stations · ${await n("SELECT count(*) AS n FROM studios WHERE online")} online · ${await n("SELECT count(*) AS n FROM subdomains WHERE status = 'suspended'")} suspended</span></a>
        <a class="stat" href="/admin/certificates"><b>${await n("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")} <span>of ${d.config.certWeeklyLimit}</span></b><span>New certificates, 7 days</span></a>
        <a class="stat" href="/admin/operations"><b>${await n("SELECT count(*) AS n FROM ops_events WHERE level = 'error' AND created_at > now() - interval '1 day'")}</b><span>Problems, 24 h</span></a>
      </div>`, h.takeFlash(req, reply));
  });

  // ------------------------------------------------------------------ setup

  const setupPage = (req: FastifyRequest, reply: FastifyReply, s: Session, tested?: { dns: DnsCheckStep[] | null; names: { name: string; found: string[] }[] }) => {
    const c = d.config;
    const cloudflare = c.dnsProvider === "cloudflare";
    const production = c.acmeDirectoryUrl === LE_PRODUCTION;
    const failed = tested?.dns?.some((x) => x.ok === false);
    return h.render(req, reply, "Setup", html`${tabs(req)}<div class="card"><h1>Setup</h1><div class="grid">
      <span class="dim">Domain</span><span>${c.rootDomain}</span>
      <span class="dim">DNS provider</span><span>${cloudflare ? html`<span class="chip ok">Cloudflare</span>` : html`<span class="chip bad">${c.dnsProvider}</span> Station names are not published on the internet and their certificates fail. Set up Cloudflare with the guide below.`}</span>
      <span class="dim">Certificates</span><span>${production ? html`<span class="chip ok">Let's Encrypt, production</span>` : html`<span class="chip bad">test certificates</span> Browsers warn about these. Once a station works, run <span class="mono">./setup.sh</span> again and choose production.`}</span>
      <span class="dim">Email</span><span>${c.smtpUrl ? html`<span class="chip ok">sending</span> as ${c.mailFrom}` : html`<span class="chip bad">not sending</span> Confirmation and reset links are only written to the dashboard's log. Run <span class="mono">./setup.sh</span> again to add an SMTP address.`}</span>
      <span class="dim">Admins</span><span>${c.adminEmails.join(", ") || "none named"}</span>
      </div>
      <form method="post" action="/admin/setup/check">${csrfField(s.csrf)}<div class="row"><button class="primary">${cloudflare ? "Test the Cloudflare connection" : "Check the platform's addresses"}</button>
        <span class="dim">${cloudflare ? "Adds and removes one test record, and looks up the platform's own addresses." : "Looks up the platform's own addresses."}</span></div></form></div>
      ${tested ? html`<div class="card" id="result"><h2>${tested.dns ? (failed ? "Cloudflare: something needs fixing" : "Cloudflare: working") : "The platform's addresses"}</h2>
        ${tested.dns ? html`<ul class="checks">${tested.dns.map((x) => html`<li>${mark(x.ok)} <b>${x.name}</b><br><span class="${x.ok === false ? "bad" : "dim"}">${x.detail}</span></li>`)}</ul><h2 style="margin-top:20px">The platform's addresses</h2>` : ""}
        <ul class="checks">${tested.names.map((x) => html`<li>${mark(x.found.length > 0)} <b>${x.name}</b><br><span class="${x.found.length ? "dim" : "bad"}">${x.found.length
          ? `Points to ${x.found.join(", ")}. Check that this is the right machine's public address.`
          : "Not found on the internet. Add this record at your DNS provider (the guide's step 6); a new record can take a few minutes to show."}</span></li>`)}</ul></div>` : ""}
      ${cloudflareGuide(c.rootDomain)}`, h.takeFlash(req, reply));
  };

  app.get("/admin/setup", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    return setupPage(req, reply, s);
  });
  app.post("/admin/setup/check", async (req, reply) => {
    const s = admin(req, reply);
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

  // ------------------------------------------------------------------ people

  app.get("/admin/users", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, count(sd.id)::int AS stations
         FROM users u LEFT JOIN subdomains sd ON sd.user_id = u.id
        WHERE $1 = '' OR lower(u.email) LIKE '%' || $1 || '%' GROUP BY u.id ORDER BY u.created_at DESC LIMIT 200`, [q(req)])).rows;
    return h.render(req, reply, "People", html`${tabs(req)}<div class="card"><h1>People</h1>
      <form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search by email"> <button>Search</button></form>
      <table><tr><th>Email</th><th>Role</th><th>Status</th><th>Stations</th><th>Joined</th><th></th></tr>${rows.map((u) => html`<tr>
        <td>${u.email}${u.email_verified_at ? "" : html` <span class="chip">unconfirmed</span>`}</td><td>${u.role}</td>
        <td>${u.status === "active" ? html`<span class="chip ok">active</span>` : html`<span class="chip bad">suspended</span>`}</td>
        <td><a href="/admin/stations?q=${u.email}">${u.stations}</a></td><td>${when(u.created_at)}</td>
        <td>${u.id === s.user.id ? "" : html`<form class="inline" method="post" action="/admin/users/${u.id}/${u.status === "active" ? "suspend" : "unsuspend"}" data-confirm="${u.status === "active" ? "Suspend" : "Restore"} ${u.email} and all their stations?">${csrfField(s.csrf)}<button class="${u.status === "active" ? "danger" : ""}">${u.status === "active" ? "Suspend" : "Restore"}</button></form>`}</td>
      </tr>`)}</table></div>`, h.takeFlash(req, reply));
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    app.post(`/admin/users/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply);
      if (!s) return reply;
      const id = Number((req.params as { id: string }).id);
      if (id === s.user.id) return h.back(reply, "/admin/users", { kind: "bad", text: "You cannot suspend yourself." });
      await subs.setUserSuspended(h.ctx(), h.actor(s, req), id, on);
      return h.back(reply, "/admin/users", { kind: "ok", text: on ? "Suspended, with their stations' DNS removed." : "Restored." });
    });
  }

  // ------------------------------------------------------------------ stations

  app.get("/admin/stations", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT sd.id, sd.label, sd.status, u.email, st.last_ip, st.last_port, st.last_seen_at, st.app_version
         FROM subdomains sd JOIN users u ON u.id = sd.user_id JOIN studios st ON st.subdomain_id = sd.id
        WHERE $1 = '' OR sd.label LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%'
        ORDER BY sd.label LIMIT 200`, [q(req)])).rows;
    return h.render(req, reply, "Stations", html`${tabs(req)}<div class="card"><h1>Stations</h1>
      <form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search by name or owner"> <button>Search</button></form>
      <table><tr><th>Address</th><th>Owner</th><th>Status</th><th>Last address</th><th>Last seen</th><th>Nova</th><th></th></tr>${rows.map((r) => html`<tr>
        <td><a href="/stations/${r.id}">${fqdnOf(r.label, d.config.rootDomain)}</a></td><td>${r.email}</td><td>${statusChip(r.status, r.last_seen_at)}</td>
        <td>${r.last_ip ?? "—"}${r.last_port ? `:${r.last_port}` : ""}</td><td>${when(r.last_seen_at)}</td><td>${r.app_version ?? "—"}</td>
        <td><form class="inline" method="post" action="/admin/stations/${r.id}/${r.status === "active" ? "suspend" : "unsuspend"}" data-confirm="${r.status === "active" ? "Suspend" : "Restore"} ${r.label}?">${csrfField(s.csrf)}<button class="${r.status === "active" ? "danger" : ""}">${r.status === "active" ? "Suspend" : "Restore"}</button></form></td>
      </tr>`)}</table></div>`, h.takeFlash(req, reply));
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    app.post(`/admin/stations/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply);
      if (!s) return reply;
      await subs.setSuspended(h.ctx(), h.actor(s, req), Number((req.params as { id: string }).id), on);
      return h.back(reply, "/admin/stations", { kind: "ok", text: on ? "Suspended: its DNS record is gone and the API answers 403." : "Restored." });
    });
  }

  // ------------------------------------------------------------------ names

  app.get("/admin/names", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const names = (await d.db.query("SELECT label, kind, reason, created_at FROM reserved_names ORDER BY kind, label")).rows;
    const cooling = (await d.db.query("SELECT label, available_after FROM name_cooldowns WHERE available_after > now() ORDER BY available_after")).rows;
    return h.render(req, reply, "Names", html`${tabs(req)}<div class="card"><h1>Reserved and blocked names</h1>
      <form method="post" action="/admin/names">${csrfField(s.csrf)}<div class="row">
        <input name="label" placeholder="name" required maxlength="63" style="max-width:200px">
        <select name="kind"><option value="blocked">Blocked (not allowed)</option><option value="reserved">Reserved (the platform's)</option></select>
        <input name="reason" placeholder="Why (optional)" style="max-width:260px"><button class="primary">Add</button></div></form>
      <table><tr><th>Name</th><th>Kind</th><th>Why</th><th></th></tr>${names.map((n) => html`<tr><td>${n.label}</td><td>${n.kind}</td><td>${n.reason ?? ""}</td>
        <td><form class="inline" method="post" action="/admin/names/remove">${csrfField(s.csrf)}<input type="hidden" name="label" value="${n.label}"><button>Remove</button></form></td></tr>`)}</table></div>
      <div class="card"><h2>Cooling down</h2>${cooling.length ? html`<table><tr><th>Name</th><th>Free again</th><th></th></tr>${cooling.map((c) => html`<tr><td>${c.label}</td><td>${when(c.available_after)}</td>
        <td><form class="inline" method="post" action="/admin/names/release" data-confirm="Release ${c.label} now?">${csrfField(s.csrf)}<input type="hidden" name="label" value="${c.label}"><button>Release now</button></form></td></tr>`)}</table>` : html`<p class="dim">None.</p>`}</div>`,
    h.takeFlash(req, reply));
  });
  app.post("/admin/names", async (req, reply) => {
    const s = admin(req, reply);
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
    const s = admin(req, reply);
    if (!s) return reply;
    const label = String(h.form(req).label ?? "");
    await d.db.query("DELETE FROM reserved_names WHERE label = $1", [label]);
    await audit(d.db, { actor: s.user.id, action: "name.unreserve", target: label, ip: req.ip });
    return h.back(reply, "/admin/names", { kind: "ok", text: formError(label) ? `${label} removed.` : `${label} can be claimed.` });
  });
  app.post("/admin/names/release", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const label = String(h.form(req).label ?? "");
    await subs.forceRelease(d.db, h.actor(s, req), label);
    return h.back(reply, "/admin/names", { kind: "ok", text: `${label} is free now.` });
  });

  // ------------------------------------------------------------------ certificates

  app.get("/admin/certificates", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const week = Number((await d.db.query("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")).rows[0].n);
    const renewals = Number((await d.db.query("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NOT NULL")).rows[0].n);
    const queued = (await d.db.query("SELECT fqdn, created_at, next_attempt_at, error FROM certificates WHERE status = 'pending' ORDER BY created_at")).rows;
    const failed = (await d.db.query("SELECT fqdn, created_at, error FROM certificates WHERE status = 'failed' AND created_at > now() - interval '30 days' ORDER BY created_at DESC LIMIT 50")).rows;
    const upcoming = (await d.db.query(
      "SELECT fqdn, expires_at, ari_renewal_after FROM certificates WHERE status = 'issued' ORDER BY coalesce(ari_renewal_after, expires_at - interval '30 days') LIMIT 50")).rows;
    const near = week >= d.config.certWeeklyLimit - 5;
    return h.render(req, reply, "Certificates", html`${tabs(req)}<div class="card"><h1>Certificates</h1>
      <p class="${near ? "bad" : ""}"><b>${week}</b> new certificates in the last 7 days, of Let's Encrypt's ${d.config.certWeeklyLimit} per registered domain (plus ${renewals} renewals, which ARI exempts).
      ${near ? " New ones wait in the queue once the limit is near. Consider asking Let's Encrypt for a higher limit, or Public Suffix List inclusion." : ""}</p></div>
      <div class="card"><h2>Waiting (${queued.length})</h2>${queued.length ? html`<table><tr><th>Name</th><th>Asked</th><th>Next try</th><th>Note</th></tr>${queued.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td>${when(c.next_attempt_at)}</td><td class="dim">${c.error ?? ""}</td></tr>`)}</table>` : html`<p class="dim">None.</p>`}</div>
      <div class="card"><h2>Failed, 30 days (${failed.length})</h2>${failed.length ? html`<table><tr><th>Name</th><th>When</th><th>Error</th></tr>${failed.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td class="bad">${c.error ?? ""}</td></tr>`)}</table>` : html`<p class="dim">None.</p>`}</div>
      <div class="card"><h2>Upcoming renewals</h2><table><tr><th>Name</th><th>Renew from</th><th>Expires</th></tr>${upcoming.map((c) => html`<tr><td>${c.fqdn}</td><td>${when(c.ari_renewal_after ?? new Date(new Date(c.expires_at).getTime() - 30 * 86400_000))}${c.ari_renewal_after ? html` <span class="chip">ARI</span>` : ""}</td><td>${when(c.expires_at)}</td></tr>`)}</table></div>`);
  });

  // ------------------------------------------------------------------ TURN usage

  app.get("/admin/turn", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT sd.label, sum(t.bytes_relayed)::bigint AS b, sum(t.sessions)::int AS n
         FROM turn_usage t JOIN studios st ON st.id = t.studio_id JOIN subdomains sd ON sd.id = st.subdomain_id
        WHERE t.day >= current_date - 30 GROUP BY sd.label ORDER BY b DESC LIMIT 100`)).rows;
    return h.render(req, reply, "Audio relay", html`${tabs(req)}<div class="card"><h1>Audio relay (TURN), 30 days</h1>
      <p class="dim">Audio relayed for stations whose presenters could not connect directly. Largest first.</p>
      ${rows.length ? html`<table><tr><th>Station</th><th>Relayed</th><th>Sessions</th></tr>${rows.map((r) => html`<tr><td>${r.label}</td><td>${bytes(Number(r.b))}</td><td>${r.n}</td></tr>`)}</table>` : html`<p class="dim">Nothing relayed.</p>`}</div>`);
  });

  // ------------------------------------------------------------------ logs

  app.get("/admin/audit", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT a.created_at, a.action, a.target, a.ip, a.metadata, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
        WHERE $1 = '' OR a.action LIKE '%' || $1 || '%' OR a.target LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%'
        ORDER BY a.created_at DESC LIMIT 300`, [q(req)])).rows;
    return h.render(req, reply, "Audit log", html`${tabs(req)}<div class="card"><h1>Audit log</h1>
      <form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search action, name or person"> <button>Search</button></form>
      <table><tr><th>When</th><th>Who</th><th>What</th><th>On</th><th>From</th><th>Details</th></tr>${rows.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.email ?? "—"}</td><td>${r.action}</td><td>${r.target ?? ""}</td><td>${r.ip ?? ""}</td>
        <td class="dim">${Object.keys(r.metadata ?? {}).length ? JSON.stringify(r.metadata) : ""}</td></tr>`)}</table></div>`);
  });

  app.get("/admin/operations", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query("SELECT created_at, kind, level, target, message FROM ops_events ORDER BY created_at DESC LIMIT 300")).rows;
    return h.render(req, reply, "DNS / ACME", html`${tabs(req)}<div class="card"><h1>DNS, certificate and probe events</h1>
      <table><tr><th>When</th><th>Kind</th><th>Name</th><th>Message</th></tr>${rows.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.kind}</td><td>${r.target ?? ""}</td><td class="${r.level === "error" ? "bad" : "dim"}">${r.message}</td></tr>`)}</table></div>`);
  });
}
