/**
 * The admin dashboard (spec section 2): people and stations (search, suspend), reserved
 * and blocked names, certificates against the CA's weekly limit, TURN usage, the audit
 * log and DNS/ACME problems. Role `admin` only.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { audit } from "../lib/audit.js";
import { formError, fqdnOf } from "../lib/names.js";
import * as subs from "../lib/subdomains.js";
import type { DashDeps, Helpers } from "./app.js";
import { statusChip } from "./app.js";
import { bytes, csrfField, html, when } from "./html.js";
import type { Session } from "./session.js";

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
  const tabs = html`<p class="row"><a href="/admin">Overview</a><a href="/admin/users">People</a><a href="/admin/stations">Stations</a><a href="/admin/names">Names</a>
    <a href="/admin/certificates">Certificates</a><a href="/admin/turn">Audio relay</a><a href="/admin/audit">Audit log</a><a href="/admin/operations">DNS / ACME problems</a></p>`;

  app.get("/admin", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const n = async (sql: string) => Number((await d.db.query(sql)).rows[0].n);
    return h.render(req, reply, "Admin", html`<div class="card"><h1>Admin</h1>${tabs}<div class="grid">
      <span class="dim">People</span><span>${await n("SELECT count(*) AS n FROM users")}</span>
      <span class="dim">Stations</span><span>${await n("SELECT count(*) AS n FROM subdomains")} (${await n("SELECT count(*) AS n FROM studios WHERE online")} online, ${await n("SELECT count(*) AS n FROM subdomains WHERE status = 'suspended'")} suspended)</span>
      <span class="dim">New certificates, 7 days</span><span>${await n("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")} of ${d.config.certWeeklyLimit}</span>
      <span class="dim">Problems, 24 h</span><span>${await n("SELECT count(*) AS n FROM ops_events WHERE level = 'error' AND created_at > now() - interval '1 day'")}</span>
      </div></div>`, h.takeFlash(req, reply));
  });

  // ------------------------------------------------------------------ people

  app.get("/admin/users", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, count(sd.id)::int AS stations
         FROM users u LEFT JOIN subdomains sd ON sd.user_id = u.id
        WHERE $1 = '' OR lower(u.email) LIKE '%' || $1 || '%' GROUP BY u.id ORDER BY u.created_at DESC LIMIT 200`, [q(req)])).rows;
    return h.render(req, reply, "People", html`<div class="card"><h1>People</h1>${tabs}
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
    return h.render(req, reply, "Stations", html`<div class="card"><h1>Stations</h1>${tabs}
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
    return h.render(req, reply, "Names", html`<div class="card"><h1>Reserved and blocked names</h1>${tabs}
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
    return h.render(req, reply, "Certificates", html`<div class="card"><h1>Certificates</h1>${tabs}
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
    return h.render(req, reply, "Audio relay", html`<div class="card"><h1>Audio relay (TURN), 30 days</h1>${tabs}
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
    return h.render(req, reply, "Audit log", html`<div class="card"><h1>Audit log</h1>${tabs}
      <form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search action, name or person"> <button>Search</button></form>
      <table><tr><th>When</th><th>Who</th><th>What</th><th>On</th><th>From</th><th>Details</th></tr>${rows.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.email ?? "—"}</td><td>${r.action}</td><td>${r.target ?? ""}</td><td>${r.ip ?? ""}</td>
        <td class="dim">${Object.keys(r.metadata ?? {}).length ? JSON.stringify(r.metadata) : ""}</td></tr>`)}</table></div>`);
  });

  app.get("/admin/operations", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query("SELECT created_at, kind, level, target, message FROM ops_events ORDER BY created_at DESC LIMIT 300")).rows;
    return h.render(req, reply, "DNS / ACME", html`<div class="card"><h1>DNS, certificate and probe events</h1>${tabs}
      <table><tr><th>When</th><th>Kind</th><th>Name</th><th>Message</th></tr>${rows.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.kind}</td><td>${r.target ?? ""}</td><td class="${r.level === "error" ? "bad" : "dim"}">${r.message}</td></tr>`)}</table></div>`);
  });
}
