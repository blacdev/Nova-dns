/**
 * Admin > People and Admin > Plans: add a person, change their plan or their own station
 * limit, confirm their email, send a reset link, turn off their two-step sign-in, suspend
 * or delete them, create stations for them; and, for the super admin only, roles and
 * permissions. Who may act on whom is in rbac.ts (mayActOn).
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { transaction } from "../db/db.js";
import { audit } from "../lib/audit.js";
import { hit, LIMITS } from "../lib/limits.js";
import { fqdnOf } from "../lib/names.js";
import { allowance, stationWord } from "../lib/plans.js";
import { ALL_PERMISSIONS, can, cleanPermissions, isSuper, mayActOn, PERMISSIONS, type Role } from "../lib/rbac.js";
import { hashSecret, newToken, verifySecret } from "../lib/secrets.js";
import * as subs from "../lib/subdomains.js";
import { adminGuard, adminTabs } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { statusChip } from "./app.js";
import { csrfField, html, when, type Html } from "./html.js";
import type { Session } from "./session.js";

interface UserRow {
  id: number;
  email: string;
  role: Role;
  status: string;
  permissions: string[];
  email_verified_at: Date | null;
  totp: boolean;
  created_at: Date;
  plan_id: number | null;
  station_limit_override: number | null;
}

interface PlanRow {
  id: number;
  name: string;
  station_limit: number;
  is_default: boolean;
  people: number;
}

const roleName = (r: string) => (r === "superadmin" ? "super admin" : r);
const isUnique = (e: unknown) => (e as { code?: string })?.code === "23505";

/** Every value of a form field that may be repeated (checkboxes). */
const many = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

export function peopleRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);
  const q = (req: FastifyRequest) => String((req.query as Record<string, string>).q ?? "").trim().toLowerCase();
  const plans = async () => (await d.db.query<PlanRow>(
    `SELECT p.id, p.name, p.station_limit, p.is_default, count(u.id)::int AS people
       FROM plans p LEFT JOIN users u ON u.plan_id = p.id GROUP BY p.id ORDER BY p.station_limit, lower(p.name)`)).rows;
  const loadUser = async (id: number) => Number.isSafeInteger(id) ? (await d.db.query<UserRow>(
    `SELECT id, email, role, status, permissions, email_verified_at, totp_secret_enc IS NOT NULL AS totp, created_at, plan_id, station_limit_override
       FROM users WHERE id = $1`, [id])).rows[0] : undefined;
  const idOf = (req: FastifyRequest) => Number((req.params as { id: string }).id);

  /** The person to act on, if `s` may act on them; else back with a reason. */
  async function target(req: FastifyRequest, reply: FastifyReply, s: Session): Promise<UserRow | null> {
    const u = await loadUser(idOf(req));
    if (!u) {
      void h.back(reply, "/admin/users", { kind: "bad", text: "No such person." });
      return null;
    }
    if (!mayActOn(s.user, u)) {
      void h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: u.id === s.user.id ? "Change your own account on the Account page." : `Only the super admin may change ${u.role === "superadmin" ? "the super admin's" : "an admin's"} account.` });
      return null;
    }
    return u;
  }

  /** The signed-in admin's own password again, before a change of roles. */
  async function confirmed(s: Session, password: unknown): Promise<string | null> {
    if (!(await hit(d.db, `reauth:${s.user.id}`, LIMITS.login)).ok) return "Too many tries; wait 10 minutes.";
    const hash = (await d.db.query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [s.user.id])).rows[0]?.password_hash;
    return hash && (await verifySecret(hash, String(password ?? ""))) ? null : "Your password is not right.";
  }

  const planPicker = (all: PlanRow[], current: number | null) => html`<select name="plan" id="plan">
    <option value="">Default plan${all.find((p) => p.is_default) ? ` (${all.find((p) => p.is_default)!.name})` : ""}</option>
    ${all.map((p) => html`<option value="${p.id}"${p.id === current ? " selected" : ""}>${p.name} (${stationWord(p.station_limit)})</option>`)}</select>`;

  // ------------------------------------------------------------------ the list

  app.get("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.view");
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, u.station_limit_override,
              coalesce(p.name, dp.name) AS plan, count(sd.id)::int AS stations
         FROM users u LEFT JOIN plans p ON p.id = u.plan_id LEFT JOIN plans dp ON dp.is_default LEFT JOIN subdomains sd ON sd.user_id = u.id
        WHERE $1 = '' OR lower(u.email) LIKE '%' || $1 || '%' GROUP BY u.id, p.name, dp.name ORDER BY u.created_at DESC LIMIT 200`, [q(req)])).rows;
    const all = can(s.user, "users.manage") ? await plans() : [];
    return h.render(req, reply, "People", html`${adminTabs(req, s)}
      ${can(s.user, "users.manage") ? html`<div class="card"><h2>Add a person</h2>
        <form method="post" action="/admin/users">${csrfField(s.csrf)}<div class="row">
          <input name="email" type="email" placeholder="email" required autocomplete="off" style="max-width:280px">${planPicker(all, null)}
          ${isSuper(s.user) ? html`<select name="role"><option value="user">Station owner</option><option value="admin">Admin (no permissions yet)</option></select>` : ""}
          <button class="primary">Add</button></div>
          <p class="dim">They get an email with a link to choose their password (it works for 3 days).</p></form></div>` : ""}
      <div class="card"><h1>People</h1>
      <form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search by email"> <button>Search</button></form>
      <table><tr><th>Email</th><th>Role</th><th>Status</th><th>Plan</th><th>Stations</th><th>Joined</th><th></th></tr>${rows.map((u) => html`<tr>
        <td><a href="/admin/users/${u.id}">${u.email}</a>${u.email_verified_at ? "" : html` <span class="chip">unconfirmed</span>`}</td><td>${roleName(u.role)}</td>
        <td>${u.status === "active" ? html`<span class="chip ok">active</span>` : html`<span class="chip bad">suspended</span>`}</td>
        <td>${u.plan ?? "—"}${u.station_limit_override !== null ? html` <span class="chip">own limit: ${u.station_limit_override}</span>` : ""}</td>
        <td>${can(s.user, "stations.view") ? html`<a href="/admin/stations?q=${u.email}">${u.stations}</a>` : u.stations}</td><td>${when(u.created_at)}</td>
        <td><a href="/admin/users/${u.id}">Open</a></td>
      </tr>`)}</table></div>`, h.takeFlash(req, reply));
  });

  app.post("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.manage");
    if (!s) return reply;
    const f = h.form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return h.back(reply, "/admin/users", { kind: "bad", text: "That is not an email address." });
    const role: Role = isSuper(s.user) && f.role === "admin" ? "admin" : "user";
    const plan = /^\d+$/.test(String(f.plan ?? "")) ? Number(f.plan) : null;
    // A password nobody knows: the person chooses theirs through the emailed link.
    const r = await d.db.query<{ id: number }>(
      `INSERT INTO users (email, password_hash, role, plan_id) VALUES ($1, $2, $3, (SELECT id FROM plans WHERE id = $4))
       ON CONFLICT DO NOTHING RETURNING id`, [email, await hashSecret(newToken()), role, plan]);
    if (!r.rows[0]) return h.back(reply, "/admin/users", { kind: "bad", text: `There is already an account for ${email}.` });
    const id = r.rows[0].id;
    await audit(d.db, { actor: s.user.id, action: "user.create", target: email, ip: req.ip, metadata: { role } });
    const sent = await h.mailLink(id, email, "invite");
    return h.back(reply, `/admin/users/${id}`, { kind: sent ? "ok" : "bad", text: sent ? `Added. A link to choose a password is on its way to ${email}.` : `Added, but the email could not be sent. Check the email settings, then use "Send a password link".` });
  });

  // ------------------------------------------------------------------ one person

  app.get("/admin/users/:id", async (req, reply) => {
    const s = admin(req, reply, "users.view");
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!u) return h.render(req, reply, "Not found", html`${adminTabs(req, s)}<div class="card"><h1>No such person</h1></div>`, null, 404);
    const all = await plans();
    const a = await allowance(d.db, u.id, d.config.subdomainLimit);
    const stations = (await d.db.query(
      `SELECT sd.id, sd.label, sd.status, st.last_seen_at FROM subdomains sd JOIN studios st ON st.subdomain_id = sd.id WHERE sd.user_id = $1 ORDER BY sd.label`, [u.id])).rows;
    const act = mayActOn(s.user, u);
    const editPlan = act || (isSuper(s.user) && u.id === s.user.id);
    const post = (path: string, label: string, confirm = "", danger = false) =>
      html`<form class="inline" method="post" action="/admin/users/${u.id}/${path}"${confirm ? html` data-confirm="${confirm}"` : ""}>${csrfField(s.csrf)}<button class="${danger ? "danger" : ""}">${label}</button></form>`;

    let roles: Html | string = "";
    if (isSuper(s.user) && u.id !== s.user.id) {
      roles = html`<div class="card"><h2>Role and permissions</h2>
        <form method="post" action="/admin/users/${u.id}/role">${csrfField(s.csrf)}
          <label for="role">Role</label><select id="role" name="role"><option value="user"${u.role === "user" ? " selected" : ""}>Station owner</option><option value="admin"${u.role === "admin" ? " selected" : ""}>Admin</option></select>
          <p class="dim">An admin may do only what is ticked. Ticks are ignored for a station owner.</p>
          ${ALL_PERMISSIONS.map((p) => html`<label class="check"><input type="checkbox" name="perm" value="${p}"${u.permissions.includes(p) ? " checked" : ""}> <span><b>${p}</b><br><span class="dim">${PERMISSIONS[p]}</span></span></label>`)}
          <label for="pw-role">Your password, to confirm</label><input id="pw-role" type="password" name="password" required autocomplete="current-password">
          <div class="row"><button class="primary">Save role</button></div></form></div>
        ${u.role === "admin" && u.status === "active" ? html`<div class="card danger"><h2>Make super admin</h2>
          <p class="dim">There is one super admin. ${u.email} takes over; you become an admin with every permission.</p>
          <form method="post" action="/admin/users/${u.id}/superadmin" data-confirm="Hand the super admin role to ${u.email}?">${csrfField(s.csrf)}
            <label for="pw-super">Your password, to confirm</label><input id="pw-super" type="password" name="password" required autocomplete="current-password">
            <div class="row"><button class="danger">Make ${u.email} super admin</button></div></form></div>` : ""}`;
    }

    return h.render(req, reply, u.email, html`${adminTabs(req, s)}<p><a href="/admin/users">← People</a></p>
      <div class="card"><h1>${u.email}</h1><div class="grid">
        <span class="dim">Role</span><span>${roleName(u.role)}${u.role === "admin" ? html` <span class="dim">· ${u.permissions.length ? u.permissions.join(", ") : "no permissions"}</span>` : ""}</span>
        <span class="dim">Status</span><span>${u.status === "active" ? html`<span class="chip ok">active</span>` : html`<span class="chip bad">suspended</span>`}</span>
        <span class="dim">Email</span><span>${u.email_verified_at ? html`<span class="chip ok">confirmed</span>` : html`<span class="chip">not confirmed</span>`}</span>
        <span class="dim">Two-step sign-in</span><span>${u.totp ? "on" : "off"}</span>
        <span class="dim">Joined</span><span>${when(u.created_at)}</span>
        <span class="dim">Stations</span><span>${stations.length} of ${a.limit} ${a.custom ? html`<span class="chip">own limit</span>` : a.plan ? html`<span class="dim">(${a.plan} plan)</span>` : html`<span class="dim">(SUBDOMAIN_LIMIT)</span>`}</span>
      </div></div>

      ${editPlan && can(s.user, "users.manage") ? html`<div class="card"><h2>Plan and limit</h2>
        <form method="post" action="/admin/users/${u.id}/plan">${csrfField(s.csrf)}
          <label for="plan">Plan</label>${planPicker(all, u.plan_id)}
          <label for="limit">Their own station limit (leave empty to follow the plan)</label><input id="limit" type="number" name="limit" min="0" max="10000" value="${u.station_limit_override ?? ""}">
          <div class="row"><button class="primary">Save</button>${can(s.user, "plans.manage") ? html`<a href="/admin/plans">Change the plans</a>` : ""}</div></form></div>` : ""}

      <div class="card"><h2>Stations</h2>
        ${stations.length ? html`<table><tr><th>Address</th><th>Status</th><th></th></tr>${stations.map((r) => html`<tr><td>${fqdnOf(r.label, d.config.rootDomain)}</td><td>${statusChip(r.status, r.last_seen_at)}</td>
          <td>${can(s.user, "stations.view") ? html`<a href="/stations/${r.id}">Manage</a>` : ""}</td></tr>`)}</table>` : html`<p class="dim">None.</p>`}
        ${can(s.user, "stations.manage") ? html`<form method="post" action="/admin/stations">${csrfField(s.csrf)}<input type="hidden" name="email" value="${u.email}"><input type="hidden" name="back" value="user">
          <label for="label">Create a station for ${u.email}</label><div class="row" style="margin-top:0"><input id="label" name="label" placeholder="name, e.g. kfm" required maxlength="63" autocomplete="off" style="max-width:220px"><button>Create</button></div></form>` : ""}</div>

      ${act ? html`<div class="card"><h2>Account</h2><div class="row">
        ${u.email_verified_at ? "" : post("verify", "Mark the email confirmed")}
        ${post("reset", "Send a password link", `Email ${u.email} a link to choose a new password?`)}
        ${u.totp ? post("totp-off", "Turn off two-step sign-in", `Turn off ${u.email}'s two-step sign-in? Do this only once you know it is them.`) : ""}
        ${u.status === "active" ? post("suspend", "Suspend", `Suspend ${u.email} and all their stations?`, true) : post("unsuspend", "Restore")}
        </div></div>
        <div class="card danger"><h2>Delete</h2><p class="dim">Deletes the account and every station it has (addresses, certificates, sign-ins). Names are held for 30 days.</p>
          <form method="post" action="/admin/users/${u.id}/delete">${csrfField(s.csrf)}<label for="confirm">Type <b>${u.email}</b> to confirm</label><input id="confirm" name="confirm" required autocomplete="off">
          <div class="row"><button class="danger">Delete this person</button></div></form></div>` : u.id === s.user.id ? "" : html`<p class="dim">Only the super admin may change ${u.role === "superadmin" ? "the super admin's" : "an admin's"} account.</p>`}
      ${roles}`, h.takeFlash(req, reply));
  });

  app.post("/admin/users/:id/plan", async (req, reply) => {
    const s = admin(req, reply, "users.manage");
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!u) return h.back(reply, "/admin/users", { kind: "bad", text: "No such person." });
    if (!mayActOn(s.user, u) && !(isSuper(s.user) && u.id === s.user.id)) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "Only the super admin may change an admin's plan." });
    const f = h.form(req);
    const plan = /^\d+$/.test(String(f.plan ?? "")) ? Number(f.plan) : null;
    const raw = String(f.limit ?? "").trim();
    if (raw && !/^\d{1,5}$/.test(raw)) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "The limit is a whole number, or empty." });
    const limit = raw ? Number(raw) : null;
    const r = await d.db.query("UPDATE users SET plan_id = (SELECT id FROM plans WHERE id = $2), station_limit_override = $3 WHERE id = $1 RETURNING plan_id", [u.id, plan, limit]);
    if (plan !== null && r.rows[0]?.plan_id === null) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "That plan no longer exists." });
    await audit(d.db, { actor: s.user.id, action: "user.plan", target: u.email, ip: req.ip, metadata: { plan, limit } });
    const a = await allowance(d.db, u.id, d.config.subdomainLimit);
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: `${u.email} may now have ${stationWord(a.limit)}. Stations they already have stay.` });
  });

  // Account actions: each on someone the admin may act on (mayActOn).
  const accountAction = (path: string, run: (s: Session, u: UserRow, req: FastifyRequest, reply: FastifyReply) => Promise<FastifyReply>) =>
    app.post(`/admin/users/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply, "users.manage");
      if (!s) return reply;
      const u = await target(req, reply, s);
      if (!u) return reply;
      return run(s, u, req, reply);
    });

  accountAction("verify", async (s, u, req, reply) => {
    await d.db.query("UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.verify", target: u.email, ip: req.ip });
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: "The email is marked confirmed." });
  });
  accountAction("reset", async (s, u, req, reply) => {
    const sent = await h.mailLink(u.id, u.email, "reset");
    await audit(d.db, { actor: s.user.id, action: "user.reset_link", target: u.email, ip: req.ip });
    return h.back(reply, `/admin/users/${u.id}`, sent ? { kind: "ok", text: `A link is on its way to ${u.email} (it works for an hour).` } : { kind: "bad", text: "The email could not be sent (too many in the last hour, or email is not set up)." });
  });
  accountAction("totp-off", async (s, u, req, reply) => {
    await d.db.query("UPDATE users SET totp_secret_enc = NULL WHERE id = $1", [u.id]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.totp_off", target: u.email, ip: req.ip, metadata: { admin: true } });
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: "Two-step sign-in is off and they are signed out everywhere." });
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    accountAction(path, async (s, u, req, reply) => {
      await subs.setUserSuspended(h.ctx(), h.actor(s, req), u.id, on);
      return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: on ? "Suspended, with their stations' DNS removed." : "Restored." });
    });
  }
  accountAction("delete", async (s, u, req, reply) => {
    if (String(h.form(req).confirm ?? "").trim().toLowerCase() !== u.email.toLowerCase()) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "Type the email exactly to delete." });
    await subs.removeUser(h.ctx(), h.actor(s, req), u.id);
    return h.back(reply, "/admin/users", { kind: "ok", text: `${u.email} and their stations are deleted.` });
  });

  // ------------------------------------------------------------------ roles (super admin only)

  app.post("/admin/users/:id/role", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!isSuper(s.user) || !u || u.id === s.user.id || u.role === "superadmin") return h.back(reply, u ? `/admin/users/${u.id}` : "/admin/users", { kind: "bad", text: "Only the super admin changes roles, and not their own." });
    const f = h.form(req);
    const wrong = await confirmed(s, f.password);
    if (wrong) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: wrong });
    const role: Role = f.role === "admin" ? "admin" : "user";
    const perms = role === "admin" ? cleanPermissions(many((req.body as Record<string, unknown>).perm)) : [];
    await d.db.query("UPDATE users SET role = $2, permissions = $3 WHERE id = $1", [u.id, role, perms]);
    await audit(d.db, { actor: s.user.id, action: "user.role", target: u.email, ip: req.ip, metadata: { from: u.role, role, permissions: perms } });
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: role === "admin" ? `${u.email} is an admin${perms.length ? `: ${perms.join(", ")}` : " with no permissions yet"}.` : `${u.email} is a station owner.` });
  });

  app.post("/admin/users/:id/superadmin", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!isSuper(s.user) || !u || u.role !== "admin" || u.status !== "active") return h.back(reply, u ? `/admin/users/${u.id}` : "/admin/users", { kind: "bad", text: "Only the super admin hands over the role, to an active admin." });
    const wrong = await confirmed(s, h.form(req).password);
    if (wrong) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: wrong });
    await transaction(d.db, async (tx) => {
      await tx.query("UPDATE users SET role = 'admin', permissions = $2 WHERE id = $1", [s.user.id, ALL_PERMISSIONS]);
      await tx.query("UPDATE users SET role = 'superadmin', permissions = '{}' WHERE id = $1", [u.id]);
      await audit(tx, { actor: s.user.id, action: "user.superadmin", target: u.email, ip: req.ip, metadata: { from: s.user.email } });
    });
    return h.back(reply, "/admin", { kind: "ok", text: `${u.email} is the super admin now. You are an admin with every permission.` });
  });

  // ------------------------------------------------------------------ plans

  app.get("/admin/plans", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    const all = await plans();
    const unplanned = Number((await d.db.query("SELECT count(*) AS n FROM users WHERE plan_id IS NULL")).rows[0].n);
    const def = all.find((p) => p.is_default);
    return h.render(req, reply, "Plans", html`${adminTabs(req, s)}<div class="card"><h1>Plans</h1>
      <p class="dim">A plan sets how many stations a person may have. People without a plan are on the default plan${def ? html` (<b>${def.name}</b>)` : html`; there is none, so they may have ${stationWord(d.config.subdomainLimit)} (SUBDOMAIN_LIMIT)`}: ${unplanned} ${unplanned === 1 ? "person" : "people"}. A limit set on a person's own page wins over any plan.</p>
      ${all.length ? html`<table><tr><th colspan="3">Plan · stations allowed</th><th>People on it</th><th></th></tr>${all.map((p) => html`<tr>
        <td colspan="3"><form class="inline" method="post" action="/admin/plans/${p.id}">${csrfField(s.csrf)}<div class="row" style="margin-top:0">
          <input name="name" value="${p.name}" required maxlength="60" style="max-width:200px" aria-label="Name">
          <input type="number" name="limit" value="${p.station_limit}" min="0" max="10000" required aria-label="Stations">
          <label class="check" style="margin:0"><input type="checkbox" name="default" value="1"${p.is_default ? " checked" : ""}> default</label>
          <button>Save</button></div></form></td>
        <td>${p.people}</td>
        <td><form class="inline" method="post" action="/admin/plans/${p.id}/delete" data-confirm="Delete the ${p.name} plan? Its ${p.people} ${p.people === 1 ? "person moves" : "people move"} to the default plan.">${csrfField(s.csrf)}<button class="danger">Delete</button></form></td>
      </tr>`)}</table>` : html`<p class="dim">No plans yet.</p>`}</div>
      <div class="card"><h2>New plan</h2><form method="post" action="/admin/plans">${csrfField(s.csrf)}<div class="row">
        <input name="name" placeholder="name, e.g. Pro" required maxlength="60" style="max-width:200px">
        <input type="number" name="limit" placeholder="stations" min="0" max="10000" required>
        <label class="check" style="margin:0"><input type="checkbox" name="default" value="1"${all.length ? "" : " checked"}> the default plan</label>
        <button class="primary">Create</button></div></form></div>`, h.takeFlash(req, reply));
  });

  /** Create (id null) or change a plan. */
  async function savePlan(req: FastifyRequest, reply: FastifyReply, s: Session, id: number | null) {
    const f = h.form(req);
    const name = String(f.name ?? "").trim().replace(/\s+/g, " ");
    const raw = String(f.limit ?? "").trim();
    if (!name || name.length > 60) return h.back(reply, "/admin/plans", { kind: "bad", text: "A plan needs a name (60 characters at most)." });
    if (!/^\d{1,5}$/.test(raw)) return h.back(reply, "/admin/plans", { kind: "bad", text: "The number of stations is a whole number." });
    const makeDefault = f.default === "1";
    try {
      await transaction(d.db, async (tx) => {
        if (makeDefault) await tx.query("UPDATE plans SET is_default = false WHERE is_default AND id IS DISTINCT FROM $1", [id]);
        if (id === null) await tx.query("INSERT INTO plans (name, station_limit, is_default) VALUES ($1, $2, $3)", [name, Number(raw), makeDefault]);
        else {
          const r = await tx.query("UPDATE plans SET name = $2, station_limit = $3, is_default = $4, updated_at = now() WHERE id = $1", [id, name, Number(raw), makeDefault]);
          if (!r.rowCount) throw new subs.SubdomainError("That plan no longer exists.");
        }
        await audit(tx, { actor: s.user.id, action: id === null ? "plan.create" : "plan.update", target: name, ip: req.ip, metadata: { limit: Number(raw), default: makeDefault } });
      });
    } catch (e) {
      if (isUnique(e)) return h.back(reply, "/admin/plans", { kind: "bad", text: `There is already a plan called ${name}.` });
      if (e instanceof subs.SubdomainError) return h.back(reply, "/admin/plans", { kind: "bad", text: e.message });
      throw e;
    }
    return h.back(reply, "/admin/plans", { kind: "ok", text: `${name}: ${stationWord(Number(raw))}${makeDefault ? ", the default plan" : ""}. Stations people already have stay.` });
  }

  app.post("/admin/plans", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    return savePlan(req, reply, s, null);
  });
  app.post("/admin/plans/:id", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    return savePlan(req, reply, s, idOf(req));
  });
  app.post("/admin/plans/:id/delete", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    const r = await d.db.query<{ name: string }>("DELETE FROM plans WHERE id = $1 RETURNING name", [idOf(req)]);
    if (!r.rows[0]) return h.back(reply, "/admin/plans", { kind: "bad", text: "That plan no longer exists." });
    await audit(d.db, { actor: s.user.id, action: "plan.delete", target: r.rows[0].name, ip: req.ip });
    return h.back(reply, "/admin/plans", { kind: "ok", text: `${r.rows[0].name} is deleted; its people are on the default plan.` });
  });
}
