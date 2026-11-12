/**
 * Admin > People and Admin > Plans: add a person, change their plan or their own station
 * limit, confirm their email, send a reset link, turn off their two-step sign-in, suspend
 * or delete them, create stations for them; for the super admin only, roles and
 * permissions. Plans: station limits, and a price when they are for sale.
 *
 * Who may act on whom is in rbac.ts (mayActOn). Role changes, handing over the super
 * admin role and deleting a person need sudo mode (identity confirmed in the last minutes).
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { exponent, formatMoney, toMinor } from "../billing/gateways.js";
import { transaction } from "../db/db.js";
import { audit } from "../lib/audit.js";
import { fqdnOf } from "../lib/names.js";
import { allowance, stationWord } from "../lib/plans.js";
import { ALL_PERMISSIONS, can, cleanPermissions, isSuper, mayActOn, PERMISSIONS, type Role } from "../lib/rbac.js";
import { hashSecret, newToken } from "../lib/secrets.js";
import * as subs from "../lib/subdomains.js";
import { adminGuard } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { statusChip } from "./app.js";
import { badge, csrfField, day, emptyState, facts, field, formSection, html, icon, pageHead, panel, when, type Html } from "./html.js";
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
  last_login_at: Date | null;
  plan_id: number | null;
  plan_expires_at: Date | null;
  station_limit_override: number | null;
}

interface PlanRow {
  id: number;
  name: string;
  description: string | null;
  station_limit: number;
  is_default: boolean;
  price_minor: number | null;
  currency: string | null;
  period: "month" | "year";
  people: number;
}

export const CURRENCIES = ["USD", "EUR", "GBP", "NGN", "GHS", "KES", "ZAR", "UGX", "TZS", "RWF", "XOF", "XAF", "EGP", "MAD", "CAD", "AUD", "INR", "JPY"];

const roleName = (r: string) => (r === "superadmin" ? "Super admin" : r === "admin" ? "Admin" : "Station owner");
const roleBadge = (r: string) => (r === "superadmin" ? badge("accent", "Super admin") : r === "admin" ? badge("info", "Admin") : badge("neutral", "Owner"));
const isUnique = (e: unknown) => (e as { code?: string })?.code === "23505";
export const priceText = (p: { price_minor: number | null; currency: string | null; period: string }) =>
  p.price_minor && p.currency ? `${formatMoney(Number(p.price_minor), p.currency)} / ${p.period}` : "Not for sale";

/** Every value of a form field that may be repeated (checkboxes). */
const many = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

export function peopleRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);
  const q = (req: FastifyRequest) => String((req.query as Record<string, string>).q ?? "").trim().toLowerCase().slice(0, 100);
  const plans = async () => (await d.db.query<PlanRow>(
    `SELECT p.id, p.name, p.description, p.station_limit, p.is_default, p.price_minor, p.currency, p.period, count(u.id)::int AS people
       FROM plans p LEFT JOIN users u ON u.plan_id = p.id GROUP BY p.id ORDER BY p.station_limit, lower(p.name)`)).rows;
  const loadUser = async (id: number) => Number.isSafeInteger(id) ? (await d.db.query<UserRow>(
    `SELECT id, email, role, status, permissions, email_verified_at, totp_secret_enc IS NOT NULL AS totp, created_at, last_login_at, plan_id, plan_expires_at, station_limit_override
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

  const planPicker = (all: PlanRow[], current: number | null, id = "plan") => html`<select name="plan" id="${id}">
    <option value="">Default plan${all.find((p) => p.is_default) ? ` (${all.find((p) => p.is_default)!.name})` : ""}</option>
    ${all.map((p) => html`<option value="${p.id}"${p.id === current ? " selected" : ""}>${p.name} · ${stationWord(p.station_limit)}</option>`)}</select>`;

  // ------------------------------------------------------------------ the list

  app.get("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.view");
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, u.last_login_at, u.station_limit_override, u.totp_secret_enc IS NOT NULL AS totp,
              coalesce(CASE WHEN u.plan_expires_at IS NULL OR u.plan_expires_at > now() THEN p.name END, dp.name) AS plan, count(sd.id)::int AS stations
         FROM users u LEFT JOIN plans p ON p.id = u.plan_id LEFT JOIN plans dp ON dp.is_default LEFT JOIN subdomains sd ON sd.user_id = u.id
        WHERE $1 = '' OR lower(u.email) LIKE '%' || $1 || '%' GROUP BY u.id, p.name, dp.name ORDER BY u.created_at DESC LIMIT 200`, [q(req)])).rows;
    const manage = can(s.user, "users.manage");
    const all = manage ? await plans() : [];
    return h.render(req, reply, "People", html`${pageHead({ title: "People", sub: "Everyone with an account: station owners and admins." })}
      ${manage ? panel({ title: "Add a person", sub: "They get an email with a link to choose their password (it works for 3 days)." }, html`
        <form method="post" action="/admin/users">${csrfField(s.csrf)}<div class="form-grid">
          ${field({ id: "add-email", label: "Email", control: html`<input id="add-email" name="email" type="email" required autocomplete="off" placeholder="name@example.com">` })}
          ${field({ id: "add-plan", label: "Plan", control: planPicker(all, null, "add-plan") })}
          ${isSuper(s.user) ? field({ id: "add-role", label: "Role", control: html`<select id="add-role" name="role"><option value="user">Station owner</option><option value="admin">Admin (no permissions yet)</option></select>` }) : ""}</div>
          <div class="row"><button class="primary">${icon("plus", 16)} Add person</button></div></form>`) : ""}
      ${panel({ flush: true }, html`<div class="toolbar"><form method="get"><input type="search" name="q" value="${q(req)}" placeholder="Search by email" aria-label="Search"><button>Search</button></form></div>
        ${rows.length ? html`<div class="table-wrap"><table><tr><th>Person</th><th>Role</th><th>Status</th><th>Plan</th><th class="num">Stations</th><th class="wide-only">Last sign-in</th><th class="actions"></th></tr>${rows.map((u) => html`<tr>
        <td><a href="/admin/users/${u.id}"><b>${u.email}</b></a><span class="sub">Joined ${day(u.created_at)}${u.email_verified_at ? "" : " · email not confirmed"}${u.totp ? " · 2FA" : ""}</span></td>
        <td>${roleBadge(u.role)}</td><td>${u.status === "active" ? badge("ok", "Active") : badge("bad", "Suspended")}</td>
        <td>${u.plan ?? "—"}${u.station_limit_override !== null ? html` <span class="sub">Own limit: ${u.station_limit_override}</span>` : ""}</td>
        <td class="num">${u.stations}</td><td class="wide-only">${when(u.last_login_at)}</td><td class="actions"><a class="btn sm" href="/admin/users/${u.id}">Open</a></td>
      </tr>`)}</table></div>` : emptyState("No one found", "Nothing matches that search.")}`)}`, h.takeFlash(req, reply));
  });

  app.post("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.manage");
    if (!s) return reply;
    const f = h.form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) return h.back(reply, "/admin/users", { kind: "bad", text: "That is not an email address." });
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
    if (!u) return h.render(req, reply, "Not found", html`${pageHead({ title: "No such person", back: { href: "/admin/users", text: "People" } })}`, null, 404);
    const all = await plans();
    const a = await allowance(d.db, u.id, d.config.subdomainLimit);
    const stations = (await d.db.query(
      "SELECT sd.id, sd.label, sd.status, st.last_seen_at FROM subdomains sd JOIN studios st ON st.subdomain_id = sd.id WHERE sd.user_id = $1 ORDER BY sd.label", [u.id])).rows;
    const payments = can(s.user, "billing.manage") ? (await d.db.query("SELECT plan_name, amount_minor, currency, status, created_at FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10", [u.id])).rows : [];
    const act = mayActOn(s.user, u);
    const editPlan = can(s.user, "users.manage") && (act || (isSuper(s.user) && u.id === s.user.id));
    const post = (path: string, label: string, confirm = "", danger = false) =>
      html`<form class="inline" method="post" action="/admin/users/${u.id}/${path}"${confirm ? html` data-confirm="${confirm}"` : ""}>${csrfField(s.csrf)}<button class="${danger ? "danger" : ""}">${label}</button></form>`;
    const sudoLink = html`<a class="btn" href="/sudo?next=${encodeURIComponent(`/admin/users/${u.id}`)}">${icon("lock", 15)} Confirm it is you to continue</a>`;

    let roles: Html | string = "";
    if (isSuper(s.user) && u.id !== s.user.id) {
      roles = panel({ title: "Role and permissions", sub: "Only you, the super admin, change these. An admin may do only what is ticked." }, s.elevated ? html`
        <form method="post" action="/admin/users/${u.id}/role">${csrfField(s.csrf)}
          ${field({ id: "role", label: "Role", control: html`<select id="role" name="role" class="w-sm"><option value="user"${u.role === "user" ? " selected" : ""}>Station owner</option><option value="admin"${u.role === "admin" ? " selected" : ""}>Admin</option></select>` })}
          <div class="checks-grid">${ALL_PERMISSIONS.map((p) => html`<label class="check"><input type="checkbox" name="perm" value="${p}"${u.permissions.includes(p) ? " checked" : ""}><span><b>${p}</b><br><span class="dim">${PERMISSIONS[p]}</span></span></label>`)}</div>
          <div class="row"><button class="primary">Save role</button><span class="dim small">Ticks are ignored for a station owner.</span></div></form>
        ${u.role === "admin" && u.status === "active" ? html`<div class="callout" style="margin:24px 0 0">${icon("key")}<div><b>Hand over the super admin role</b><p>There is one super admin. ${u.email} takes over; you become an admin with every permission.</p></div>
          <form method="post" action="/admin/users/${u.id}/superadmin" data-confirm="Hand the super admin role to ${u.email}? You cannot undo this yourself." style="margin-left:auto">${csrfField(s.csrf)}<button class="danger">Make super admin</button></form></div>` : ""}` : html`<p class="dim">Changing roles needs your identity confirmed again.</p>${sudoLink}`);
    }

    return h.render(req, reply, u.email, html`${pageHead({ title: u.email, back: { href: "/admin/users", text: "People" },
        meta: html`${roleBadge(u.role)}${u.status === "active" ? badge("ok", "Active") : badge("bad", "Suspended")}${u.email_verified_at ? badge("ok", "Email confirmed") : badge("warn", "Email not confirmed")}${u.totp ? badge("ok", "2FA on") : badge("neutral", "2FA off")}` })}
      <div class="split"><div>
      ${panel({ title: "Details" }, facts([
        ["Role", u.role === "admin" ? html`Admin <span class="sub dim small">${u.permissions.length ? u.permissions.join(", ") : "No permissions"}</span>` : roleName(u.role)],
        ["Plan", html`${a.custom ? "Own limit" : a.plan || "None (SUBDOMAIN_LIMIT)"}${a.expiresAt ? html` <span class="dim">· paid until ${day(a.expiresAt)}</span>` : ""}${a.lapsed ? html` <span class="dim">· ${a.lapsed} ended</span>` : ""}`],
        ["Stations", `${stations.length} of ${a.limit}`],
        ["Joined", day(u.created_at)],
        ["Last sign-in", when(u.last_login_at)],
      ]))}
      ${editPlan ? panel({ title: "Plan and limit", sub: "Their own limit wins over any plan. Choosing a plan here has no end date." }, html`
        <form method="post" action="/admin/users/${u.id}/plan">${csrfField(s.csrf)}<div class="form-grid">
          ${field({ id: "plan", label: "Plan", control: planPicker(all, u.plan_id) })}
          ${field({ id: "limit", label: "Own station limit", help: "Leave empty to follow the plan.", control: html`<input id="limit" type="number" name="limit" min="0" max="10000" value="${u.station_limit_override ?? ""}">` })}</div>
          <div class="row"><button class="primary">Save</button>${can(s.user, "plans.manage") ? html`<a class="btn ghost" href="/admin/plans">Manage plans</a>` : ""}</div></form>`) : ""}
      ${panel({ title: "Stations", flush: true }, html`${stations.length ? html`<div class="table-wrap"><table><tr><th>Address</th><th>Status</th><th class="actions"></th></tr>${stations.map((r) => html`<tr><td><b>${fqdnOf(r.label, d.config.rootDomain)}</b></td><td>${statusChip(r.status, r.last_seen_at)}</td>
          <td class="actions">${can(s.user, "stations.view") ? html`<a class="btn sm" href="/stations/${r.id}">Open</a>` : ""}</td></tr>`)}</table></div>` : html`<div class="card-body"><p class="dim" style="margin:0">No stations.</p></div>`}
        ${can(s.user, "stations.manage") ? html`<div class="card-body" style="border-top:1px solid var(--line)"><form method="post" action="/admin/stations">${csrfField(s.csrf)}<input type="hidden" name="email" value="${u.email}"><input type="hidden" name="back" value="user">
          ${field({ id: "label", label: `Create a station for ${u.email}`, control: html`<div class="row tight"><div class="input-group" style="flex:1;min-width:220px"><input id="label" name="label" placeholder="kfm" required maxlength="63" autocomplete="off"><span class="addon">.${d.config.rootDomain}</span></div><button>Create</button></div>` })}</form></div>` : ""}`)}
      ${payments.length ? panel({ title: "Payments", flush: true }, html`<div class="table-wrap"><table><tr><th>Date</th><th>Plan</th><th class="num">Amount</th><th>Status</th></tr>${payments.map((p) => html`<tr><td>${when(p.created_at)}</td><td>${p.plan_name}</td><td class="num">${formatMoney(Number(p.amount_minor), p.currency)}</td><td>${p.status === "paid" ? badge("ok", "Paid") : p.status === "pending" ? badge("info", "Pending") : badge("neutral", p.status)}</td></tr>`)}</table></div>`) : ""}
      ${roles}
      </div><div>
      ${act ? panel({ title: "Account actions" }, html`<div style="display:grid;gap:10px">
        ${u.email_verified_at ? "" : post("verify", "Mark the email confirmed")}
        ${post("reset", "Send a password link", `Email ${u.email} a link to choose a new password?`)}
        ${u.totp ? post("totp-off", "Turn off two-step sign-in", `Turn off ${u.email}'s two-step sign-in? Do this only once you know it is them.`) : ""}
        ${post("signout", "Sign out everywhere", `Sign ${u.email} out of every device?`)}
        ${u.status === "active" ? post("suspend", "Suspend account", `Suspend ${u.email} and all their stations?`, true) : post("unsuspend", "Restore account")}</div>`) : u.id === s.user.id ? "" : panel({}, html`<p class="dim" style="margin:0">Only the super admin may change ${u.role === "superadmin" ? "the super admin's" : "an admin's"} account.</p>`)}
      ${act ? panel({ title: "Delete person", tone: "danger", sub: "Deletes the account and every station it has. Names are held for 30 days." }, s.elevated ? html`
          <form method="post" action="/admin/users/${u.id}/delete">${csrfField(s.csrf)}${field({ id: "confirm", label: `Type ${u.email} to confirm`, control: html`<input id="confirm" name="confirm" required autocomplete="off">` })}
          <div class="row"><button class="danger-solid">Delete this person</button></div></form>` : sudoLink) : ""}
      </div></div>`, h.takeFlash(req, reply));
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
    // The same plan keeps what was paid for; a plan chosen here has no end.
    const r = await d.db.query(
      `UPDATE users SET plan_id = (SELECT id FROM plans WHERE id = $2), station_limit_override = $3,
              plan_expires_at = CASE WHEN plan_id IS NOT DISTINCT FROM $2::bigint THEN plan_expires_at END
        WHERE id = $1 RETURNING plan_id`, [u.id, plan, limit]);
    if (plan !== null && r.rows[0]?.plan_id === null) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "That plan no longer exists." });
    await audit(d.db, { actor: s.user.id, action: "user.plan", target: u.email, ip: req.ip, metadata: { plan, limit } });
    const a = await allowance(d.db, u.id, d.config.subdomainLimit);
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: `${u.email} may now have ${stationWord(a.limit)}. Stations they already have stay.` });
  });

  // Account actions: each on someone the admin may act on (mayActOn).
  const accountAction = (path: string, run: (s: Session, u: UserRow, req: FastifyRequest, reply: FastifyReply) => Promise<FastifyReply>, sudo = false) =>
    app.post(`/admin/users/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply, "users.manage");
      if (!s) return reply;
      const u = await target(req, reply, s);
      if (!u) return reply;
      if (sudo && !h.requireSudo(req, reply, s, `/admin/users/${u.id}`)) return reply;
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
    void h.notify(u.email, "Two-step sign-in was turned off", "An administrator turned off two-step sign-in for your account and signed you out everywhere. Turn it on again from Account & security.");
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: "Two-step sign-in is off and they are signed out everywhere." });
  }, true);
  accountAction("signout", async (s, u, req, reply) => {
    const r = await d.db.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.sessions_end", target: u.email, ip: req.ip, metadata: { count: r.rowCount, admin: true } });
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: `Signed out of ${r.rowCount} device${r.rowCount === 1 ? "" : "s"}.` });
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
  }, true);

  // ------------------------------------------------------------------ roles (super admin only, sudo mode)

  app.post("/admin/users/:id/role", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!isSuper(s.user) || !u || u.id === s.user.id || u.role === "superadmin") return h.back(reply, u ? `/admin/users/${u.id}` : "/admin/users", { kind: "bad", text: "Only the super admin changes roles, and not their own." });
    if (!h.requireSudo(req, reply, s, `/admin/users/${u.id}`)) return reply;
    const role: Role = h.form(req).role === "admin" ? "admin" : "user";
    const perms = role === "admin" ? cleanPermissions(many((req.body as Record<string, unknown>).perm)) : [];
    await d.db.query("UPDATE users SET role = $2, permissions = $3 WHERE id = $1", [u.id, role, perms]);
    await audit(d.db, { actor: s.user.id, action: "user.role", target: u.email, ip: req.ip, metadata: { from: u.role, role, permissions: perms } });
    if (role !== u.role || perms.join() !== u.permissions.join()) {
      void h.notify(u.email, "Your access changed", role === "admin" ? `You are now an admin on ${d.config.rootDomain}, with: ${perms.join(", ") || "no permissions yet"}. The admin console needs two-step sign-in.` : `You are now a station owner on ${d.config.rootDomain}.`);
    }
    return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: role === "admin" ? `${u.email} is an admin${perms.length ? `: ${perms.join(", ")}` : " with no permissions yet"}.` : `${u.email} is a station owner.` });
  });

  app.post("/admin/users/:id/superadmin", async (req, reply) => {
    const s = admin(req, reply);
    if (!s) return reply;
    const u = await loadUser(idOf(req));
    if (!isSuper(s.user) || !u || u.role !== "admin" || u.status !== "active") return h.back(reply, u ? `/admin/users/${u.id}` : "/admin/users", { kind: "bad", text: "Only the super admin hands over the role, to an active admin." });
    if (!h.requireSudo(req, reply, s, `/admin/users/${u.id}`)) return reply;
    await transaction(d.db, async (tx) => {
      await tx.query("UPDATE users SET role = 'admin', permissions = $2 WHERE id = $1", [s.user.id, ALL_PERMISSIONS]);
      await tx.query("UPDATE users SET role = 'superadmin', permissions = '{}' WHERE id = $1", [u.id]);
      await audit(tx, { actor: s.user.id, action: "user.superadmin", target: u.email, ip: req.ip, metadata: { from: s.user.email } });
    });
    void h.notify(u.email, "You are the super admin", `${s.user.email} handed you the super admin role on ${d.config.rootDomain}.`);
    return h.back(reply, "/admin", { kind: "ok", text: `${u.email} is the super admin now. You are an admin with every permission.` });
  });

  // ------------------------------------------------------------------ plans

  app.get("/admin/plans", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    const all = await plans();
    const unplanned = Number((await d.db.query("SELECT count(*) AS n FROM users WHERE plan_id IS NULL")).rows[0].n);
    const def = all.find((p) => p.is_default);
    return h.render(req, reply, "Plans", html`${pageHead({ title: "Plans", sub: "A plan sets how many stations a person may have. Give a plan a price to sell it when payments are on.",
        actions: html`<a class="btn primary" href="/admin/plans/new">${icon("plus", 16)} New plan</a>` })}
      <div class="callout info">${icon("info")}<div><b>Who is on which plan</b><p>People without a plan are on the default plan${def ? html` (<b>${def.name}</b>)` : html`; there is none, so they may have ${stationWord(d.config.subdomainLimit)} (SUBDOMAIN_LIMIT)`}: ${unplanned} ${unplanned === 1 ? "person" : "people"}. A limit set on a person's page wins over any plan.</p></div></div>
      ${panel({ flush: true }, all.length ? html`<div class="table-wrap"><table><tr><th>Plan</th><th class="num">Stations</th><th>Price</th><th class="num">People</th><th class="actions"></th></tr>${all.map((p) => html`<tr>
        <td><a href="/admin/plans/${p.id}"><b>${p.name}</b></a> ${p.is_default ? badge("accent", "Default") : ""}${p.description ? html`<span class="sub">${p.description}</span>` : ""}</td>
        <td class="num">${p.station_limit}</td><td>${p.price_minor ? badge("ok", priceText(p)) : badge("neutral", "Not for sale")}</td><td class="num">${p.people}</td>
        <td class="actions"><a class="btn sm" href="/admin/plans/${p.id}">Edit</a></td></tr>`)}</table></div>`
        : emptyState("No plans yet", "Create a plan to give people more stations, or to sell more.", html`<a class="btn primary" href="/admin/plans/new">New plan</a>`))}`, h.takeFlash(req, reply));
  });

  const planForm = (s: Session, p: PlanRow | null) => {
    const price = p?.price_minor && p.currency ? (Number(p.price_minor) / 10 ** exponent(p.currency)).toFixed(exponent(p.currency)) : "";
    return html`<form method="post" action="${p ? `/admin/plans/${p.id}` : "/admin/plans"}">${csrfField(s.csrf)}${panel({}, html`
      ${formSection("Plan", "What people see, and how many stations it allows.", html`
        ${field({ id: "name", label: "Name", control: html`<input id="name" name="name" value="${p?.name ?? ""}" required maxlength="60" placeholder="Pro">` })}
        ${field({ id: "description", label: "Description (optional)", control: html`<input id="description" name="description" value="${p?.description ?? ""}" maxlength="200" placeholder="For networks with several studios">` })}
        ${field({ id: "limit", label: "Stations allowed", control: html`<input id="limit" type="number" name="limit" value="${p?.station_limit ?? ""}" min="0" max="10000" required class="w-sm">` })}
        <label class="check"><input type="checkbox" name="default" value="1"${p?.is_default ? " checked" : ""}><span><b>Default plan</b><br><span class="dim">Everyone without a plan is on this one. There is one default.</span></span></label>`)}
      ${formSection("Price", "Leave the price empty to keep the plan out of the shop: admins can still assign it. A change applies to new payments only.", html`
        <div class="form-grid">
          ${field({ id: "price", label: "Price", control: html`<input id="price" name="price" value="${price}" inputmode="decimal" placeholder="19.99">` })}
          ${field({ id: "currency", label: "Currency", control: html`<select id="currency" name="currency">${CURRENCIES.map((c) => html`<option${(p?.currency ?? "USD") === c ? " selected" : ""}>${c}</option>`)}</select>` })}
          ${field({ id: "period", label: "Each payment covers", control: html`<select id="period" name="period"><option value="month"${p?.period !== "year" ? " selected" : ""}>1 month</option><option value="year"${p?.period === "year" ? " selected" : ""}>1 year</option></select>` })}</div>`)}`,
      html`<a class="btn ghost" href="/admin/plans">Cancel</a><button class="primary">${p ? "Save plan" : "Create plan"}</button>`)}</form>`;
  };

  app.get("/admin/plans/new", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    return h.render(req, reply, "New plan", html`${pageHead({ title: "New plan", back: { href: "/admin/plans", text: "Plans" } })}${planForm(s, null)}`, h.takeFlash(req, reply));
  });
  app.get("/admin/plans/:id", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    const p = (await plans()).find((x) => x.id === idOf(req));
    if (!p) return h.render(req, reply, "Not found", html`${pageHead({ title: "No such plan", back: { href: "/admin/plans", text: "Plans" } })}`, null, 404);
    return h.render(req, reply, p.name, html`${pageHead({ title: p.name, back: { href: "/admin/plans", text: "Plans" }, meta: html`${p.is_default ? badge("accent", "Default") : ""}${badge(p.price_minor ? "ok" : "neutral", priceText(p))}<span>${p.people} ${p.people === 1 ? "person" : "people"}</span>` })}
      ${planForm(s, p)}
      ${panel({ title: "Delete plan", tone: "danger", sub: `Its ${p.people} ${p.people === 1 ? "person moves" : "people move"} to the default plan. Past payments stay in the records.` },
        html`<form method="post" action="/admin/plans/${p.id}/delete" data-confirm="Delete the ${p.name} plan?">${csrfField(s.csrf)}<button class="danger">Delete plan</button></form>`)}`, h.takeFlash(req, reply));
  });

  /** Create (id null) or change a plan. */
  async function savePlan(req: FastifyRequest, reply: FastifyReply, s: Session, id: number | null) {
    const f = h.form(req);
    const here = id === null ? "/admin/plans/new" : `/admin/plans/${id}`;
    const name = String(f.name ?? "").trim().replace(/\s+/g, " ");
    const description = String(f.description ?? "").trim().slice(0, 200) || null;
    const raw = String(f.limit ?? "").trim();
    if (!name || name.length > 60) return h.back(reply, here, { kind: "bad", text: "A plan needs a name (60 characters at most)." });
    if (!/^\d{1,5}$/.test(raw)) return h.back(reply, here, { kind: "bad", text: "The number of stations is a whole number." });
    const currency = CURRENCIES.includes(String(f.currency)) ? String(f.currency) : "USD";
    const period = f.period === "year" ? "year" : "month";
    let price: number | null = null;
    if (String(f.price ?? "").trim()) {
      price = toMinor(String(f.price), currency);
      if (price === null) return h.back(reply, here, { kind: "bad", text: exponent(currency) ? "Write the price like 19.99." : `Write the price as a whole number (${currency} has no cents).` });
    }
    const makeDefault = f.default === "1";
    try {
      await transaction(d.db, async (tx) => {
        if (makeDefault) await tx.query("UPDATE plans SET is_default = false WHERE is_default AND id IS DISTINCT FROM $1", [id]);
        const values = [name, Number(raw), makeDefault, price, price === null ? null : currency, period, description];
        if (id === null) await tx.query("INSERT INTO plans (name, station_limit, is_default, price_minor, currency, period, description) VALUES ($1, $2, $3, $4, $5, $6, $7)", values);
        else {
          const r = await tx.query("UPDATE plans SET name = $1, station_limit = $2, is_default = $3, price_minor = $4, currency = $5, period = $6, description = $7, updated_at = now() WHERE id = $8", [...values, id]);
          if (!r.rowCount) throw new subs.SubdomainError("That plan no longer exists.");
        }
        await audit(tx, { actor: s.user.id, action: id === null ? "plan.create" : "plan.update", target: name, ip: req.ip,
          metadata: { limit: Number(raw), default: makeDefault, price: price === null ? null : formatMoney(price, currency), period } });
      });
    } catch (e) {
      if (isUnique(e)) return h.back(reply, here, { kind: "bad", text: `There is already a plan called ${name}.` });
      if (e instanceof subs.SubdomainError) return h.back(reply, "/admin/plans", { kind: "bad", text: e.message });
      throw e;
    }
    return h.back(reply, "/admin/plans", { kind: "ok", text: `${name}: ${stationWord(Number(raw))}${price !== null ? `, ${formatMoney(price, currency)} / ${period}` : ""}${makeDefault ? ", the default plan" : ""}. Stations people already have stay.` });
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
