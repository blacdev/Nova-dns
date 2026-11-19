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
import { paymentBadge, statusChip } from "./app.js";
import { badge, csrfField, day, emptyState, facts, field, formSection, html, icon, pageHead, panel, when, type Html } from "./html.js";
import { choiceCards, FormState, segmented, filterBar, like, menu, menuLink, menuOpen, menuPost, menuSep, modal, opener, pageOf, paged, pager, table, withQuery } from "./ui.js";
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
  invited_at: Date | null;
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
/** Added by an admin and not signed in yet. */
const invited = (u: { invited_at: Date | null; last_login_at: Date | null }) => !!u.invited_at && !u.last_login_at;
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
    `SELECT id, email, role, status, permissions, email_verified_at, totp_secret_enc IS NOT NULL AS totp, created_at, last_login_at, plan_id, plan_expires_at, station_limit_override, invited_at
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

  /** Station owner or admin, as two cards. */
  const roleCards = (selected: string, id: string, adding = false) => choiceCards({ name: "role", id, label: "Role", selected, options: [
    { value: "user", title: "Station owner", text: "Claims and runs their own stations." },
    { value: "admin", title: "Admin", text: adding ? "Starts with no permissions; you tick them on their page. Needs two-step sign-in." : "Opens the admin console with the permissions ticked below. Needs two-step sign-in." }] });

  // ------------------------------------------------------------------ the list

  app.get("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const all = await plans();
    const role = ["user", "admin"].includes(query.role) ? query.role : "";
    const status = ["active", "suspended"].includes(query.status) ? query.status : "";
    const show = ["invited", "unconfirmed", "never", "no2fa", "2fa"].includes(query.show) ? query.show : "";
    const plan = query.plan === "none" || all.some((p) => String(p.id) === query.plan) ? query.plan : "";
    const pg = pageOf(query);
    const { rows, total } = await paged<{ id: number; email: string; role: Role; status: string; email_verified_at: Date | null; created_at: Date; last_login_at: Date | null; invited_at: Date | null; station_limit_override: number | null; totp: boolean; plan: string | null; stations: number }>(d.db,
      `SELECT u.id, u.email, u.role, u.status, u.email_verified_at, u.created_at, u.last_login_at, u.invited_at, u.station_limit_override, u.totp_secret_enc IS NOT NULL AS totp,
              coalesce(CASE WHEN u.plan_expires_at IS NULL OR u.plan_expires_at > now() THEN p.name END, dp.name) AS plan,
              (SELECT count(*) FROM subdomains sd WHERE sd.user_id = u.id)::int AS stations
         FROM users u LEFT JOIN plans p ON p.id = u.plan_id LEFT JOIN plans dp ON dp.is_default
        WHERE ($1 = '' OR lower(u.email) LIKE '%' || $1 || '%')
          AND ($2 = '' OR ($2 = 'user' AND u.role = 'user') OR ($2 = 'admin' AND u.role IN ('admin', 'superadmin')))
          AND ($3 = '' OR u.status = $3)
          AND ($4 = '' OR ($4 = 'invited' AND u.invited_at IS NOT NULL AND u.last_login_at IS NULL) OR ($4 = 'unconfirmed' AND u.email_verified_at IS NULL) OR ($4 = 'never' AND u.last_login_at IS NULL)
               OR ($4 = 'no2fa' AND u.totp_secret_enc IS NULL) OR ($4 = '2fa' AND u.totp_secret_enc IS NOT NULL))
          AND ($5 = '' OR ($5 = 'none' AND (u.plan_id IS NULL OR u.plan_expires_at <= now())) OR (u.plan_id::text = $5 AND (u.plan_expires_at IS NULL OR u.plan_expires_at > now())))
        ORDER BY u.created_at DESC`, [like(q(req)), role, status, show, plan], pg);
    const manage = can(s.user, "users.manage");
    const here = withQuery("/admin/users", query);
    const add = h.takeForm(req, reply).for("user-add");
    const deleteLink = (id: number) => (s.elevated ? `/admin/users/${id}#delete-person` : `/sudo?next=${encodeURIComponent(`/admin/users/${id}#delete-person`)}`);
    return h.render(req, reply, "People", html`${pageHead({ title: "People", sub: "Everyone with an account: station owners and admins.",
        actions: manage ? opener("add-person", html`${icon("plus", 16)} Add a person`, "primary") : "" })}
      ${manage ? modal({ id: "add-person", title: "Add a person", text: "They get an email with a link to choose their password (it works for 3 days).", action: "/admin/users", csrf: s.csrf, submit: "Add person", open: add.returned,
        body: html`${field({ id: "add-email", label: "Email", error: add.e("email"), control: html`<input id="add-email" name="email" type="email" required autocomplete="off" placeholder="name@example.com" value="${add.v("email")}">` })}
          ${field({ id: "add-plan", label: "Plan", control: planPicker(all, add.v("plan") ? Number(add.v("plan")) : null, "add-plan") })}
          ${isSuper(s.user) ? roleCards(add.v("role", "user"), "add-role", true) : ""}` }) : ""}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/users", query, search: { placeholder: "Search by email" },
          chips: { name: "role", label: "Role", options: [["", "Everyone"], ["user", "Station owners"], ["admin", "Admins"]] },
          selects: [
            { name: "status", label: "Status", options: [["", "Any status"], ["active", "Active"], ["suspended", "Suspended"]] },
            { name: "show", label: "Account", options: [["", "Any account"], ["invited", "Invited, not signed in yet"], ["unconfirmed", "Email not confirmed"], ["never", "Never signed in"], ["no2fa", "Two-step off"], ["2fa", "Two-step on"]] },
            { name: "plan", label: "Plan", options: [["", "Any plan"], ["none", "Default plan"], ...all.map((p) => [String(p.id), p.name] as [string, string])] },
          ] })}
        ${rows.length ? table(["Person", "Role", "Status", "Plan", { text: "Stations", cls: "num" }, { text: "Last sign-in", cls: "wide-only" }, { text: "", cls: "actions" }], rows.map((u) => {
          const act = mayActOn(s.user, u);
          return html`<tr>
          <td><a href="/admin/users/${u.id}"><b>${u.email}</b></a><span class="sub">Joined ${day(u.created_at)}${u.email_verified_at ? "" : " · email not confirmed"}${u.totp ? " · 2FA" : ""}${u.last_login_at || u.invited_at ? "" : " · never signed in"}</span></td>
          <td>${roleBadge(u.role)}</td><td>${u.status !== "active" ? badge("bad", "Suspended") : invited(u) ? badge("info", "Invited") : badge("ok", "Active")}</td>
          <td>${u.plan ?? "—"}${u.station_limit_override !== null ? html` <span class="sub">Own limit: ${u.station_limit_override}</span>` : ""}</td>
          <td class="num">${u.stations}</td><td class="wide-only">${when(u.last_login_at)}</td>
          <td class="actions">${menu([
            menuLink(`/admin/users/${u.id}`, "Open", "user"),
            act && manage && menuPost(`/admin/users/${u.id}/reset`, invited(u) ? "Resend the invitation" : "Send a password link", s.csrf, { confirm: invited(u) ? `Send ${u.email} a new invitation? It works for 3 days; the earlier link stops working.` : `Email ${u.email} a link to choose a new password? It works for an hour.`, title: invited(u) ? "Resend the invitation" : "Send a password link", hidden: { back: here }, ic: "key" }),
            act && manage && menuSep(),
            act && manage && menuPost(`/admin/users/${u.id}/${u.status === "active" ? "suspend" : "unsuspend"}`, u.status === "active" ? "Suspend" : "Restore", s.csrf,
              { confirm: u.status === "active" ? `Suspend ${u.email}? They are signed out and their stations stop resolving.` : `Restore ${u.email} and their stations?`, title: u.status === "active" ? "Suspend account" : "Restore account", danger: u.status === "active", hidden: { back: here }, ic: u.status === "active" ? "lock" : "check" }),
            act && manage && menuLink(deleteLink(u.id), "Delete…", "alert"),
          ], { aria: `Actions for ${u.email}` })}</td></tr>`;
        })) : emptyState("No one found", "Nothing matches these filters.")}
        ${pager("/admin/users", query, pg, total, "people")}`)}`, h.takeFlash(req, reply));
  });

  app.post("/admin/users", async (req, reply) => {
    const s = admin(req, reply, "users.manage");
    if (!s) return reply;
    const f = h.form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    const bad = (text: string) => h.back(reply, "/admin/users", { kind: "bad", text }, { form: "user-add", values: f, errors: { email: text } });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) return bad("That is not an email address.");
    const role: Role = isSuper(s.user) && f.role === "admin" ? "admin" : "user";
    const plan = /^\d+$/.test(String(f.plan ?? "")) ? Number(f.plan) : null;
    // A password nobody knows: the person chooses theirs through the emailed link.
    const r = await d.db.query<{ id: number }>(
      `INSERT INTO users (email, password_hash, role, plan_id, invited_at) VALUES ($1, $2, $3, (SELECT id FROM plans WHERE id = $4), now())
       ON CONFLICT DO NOTHING RETURNING id`, [email, await hashSecret(newToken()), role, plan]);
    if (!r.rows[0]) return bad(`There is already an account for ${email}.`);
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
    const payments = can(s.user, "billing.manage") ? (await d.db.query("SELECT id, plan_name, amount_minor, currency, status, created_at FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10", [u.id])).rows : [];
    const paymentCount = payments.length === 10 ? Number((await d.db.query("SELECT count(*) AS n FROM payments WHERE user_id = $1", [u.id])).rows[0].n) : payments.length;
    const act = mayActOn(s.user, u);
    const manage = can(s.user, "users.manage") && act;
    const editPlan = can(s.user, "users.manage") && (act || (isSuper(s.user) && u.id === s.user.id));
    const forms = h.takeForm(req, reply);
    const stationForm = forms.for("user-station");
    const sudoNext = (hash = "") => `/sudo?next=${encodeURIComponent(`/admin/users/${u.id}${hash}`)}`;
    const sudoLink = html`<a class="btn" href="${sudoNext()}">${icon("lock", 15)} Confirm it is you to continue</a>`;
    const base = `/admin/users/${u.id}`;

    let roles: Html | string = "";
    if (isSuper(s.user) && u.id !== s.user.id) {
      roles = panel({ title: "Role and permissions", sub: "Only you, the super admin, change these. An admin may do only what is ticked." }, s.elevated ? html`
        <form method="post" action="/admin/users/${u.id}/role">${csrfField(s.csrf)}
          ${roleCards(u.role === "admin" ? "admin" : "user", "role")}
          <div class="checks-grid">${ALL_PERMISSIONS.map((p) => html`<label class="check"><input type="checkbox" name="perm" value="${p}"${u.permissions.includes(p) ? " checked" : ""}><span><b>${p}</b><br><span class="dim">${PERMISSIONS[p]}</span></span></label>`)}</div>
          <div class="row"><button class="primary">Save role</button><span class="dim small">Ticks are ignored for a station owner.</span></div></form>
        ${u.role === "admin" && u.status === "active" ? html`<div class="callout" style="margin:24px 0 0">${icon("key")}<div><b>Hand over the super admin role</b><p>There is one super admin. ${u.email} takes over; you become an admin with every permission.</p></div>
          <form method="post" action="/admin/users/${u.id}/superadmin" data-confirm="Hand the super admin role to ${u.email}? You become an admin, and cannot undo this yourself." data-confirm-title="Hand over the super admin role" style="margin-left:auto">${csrfField(s.csrf)}<button class="danger">Make super admin</button></form></div>` : ""}` : html`<p class="dim">Changing roles needs your identity confirmed again.</p>${sudoLink}`);
    }

    const actions = manage ? menu([
      menuOpen("change-email", "Change email…", { ic: "user" }),
      u.email_verified_at ? "" : menuPost(`${base}/verify`, "Mark the email confirmed", s.csrf, { ic: "check" }),
      menuPost(`${base}/reset`, invited(u) ? "Resend the invitation" : "Send a password link", s.csrf, { confirm: invited(u) ? `Send ${u.email} a new invitation? It works for 3 days; the earlier link stops working.` : `Email ${u.email} a link to choose a new password? It works for an hour.`, title: invited(u) ? "Resend the invitation" : "Send a password link", ic: "key" }),
      u.totp ? menuPost(`${base}/totp-off`, "Turn off two-step sign-in", s.csrf, { confirm: `Turn off ${u.email}'s two-step sign-in and sign them out everywhere? Do this only once you know it is them.`, title: "Turn off two-step sign-in", danger: true, ic: "shield" }) : "",
      menuPost(`${base}/signout`, "Sign out everywhere", s.csrf, { confirm: `Sign ${u.email} out of every device?`, title: "Sign out everywhere", ic: "logout" }),
      menuSep(),
      u.status === "active"
        ? menuPost(`${base}/suspend`, "Suspend account", s.csrf, { confirm: `Suspend ${u.email}? They are signed out and their stations stop resolving.`, title: "Suspend account", danger: true, ic: "lock" })
        : menuPost(`${base}/unsuspend`, "Restore account", s.csrf, { confirm: `Restore ${u.email} and their stations?`, title: "Restore account", ic: "check" }),
      s.elevated ? menuOpen("delete-person", "Delete…", { danger: true, ic: "alert" }) : menuLink(sudoNext("#delete-person"), "Delete… (confirm it is you first)", "alert"),
    ], { label: "Actions" }) : "";

    return h.render(req, reply, u.email, html`${pageHead({ title: u.email, back: { href: "/admin/users", text: "People" }, actions,
        meta: html`${roleBadge(u.role)}${u.status === "active" ? badge("ok", "Active") : badge("bad", "Suspended")}${u.email_verified_at ? badge("ok", "Email confirmed") : badge("warn", "Email not confirmed")}${u.totp ? badge("ok", "2FA on") : badge("neutral", "2FA off")}${invited(u) ? badge("info", `Invited ${day(u.invited_at)}`) : u.last_login_at ? "" : badge("neutral", "Never signed in")}` })}
      ${!act && u.id !== s.user.id ? html`<div class="callout info">${icon("info")}<div><p>Only the super admin may change ${u.role === "superadmin" ? "the super admin's" : "an admin's"} account.</p></div></div>` : ""}
      ${u.id === s.user.id ? html`<div class="callout info">${icon("info")}<div><p>This is you. Change your own account on <a href="/account">Account &amp; security</a>.</p></div></div>` : ""}
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
          ${field({ id: "limit", label: "Own station limit", help: "Leave empty to follow the plan.", error: forms.for("user-plan").e("limit"), control: html`<input id="limit" type="number" name="limit" min="0" max="10000" value="${forms.for("user-plan").v("limit", u.station_limit_override ?? "")}">` })}</div>
          <div class="row"><button class="primary">Save</button>${can(s.user, "plans.manage") ? html`<a class="btn ghost" href="/admin/plans">Manage plans</a>` : ""}</div></form>`) : ""}
      ${roles}
      </div><div>
      ${panel({ title: "Stations", flush: true }, html`${stations.length ? table(["Address", "Status", { text: "", cls: "actions" }], stations.map((r) => html`<tr><td><b>${fqdnOf(r.label, d.config.rootDomain)}</b></td><td>${statusChip(r.status, r.last_seen_at)}</td>
          <td class="actions">${can(s.user, "stations.view") ? html`<a class="btn sm" href="/stations/${r.id}">Open</a>` : ""}</td></tr>`)) : html`<div class="card-body"><p class="dim" style="margin:0">No stations.</p></div>`}
        ${can(s.user, "stations.manage") ? html`<div class="card-body" style="border-top:1px solid var(--line)"><form method="post" action="/admin/stations">${csrfField(s.csrf)}<input type="hidden" name="email" value="${u.email}"><input type="hidden" name="back" value="user">
          ${field({ id: "label", label: "Create a station for them", error: stationForm.e("label"), control: html`<div class="row tight"><div class="input-group" style="flex:1;min-width:200px"><input id="label" name="label" placeholder="kfm" required maxlength="63" autocomplete="off" spellcheck="false" value="${stationForm.v("label")}"><span class="addon">.${d.config.rootDomain}</span></div><button>Create</button></div>` })}</form></div>` : ""}`)}
      ${payments.length ? panel({ title: "Payments", flush: true, actions: paymentCount > payments.length ? html`<a class="btn sm" href="/admin/billing?q=${encodeURIComponent(u.email)}">All ${paymentCount}</a>` : "" },
        table(["Date", "Plan", { text: "Amount", cls: "num" }, "Status"], payments.map((p) => html`<tr><td style="white-space:nowrap"><a href="/admin/billing/payments/${p.id}">${day(p.created_at)}</a></td><td>${p.plan_name}</td><td class="num">${formatMoney(Number(p.amount_minor), p.currency)}</td><td>${paymentBadge(p.status)}</td></tr>`))) : ""}
      </div></div>
      ${manage ? modal({ id: "change-email", title: "Change email", action: `${base}/email`, csrf: s.csrf, submit: "Change email", open: forms.for("user-email").returned,
        text: html`<p>${invited(u) ? "A new invitation goes to the new address." : "The new address must be confirmed: a link goes to it."} ${u.email} is told about the change.</p>`,
        body: field({ id: "new-email", label: "New email", error: forms.for("user-email").e("email"), control: html`<input id="new-email" name="email" type="email" required autocomplete="off" maxlength="254" value="${forms.for("user-email").v("email", u.email)}">` }) }) : ""}
      ${manage && s.elevated ? modal({ id: "delete-person", title: `Delete ${u.email}`, tone: "danger", action: `${base}/delete`, csrf: s.csrf, submit: "Delete this person", typed: u.email,
        text: html`<p>This deletes the account and ${stations.length ? html`<b>${stations.length} station${stations.length === 1 ? "" : "s"}</b>` : "any stations it has"}. Their names are held for 30 days. Past payments stay in the records.</p>` }) : ""}`, h.takeFlash(req, reply));
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
    if (raw && !/^\d{1,5}$/.test(raw)) return h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text: "The limit is a whole number, or empty." }, { form: "user-plan", values: f, errors: { limit: "A whole number from 0 to 10000, or empty." } });
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
  const accountAction = (path: string, run: (s: Session, u: UserRow, req: FastifyRequest, reply: FastifyReply, to: string) => Promise<FastifyReply>, sudo = false) =>
    app.post(`/admin/users/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply, "users.manage");
      if (!s) return reply;
      const u = await target(req, reply, s);
      if (!u) return reply;
      if (sudo && !h.requireSudo(req, reply, s, `/admin/users/${u.id}`)) return reply;
      // From the People list, back to it (with its filters).
      const b = h.form(req).back ?? "";
      return run(s, u, req, reply, /^\/admin\/users(\?[\w=&%.\-+]*)?$/.test(b) ? b : `/admin/users/${u.id}`);
    });

  accountAction("verify", async (s, u, req, reply, to) => {
    await d.db.query("UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.verify", target: u.email, ip: req.ip });
    return h.back(reply, to, { kind: "ok", text: "The email is marked confirmed." });
  });
  accountAction("reset", async (s, u, req, reply, to) => {
    const invite = invited(u);
    // A new link replaces the earlier ones.
    await d.db.query("UPDATE email_tokens SET used_at = now() WHERE user_id = $1 AND kind = 'reset' AND used_at IS NULL", [u.id]);
    const sent = await h.mailLink(u.id, u.email, invite ? "invite" : "reset");
    await audit(d.db, { actor: s.user.id, action: invite ? "user.invite_resent" : "user.reset_link", target: u.email, ip: req.ip });
    return h.back(reply, to, sent
      ? { kind: "ok", text: invite ? `A new invitation is on its way to ${u.email} (it works for 3 days).` : `A link is on its way to ${u.email} (it works for an hour).` }
      : { kind: "bad", text: "The email could not be sent (too many in the last hour, or email is not set up: check Settings > Email)." });
  });
  accountAction("email", async (s, u, req, reply) => {
    const f = h.form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    const bad = (text: string) => h.back(reply, `/admin/users/${u.id}`, { kind: "bad", text }, { form: "user-email", values: f, errors: { email: text } });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) return bad("That is not an email address.");
    if (email === u.email.toLowerCase()) return h.back(reply, `/admin/users/${u.id}`, { kind: "ok", text: "Nothing changed." });
    try {
      await d.db.query("UPDATE users SET email = $2, email_verified_at = NULL WHERE id = $1", [u.id, email]);
    } catch (e) {
      if (isUnique(e)) return bad(`There is already an account for ${email}.`);
      throw e;
    }
    // Links sent to the old address stop working.
    await d.db.query("UPDATE email_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.email", target: email, ip: req.ip, metadata: { from: u.email } });
    void h.notify(u.email, "Your email address was changed", `An administrator changed the email address of your ${d.config.rootDomain} account to ${email}. Sign in with the new address from now on.`);
    const sent = await h.mailLink(u.id, email, invited(u) ? "invite" : "verify");
    return h.back(reply, `/admin/users/${u.id}`, { kind: sent ? "ok" : "bad", text: sent ? `The email is now ${email}. ${invited(u) ? "A new invitation" : "A link to confirm it"} is on its way.` : `The email is now ${email}, but the link could not be sent: check Settings > Email, then use "${invited(u) ? "Resend the invitation" : "Send a password link"}".` });
  });
  accountAction("totp-off", async (s, u, req, reply, to) => {
    await d.db.query("UPDATE users SET totp_secret_enc = NULL WHERE id = $1", [u.id]);
    await d.db.query("DELETE FROM recovery_codes WHERE user_id = $1", [u.id]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.totp_off", target: u.email, ip: req.ip, metadata: { admin: true } });
    void h.notify(u.email, "Two-step sign-in was turned off", "An administrator turned off two-step sign-in for your account and signed you out everywhere. Turn it on again from Account & security.");
    return h.back(reply, to, { kind: "ok", text: "Two-step sign-in is off and they are signed out everywhere." });
  }, true);
  accountAction("signout", async (s, u, req, reply, to) => {
    const r = await d.db.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
    await audit(d.db, { actor: s.user.id, action: "user.sessions_end", target: u.email, ip: req.ip, metadata: { count: r.rowCount, admin: true } });
    return h.back(reply, to, { kind: "ok", text: `Signed out of ${r.rowCount} device${r.rowCount === 1 ? "" : "s"}.` });
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    accountAction(path, async (s, u, req, reply, to) => {
      await subs.setUserSuspended(h.ctx(), h.actor(s, req), u.id, on);
      return h.back(reply, to, { kind: "ok", text: on ? "Suspended, with their stations' DNS removed." : "Restored." });
    });
  }
  accountAction("delete", async (s, u, req, reply) => {
    if (String(h.form(req).confirm ?? "").trim().toLowerCase() !== u.email.toLowerCase()) return h.back(reply, `/admin/users/${u.id}#delete-person`, { kind: "bad", text: "Type the email exactly to delete." });
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
      ${panel({ flush: true }, all.length ? table(["Plan", { text: "Stations", cls: "num" }, "Price", { text: "People", cls: "num" }, { text: "", cls: "actions" }], all.map((p) => html`<tr>
        <td><a href="/admin/plans/${p.id}"><b>${p.name}</b></a> ${p.is_default ? badge("accent", "Default") : ""}${p.description ? html`<span class="sub">${p.description}</span>` : ""}</td>
        <td class="num">${p.station_limit}</td><td>${p.price_minor ? badge("ok", priceText(p)) : badge("neutral", "Not for sale")}</td><td class="num">${p.people}</td>
        <td class="actions">${menu([menuLink(`/admin/plans/${p.id}`, "Edit", "sliders"), p.is_default ? "" : menuLink(`/admin/plans/${p.id}#delete-plan`, "Delete…", "alert")], { aria: `Actions for ${p.name}` })}</td></tr>`))
        : emptyState("No plans yet", "Create a plan to give people more stations, or to sell more.", html`<a class="btn primary" href="/admin/plans/new">New plan</a>`))}`, h.takeFlash(req, reply));
  });

  const planForm = (s: Session, p: PlanRow | null, fs: FormState) => {
    const price = p?.price_minor && p.currency ? (Number(p.price_minor) / 10 ** exponent(p.currency)).toFixed(exponent(p.currency)) : "";
    const currency = fs.v("currency", p?.currency ?? "USD");
    return html`<form method="post" action="${p ? `/admin/plans/${p.id}` : "/admin/plans"}">${csrfField(s.csrf)}${panel({}, html`
      ${formSection("Plan", "What people see, and how many stations it allows.", html`
        ${field({ id: "name", label: "Name", error: fs.e("name"), control: html`<input id="name" name="name" value="${fs.v("name", p?.name)}" required maxlength="60" placeholder="Pro">` })}
        ${field({ id: "description", label: "Description (optional)", control: html`<input id="description" name="description" value="${fs.v("description", p?.description)}" maxlength="200" placeholder="For networks with several studios">` })}
        ${field({ id: "limit", label: "Stations allowed", error: fs.e("limit"), control: html`<input id="limit" type="number" name="limit" value="${fs.v("limit", p?.station_limit)}" min="0" max="10000" required class="w-sm">` })}
        <label class="check"><input type="checkbox" name="default" value="1"${(fs.returned ? fs.v("default") === "1" : p?.is_default) ? " checked" : ""}><span><b>Default plan</b><br><span class="dim">Everyone without a plan is on this one. There is one default.</span></span></label>`)}
      ${formSection("Price", "Leave the price empty to keep the plan out of the shop: admins can still assign it. A change applies to new payments only.", html`
        <div class="form-grid">
          ${field({ id: "price", label: "Price", error: fs.e("price"), control: html`<input id="price" name="price" value="${fs.v("price", price)}" inputmode="decimal" placeholder="19.99">` })}
          ${field({ id: "currency", label: "Currency", control: html`<select id="currency" name="currency">${CURRENCIES.map((c) => html`<option${currency === c ? " selected" : ""}>${c}</option>`)}</select>` })}</div>
        ${segmented({ name: "period", label: "Each payment covers", selected: fs.v("period", p?.period ?? "month"), options: [["month", "1 month"], ["year", "1 year"]] })}`)}`,
      html`<a class="btn ghost" href="/admin/plans">Cancel</a><button class="primary">${p ? "Save plan" : "Create plan"}</button>`)}</form>`;
  };

  app.get("/admin/plans/new", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    return h.render(req, reply, "New plan", html`${pageHead({ title: "New plan", back: { href: "/admin/plans", text: "Plans" } })}${planForm(s, null, h.takeForm(req, reply).for("plan"))}`, h.takeFlash(req, reply));
  });
  app.get("/admin/plans/:id", async (req, reply) => {
    const s = admin(req, reply, "plans.manage");
    if (!s) return reply;
    const p = (await plans()).find((x) => x.id === idOf(req));
    if (!p) return h.render(req, reply, "Not found", html`${pageHead({ title: "No such plan", back: { href: "/admin/plans", text: "Plans" } })}`, null, 404);
    return h.render(req, reply, p.name, html`${pageHead({ title: p.name, back: { href: "/admin/plans", text: "Plans" }, meta: html`${p.is_default ? badge("accent", "Default") : ""}${badge(p.price_minor ? "ok" : "neutral", priceText(p))}<span>${p.people} ${p.people === 1 ? "person" : "people"}</span>` })}
      ${planForm(s, p, h.takeForm(req, reply).for("plan"))}
      ${panel({ title: "Delete plan", tone: "danger", sub: p.is_default ? "The default plan cannot be deleted: make another plan the default first." : `Its ${p.people} ${p.people === 1 ? "person moves" : "people move"} to the default plan. Past payments stay in the records.` },
        p.is_default ? html`<button class="danger" disabled>Delete plan</button>` : opener("delete-plan", "Delete plan…", "danger"))}
      ${p.is_default ? "" : modal({ id: "delete-plan", title: `Delete the ${p.name} plan`, tone: "danger", action: `/admin/plans/${p.id}/delete`, csrf: s.csrf, submit: "Delete plan",
        text: html`<p>${p.people ? html`<b>${p.people} ${p.people === 1 ? "person moves" : "people move"}</b> to the default plan; stations they already have stay.` : "Nobody is on this plan."} Past payments stay in the records.</p>` })}`, h.takeFlash(req, reply));
  });

  /** Create (id null) or change a plan. */
  async function savePlan(req: FastifyRequest, reply: FastifyReply, s: Session, id: number | null) {
    const f = h.form(req);
    const here = id === null ? "/admin/plans/new" : `/admin/plans/${id}`;
    const bad = (field: string, text: string) => h.back(reply, here, { kind: "bad", text }, { form: "plan", values: f, errors: { [field]: text } });
    const name = String(f.name ?? "").trim().replace(/\s+/g, " ");
    const description = String(f.description ?? "").trim().slice(0, 200) || null;
    const raw = String(f.limit ?? "").trim();
    if (!name || name.length > 60) return bad("name", "A plan needs a name (60 characters at most).");
    if (!/^\d{1,5}$/.test(raw) || Number(raw) > 10000) return bad("limit", "The number of stations is a whole number from 0 to 10000.");
    const currency = CURRENCIES.includes(String(f.currency)) ? String(f.currency) : "USD";
    const period = f.period === "year" ? "year" : "month";
    let price: number | null = null;
    if (String(f.price ?? "").trim()) {
      price = toMinor(String(f.price), currency);
      if (price === null) return bad("price", exponent(currency) ? "Write the price like 19.99." : `Write the price as a whole number (${currency} has no cents).`);
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
      if (isUnique(e)) return bad("name", `There is already a plan called ${name}.`);
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
    const r = await d.db.query<{ name: string }>("DELETE FROM plans WHERE id = $1 AND NOT is_default RETURNING name", [idOf(req)]);
    if (!r.rows[0]) {
      const def = (await d.db.query("SELECT 1 FROM plans WHERE id = $1 AND is_default", [idOf(req)])).rowCount;
      return h.back(reply, def ? `/admin/plans/${idOf(req)}` : "/admin/plans", { kind: "bad", text: def ? "The default plan cannot be deleted: make another plan the default first." : "That plan no longer exists." });
    }
    await audit(d.db, { actor: s.user.id, action: "plan.delete", target: r.rows[0].name, ip: req.ip });
    return h.back(reply, "/admin/plans", { kind: "ok", text: `${r.rows[0].name} is deleted; its people are on the default plan.` });
  });
}
