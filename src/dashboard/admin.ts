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
import { badge, bytes, csrfField, day, emptyState, field, html, icon, pageHead, panel, when, type Html } from "./html.js";
import { choiceCards, dateParam, tabs, filterBar, like, menu, menuLink, menuOpen, menuPost, menuSep, modal, opener, pageOf, paged, pager, table, withQuery } from "./ui.js";
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

/** The first part of audit actions ("user.login"): the Audit log's area filter. */
const AUDIT_AREAS: Record<string, string> = { user: "People and sign-in", subdomain: "Stations", name: "Names", plan: "Plans", billing: "Payments", settings: "Settings", setup: "Setup checks", cert: "Certificates" };
/** ops_events.kind. */
const OPS_KINDS: Record<string, string> = { dns: "DNS", acme: "Certificates (ACME)", probe: "Reachability probes", mail: "Email", job: "Background jobs" };

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
  const none = html`<div class="card-body"><p class="dim" style="margin:0">None.</p></div>`;
  const unfinished = () => [
    d.config.dnsProvider === "memory" ? "station names are not published (no DNS provider)" : "",
    d.config.dnsProvider !== "challtestsrv" && d.config.acmeDirectoryUrl !== LE_PRODUCTION ? "certificates are test certificates (Let's Encrypt staging)" : "",
    d.config.smtpHost ? "" : "no email is sent",
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
      ${todo.length ? html`<div class="callout warn">${icon("alert")}<div><b>Setup is not finished</b><p>${todo.join("; ")}.</p></div><a class="btn sm" href="/admin/setup" style="margin-left:auto">See what is missing</a></div>` : ""}
      ${tiles.length ? html`<div class="stats">${tiles}</div>` : ""}
      ${recent.length ? panel({ title: "Recent activity", flush: true, actions: html`<a class="btn sm" href="/admin/audit">Full audit log</a>` }, table(["When", "Who", "Action", "On"], recent.map((r) => html`<tr>
        <td>${when(r.created_at)}</td><td>${r.email ?? "—"}</td><td><code>${r.action}</code></td><td>${r.target ?? ""}</td></tr>`), { fit: false })) : ""}`, h.takeFlash(req, reply));
  });

  // ------------------------------------------------------------------ setup checks

  const setupPage = (req: FastifyRequest, reply: FastifyReply, s: Session, tested?: { dns: DnsCheckStep[] | null; names: { name: string; found: string[] }[] }) => {
    const c = d.config;
    const cloudflare = c.dnsProvider === "cloudflare";
    const production = c.acmeDirectoryUrl === LE_PRODUCTION;
    const failed = tested?.dns?.some((x) => x.ok === false);
    const tile = (name: string, state: Html, text: Html | string) => html`<div class="tile"><div class="row tight" style="justify-content:space-between;gap:8px"><b>${name}</b>${state}</div><p>${text}</p></div>`;
    return h.render(req, reply, "Setup checks", html`${pageHead({ title: "Setup checks", sub: "Whether the platform is ready to serve stations.",
        actions: html`<a class="btn" href="/admin/setup/guide">${icon("info", 16)} Cloudflare setup guide</a><form method="post" action="/admin/setup/check">${csrfField(s.csrf)}<button class="primary">${cloudflare ? "Test the Cloudflare connection" : "Check the platform's addresses"}</button></form>` })}
      <div class="tiles" style="margin-bottom:20px">
        ${tile("Domain", badge("neutral", c.rootDomain), "Stations get names under this domain.")}
        ${tile("DNS provider", cloudflare ? badge("ok", "Cloudflare") : badge("bad", "None"), cloudflare ? "Station names are published at Cloudflare." : html`Names are not published and certificates fail. Follow <a href="/admin/setup/guide">the guide</a>, then add the token in <a href="/admin/settings?section=dns">Settings</a>.`)}
        ${tile("Certificates", production ? badge("ok", "Production") : badge("warn", "Staging"), production ? "Browsers trust the certificates." : html`Browsers warn about test certificates. Choose production in <a href="/admin/settings?section=acme">Settings</a> once a station works.`)}
        ${tile("Email", c.smtpHost ? badge("ok", "Sending") : badge("bad", "Not sending"), c.smtpHost ? `Through ${c.smtpHost}:${c.smtpPort || ({ ssl: 465, starttls: 587, none: 25 } as const)[c.smtpSecurity]} as ${c.mailFrom}.` : html`Links are only written to the dashboard's log. Add your mail server in <a href="/admin/settings?section=mail">Settings</a>.`)}
      </div>
      ${tested ? html`<div class="grid2">
        ${tested.dns ? panel({ title: failed ? "Cloudflare: something needs fixing" : "Cloudflare: working", id: "result" }, html`<ul class="checks">${tested.dns.map((x) => html`<li>${mark(x.ok)} <b>${x.name}</b><br><span class="${x.ok === false ? "bad" : "dim"}">${x.detail}</span></li>`)}</ul>`) : ""}
        ${panel({ title: "The platform's addresses", id: tested.dns ? "names" : "result" }, html`<ul class="checks">${tested.names.map((x) => html`<li>${mark(x.found.length > 0)} <b>${x.name}</b><br><span class="${x.found.length ? "dim" : "bad"}">${x.found.length
          ? `Points to ${x.found.join(", ")}. Check that this is the right machine's public address.`
          : html`Not found on the internet. Add this record at your DNS provider (<a href="/admin/setup/guide#step-6-add-the-platform-s-own-addresses">the guide's step 6</a>); a new record can take a few minutes to show.`}</span></li>`)}</ul>`)}</div>`
        : panel({}, emptyState("Not tested yet", cloudflare ? "Test the connection: it adds and removes one TXT record at Cloudflare and looks up the platform's own addresses." : "Check the platform's addresses: it looks up api, app and turn on the public internet."))}`, h.takeFlash(req, reply));
  };

  app.get("/admin/setup", async (req, reply) => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return reply;
    return setupPage(req, reply, s);
  });
  app.get("/admin/setup/guide", async (req, reply) => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return reply;
    return h.render(req, reply, "Cloudflare setup guide", html`${pageHead({ title: "Cloudflare setup guide", back: { href: "/admin/setup", text: "Setup checks" }, sub: "Step by step: the domain on Cloudflare, an API token for station names, and the platform's own records." })}
      ${cloudflareGuide(d.config.rootDomain)}`);
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

  const ONLINE = "st.last_seen_at > now() - interval '10 minutes'";

  app.get("/admin/stations", async (req, reply) => {
    const s = admin(req, reply, "stations.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const state = ["online", "offline", "suspended"].includes(query.state) ? query.state : "";
    const pg = pageOf(query);
    const { rows, total } = await paged<{ id: number; label: string; status: string; user_id: number; email: string; last_ip: string | null; last_port: number | null; last_seen_at: Date | null; app_version: string | null }>(d.db,
      `SELECT sd.id, sd.label, sd.status, sd.user_id, u.email, st.last_ip, st.last_port, st.last_seen_at, st.app_version
         FROM subdomains sd JOIN users u ON u.id = sd.user_id JOIN studios st ON st.subdomain_id = sd.id
        WHERE ($1 = '' OR sd.label LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%')
          AND ($2 = '' OR ($2 = 'suspended' AND sd.status = 'suspended')
               OR ($2 = 'online' AND sd.status = 'active' AND ${ONLINE})
               OR ($2 = 'offline' AND sd.status = 'active' AND NOT coalesce(${ONLINE}, false)))
        ORDER BY sd.label`, [like(q(req)), state], pg);
    const manage = can(s.user, "stations.manage");
    const form = h.takeForm(req, reply).for("station-create");
    const here = withQuery("/admin/stations", query);
    const fqdn = (label: string) => fqdnOf(label, d.config.rootDomain);
    return h.render(req, reply, "All stations", html`${pageHead({ title: "All stations", sub: "Every station address on the platform.",
        actions: manage ? opener("create-station", html`${icon("plus", 16)} Create a station`, "primary") : "" })}
      ${manage ? modal({ id: "create-station", title: "Create a station for someone", text: "The owner's plan limit applies. Their access code is shown once, on the next page.", action: "/admin/stations", csrf: s.csrf, submit: "Create station", open: form.returned, error: form.e("_"),
        body: html`${field({ id: "new-owner", label: "Owner's email", error: form.e("email"), control: html`<input id="new-owner" name="email" type="email" required autocomplete="off" placeholder="owner@example.com" value="${form.v("email")}">` })}
          ${field({ id: "new-label", label: "Name", error: form.e("label"), control: html`<div class="input-group"><input id="new-label" name="label" required maxlength="63" autocomplete="off" spellcheck="false" placeholder="kfm" value="${form.v("label")}"><span class="addon">.${d.config.rootDomain}</span></div>` })}` }) : ""}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/stations", query, search: { placeholder: "Search by name or owner" },
          chips: { name: "state", label: "Status", options: [["", "All"], ["online", "Online"], ["offline", "Offline"], ["suspended", "Suspended"]] } })}
        ${rows.length ? table(["Address", "Owner", "Status", { text: "Last address", cls: "wide-only" }, "Last seen", { text: "Nova", cls: "wide-only" }, { text: "", cls: "actions" }], rows.map((r) => html`<tr>
          <td><a href="/stations/${r.id}"><b>${fqdn(r.label)}</b></a></td>
          <td>${can(s.user, "users.view") ? html`<a href="/admin/users/${r.user_id}">${r.email}</a>` : r.email}</td><td>${statusChip(r.status, r.last_seen_at)}</td>
          <td class="wide-only">${r.last_ip ?? "—"}${r.last_port ? `:${r.last_port}` : ""}</td><td>${when(r.last_seen_at)}</td><td class="wide-only">${r.app_version ?? "—"}</td>
          <td class="actions">${menu([
            menuLink(`/stations/${r.id}`, "Open", "ext"),
            html`<button type="button" class="menu-item" role="menuitem" data-copy="https://${fqdn(r.label)}">${icon("copy", 16)}<span>Copy address</span></button>`,
            manage && can(s.user, "users.view") ? menuLink(`/admin/users/${r.user_id}`, "Open the owner", "user") : "",
            manage && menuSep(),
            manage && menuPost(`/admin/stations/${r.id}/${r.status === "active" ? "suspend" : "unsuspend"}`, r.status === "active" ? "Suspend" : "Restore", s.csrf,
              { confirm: r.status === "active" ? `Suspend ${fqdn(r.label)}? Its address stops resolving and Nova's requests are refused.` : `Restore ${fqdn(r.label)}?`, title: r.status === "active" ? "Suspend station" : "Restore station", danger: r.status === "active", hidden: { back: here }, ic: r.status === "active" ? "lock" : "check" }),
            manage && menuOpen(`del-st-${r.id}`, "Delete…", { danger: true, ic: "alert" }),
          ], { aria: `Actions for ${r.label}` })}</td></tr>`))
          : emptyState("No stations", q(req) || state ? "Nothing matches these filters." : "No station has been claimed yet.")}
        ${pager("/admin/stations", query, pg, total, "stations")}`)}
      ${manage ? rows.map((r) => modal({ id: `del-st-${r.id}`, title: `Delete ${fqdn(r.label)}`, tone: "danger", action: `/stations/${r.id}/delete`, csrf: s.csrf, submit: "Delete station", typed: r.label,
        text: html`<p>This removes the address, its certificate and every sign-in of <b>${r.email}</b>'s station. The name is held for 30 days.</p>`, hidden: { back: here } })) : ""}`, h.takeFlash(req, reply));
  });
  for (const [path, on] of [["suspend", true], ["unsuspend", false]] as const) {
    app.post(`/admin/stations/:id/${path}`, async (req, reply) => {
      const s = admin(req, reply, "stations.manage");
      if (!s) return reply;
      const b = h.form(req).back ?? "";
      const to = /^\/stations\/\d+$/.test(b) || /^\/admin\/stations(\?[\w=&%.\-+]*)?$/.test(b) ? b : "/admin/stations";
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
    const fromUser = f.back === "user";
    const owner = (await d.db.query<{ id: number }>("SELECT id FROM users WHERE lower(email) = lower($1)", [String(f.email ?? "").trim()])).rows[0];
    const keep = (field: string, text: string) => ({ form: fromUser ? "user-station" : "station-create", values: f, errors: { [field]: text } });
    if (!owner) {
      const text = `There is no account for ${String(f.email ?? "").trim() || "that email"}. Add the person first (People).`;
      return h.back(reply, "/admin/stations", { kind: "bad", text }, keep("email", text));
    }
    const label = normaliseLabel(f.label, d.config.rootDomain);
    try {
      const { accessCode } = await subs.claim(h.ctx(), h.actor(s, req), label, owner.id);
      return h.codeOnce(req, reply, label, accessCode, `${fqdnOf(label, d.config.rootDomain)} is created`);
    } catch (e) {
      if (e instanceof subs.SubdomainError) return h.back(reply, fromUser ? `/admin/users/${owner.id}` : "/admin/stations", { kind: "bad", text: e.message }, keep("label", e.message));
      throw e;
    }
  });

  // ------------------------------------------------------------------ names

  app.get("/admin/names", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const kind = ["blocked", "reserved"].includes(query.kind) ? query.kind : "";
    const pg = pageOf(query);
    const cpg = pageOf(query);
    const { rows: names, total } = await paged<{ label: string; kind: string; reason: string | null; created_at: Date }>(d.db,
      "SELECT label, kind, reason, created_at FROM reserved_names WHERE ($1 = '' OR label LIKE '%' || $1 || '%' OR lower(coalesce(reason, '')) LIKE '%' || $1 || '%') AND ($2 = '' OR kind = $2) ORDER BY kind, label",
      [like(q(req)), kind], pg);
    const { rows: cooling, total: coolingTotal } = await paged<{ label: string; available_after: Date }>(d.db,
      "SELECT label, available_after FROM name_cooldowns WHERE available_after > now() AND ($1 = '' OR label LIKE '%' || $1 || '%') ORDER BY available_after", [like(q(req))], cpg);
    const form = h.takeForm(req, reply);
    const add = form.for("name-add");
    const edit = form.for("name-edit");
    const kindCards = (selected: string, id: string) => choiceCards({ name: "kind", id, label: "Kind", selected, options: [
      { value: "blocked", title: "Blocked", text: "Not allowed (offensive, misleading, a brand)." },
      { value: "reserved", title: "Reserved", text: "Kept for the platform's own use." }] });
    const here = withQuery("/admin/names", query);
    const cool = query.view === "cooling";
    const counts = (await d.db.query<{ r: string; c: string }>("SELECT (SELECT count(*) FROM reserved_names) AS r, (SELECT count(*) FROM name_cooldowns WHERE available_after > now()) AS c")).rows[0];
    return h.render(req, reply, "Names", html`${pageHead({ title: "Names", sub: "Names nobody may claim, and names waiting 30 days after a rename or delete.",
        actions: opener("add-name", html`${icon("plus", 16)} Reserve or block a name`, "primary") })}
      ${tabs([
        { href: "/admin/names", label: "Reserved and blocked", count: Number(counts.r), current: !cool },
        { href: "/admin/names?view=cooling", label: "Cooling down", count: Number(counts.c), current: cool },
      ], "Names")}
      ${modal({ id: "add-name", title: "Reserve or block a name", text: "Existing stations keep their names.", action: "/admin/names", csrf: s.csrf, submit: "Add name", open: add.returned,
        body: html`${field({ id: "n-label", label: "Name", error: add.e("label"), control: html`<input id="n-label" name="label" required maxlength="63" autocomplete="off" spellcheck="false" value="${add.v("label")}">` })}
          ${kindCards(add.v("kind", "blocked"), "n-kind")}
          ${field({ id: "n-reason", label: "Reason (optional)", control: html`<input id="n-reason" name="reason" maxlength="200" value="${add.v("reason")}">` })}` })}
      ${cool ? "" : panel({ flush: true }, html`${filterBar({ path: "/admin/names", query, search: { placeholder: "Search names and reasons" },
          chips: { name: "kind", label: "Kind", options: [["", "All"], ["blocked", "Blocked"], ["reserved", "Reserved"]] } })}
        ${names.length ? table(["Name", "Kind", "Reason", "Added", { text: "", cls: "actions" }], names.map((n) => html`<tr><td><b>${n.label}</b></td>
          <td>${n.kind === "blocked" ? badge("bad", "Blocked") : badge("neutral", "Reserved")}</td><td class="dim">${n.reason ?? ""}</td><td>${day(n.created_at)}</td>
          <td class="actions">${menu([menuOpen(`edit-name-${n.label}`, "Edit…", { ic: "sliders" }),
            menuPost("/admin/names/remove", "Remove from the list", s.csrf, { confirm: `Remove ${n.label} from the list? It can then be claimed.`, title: "Remove name", danger: true, hidden: { label: n.label, back: here }, ic: "alert" })], { aria: `Actions for ${n.label}` })}</td></tr>`))
          : emptyState("No names", q(req) || kind ? "Nothing matches these filters." : "No name is reserved or blocked.")}
        ${pager("/admin/names", query, pg, total, "names")}`)}
      ${names.map((n) => modal({ id: `edit-name-${n.label}`, title: `Edit ${n.label}`, action: "/admin/names/edit", csrf: s.csrf, submit: "Save", hidden: { label: n.label, back: here },
        open: edit.returned && edit.v("label") === n.label,
        body: html`${kindCards(edit.returned && edit.v("label") === n.label ? edit.v("kind", n.kind) : n.kind, `e-kind-${n.label}`)}
          ${field({ id: `e-reason-${n.label}`, label: "Reason (optional)", control: html`<input id="e-reason-${n.label}" name="reason" maxlength="200" value="${n.reason ?? ""}">` })}` }))}
      ${!cool ? "" : panel({ flush: true }, html`${filterBar({ path: "/admin/names", query, search: { placeholder: "Search names" } })}
        <p class="dim small" style="margin:0;padding:10px 16px;border-bottom:1px solid var(--line)">Names freed by a rename or delete wait 30 days, so an old address cannot be taken over at once.</p>
        ${cooling.length ? table(["Name", "Free again", { text: "", cls: "actions" }], cooling.map((c) => html`<tr><td><b>${c.label}</b></td><td>${when(c.available_after)}</td>
          <td class="actions"><form class="inline" method="post" action="/admin/names/release" data-confirm="Release ${c.label} now? Anyone can then claim it." data-confirm-title="Release name">${csrfField(s.csrf)}<input type="hidden" name="label" value="${c.label}"><button class="sm">Release now</button></form></td></tr>`))
          : none}
        ${pager("/admin/names", query, cpg, coolingTotal, "names")}`)}`,
    h.takeFlash(req, reply));
  });
  const namesBack = (f: Record<string, string>) => (/^\/admin\/names(\?[\w=&%.\-+]*)?$/.test(f.back ?? "") ? f.back : "/admin/names");
  app.post("/admin/names", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const f = h.form(req);
    const label = String(f.label ?? "").trim().toLowerCase();
    const bad = (text: string) => h.back(reply, "/admin/names", { kind: "bad", text }, { form: "name-add", values: f, errors: { label: text } });
    if (!label || label.length > 63 || !/^[a-z0-9-]+$/.test(label)) return bad("Letters, digits and hyphens only (63 at most).");
    const kind = f.kind === "reserved" ? "reserved" : "blocked";
    const r = await d.db.query("INSERT INTO reserved_names (label, kind, reason, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (label) DO NOTHING",
      [label, kind, String(f.reason ?? "").slice(0, 200) || null, s.user.id]);
    if (!r.rowCount) {
      const was = (await d.db.query<{ kind: string }>("SELECT kind FROM reserved_names WHERE label = $1", [label])).rows[0]?.kind;
      return bad(`${label} is already ${was ?? "on the list"}. Change it with Edit in the list.`);
    }
    await audit(d.db, { actor: s.user.id, action: `name.${kind}`, target: label, ip: req.ip });
    return h.back(reply, "/admin/names", { kind: "ok", text: `${label} is ${kind}. Existing stations keep their names.` });
  });
  app.post("/admin/names/edit", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const f = h.form(req);
    const label = String(f.label ?? "");
    const kind = f.kind === "reserved" ? "reserved" : "blocked";
    const r = await d.db.query("UPDATE reserved_names SET kind = $2, reason = $3 WHERE label = $1", [label, kind, String(f.reason ?? "").trim().slice(0, 200) || null]);
    if (!r.rowCount) return h.back(reply, namesBack(f), { kind: "bad", text: `${label} is no longer on the list.` });
    await audit(d.db, { actor: s.user.id, action: "name.update", target: label, ip: req.ip, metadata: { kind } });
    return h.back(reply, namesBack(f), { kind: "ok", text: `${label} is ${kind}.` });
  });
  app.post("/admin/names/remove", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const f = h.form(req);
    const label = String(f.label ?? "");
    await d.db.query("DELETE FROM reserved_names WHERE label = $1", [label]);
    await audit(d.db, { actor: s.user.id, action: "name.unreserve", target: label, ip: req.ip });
    return h.back(reply, namesBack(f), { kind: "ok", text: formError(label) ? `${label} removed.` : `${label} can be claimed.` });
  });
  app.post("/admin/names/release", async (req, reply) => {
    const s = admin(req, reply, "names.manage");
    if (!s) return reply;
    const label = String(h.form(req).label ?? "");
    await subs.forceRelease(d.db, h.actor(s, req), label);
    return h.back(reply, "/admin/names", { kind: "ok", text: `${label} is free now.` });
  });

  // ------------------------------------------------------------------ certificates

  const CERT_VIEWS: Record<string, { title: string; where: string; order: string }> = {
    waiting: { title: "Waiting", where: "status = 'pending'", order: "created_at" },
    failed: { title: "Failed", where: "status = 'failed'", order: "created_at DESC" },
    renewals: { title: "Upcoming renewals", where: "status = 'issued'", order: "coalesce(ari_renewal_after, expires_at - interval '30 days')" },
    issued: { title: "Issued", where: "status = 'issued'", order: "issued_at DESC" },
  };

  app.get("/admin/certificates", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const view = CERT_VIEWS[query.view] ? query.view : "waiting";
    const n = async (sql: string) => Number((await d.db.query(sql)).rows[0].n);
    const week = await n("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL");
    const renewals = await n("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NOT NULL");
    const waiting = await n("SELECT count(*) AS n FROM certificates WHERE status = 'pending'");
    const failed30 = await n("SELECT count(*) AS n FROM certificates WHERE status = 'failed' AND created_at > now() - interval '30 days'");
    const v = CERT_VIEWS[view];
    const pg = pageOf(query);
    const { rows, total } = await paged<{ id: number; fqdn: string; subdomain_id: number; created_at: Date; next_attempt_at: Date; issued_at: Date | null; expires_at: Date | null; ari_renewal_after: Date | null; error: string | null; attempts: number }>(d.db,
      `SELECT id, fqdn, subdomain_id, created_at, next_attempt_at, issued_at, expires_at, ari_renewal_after, error, attempts FROM certificates
        WHERE ${v.where} AND ($1 = '' OR fqdn LIKE '%' || $1 || '%') ORDER BY ${v.order}`, [like(q(req))], pg);
    const near = week >= d.config.certWeeklyLimit - 5;
    const retry = can(s.user, "stations.manage");
    const retryForm = (id: number, fqdn: string) => retry ? html`<form class="inline" method="post" action="/admin/certificates/${id}/retry" data-confirm="Try to issue ${fqdn}'s certificate again now?" data-confirm-title="Retry certificate">${csrfField(s.csrf)}<input type="hidden" name="back" value="${withQuery("/admin/certificates", query)}"><button class="sm">Retry now</button></form>` : "";
    const cols: Record<string, Parameters<typeof table>[0]> = {
      waiting: ["Name", "Asked", "Next try", "Tries", "Note", { text: "", cls: "actions" }],
      failed: ["Name", "When", "Error", { text: "", cls: "actions" }],
      renewals: ["Name", "Renew from", "Expires"],
      issued: ["Name", "Issued", "Expires"],
    };
    const row = (c: (typeof rows)[number]) => view === "waiting"
      ? html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td>${when(c.next_attempt_at)}</td><td class="num">${c.attempts}</td><td class="dim">${c.error ?? ""}</td><td class="actions">${retryForm(c.id, c.fqdn)}</td></tr>`
      : view === "failed"
        ? html`<tr><td>${c.fqdn}</td><td>${when(c.created_at)}</td><td class="bad">${c.error ?? ""}</td><td class="actions">${retryForm(c.id, c.fqdn)}</td></tr>`
        : view === "renewals"
          ? html`<tr><td>${c.fqdn}</td><td>${when(c.ari_renewal_after ?? new Date(new Date(c.expires_at!).getTime() - 30 * 86400_000))}${c.ari_renewal_after ? html` ${badge("info", "ARI")}` : ""}</td><td>${when(c.expires_at)}</td></tr>`
          : html`<tr><td>${c.fqdn}</td><td>${when(c.issued_at)}</td><td>${when(c.expires_at)}</td></tr>`;
    return h.render(req, reply, "Certificates", html`${pageHead({ title: "Certificates", sub: "Station certificates from Let's Encrypt, issued by the worker over DNS-01." })}
      <div class="stats"><div class="stat"><span>New, last 7 days</span><b>${week} <span>of ${d.config.certWeeklyLimit}</span></b><small>${near ? "Near the limit: new ones wait in the queue." : "Let's Encrypt's limit per registered domain"}</small></div>
        <div class="stat"><span>Renewals, last 7 days</span><b>${renewals}</b><small>Exempt from the limit (ARI)</small></div>
        <a class="stat" href="/admin/certificates?view=waiting"><span>Waiting</span><b>${waiting}</b></a><a class="stat" href="/admin/certificates?view=failed"><span>Failed, 30 days</span><b>${failed30}</b></a></div>
      ${near ? html`<div class="callout warn">${icon("alert")}<div><b>Near the weekly limit</b><p>Consider asking Let's Encrypt for a higher limit, or Public Suffix List inclusion.</p></div></div>` : ""}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/certificates", query, search: { placeholder: "Search by name" },
          chips: { name: "view", label: "Show", options: [["", "Waiting"], ["failed", "Failed"], ["renewals", "Upcoming renewals"], ["issued", "Issued"]] } })}
        ${rows.length ? table(cols[view], rows.map(row)) : none}
        ${pager("/admin/certificates", query, pg, total, "certificates")}`)}`, h.takeFlash(req, reply));
  });

  app.post("/admin/certificates/:id/retry", async (req, reply) => {
    const s = admin(req, reply, "stations.manage");
    if (!s) return reply;
    const b = h.form(req).back ?? "";
    const to = /^\/admin\/certificates(\?[\w=&%.\-+]*)?$/.test(b) ? b : "/admin/certificates";
    const id = Number((req.params as { id: string }).id);
    // Only the station's newest attempt, and only when nothing newer is waiting or issued.
    const r = await d.db.query<{ fqdn: string }>(
      `UPDATE certificates c SET status = 'pending', attempts = 0, error = NULL, next_attempt_at = now()
        WHERE c.id = $1 AND c.status IN ('failed', 'pending')
          AND NOT EXISTS (SELECT 1 FROM certificates n WHERE n.subdomain_id = c.subdomain_id AND n.id <> c.id AND n.created_at > c.created_at AND n.status IN ('pending', 'issued'))
        RETURNING fqdn`, [Number.isSafeInteger(id) ? id : -1]);
    if (!r.rows[0]) return h.back(reply, to, { kind: "bad", text: "That certificate cannot be retried: a newer one replaced it, or it was issued." });
    await d.db.query("SELECT pg_notify('cert_queue', '')");
    await audit(d.db, { actor: s.user.id, action: "cert.retry", target: r.rows[0].fqdn, ip: req.ip });
    return h.back(reply, to, { kind: "ok", text: `${r.rows[0].fqdn} is queued; the worker tries within seconds.` });
  });

  // ------------------------------------------------------------------ TURN usage

  app.get("/admin/turn", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const from = dateParam(query.from) || new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10);
    const to = dateParam(query.to);
    const pg = pageOf(query);
    const { rows, total } = await paged<{ label: string; b: string; n: number }>(d.db,
      `SELECT sd.label, sum(t.bytes_relayed)::bigint AS b, sum(t.sessions)::int AS n
         FROM turn_usage t JOIN studios st ON st.id = t.studio_id JOIN subdomains sd ON sd.id = st.subdomain_id
        WHERE t.day >= $1::date AND ($2 = '' OR t.day <= NULLIF($2, '')::date) AND ($3 = '' OR sd.label LIKE '%' || $3 || '%')
        GROUP BY sd.label ORDER BY b DESC`, [from, to, like(q(req))], pg);
    return h.render(req, reply, "Audio relay", html`${pageHead({ title: "Audio relay", sub: "Audio relayed by TURN for stations whose presenters could not connect directly. Largest first." })}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/turn", query: { ...query, from }, search: { placeholder: "Search by station" }, dates: true })}
        ${rows.length ? table(["Station", { text: "Relayed", cls: "num" }, { text: "Sessions", cls: "num" }], rows.map((r) => html`<tr><td>${r.label}</td><td class="num">${bytes(Number(r.b))}</td><td class="num">${r.n}</td></tr>`))
          : emptyState("Nothing relayed", "Every presenter connected directly in this period.")}
        ${pager("/admin/turn", query, pg, total, "stations")}`)}`);
  });

  // ------------------------------------------------------------------ logs

  const metaCell = (m: unknown) => {
    const keys = Object.keys((m ?? {}) as object);
    if (!keys.length) return "";
    return html`<details class="meta"><summary>${keys.slice(0, 3).join(", ")}${keys.length > 3 ? "…" : ""}</summary><pre>${JSON.stringify(m, null, 2)}</pre></details>`;
  };

  app.get("/admin/audit", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const area = query.area in AUDIT_AREAS ? query.area : "";
    const pg = pageOf(query);
    const { rows, total } = await paged<{ created_at: Date; action: string; target: string | null; ip: string | null; metadata: unknown; email: string | null; actor_user_id: number | null }>(d.db,
      `SELECT a.created_at, a.action, a.target, a.ip, a.metadata, u.email, a.actor_user_id FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
        WHERE ($1 = '' OR a.action LIKE '%' || $1 || '%' OR lower(coalesce(a.target, '')) LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%' OR a.ip LIKE $1 || '%')
          AND ($2 = '' OR split_part(a.action, '.', 1) = $2)
          AND ($3 = '' OR a.created_at >= NULLIF($3, '')::date)
          AND ($4 = '' OR a.created_at < NULLIF($4, '')::date + 1)
        ORDER BY a.created_at DESC`, [like(q(req)), area, dateParam(query.from), dateParam(query.to)], pg);
    const people = can(s.user, "users.view");
    return h.render(req, reply, "Audit log", html`${pageHead({ title: "Audit log", sub: "Every change, who made it and from where. Secrets are never written here." })}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/audit", query, search: { placeholder: "Search action, name, person or IP" }, dates: true,
          selects: [{ name: "area", label: "Area", options: [["", "Every area"], ...Object.entries(AUDIT_AREAS)] }] })}
        ${rows.length ? table(["When", "Who", "Action", "On", { text: "From", cls: "wide-only" }, { text: "Details", cls: "wide-only" }], rows.map((r) => html`<tr>
          <td style="white-space:nowrap">${when(r.created_at)}</td><td>${r.email ? (people && r.actor_user_id ? html`<a href="/admin/users/${r.actor_user_id}">${r.email}</a>` : r.email) : "—"}</td><td><code>${r.action}</code></td><td>${r.target ?? ""}</td><td class="wide-only">${r.ip ?? ""}</td>
          <td class="wide-only small">${metaCell(r.metadata)}</td></tr>`)) : emptyState("Nothing found", "No entry matches these filters.")}
        ${pager("/admin/audit", query, pg, total, "entries")}`)}`);
  });

  app.get("/admin/operations", async (req, reply) => {
    const s = admin(req, reply, "logs.view");
    if (!s) return reply;
    const query = req.query as Record<string, string>;
    const kind = query.kind in OPS_KINDS ? query.kind : "";
    const level = ["error", "info"].includes(query.level) ? query.level : "";
    const pg = pageOf(query);
    const { rows, total } = await paged<{ created_at: Date; kind: string; level: string; target: string | null; message: string }>(d.db,
      `SELECT created_at, kind, level, target, message FROM ops_events
        WHERE ($1 = '' OR lower(coalesce(target, '')) LIKE '%' || $1 || '%' OR lower(message) LIKE '%' || $1 || '%')
          AND ($2 = '' OR kind = $2) AND ($3 = '' OR level = $3)
          AND ($4 = '' OR created_at >= NULLIF($4, '')::date) AND ($5 = '' OR created_at < NULLIF($5, '')::date + 1)
        ORDER BY created_at DESC`, [like(q(req)), kind, level, dateParam(query.from), dateParam(query.to)], pg);
    return h.render(req, reply, "DNS & ACME events", html`${pageHead({ title: "DNS & ACME events", sub: "Problems with DNS, certificates, probes and background jobs. Admins get a daily email of new errors." })}
      ${panel({ flush: true }, html`${filterBar({ path: "/admin/operations", query, search: { placeholder: "Search name or message" }, dates: true,
          chips: { name: "level", label: "Level", options: [["", "All"], ["error", "Errors"], ["info", "Notes"]] },
          selects: [{ name: "kind", label: "Kind", options: [["", "Every kind"], ...Object.entries(OPS_KINDS)] }] })}
        ${rows.length ? table(["When", "Kind", "Name", "Message"], rows.map((r) => html`<tr>
          <td style="white-space:nowrap">${when(r.created_at)}</td><td>${r.level === "error" ? badge("bad", r.kind) : badge("neutral", r.kind)}</td><td>${r.target ?? ""}</td><td class="${r.level === "error" ? "bad" : "dim"}">${r.message}</td></tr>`))
          : emptyState("No events", q(req) || kind || level ? "Nothing matches these filters." : "Nothing has gone wrong.")}
        ${pager("/admin/operations", query, pg, total, "events")}`)}`);
  });
}
