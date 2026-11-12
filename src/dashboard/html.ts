/**
 * Server-rendered pages: an escaping `html` template tag, the application shell (a
 * sidebar console when signed in, a centred panel when not; light and dark), the design
 * system's CSS, icons and small pieces. No inline script (the CSP forbids it): the few
 * behaviours (the live name check, copy buttons, confirmations, continuing to checkout)
 * are /static/app.js.
 */

import { can, isStaff, type Permission, type Role } from "../lib/rbac.js";

export class Html {
  constructor(readonly value: string) {}
  toString() {
    return this.value;
  }
}

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escape = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

function piece(v: unknown): string {
  if (v instanceof Html) return v.value;
  if (Array.isArray(v)) return v.map(piece).join("");
  if (v === null || v === undefined || v === false) return "";
  return escape(v);
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): Html {
  let out = strings[0];
  values.forEach((v, i) => {
    out += piece(v) + strings[i + 1];
  });
  return new Html(out);
}

export const raw = (s: string) => new Html(s);

// ---------------------------------------------------------------- icons (24px, stroked)

const ICONS: Record<string, string> = {
  radio: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 19.1a10 10 0 0 1 0-14.2"/>',
  card: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="M2.5 10h19M6.5 15h4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20.5a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M21.5 20.5a6.5 6.5 0 0 0-3.8-5.9"/>',
  grid: '<rect x="3" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5"/>',
  layers: '<path d="M12 3 2.5 8 12 13l9.5-5L12 3Z"/><path d="m2.5 12.5 9.5 5 9.5-5M2.5 17l9.5 5 9.5-5"/>',
  tag: '<path d="M3 12.6V4a1 1 0 0 1 1-1h8.6l8.7 8.7a1 1 0 0 1 0 1.4l-7.9 7.9a1 1 0 0 1-1.4 0L3 12.6Z"/><circle cx="7.8" cy="7.8" r="1.4"/>',
  shield: '<path d="M12 2.8 20 6v6c0 4.8-3.4 8.2-8 9.2-4.6-1-8-4.4-8-9.2V6l8-3.2Z"/><path d="m8.8 12 2.2 2.2 4.2-4.4"/>',
  activity: '<path d="M2.5 12h4l3-7.5 5 15 3-7.5h4"/>',
  list: '<path d="M8.5 6h12M8.5 12h12M8.5 18h12"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
  alert: '<path d="M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4.5M12 17.2v.1"/>',
  sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12.2 2.8 2.8L16.2 9.5"/>',
  logout: '<path d="M14.5 4H19a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4.5"/><path d="m9.5 8-4 4 4 4M5.5 12H16"/>',
  lock: '<rect x="4" y="10.5" width="16" height="10.5" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>',
  key: '<circle cx="7.5" cy="15.5" r="4"/><path d="m10.5 12.5 9-9M16.5 6.5l2.5 2.5M14 9l2 2"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5V5a1.5 1.5 0 0 0-1.5-1.5H5A1.5 1.5 0 0 0 3.5 5v9A1.5 1.5 0 0 0 5 15.5h3.5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.1"/>',
};

export const icon = (name: keyof typeof ICONS | string, size = 18) =>
  raw(`<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] ?? ""}</svg>`);

// ---------------------------------------------------------------- pieces

export type Tone = "ok" | "bad" | "warn" | "info" | "neutral" | "accent";

/** A small status label with a dot. */
export const badge = (tone: Tone, text: string) => html`<span class="badge ${tone}">${text}</span>`;

/** The heading of a page: title, a line under it, actions at the right, an optional way back. */
export function pageHead(o: { title: string; sub?: Html | string; actions?: Html | string; back?: { href: string; text: string }; meta?: Html | string }): Html {
  return html`<div class="page-head">${o.back ? html`<a class="back" href="${o.back.href}">${icon("arrow", 15)} ${o.back.text}</a>` : ""}
    <div class="page-head-row"><div class="page-head-text"><h1>${o.title}</h1>${o.meta ? html`<div class="page-meta">${o.meta}</div>` : ""}${o.sub ? html`<p class="page-sub">${o.sub}</p>` : ""}</div>
    ${o.actions ? html`<div class="page-actions">${o.actions}</div>` : ""}</div></div>`;
}

/** A panel with a heading row (title, a line of explanation, actions) and its body. */
export function panel(o: { title?: string; sub?: Html | string; actions?: Html | string; tone?: "danger"; id?: string; flush?: boolean }, body: Html | string, foot?: Html | string): Html {
  return html`<section class="card${o.tone === "danger" ? " danger" : ""}${o.flush ? " flush" : ""}"${o.id ? raw(` id="${escape(o.id)}"`) : ""}>
    ${o.title ? html`<header class="card-head"><div><h2>${o.title}</h2>${o.sub ? html`<p>${o.sub}</p>` : ""}</div>${o.actions ? html`<div class="card-actions">${o.actions}</div>` : ""}</header>` : ""}
    <div class="card-body">${body}</div>${foot ? html`<footer class="card-foot">${foot}</footer>` : ""}</section>`;
}

/** A settings-style section: what it is on the left, the fields on the right. */
export function formSection(title: string, sub: Html | string, fields: Html | string): Html {
  return html`<div class="fsec"><div class="fsec-text"><h3>${title}</h3><p>${sub}</p></div><div class="fsec-fields">${fields}</div></div>`;
}

/** A label, the field, and help under it. */
export function field(o: { id: string; label: string; help?: Html | string; control: Html }): Html {
  return html`<div class="field"><label for="${o.id}">${o.label}</label>${o.control}${o.help ? html`<p class="help">${o.help}</p>` : ""}</div>`;
}

/** A list of facts: term and value. */
export const facts = (rows: [string, Html | string | number][]) =>
  html`<dl class="facts">${rows.map(([k, v]) => html`<div><dt>${k}</dt><dd>${v}</dd></div>`)}</dl>`;

export const emptyState = (title: string, text: Html | string, action?: Html | string) =>
  html`<div class="empty"><div class="empty-ic">${icon("radio", 22)}</div><h3>${title}</h3><p>${text}</p>${action ?? ""}</div>`;

// ---------------------------------------------------------------- the frame

export interface Frame {
  title: string;
  user?: { email: string; role: Role | string; permissions?: string[] } | null;
  csrf?: string;
  flash?: { kind: "ok" | "bad"; text: string } | null;
  rootDomain: string;
  /** The page's address, to mark where the visitor is in the menu. */
  path?: string;
  /** Payments are on: owners see Billing. */
  billing?: boolean;
}

type NavItem = { href: string; text: string; icon: string; perm?: Permission | null };

const OWNER_NAV = (billing: boolean): NavItem[] => [
  { href: "/", text: "Stations", icon: "radio" },
  ...(billing ? [{ href: "/billing", text: "Billing", icon: "card" }] : []),
  { href: "/account", text: "Account & security", icon: "user" },
];
const ADMIN_NAV: [string, NavItem[]][] = [
  ["Administration", [
    { href: "/admin", text: "Overview", icon: "grid", perm: null },
    { href: "/admin/users", text: "People", icon: "users", perm: "users.view" },
    { href: "/admin/stations", text: "All stations", icon: "radio", perm: "stations.view" },
    { href: "/admin/plans", text: "Plans", icon: "layers", perm: "plans.manage" },
    { href: "/admin/billing", text: "Payments", icon: "card", perm: "billing.manage" },
    { href: "/admin/names", text: "Names", icon: "tag", perm: "names.manage" },
  ]],
  ["Operations", [
    { href: "/admin/certificates", text: "Certificates", icon: "shield", perm: "logs.view" },
    { href: "/admin/turn", text: "Audio relay", icon: "activity", perm: "logs.view" },
    { href: "/admin/operations", text: "DNS & ACME events", icon: "alert", perm: "logs.view" },
    { href: "/admin/audit", text: "Audit log", icon: "list", perm: "logs.view" },
  ]],
  ["Platform", [
    { href: "/admin/settings", text: "Settings", icon: "sliders", perm: "settings.manage" },
    { href: "/admin/setup", text: "Setup checks", icon: "check", perm: "settings.manage" },
  ]],
];

function nav(f: Frame): Html {
  const user = f.user!;
  const principal = { id: 0, role: user.role as Role, permissions: user.permissions ?? [] };
  const groups: [string, NavItem[]][] = [["Workspace", OWNER_NAV(!!f.billing)]];
  if (isStaff(principal)) for (const [g, items] of ADMIN_NAV) {
    const mine = items.filter((i) => !i.perm || can(principal, i.perm));
    if (mine.length) groups.push([g, mine]);
  }
  const path = (f.path ?? "").split("?")[0];
  const all = groups.flatMap(([, items]) => items.map((i) => i.href));
  // The most specific item containing this page; "/" also stands for /stations/*.
  const here = all.filter((h) => (h === "/" ? path === "/" || path.startsWith("/stations") : path === h || path.startsWith(`${h}/`))).sort((a, b) => b.length - a.length)[0];
  return html`${groups.map(([g, items]) => html`<div class="nav-group"><div class="nav-title">${g}</div>${items.map((i) => html`<a href="${i.href}"${i.href === here ? raw(' aria-current="page"') : ""}>${icon(i.icon)}<span>${i.text}</span></a>`)}</div>`)}`;
}

const roleLabel = (r: string) => (r === "superadmin" ? "Super admin" : r === "admin" ? "Admin" : "Station owner");

export function page(f: Frame, body: Html): string {
  const head = html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${f.title} · ${f.rootDomain}</title><style>${raw(CSS)}</style><script src="/static/app.js" defer></script></head>`;
  const flash = f.flash ? html`<div class="flash ${f.flash.kind}" role="status">${icon(f.flash.kind === "ok" ? "check" : "alert")}<span>${f.flash.text}</span></div>` : "";
  const brand = html`<a class="brand" href="/"><span class="logo">${icon("radio", 18)}</span><span class="brand-text"><b>Nova</b><small>${f.rootDomain}</small></span></a>`;

  if (!f.user) {
    return html`${head}<body class="auth"><main class="auth-box">${brand}${flash}${body}
      <p class="auth-foot">Remote Studio addresses for Nova · ${f.rootDomain}</p></main></body></html>`.value;
  }
  const initial = (f.user.email[0] ?? "?").toUpperCase();
  const who = html`<div class="who"><span class="avatar">${initial}</span><span class="who-text"><b title="${f.user.email}">${f.user.email}</b><small>${roleLabel(String(f.user.role))}</small></span>
    <form method="post" action="/logout">${csrfField(f.csrf)}<button class="icon-btn" title="Sign out" aria-label="Sign out">${icon("logout")}</button></form></div>`;
  return html`${head}<body class="app">
<aside class="side">${brand}<nav aria-label="Main">${nav(f)}</nav>${who}</aside>
<div class="main"><header class="top"><details class="mnav"><summary aria-label="Menu">${icon("menu")}</summary><div class="mnav-panel"><nav aria-label="Main">${nav(f)}</nav>${who}</div></details>${brand}</header>
<main class="content">${flash}${body}</main>
<footer class="foot">Remote Studio addresses for Nova · ${f.rootDomain}</footer></div></body></html>`.value;
}

export const csrfField = (token?: string) => (token ? html`<input type="hidden" name="_csrf" value="${token}">` : "");

export const when = (d: Date | string | null | undefined) =>
  d ? new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—";

export const day = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString().slice(0, 10) : "—");

export function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n) || 0;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

// ---------------------------------------------------------------- the design system

const CSS = `
:root{color-scheme:light dark;
--bg:#f6f7f9;--surface:#fff;--surface-2:#f9fafb;--ink:#101828;--ink-2:#344054;--muted:#667085;--line:#e4e7ec;--line-2:#d0d5dd;
--accent:#4f46e5;--accent-ink:#fff;--accent-soft:#eef2ff;--focus:#a5b4fc;
--ok:#067647;--ok-soft:#ecfdf3;--bad:#b42318;--bad-soft:#fef3f2;--warn:#b54708;--warn-soft:#fffaeb;--info:#175cd3;--info-soft:#eff8ff;--neutral-soft:#f2f4f7;
--side:#0c111d;--side-ink:#cecfd2;--side-muted:#85888e;--side-hover:#161b26;--side-line:#1f242f;
--shadow:0 1px 2px rgba(16,24,40,.05);--shadow-lg:0 12px 16px -4px rgba(16,24,40,.08),0 4px 6px -2px rgba(16,24,40,.03);--r:10px}
@media (prefers-color-scheme:dark){:root{
--bg:#0c111d;--surface:#111522;--surface-2:#0f1420;--ink:#f5f5f6;--ink-2:#cecfd2;--muted:#94969c;--line:#1f242f;--line-2:#333741;
--accent:#818cf8;--accent-ink:#0c111d;--accent-soft:#1e1b4b;--focus:#4f46e5;
--ok:#47cd89;--ok-soft:#053321;--bad:#f97066;--bad-soft:#55160c;--warn:#fdb022;--warn-soft:#4e1d09;--info:#53b1fd;--info-soft:#102a56;--neutral-soft:#1f242f;
--side:#080b13;--side-hover:#131824;--side-line:#1a1f2b;--shadow:none;--shadow-lg:0 12px 24px rgba(0,0,0,.4)}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:3px solid var(--focus);outline-offset:1px;border-radius:6px}
.ic{flex:none;display:inline-block;vertical-align:middle}
h1,h2,h3{color:var(--ink);letter-spacing:-.01em}
p{margin:0 0 10px}

/* ---------- shell */
body.app{display:grid;grid-template-columns:264px minmax(0,1fr);min-height:100vh;background:linear-gradient(to right,var(--side) 264px,var(--bg) 264px)}
.side{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;background:var(--side);color:var(--side-ink);border-right:1px solid var(--side-line);padding:18px 12px 12px;overflow-y:auto}
.brand{display:flex;align-items:center;gap:10px;padding:2px 8px 18px;color:inherit;text-decoration:none!important}
.side .brand,.mnav-panel .brand{color:#fff}
.logo{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#6366f1,#4338ca);color:#fff;box-shadow:inset 0 0 0 1px rgba(255,255,255,.12)}
.brand-text{display:flex;flex-direction:column;line-height:1.2;min-width:0}.brand-text b{font-size:15px}.brand-text small{font-size:12px;opacity:.65;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.side nav{flex:1}
.nav-group{margin-bottom:18px}.nav-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--side-muted);padding:0 10px 6px}
.side nav a,.mnav nav a{display:flex;align-items:center;gap:10px;padding:7px 10px;margin:1px 0;border-radius:7px;color:var(--side-ink);font-weight:500;text-decoration:none}
.side nav a .ic,.mnav nav a .ic{color:var(--side-muted)}
.side nav a:hover,.mnav nav a:hover{background:var(--side-hover);color:#fff}
.side nav a[aria-current],.mnav nav a[aria-current]{background:var(--side-hover);color:#fff;box-shadow:inset 2px 0 0 #818cf8}.side nav a[aria-current] .ic,.mnav nav a[aria-current] .ic{color:#a5b4fc}
.who{display:flex;align-items:center;gap:10px;padding:12px 8px 4px;border-top:1px solid var(--side-line);margin-top:8px}
.avatar{display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:#1f2a44;color:#c7d2fe;font-weight:600;flex:none}
.who-text{display:flex;flex-direction:column;min-width:0;flex:1;line-height:1.25}.who-text b{color:#fff;font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.who-text small{color:var(--side-muted);font-size:12px}
.icon-btn{display:grid;place-items:center;width:32px;height:32px;padding:0;border:0;border-radius:7px;background:transparent;color:var(--side-muted);cursor:pointer}.icon-btn:hover{background:var(--side-hover);color:#fff}
.main{display:flex;flex-direction:column;min-width:0;min-height:100vh}
.top{display:none}
.content{width:100%;max-width:1160px;margin:0 auto;padding:32px 32px 24px;flex:1}
.foot{padding:16px 32px 24px;color:var(--muted);font-size:12px;text-align:center}
@media (max-width:960px){
  body.app{display:block;background:var(--bg)}.side{display:none}
  .top{display:flex;align-items:center;gap:8px;position:sticky;top:0;z-index:20;height:56px;padding:0 12px;background:var(--side);border-bottom:1px solid var(--side-line)}
  .top>.brand{padding:0;color:#fff}.top .brand-text small{display:none}
  .mnav summary{list-style:none;display:grid;place-items:center;width:40px;height:40px;border-radius:8px;color:#fff;cursor:pointer}.mnav summary::-webkit-details-marker{display:none}
  .mnav[open] summary{background:var(--side-hover)}
  .mnav-panel{position:fixed;top:56px;left:0;bottom:0;width:min(300px,86vw);background:var(--side);color:var(--side-ink);padding:16px 12px;overflow-y:auto;z-index:30;box-shadow:var(--shadow-lg);display:flex;flex-direction:column}
  .mnav-panel nav{flex:1}
  .content{padding:20px 16px}.foot{padding:12px 16px 20px}
}

/* ---------- page heading */
.page-head{margin-bottom:24px}
.back{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-weight:500;font-size:13px;margin-bottom:10px}.back:hover{color:var(--ink);text-decoration:none}
.page-head-row{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.page-head h1{font-size:24px;line-height:1.25;font-weight:650;margin:0}
.page-sub{color:var(--muted);margin:6px 0 0;max-width:760px}
.page-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px;color:var(--muted);font-size:13px}
.page-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}

/* ---------- cards */
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);margin-bottom:20px;overflow:hidden}
.card>.card-body,.card:not(:has(>.card-body)){padding:20px 24px}
.card.flush>.card-body{padding:0}.card.flush .card-body .card-body{padding:16px 24px}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:18px 24px;border-bottom:1px solid var(--line)}
.card-head h2{font-size:16px;font-weight:600;margin:0}.card-head p{color:var(--muted);margin:3px 0 0;font-size:13.5px}
.card-actions{display:flex;gap:8px;flex-wrap:wrap}
.card-foot{display:flex;justify-content:flex-end;align-items:center;gap:10px;flex-wrap:wrap;padding:14px 24px;border-top:1px solid var(--line);background:var(--surface-2)}
.card-foot .spacer{flex:1}
.card.danger{border-color:color-mix(in srgb,var(--bad) 35%,var(--line))}.card.danger .card-head h2{color:var(--bad)}
.card.notice{border-left:3px solid var(--warn)}
.card h1{font-size:20px;margin:0 0 12px}.card h2{font-size:16px;margin:0 0 8px}
.card>:last-child,.card-body>:last-child{margin-bottom:0}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px;margin-bottom:20px}.cols>.card{margin-bottom:0}
.split{display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:20px;align-items:start}@media(max-width:1060px){.split{grid-template-columns:1fr}}

/* ---------- text and status */
.dim,.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.small{font-size:12.5px}
.badge,.chip{display:inline-flex;align-items:center;gap:6px;padding:2px 9px 2px 8px;border-radius:999px;font-size:12px;font-weight:500;line-height:18px;white-space:nowrap;background:var(--neutral-soft);color:var(--ink-2);border:1px solid transparent}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.85}
.badge.ok,.chip.ok{background:var(--ok-soft);color:var(--ok)}.badge.bad,.chip.bad{background:var(--bad-soft);color:var(--bad)}
.badge.warn{background:var(--warn-soft);color:var(--warn)}.badge.info{background:var(--info-soft);color:var(--info)}.badge.accent{background:var(--accent-soft);color:var(--accent)}
.badge.neutral{color:var(--muted)}
.flash{display:flex;gap:10px;align-items:flex-start;padding:12px 16px;border-radius:var(--r);margin-bottom:20px;border:1px solid;font-weight:500}
.flash .ic{margin-top:1px}
.flash.ok{background:var(--ok-soft);border-color:color-mix(in srgb,var(--ok) 30%,transparent);color:var(--ok)}
.flash.bad{background:var(--bad-soft);border-color:color-mix(in srgb,var(--bad) 30%,transparent);color:var(--bad)}
.callout{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;border-radius:var(--r);border:1px solid var(--line);background:var(--surface-2);margin-bottom:16px}
.callout.warn{background:var(--warn-soft);border-color:color-mix(in srgb,var(--warn) 25%,transparent)}.callout.warn>.ic{color:var(--warn)}
.callout.info{background:var(--info-soft);border-color:color-mix(in srgb,var(--info) 25%,transparent)}.callout.info>.ic{color:var(--info)}
.callout.bad{background:var(--bad-soft);border-color:color-mix(in srgb,var(--bad) 25%,transparent)}.callout.bad>.ic{color:var(--bad)}
.callout p:last-child{margin:0}.callout b{display:block;margin-bottom:2px}

/* ---------- forms */
label{display:block;margin:0 0 6px;font-weight:500;font-size:13.5px;color:var(--ink-2)}
.field{margin-bottom:18px}.field:last-child{margin-bottom:0}.help{color:var(--muted);font-size:12.5px;margin:6px 0 0}
input[type=text],input[type=email],input[type=password],input[type=search],input[type=number],input[type=url],input:not([type]),select,textarea{width:100%;max-width:100%;padding:9px 12px;border:1px solid var(--line-2);border-radius:8px;background:var(--surface);color:var(--ink);font:inherit;box-shadow:var(--shadow);transition:border-color .12s,box-shadow .12s}
input::placeholder{color:var(--muted);opacity:.8}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 18%,transparent)}
select{appearance:none;padding-right:34px;background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 17px) 50%,calc(100% - 12px) 50%;background-size:5px 5px;background-repeat:no-repeat}
.input-group{display:flex;align-items:stretch;border:1px solid var(--line-2);border-radius:8px;background:var(--surface);box-shadow:var(--shadow);overflow:hidden}
.input-group:focus-within{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 18%,transparent)}
.input-group input{border:0;box-shadow:none;border-radius:0}.input-group input:focus{box-shadow:none}
.input-group .addon{display:flex;align-items:center;padding:0 12px;background:var(--surface-2);color:var(--muted);border-left:1px solid var(--line);white-space:nowrap}
.input-group .addon:first-child{border-left:0;border-right:1px solid var(--line)}
.w-sm{max-width:220px}.w-md{max-width:380px}.mono,code,.code-inline{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:8px 14px;min-height:38px;border-radius:8px;border:1px solid var(--line-2);background:var(--surface);color:var(--ink-2);font:inherit;font-weight:600;font-size:13.5px;cursor:pointer;text-decoration:none!important;white-space:nowrap;box-shadow:var(--shadow);transition:background .12s,border-color .12s}
button:hover,.btn:hover{background:var(--surface-2);border-color:var(--line-2)}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}button.primary:hover,.btn.primary:hover{background:color-mix(in srgb,var(--accent) 88%,#000)}
button.danger,.btn.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,var(--line-2))}button.danger:hover{background:var(--bad-soft)}
button.danger-solid{background:var(--bad);border-color:var(--bad);color:#fff}button.danger-solid:hover{background:color-mix(in srgb,var(--bad) 88%,#000)}
button.ghost,.btn.ghost{border-color:transparent;box-shadow:none;background:transparent}button.ghost:hover{background:var(--neutral-soft)}
button.sm,.btn.sm,td button,td .btn{min-height:30px;padding:4px 10px;font-size:12.5px}
form.inline{display:inline}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px}.row.tight{margin-top:0}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
label.check{display:flex;gap:12px;align-items:flex-start;font-weight:400;margin:0;padding:12px 14px;border:1px solid var(--line);border-radius:8px;cursor:pointer;color:var(--ink)}
label.check:hover{background:var(--surface-2)}label.check input{margin-top:3px;accent-color:var(--accent);width:16px;height:16px;flex:none}
label.check b{font-weight:600}label.check .dim{font-size:12.5px}
.checks-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.fsec{display:grid;grid-template-columns:minmax(0,300px) minmax(0,1fr);gap:24px 48px;padding:24px 0;border-top:1px solid var(--line)}
.fsec:first-child{border-top:0;padding-top:4px}.fsec h3{font-size:14.5px;font-weight:600;margin:0 0 4px}.fsec-text p{color:var(--muted);font-size:13px;margin:0}
.fsec-fields{max-width:560px}
@media(max-width:860px){.fsec{grid-template-columns:1fr;gap:12px}}
.options{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.option{position:relative;display:block;margin:0;padding:16px;border:1px solid var(--line-2);border-radius:var(--r);cursor:pointer;background:var(--surface);font-weight:400}
.option:hover{border-color:var(--muted)}
.option input{position:absolute;opacity:0;pointer-events:none}
.option:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 1px var(--accent);background:color-mix(in srgb,var(--accent-soft) 45%,var(--surface))}
.option:has(input:focus-visible){outline:3px solid var(--focus)}
.option b{display:block;font-size:14.5px;color:var(--ink);margin-bottom:2px}.option span{color:var(--muted);font-size:12.5px}
.option .badge{position:absolute;top:12px;right:12px}
.switch-row{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}

/* ---------- tables */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
th,td{text-align:left;padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
th{background:var(--surface-2);color:var(--muted);font-weight:500;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:0}tbody tr:hover td,table tr:hover td{background:color-mix(in srgb,var(--surface-2) 70%,transparent)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}td.actions,th.actions{text-align:right;white-space:nowrap;width:1%}
td .sub{display:block;color:var(--muted);font-size:12.5px}
.card.flush>.card-body>table{margin:0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;padding:14px 16px;border-bottom:1px solid var(--line)}
.toolbar form{display:flex;gap:8px;flex:1;max-width:520px}.toolbar input{flex:1}
form[method=get]:not(.toolbar form){display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}

/* ---------- facts, stats, empty */
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0;margin:0}
.facts>div{padding:14px 0;border-bottom:1px solid var(--line);display:grid;grid-template-columns:150px minmax(0,1fr);gap:12px;margin-right:24px}
.facts dt{color:var(--muted);font-size:13px}.facts dd{margin:0;color:var(--ink);overflow-wrap:anywhere}
.facts.one{grid-template-columns:1fr}
.grid{display:grid;grid-template-columns:200px minmax(0,1fr);gap:12px 20px}.grid>span:nth-child(odd){color:var(--muted)}
@media(max-width:640px){.grid,.facts>div{grid-template-columns:1fr;gap:2px}}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat{display:block;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:18px 20px;box-shadow:var(--shadow);color:var(--ink);text-decoration:none!important}
a.stat:hover{border-color:var(--line-2);box-shadow:var(--shadow-lg)}
.stat span{display:block;color:var(--muted);font-size:13px;font-weight:500}.stat b{display:block;font-size:28px;font-weight:650;letter-spacing:-.02em;margin:6px 0 2px;font-variant-numeric:tabular-nums}.stat small{color:var(--muted)}
.stat b span{display:inline;font-size:14px;font-weight:500}
.empty{text-align:center;padding:40px 16px}.empty h3{margin:12px 0 4px;font-size:15px}.empty p{color:var(--muted);max-width:420px;margin:0 auto 16px}
.empty-ic{display:inline-grid;place-items:center;width:44px;height:44px;border-radius:50%;background:var(--accent-soft);color:var(--accent)}

/* ---------- secrets and codes */
.code{display:inline-block;font:600 20px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;padding:14px 18px;border:1px dashed var(--line-2);border-radius:var(--r);background:var(--surface-2);word-break:break-all}
code,.mono{font-size:12.5px;background:var(--neutral-soft);padding:2px 6px;border-radius:5px;overflow-wrap:anywhere}
.copyline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.copyline code{padding:8px 10px;flex:1;min-width:0}
#name-state{min-height:20px;margin-top:8px;font-size:13px}

/* ---------- pricing */
.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.plan{display:flex;flex-direction:column;padding:22px;border:1px solid var(--line);border-radius:var(--r);background:var(--surface);box-shadow:var(--shadow)}
.plan.current{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.plan h3{margin:0 0 4px;font-size:15px}.plan .price{font-size:28px;font-weight:650;letter-spacing:-.02em;margin:10px 0 2px}.plan .price small{font-size:13px;color:var(--muted);font-weight:500}
.plan ul{list-style:none;padding:0;margin:14px 0 18px;color:var(--ink-2)}.plan li{padding:4px 0}.plan form{margin-top:auto}.plan form button{width:100%}

/* ---------- auth */
body.auth{min-height:100vh;display:grid;place-items:center;padding:32px 16px;background:radial-gradient(1200px 600px at 50% -20%,color-mix(in srgb,var(--accent) 10%,transparent),transparent),var(--bg)}
.auth-box{width:100%;max-width:420px}
.auth .brand{justify-content:center;padding:0 0 24px;color:var(--ink)}.auth .brand-text small{opacity:1;color:var(--muted)}
.auth .card{padding:32px;box-shadow:var(--shadow-lg)}
.auth .card h1{font-size:22px;margin:0 0 6px;text-align:center}.auth .card .lead{text-align:center;color:var(--muted);margin-bottom:24px}
.auth .card button.primary{width:100%;min-height:42px}
.auth .card .field{margin-bottom:16px}
.auth-links{display:flex;justify-content:space-between;gap:12px;margin-top:18px;font-size:13px}
.auth-foot{text-align:center;color:var(--muted);font-size:12px;margin-top:24px}

/* ---------- guides (docs/*.md) and the setup checks */
.guide{display:grid;grid-template-columns:220px minmax(0,1fr);gap:28px;align-items:start}
.toc{position:sticky;top:24px;font-size:13px}.toc b{display:block;margin-bottom:8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.toc a{display:block;padding:5px 12px;border-left:2px solid var(--line);color:var(--muted);text-decoration:none}.toc a:hover{color:var(--ink);border-left-color:var(--accent)}
@media(max-width:1060px){.guide{grid-template-columns:1fr}.toc{position:static}}
.doc{font-size:15px;line-height:1.7}.doc>*{max-width:740px}.doc>.scroll{max-width:none}.doc h1{font-size:24px;margin-bottom:16px}
.doc h2{font-size:18px;margin:32px 0 10px;padding-top:24px;border-top:1px solid var(--line)}
.doc li{margin:6px 0}.doc ol,.doc ul{padding-left:24px;margin:0 0 12px}.doc table{font-size:13.5px;margin:12px 0}
.doc pre{background:var(--surface-2);border:1px solid var(--line);padding:12px 14px;border-radius:8px;overflow-x:auto}.doc pre code{background:none;padding:0}
.doc blockquote{margin:16px 0;padding:12px 16px;border-left:3px solid var(--accent);background:var(--surface-2);border-radius:0 8px 8px 0}.doc blockquote p{margin:0}
.scroll{overflow-x:auto}.checks{list-style:none;padding:0;margin:0}.checks li{padding:12px 0;border-bottom:1px solid var(--line)}.checks li:last-child{border-bottom:0}
.tabs{display:none}
@media(max-width:640px){.wide-only{display:none}.card-head,.card>.card-body,.card:not(:has(>.card-body)){padding-left:16px;padding-right:16px}.card-foot{padding:12px 16px}
th,td{padding:10px 12px}td b,td a{overflow-wrap:anywhere}td.actions .btn,td.actions button{padding:4px 8px}.page-head h1{font-size:21px}}
`;

/** The page's small behaviours, served from /static/app.js (the CSP allows no inline script). */
export const APP_JS = `
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("label");
  const out = document.getElementById("name-state");
  if (input && out) {
    let timer = 0, seq = 0;
    input.addEventListener("input", () => {
      input.value = input.value.toLowerCase();
      clearTimeout(timer);
      const mine = ++seq;
      if (!input.value) { out.textContent = ""; return; }
      out.textContent = "Checking…"; out.className = "dim";
      timer = setTimeout(async () => {
        try {
          const r = await fetch("/names/check?label=" + encodeURIComponent(input.value), { headers: { Accept: "application/json" } });
          const j = await r.json();
          if (mine !== seq) return;
          if (r.status === 429) { out.textContent = "Slow down a little, then try again."; out.className = "dim"; return; }
          out.textContent = (j.state === "available" ? "✓ " : "") + j.message + (j.fqdn && j.state === "available" ? " " + j.fqdn : "");
          out.className = j.state === "available" ? "ok" : "bad";
        } catch { out.textContent = ""; }
      }, 300);
    });
  }
  document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => {
    navigator.clipboard.writeText(b.getAttribute("data-copy")).then(() => { const t = b.textContent; b.textContent = "Copied"; setTimeout(() => { b.textContent = t; }, 1600); });
  }));
  document.querySelectorAll("form[data-confirm]").forEach((f) => f.addEventListener("submit", (e) => {
    if (!confirm(f.getAttribute("data-confirm"))) e.preventDefault();
  }));
  // Closing the phone menu when a link in it is followed.
  document.querySelectorAll(".mnav a").forEach((a) => a.addEventListener("click", () => a.closest("details").removeAttribute("open")));
  // The checkout page continues to the payment provider by itself (the link works without script too).
  const go = document.querySelector("a[data-autoredirect]");
  if (go) setTimeout(() => { window.location.assign(go.href); }, 600);
});
`;
