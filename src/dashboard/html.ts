/**
 * Server-rendered pages: an escaping `html` template tag, the page frame (light and
 * dark), and small form pieces. No inline script (the CSP forbids it): the one bit of
 * behaviour, the live name check, is /static/app.js.
 */

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

export interface Frame {
  title: string;
  user?: { email: string; role: string } | null;
  csrf?: string;
  flash?: { kind: "ok" | "bad"; text: string } | null;
  rootDomain: string;
  /** The page's address, to mark where the visitor is in the menu and choose the page's width. */
  path?: string;
}

const CSS = `
:root{--bg:#f5f5f2;--card:#fff;--ink:#1b1d21;--dim:#5d636d;--line:#dfe1e5;--accent:#c2410c;--ok:#15803d;--bad:#b91c1c;--chip:#eef0f3;--shadow:0 1px 2px rgba(0,0,0,.04),0 6px 20px rgba(0,0,0,.04)}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--card:#16191e;--ink:#eceef2;--dim:#9aa1ac;--line:#2a2f37;--accent:#fb923c;--ok:#4ade80;--bad:#f87171;--chip:#20242b;--shadow:none}}
*{box-sizing:border-box}html{scroll-padding-top:76px}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* the frame: a bar that stays, a column of cards, a quiet footer */
header{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
.bar{max-width:1200px;margin:0 auto;display:flex;align-items:center;gap:8px 16px;padding:10px 20px;flex-wrap:wrap}
.brand{font-weight:700;font-size:17px;color:var(--ink);text-decoration:none;margin-right:8px}
header nav{display:flex;gap:4px;flex:1;flex-wrap:wrap}
header nav a{padding:6px 12px;border-radius:8px;color:var(--dim);text-decoration:none;font-weight:500}
header nav a:hover,header nav a[aria-current]{background:var(--chip);color:var(--ink)}
.who{color:var(--dim);font-size:13px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main{width:100%;max-width:880px;margin:28px auto;padding:0 16px;flex:1}
main.wide{max-width:1200px}main.narrow{max-width:440px;margin-top:max(28px,8vh)}
footer{padding:20px 16px 28px;text-align:center;color:var(--dim);font-size:13px}

/* cards and text */
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:16px;box-shadow:var(--shadow);overflow-x:auto}
.card>:last-child{margin-bottom:0}.card.notice{border-left:4px solid var(--accent)}.card.danger{border-color:color-mix(in srgb,var(--bad) 45%,var(--line))}
h1{font-size:22px;line-height:1.3;margin:0 0 14px}h2{font-size:17px;margin:0 0 10px}p{margin:0 0 12px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:16px}.cols>.card{margin-bottom:0}
.empty{text-align:center;padding:20px 0 8px}.empty p{color:var(--dim)}
.dim{color:var(--dim)}.ok{color:var(--ok)}.bad{color:var(--bad)}
.chip{display:inline-block;padding:1px 9px;border-radius:99px;background:var(--chip);font-size:12px;font-weight:500;white-space:nowrap}
.chip.ok{background:color-mix(in srgb,var(--ok) 14%,transparent)}.chip.bad{background:color-mix(in srgb,var(--bad) 14%,transparent)}
.flash{padding:12px 16px;border-radius:10px;margin-bottom:16px;border:1px solid transparent}
.flash.ok{background:color-mix(in srgb,var(--ok) 12%,var(--card));border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.flash.bad{background:color-mix(in srgb,var(--bad) 12%,var(--card));border-color:color-mix(in srgb,var(--bad) 35%,transparent)}

/* forms */
label{display:block;margin:14px 0 5px;font-weight:600;font-size:13px}
input[type=text],input[type=email],input[type=password],input[type=search],input:not([type]),select{width:100%;max-width:420px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:0;border-color:transparent}select{width:auto}
button,.btn{display:inline-block;padding:8px 14px;border-radius:8px;border:1px solid var(--line);background:var(--chip);color:var(--ink);font:inherit;font-weight:500;cursor:pointer;text-decoration:none;white-space:nowrap}
button:hover,.btn:hover{border-color:var(--dim)}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.primary:hover,.btn.primary:hover{filter:brightness(1.08)}
@media (prefers-color-scheme:dark){button.primary,.btn.primary{color:#1b1d21}}
button.danger{border-color:color-mix(in srgb,var(--bad) 60%,var(--line));color:var(--bad);background:transparent}
form.inline{display:inline}.row{display:flex;gap:10px 12px;align-items:center;flex-wrap:wrap;margin-top:16px}
form[method=get]{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}form[method=get] input{flex:1;min-width:180px}
main.narrow input{max-width:none}main.narrow .row{justify-content:space-between}

/* tables and lists of facts */
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}tr:last-child td{border-bottom:0}
td:last-child:has(form),td:last-child:has(a:only-child){text-align:right;white-space:nowrap}td button{padding:4px 10px;font-size:13px}
.grid{display:grid;grid-template-columns:190px 1fr;gap:10px 16px}@media(max-width:640px){.grid{grid-template-columns:1fr;gap:2px}.grid>span:nth-child(even){margin-bottom:10px}}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow);text-decoration:none;color:var(--ink)}
.stat b{display:block;font-size:28px;line-height:1.2}.stat span{color:var(--dim);font-size:13px}a.stat:hover{border-color:var(--dim)}
.code{font:600 20px/1.4 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.04em;padding:14px;border:2px dashed var(--accent);border-radius:10px;display:inline-block;word-break:break-all}
#name-state{min-height:1.5em;margin-top:6px;font-size:14px}

/* admin: the tab bar above every admin page */
.tabs{display:flex;gap:2px;overflow-x:auto;margin:0 0 20px;border-bottom:1px solid var(--line)}
.tabs a{padding:8px 12px;white-space:nowrap;color:var(--dim);text-decoration:none;font-weight:500;border-bottom:2px solid transparent;margin-bottom:-1px}
.tabs a:hover{color:var(--ink)}.tabs a[aria-current]{color:var(--ink);border-bottom-color:var(--accent)}

/* guides (docs/*.md) and the setup checks */
.guide{display:grid;grid-template-columns:210px minmax(0,1fr);gap:28px;align-items:start}
.toc{position:sticky;top:76px;font-size:14px}.toc b{display:block;margin-bottom:8px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--dim)}
.toc a{display:block;padding:5px 12px;border-left:2px solid var(--line);color:var(--dim);text-decoration:none}.toc a:hover{color:var(--ink);border-left-color:var(--accent)}
@media(max-width:860px){.guide{grid-template-columns:1fr}.toc{position:static}}
.doc{font-size:16px;line-height:1.65}.doc>*{max-width:720px}.doc>.scroll{max-width:none}.doc h1{font-size:26px;margin-bottom:16px}
.doc h2{font-size:20px;margin:32px 0 10px;padding-top:24px;border-top:1px solid var(--line)}
.doc li{margin:6px 0}.doc ol,.doc ul{padding-left:24px;margin:0 0 12px}.doc table{font-size:14px;margin:12px 0}.doc th{text-transform:none;letter-spacing:0;font-size:13px}
.doc code,.mono,code{font:13px ui-monospace,Menlo,Consolas,monospace;background:var(--chip);padding:1px 5px;border-radius:5px;word-break:break-word}
.doc pre{background:var(--chip);padding:12px 14px;border-radius:8px;overflow-x:auto}.doc pre code{background:none;padding:0;word-break:normal}
.doc blockquote{margin:16px 0;padding:12px 16px;border-left:4px solid var(--accent);background:var(--chip);border-radius:0 8px 8px 0}.doc blockquote p{margin:0}
.scroll{overflow-x:auto}.checks{list-style:none;padding:0;margin:12px 0 0}.checks li{padding:10px 0;border-bottom:1px solid var(--line)}.checks li:last-child{border-bottom:0}
header nav:empty{display:none}header nav:empty~.btn:first-of-type{margin-left:auto}
@media(max-width:640px){.card{padding:18px 16px}.who,.wide-only{display:none}.bar{padding:10px 16px;gap:6px 10px}.brand{flex:1;margin:0;overflow:hidden;text-overflow:ellipsis}
header nav{order:3;flex-basis:100%;flex-wrap:nowrap;overflow-x:auto;margin:0 -6px}header nav a{white-space:nowrap}}
`;

export function page(f: Frame, body: Html): string {
  const admin = f.user?.role === "admin";
  const path = (f.path ?? "").split("?")[0];
  const at = path.startsWith("/admin") ? "admin" : path.startsWith("/account") ? "account" : "stations";
  const link = (href: string, key: string, text: string) => html`<a href="${href}"${at === key ? raw(' aria-current="page"') : ""}>${text}</a>`;
  // Signed out, every page is one small form: a narrow column. The admin's tables get the width.
  const width = !f.user ? "narrow" : at === "admin" ? "wide" : "";
  return html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${f.title} · ${f.rootDomain}</title><style>${raw(CSS)}</style><script src="/static/app.js" defer></script></head>
<body><header><div class="bar"><a class="brand" href="/">${f.rootDomain}</a>
${f.user ? html`<nav aria-label="Main">${link("/", "stations", "My stations")}${link("/account", "account", "Account")}${admin ? link("/admin", "admin", "Admin") : ""}</nav>
<span class="who" title="${f.user.email}">${f.user.email}</span>
<form class="inline" method="post" action="/logout">${csrfField(f.csrf)}<button>Sign out</button></form>`
    : html`<nav></nav><a class="btn" href="/login">Sign in</a><a class="btn primary" href="/signup">Create account</a>`}
</div></header><main${width ? raw(` class="${width}"`) : ""}>${f.flash ? html`<div class="flash ${f.flash.kind}" role="status">${f.flash.text}</div>` : ""}${body}</main>
<footer>Remote Studio addresses for Nova · ${f.rootDomain}</footer></body></html>`.value;
}

export const csrfField = (token?: string) => (token ? html`<input type="hidden" name="_csrf" value="${token}">` : "");

export const when = (d: Date | string | null | undefined) =>
  d ? new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—";

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

/** The live availability check (debounced), as plain script served from /static/app.js. */
export const APP_JS = `
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("label");
  const out = document.getElementById("name-state");
  if (!input || !out) return;
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
  document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => {
    navigator.clipboard.writeText(b.getAttribute("data-copy")).then(() => { b.textContent = "Copied"; });
  }));
  document.querySelectorAll("form[data-confirm]").forEach((f) => f.addEventListener("submit", (e) => {
    if (!confirm(f.getAttribute("data-confirm"))) e.preventDefault();
  }));
});
`;
