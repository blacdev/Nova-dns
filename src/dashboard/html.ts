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
}

const CSS = `
:root{--bg:#f6f6f4;--card:#fff;--ink:#1b1d21;--dim:#5d636d;--line:#d9dbe0;--accent:#c2410c;--ok:#15803d;--bad:#b91c1c;--chip:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--card:#16191e;--ink:#eceef2;--dim:#9aa1ac;--line:#2a2f37;--accent:#fb923c;--ok:#4ade80;--bad:#f87171;--chip:#20242b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:16px;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card);flex-wrap:wrap}
header b{font-size:17px}header nav{display:flex;gap:14px;flex:1;flex-wrap:wrap}header a{color:var(--ink);text-decoration:none}header a:hover{color:var(--accent)}
main{max-width:960px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}
h1{font-size:22px;margin:0 0 12px}h2{font-size:17px;margin:0 0 10px}
label{display:block;margin:10px 0 4px;font-weight:600;font-size:13px}
input[type=text],input[type=email],input[type=password],input[type=search],input:not([type]){width:100%;max-width:420px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
button,.btn{display:inline-block;padding:8px 14px;border-radius:8px;border:1px solid var(--line);background:var(--chip);color:var(--ink);font:inherit;cursor:pointer;text-decoration:none}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{border-color:var(--bad);color:var(--bad)}
form.inline{display:inline}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--dim);font-weight:600}
.dim{color:var(--dim)}.ok{color:var(--ok)}.bad{color:var(--bad)}.chip{display:inline-block;padding:1px 8px;border-radius:99px;background:var(--chip);font-size:12px}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px}.flash.ok{background:color-mix(in srgb,var(--ok) 15%,transparent)}.flash.bad{background:color-mix(in srgb,var(--bad) 15%,transparent)}
.code{font:600 20px/1.4 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.04em;padding:14px;border:2px dashed var(--accent);border-radius:10px;display:inline-block;word-break:break-all}
.grid{display:grid;grid-template-columns:180px 1fr;gap:6px 16px}@media(max-width:640px){.grid{grid-template-columns:1fr}}
#name-state{min-height:1.5em;margin-top:6px;font-size:14px}
.doc{font-size:16px;line-height:1.65}.doc>*{max-width:720px}.doc>.scroll{max-width:none}.doc h1{font-size:26px;margin-bottom:16px}.doc h2{font-size:20px;margin:32px 0 10px;padding-top:20px;border-top:1px solid var(--line)}
.doc a{color:var(--accent)}.doc li{margin:6px 0}.doc ol,.doc ul{padding-left:24px}.doc table{font-size:14px;margin:12px 0}
.doc code,.mono{font:13px ui-monospace,Menlo,Consolas,monospace;background:var(--chip);padding:1px 5px;border-radius:5px;word-break:break-word}
.doc pre{background:var(--chip);padding:12px 14px;border-radius:8px;overflow-x:auto}.doc pre code{background:none;padding:0;word-break:normal}
.doc blockquote{margin:16px 0;padding:10px 16px;border-left:4px solid var(--accent);background:var(--chip);border-radius:0 8px 8px 0}.doc blockquote p{margin:0}
.scroll{overflow-x:auto}.checks{list-style:none;padding:0;margin:12px 0 0}.checks li{padding:8px 0;border-bottom:1px solid var(--line)}.checks li:last-child{border-bottom:0}
`;

export function page(f: Frame, body: Html): string {
  const admin = f.user?.role === "admin";
  return html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${f.title} · ${f.rootDomain}</title><style>${raw(CSS)}</style><script src="/static/app.js" defer></script></head>
<body><header><b>${f.rootDomain}</b>
${f.user ? html`<nav><a href="/">My stations</a><a href="/account">Account</a>${admin ? html`<a href="/admin">Admin</a>` : ""}</nav>
<form class="inline" method="post" action="/logout">${csrfField(f.csrf)}<button>Sign out</button></form>`
    : html`<nav></nav><a href="/login">Sign in</a><a class="btn primary" href="/signup">Create account</a>`}
</header><main>${f.flash ? html`<div class="flash ${f.flash.kind}" role="status">${f.flash.text}</div>` : ""}${body}</main></body></html>`.value;
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
