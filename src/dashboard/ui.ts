/**
 * The dashboard's interactive pieces, server-rendered and enhanced by /static/app.js
 * (no inline script: the CSP forbids it):
 *
 * - FormState: a form that failed validation comes back with what was typed and the
 *   message under the field (never secrets: those are not kept).
 * - modal(): a <dialog> with its own form (confirm, typed confirm, or fields).
 * - menu(): an actions menu (row "⋯" or "Actions ▾"), a <details> that works without script.
 * - paged() + pager(): pagination with "Showing 51–100 of 812".
 * - filterBar(): search, status chips, selects and dates, all in the address.
 * - choiceCards() / segmented(): radio buttons for two to four options.
 * - table(): a table with <thead>/<tbody>.
 */

import type { Queryable } from "../db/db.js";
import { csrfField, escape, html, icon, raw, type Html } from "./html.js";

type Query = Record<string, string | undefined>;

// ---------------------------------------------------------------- form state

/** Field names whose values never go back to the browser in the form-state cookie. */
export const SECRET_FIELD = /pass|secret|token|key|code|confirm|_csrf/i;

export class FormState {
  static readonly empty = new FormState("", {}, {});
  constructor(readonly id: string, readonly values: Record<string, string>, readonly errors: Record<string, string>) {}
  /** This state if it belongs to form `id`, else an empty one. */
  for(id: string): FormState {
    return this.id === id ? this : FormState.empty;
  }
  /** The value typed, or `fallback` (the saved value) when the form did not come back. */
  v(name: string, fallback: unknown = ""): string {
    return name in this.values ? this.values[name] : String(fallback ?? "");
  }
  e(name: string): string | undefined {
    return this.errors[name];
  }
  get returned() {
    return !!this.id;
  }
}

// ---------------------------------------------------------------- tables

export type Col = string | { text: string; cls?: string };

export function table(cols: Col[], rows: (Html | string)[] | Html, o: { cls?: string } = {}): Html {
  return html`<div class="table-wrap"><table${o.cls ? raw(` class="${escape(o.cls)}"`) : ""}><thead><tr>${cols.map((c) => typeof c === "string"
    ? html`<th scope="col">${c}</th>`
    : html`<th scope="col" class="${c.cls ?? ""}">${c.text}</th>`)}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ---------------------------------------------------------------- modal

export interface ModalOptions {
  id: string;
  title: string;
  /** A line (or more) of explanation at the top. */
  text?: Html | string;
  /** Fields inside the form. */
  body?: Html | string;
  action: string;
  csrf: string;
  submit: string;
  tone?: "danger" | "primary";
  /** The text that must be typed (in a `confirm` field) before the button works. */
  typed?: string;
  typedLabel?: string;
  hidden?: Record<string, string | number>;
  /** Open on page load (the form came back with an error). */
  open?: boolean;
  error?: string;
}

export function modal(o: ModalOptions): Html {
  const typedId = `${o.id}-confirm`;
  return html`<dialog class="modal" id="${o.id}" aria-labelledby="${o.id}-title"${o.open ? raw(" data-open-now") : ""}>
    <form method="post" action="${o.action}">${csrfField(o.csrf)}${Object.entries(o.hidden ?? {}).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
      <header class="modal-head"><h2 id="${o.id}-title">${o.title}</h2><button type="button" class="icon-btn close" data-close aria-label="Close">${raw("&times;")}</button></header>
      <div class="modal-body">${o.text ? html`<div class="modal-text">${o.text}</div>` : ""}${o.error ? html`<p class="field-error" role="alert">${o.error}</p>` : ""}${o.body ?? ""}
        ${o.typed ? html`<div class="field"><label for="${typedId}">${o.typedLabel ?? html`Type <b>${o.typed}</b> to confirm`}</label><input id="${typedId}" name="confirm" required autocomplete="off" spellcheck="false" data-typed="${o.typed}"></div>` : ""}</div>
      <footer class="modal-foot"><button type="button" class="ghost" data-close>Cancel</button><button class="${o.tone === "danger" ? "danger-solid" : "primary"}"${o.typed ? raw(" data-typed-submit disabled") : ""}>${o.submit}</button></footer>
    </form></dialog>`;
}

/** A button that opens dialog `id`. */
export const opener = (id: string, label: Html | string, cls = "") => html`<button type="button" class="${cls}" data-open="${id}" aria-haspopup="dialog">${label}</button>`;

// ---------------------------------------------------------------- menus

export const menuLink = (href: string, text: string, ic?: string) => html`<a class="menu-item" role="menuitem" href="${href}">${ic ? icon(ic, 16) : ""}<span>${text}</span></a>`;

export function menuPost(action: string, text: string, csrf: string, o: { confirm?: string; danger?: boolean; hidden?: Record<string, string | number>; ic?: string; title?: string } = {}): Html {
  return html`<form method="post" action="${action}"${o.confirm ? html` data-confirm="${o.confirm}"${o.title ? html` data-confirm-title="${o.title}"` : ""}` : ""}>${csrfField(csrf)}${Object.entries(o.hidden ?? {}).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}<button class="menu-item${o.danger ? " danger" : ""}" role="menuitem">${o.ic ? icon(o.ic, 16) : ""}<span>${text}</span></button></form>`;
}

export const menuOpen = (dialog: string, text: string, o: { danger?: boolean; ic?: string } = {}) =>
  html`<button type="button" class="menu-item${o.danger ? " danger" : ""}" role="menuitem" data-open="${dialog}" aria-haspopup="dialog">${o.ic ? icon(o.ic, 16) : ""}<span>${text}</span></button>`;

export const menuSep = () => html`<div class="menu-sep" role="separator"></div>`;

/** An actions menu: "⋯" (rows) or a labelled button ("Actions ▾"). Empty when there are no items. */
export function menu(items: (Html | string | false | null | undefined)[], o: { label?: string; cls?: string; aria?: string } = {}): Html | string {
  const list = items.filter(Boolean) as (Html | string)[];
  if (!list.length) return "";
  const summary = o.label
    ? html`<summary class="btn ${o.cls ?? ""}" aria-haspopup="menu">${o.label} ${raw('<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>')}</summary>`
    : html`<summary class="btn sm kebab ${o.cls ?? ""}" aria-haspopup="menu" aria-label="${o.aria ?? "Actions"}">${raw('<svg class="ic" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>')}</summary>`;
  return html`<details class="menu">${summary}<div class="menu-panel" role="menu">${list}</div></details>`;
}

// ---------------------------------------------------------------- the address

/** `path` with `query`, `changes` applied (undefined or "" removes a parameter). */
export function withQuery(path: string, query: Query, changes: Query = {}): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...query, ...changes })) if (v !== undefined && v !== "") p.set(k, v);
  const s = p.toString();
  return s ? `${path}?${s}` : path;
}

export const PER_PAGE = [25, 50, 100, 200];

export interface Page {
  page: number;
  per: number;
  offset: number;
}

export function pageOf(query: Query, per = 50): Page {
  const n = Number(query.per);
  const size = PER_PAGE.includes(n) ? n : per;
  const page = Math.min(Math.max(1, Math.floor(Number(query.page)) || 1), 100_000);
  return { page, per: size, offset: (page - 1) * size };
}

/**
 * One page of `sql`'s rows and how many there are in all. `sql` must not have its own
 * LIMIT/OFFSET; its parameters are $1..$n.
 */
export async function paged<T>(db: Queryable, sql: string, params: unknown[], p: Page): Promise<{ rows: T[]; total: number }> {
  const n = params.length;
  const r = await db.query(`SELECT *, count(*) OVER () AS _total FROM (${sql}) AS x LIMIT $${n + 1} OFFSET $${n + 2}`, [...params, p.per, p.offset]);
  let total = r.rows.length ? Number(r.rows[0]._total) : 0;
  if (!r.rows.length && p.page > 1) total = Number((await db.query(`SELECT count(*) AS n FROM (${sql}) AS x`, params)).rows[0].n);
  return { rows: r.rows.map(({ _total, ...rest }) => rest as T), total };
}

/** "Showing 51–100 of 812", page links and the page size; nothing when one page shows everything. */
export function pager(path: string, query: Query, p: Page, total: number, noun = "rows"): Html | string {
  if (total <= PER_PAGE[0] && p.page === 1) return "";
  const pages = Math.max(1, Math.ceil(total / p.per));
  const from = total ? Math.min(p.offset + 1, total) : 0;
  const to = Math.min(p.offset + p.per, total);
  const link = (n: number, text: Html | string, label: string, current = false) =>
    current ? html`<span class="pg cur" aria-current="page">${text}</span>` : html`<a class="pg" href="${withQuery(path, query, { page: n === 1 ? undefined : String(n) })}" aria-label="${label}">${text}</a>`;
  const nums: (number | "…")[] = [];
  for (let i = 1; i <= pages; i++) {
    if (i === 1 || i === pages || Math.abs(i - p.page) <= 1) nums.push(i);
    else if (nums[nums.length - 1] !== "…") nums.push("…");
  }
  const keep = Object.entries(query).filter(([k, v]) => k !== "per" && k !== "page" && v);
  return html`<nav class="pager" aria-label="Pages">
    <span class="pager-info">${total ? `Showing ${from.toLocaleString("en")}–${to.toLocaleString("en")} of ${total.toLocaleString("en")} ${noun}` : `No ${noun} on this page`}</span>
    <span class="pager-pages">${p.page > 1 ? link(p.page - 1, "‹ Prev", "Previous page") : html`<span class="pg off">‹ Prev</span>`}
      ${nums.map((x) => (x === "…" ? html`<span class="pg gap">…</span>` : link(x, String(x), `Page ${x}`, x === p.page)))}
      ${p.page < pages ? link(p.page + 1, "Next ›", "Next page") : html`<span class="pg off">Next ›</span>`}</span>
    <form method="get" action="${path}" class="pager-per" data-autosubmit>${keep.map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
      <label for="per-${noun.replace(/\W/g, "")}" class="sr-only">Per page</label><select id="per-${noun.replace(/\W/g, "")}" name="per">${PER_PAGE.map((n) => html`<option value="${n}"${n === p.per ? " selected" : ""}>${n} per page</option>`)}</select>
      <noscript><button class="sm">Go</button></noscript></form></nav>`;
}

// ---------------------------------------------------------------- filters

export interface Filters {
  path: string;
  query: Query;
  search?: { name?: string; placeholder: string };
  /** Links: [value, label]; the first is usually "" (all). */
  chips?: { name: string; label: string; options: [string, string][] };
  selects?: { name: string; label: string; options: [string, string][] }[];
  /** "from" and "to" date fields. */
  dates?: boolean;
}

export function filterBar(f: Filters): Html {
  const q = f.query;
  const sname = f.search?.name ?? "q";
  const names = [sname, ...(f.selects ?? []).map((s) => s.name), ...(f.dates ? ["from", "to"] : [])];
  // Parameters the form does not show itself (a chip chosen, the page size) go with it.
  const hidden = Object.entries(q).filter(([k, v]) => v && !names.includes(k) && k !== "page");
  const active = [sname, ...(f.chips ? [f.chips.name] : []), ...names.slice(1)].some((k) => q[k]);
  return html`<div class="filters">
    ${f.chips ? html`<div class="chips" role="group" aria-label="${f.chips.label}">${f.chips.options.map(([v, t]) => {
      const on = (q[f.chips!.name] ?? "") === v;
      return html`<a class="chip-link${on ? " on" : ""}" href="${withQuery(f.path, q, { [f.chips!.name]: v || undefined, page: undefined })}"${on ? raw(' aria-current="true"') : ""}>${t}</a>`;
    })}</div>` : ""}
    <form method="get" action="${f.path}" class="filter-form" data-autosubmit>${hidden.map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
      ${f.search ? html`<div class="search"><input type="search" name="${sname}" value="${q[sname] ?? ""}" placeholder="${f.search.placeholder}" aria-label="Search" data-no-autosubmit><button class="sm">Search</button></div>` : ""}
      ${(f.selects ?? []).map((s) => html`<label class="sr-only" for="f-${s.name}">${s.label}</label><select id="f-${s.name}" name="${s.name}" class="w-auto">${s.options.map(([v, t]) => html`<option value="${v}"${(q[s.name] ?? "") === v ? " selected" : ""}>${t}</option>`)}</select>`)}
      ${f.dates ? html`<span class="dates"><label for="f-from" class="sr-only">From</label><input id="f-from" type="date" name="from" value="${q.from ?? ""}" aria-label="From"><span class="dim">to</span><label for="f-to" class="sr-only">To</label><input id="f-to" type="date" name="to" value="${q.to ?? ""}" aria-label="To"></span>` : ""}
      <noscript><button class="sm">Apply</button></noscript>
      ${active ? html`<a class="btn ghost sm" href="${f.path}">Clear</a>` : ""}
    </form></div>`;
}

/** A yyyy-mm-dd date from the address, or "". */
export const dateParam = (v: unknown) => (/^\d{4}-\d{2}-\d{2}$/.test(String(v ?? "")) && !Number.isNaN(Date.parse(String(v))) ? String(v) : "");

// ---------------------------------------------------------------- choices

export interface Choice {
  value: string;
  title: string;
  text?: Html | string;
  badge?: Html | string;
  /** Extra attributes for the input (data-…), already safe. */
  attrs?: string;
}

/** Radio buttons as cards: for two to four options people should see side by side. */
export function choiceCards(o: { name: string; label: string; options: Choice[]; selected: string; id?: string; error?: string; help?: Html | string }): Html {
  const id = o.id ?? o.name;
  return html`<div class="field${o.error ? " has-error" : ""}"><span class="label" id="${id}-label">${o.label}</span>
    <div class="options" role="radiogroup" aria-labelledby="${id}-label">${o.options.map((c) => html`<label class="option"><input type="radio" name="${o.name}" value="${c.value}"${c.value === o.selected ? " checked" : ""}${c.attrs ? raw(` ${c.attrs}`) : ""}>
      ${c.badge ?? ""}<b>${c.title}</b>${c.text ? html`<span>${c.text}</span>` : ""}</label>`)}</div>
    ${o.error ? html`<p class="field-error">${o.error}</p>` : ""}${o.help ? html`<p class="help">${o.help}</p>` : ""}</div>`;
}

/** A segmented control: radio buttons in one row, for short choices (month / year). */
export function segmented(o: { name: string; label: string; options: [string, string][]; selected: string; id?: string }): Html {
  const id = o.id ?? o.name;
  return html`<div class="field"><span class="label" id="${id}-label">${o.label}</span><div class="seg" role="radiogroup" aria-labelledby="${id}-label">${o.options.map(([v, t]) => html`<label><input type="radio" name="${o.name}" value="${v}"${v === o.selected ? " checked" : ""}><span>${t}</span></label>`)}</div></div>`;
}
