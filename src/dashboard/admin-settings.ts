/**
 * Admin > Settings: the platform's credentials and choices that used to need .env and a
 * restart: the Cloudflare token and zone, the SMTP address, the Let's Encrypt account
 * email, staging or production, and the weekly certificate limit. Saved values win over
 * .env and reach every process at once (lib/settings.ts).
 *
 * Guarded more than other admin pages: the `settings.manage` permission, two-step sign-in
 * (adminGuard), and sudo mode (identity confirmed within the last minutes) to open the
 * page and to save. Secrets are never shown back, only their last characters.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.js";
import { findCloudflareZone } from "../dns/providers.js";
import { audit } from "../lib/audit.js";
import { hit, LIMITS } from "../lib/limits.js";
import { announce, clearSetting, isSettingKey, LE_PRODUCTION, LE_STAGING, masked, saveSetting, SETTINGS, type SettingKey, type Stored } from "../lib/settings.js";
import { adminGuard } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { badge, csrfField, field, formSection, html, icon, pageHead, panel, when, type Html } from "./html.js";
import type { Session } from "./session.js";

const SECTIONS: Record<string, SettingKey[]> = {
  dns: ["dnsProvider", "cloudflareApiToken", "cloudflareZoneId"],
  mail: ["smtpUrl", "mailFrom"],
  acme: ["acmeEmail", "acmeDirectoryUrl", "certWeeklyLimit"],
};

export function settingsRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);

  /** settings.manage, two-step sign-in (adminGuard), and sudo mode. */
  const guard = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return null;
    return h.requireSudo(req, reply, s, "/admin/settings") ? s : null;
  };

  const page = async (req: FastifyRequest, reply: FastifyReply, s: Session) => {
    const stored = new Map((await h.live.stored()).map((x) => [x.key, x] as const));
    const base = h.live.base;
    const c = d.config;
    /** Where the value in use comes from, and what it is (secrets masked). */
    const source = (key: SettingKey): Html => {
      const st: Stored | undefined = stored.get(key);
      const env = String(base[key as keyof Config] ?? "");
      if (st) {
        return html`<div class="help row tight" style="gap:8px">${badge("accent", "Set here")}<span>${st.updated_by ? `by ${st.updated_by}, ` : ""}${when(st.updated_at)}${SETTINGS[key].secret ? html` · <code>${masked(key, st.value)}</code>` : ""}</span>
          <button class="ghost sm" form="clear-${key}">Use .env's value</button></div>`;
      }
      return env ? html`<div class="help">${badge("neutral", "From .env")}${SETTINGS[key].secret ? html` <code>${masked(key, env)}</code>` : ""}</div>` : html`<div class="help">${badge("warn", "Not set")}</div>`;
    };
    const clearForms = html`${[...stored.keys()].map((key) => html`<form id="clear-${key}" method="post" action="/admin/settings/clear" data-confirm="Stop using the value set here and go back to .env's?">${csrfField(s.csrf)}<input type="hidden" name="key" value="${key}"></form>`)}`;
    const testsOnly = base.dnsProvider === "challtestsrv";
    const custom = !!base.acmeDirectoryUrl && base.acmeDirectoryUrl !== LE_PRODUCTION && base.acmeDirectoryUrl !== LE_STAGING;

    return h.render(req, reply, "Settings", html`${pageHead({ title: "Settings", sub: "Credentials and choices for the whole platform. Saved values win over .env and take effect everywhere within seconds, with no restart." })}
      <div class="callout info">${icon("lock")}<div><b>Secrets are stored encrypted and never shown again</b><p>Leave a secret's box empty to keep the one in place. Every change is in the audit log (never its value). The database, SESSION_SECRET, the domain, ports, proxies and TURN's secrets stay in .env.</p></div></div>
      ${clearForms}
      <form method="post" action="/admin/settings/dns" id="dns">${csrfField(s.csrf)}${panel({ title: "DNS", sub: "Where station names are published." }, testsOnly
        ? html`<p class="dim" style="margin:0">This platform uses a test DNS server (DNS_PROVIDER=challtestsrv in .env), so this is not changed here.</p>`
        : html`${formSection("Provider", "Cloudflare publishes station names. Without a provider, names are not on the internet and their certificates fail.", html`
            ${field({ id: "dnsProvider", label: "DNS provider", control: html`<select id="dnsProvider" name="dnsProvider" class="w-md"><option value="cloudflare"${c.dnsProvider === "cloudflare" ? " selected" : ""}>Cloudflare</option><option value="memory"${c.dnsProvider === "memory" ? " selected" : ""}>None</option></select>${source("dnsProvider")}` })}`)}
          ${formSection("Cloudflare credentials", html`A token from the "Edit zone DNS" template, limited to this domain's zone. <a href="/admin/setup">The guide</a> shows where to get it.`, html`
            ${field({ id: "cloudflareApiToken", label: "API token", control: html`<input id="cloudflareApiToken" type="password" name="cloudflareApiToken" autocomplete="off" placeholder="${c.cloudflareApiToken ? "Unchanged" : "Paste the token"}">${source("cloudflareApiToken")}` })}
            ${field({ id: "cloudflareZoneId", label: "Zone ID", control: html`<input id="cloudflareZoneId" name="cloudflareZoneId" autocomplete="off" value="${c.cloudflareZoneId}" maxlength="32" class="mono-input" placeholder="Found from the token when empty">${source("cloudflareZoneId")}` })}`)}`,
        testsOnly ? "" : html`<a class="btn ghost" href="/admin/setup">Test the connection</a><button class="primary">Save DNS settings</button>`)}</form>

      <form method="post" action="/admin/settings/mail" id="mail">${csrfField(s.csrf)}${panel({ title: "Email", sub: "Confirmation links, password resets, security notices and the admins' daily alert." }, html`
        ${formSection("SMTP server", "Any provider works: Postmark, SES, Mailgun, Google Workspace…", html`
          ${field({ id: "smtpUrl", label: "SMTP address", help: "smtps://user:password@smtp.example.com:465", control: html`<input id="smtpUrl" type="password" name="smtpUrl" autocomplete="off" placeholder="${c.smtpUrl ? "Unchanged" : "smtps://…"}">${source("smtpUrl")}` })}
          ${field({ id: "mailFrom", label: "Sender", control: html`<input id="mailFrom" name="mailFrom" value="${c.mailFrom}" maxlength="200">${source("mailFrom")}` })}`)}`,
        html`<button class="ghost" form="test-mail">Send a test email to ${s.user.email}</button><button class="primary">Save email settings</button>`)}</form>
      <form id="test-mail" method="post" action="/admin/settings/test-mail">${csrfField(s.csrf)}</form>

      <form method="post" action="/admin/settings/acme" id="acme">${csrfField(s.csrf)}${panel({ title: "Certificates", sub: "Let's Encrypt certificates for every station." }, html`
        ${formSection("Account", "Let's Encrypt writes here about expiring certificates and policy changes.", html`
          ${field({ id: "acmeEmail", label: "Account email", control: html`<input id="acmeEmail" type="email" name="acmeEmail" value="${c.acmeEmail}">${source("acmeEmail")}` })}`)}
        ${formSection("Environment", "Staging certificates are for testing: browsers warn about them. Switch to production once a station works.", custom
          ? html`<p class="dim">The certificate authority is set in .env (${base.acmeDirectoryUrl}), so it is not chosen here.</p>`
          : field({ id: "acmeDirectoryUrl", label: "Certificates", control: html`<select id="acmeDirectoryUrl" name="acmeDirectoryUrl" class="w-md">
              <option value="${LE_STAGING}"${c.acmeDirectoryUrl !== LE_PRODUCTION ? " selected" : ""}>Staging (test certificates)</option>
              <option value="${LE_PRODUCTION}"${c.acmeDirectoryUrl === LE_PRODUCTION ? " selected" : ""}>Production (trusted certificates)</option></select>${source("acmeDirectoryUrl")}` }))}
        ${formSection("Rate limit", "New certificates per 7 days for the registered domain. Renewals do not count.", html`
          ${field({ id: "certWeeklyLimit", label: "Weekly limit", control: html`<input id="certWeeklyLimit" type="number" name="certWeeklyLimit" min="1" max="99999" value="${c.certWeeklyLimit}" class="w-sm">${source("certWeeklyLimit")}` })}`)}`,
        html`<button class="primary">Save certificate settings</button>`)}</form>`, h.takeFlash(req, reply));
  };

  app.get("/admin/settings", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    return page(req, reply, s);
  });

  const changed = async () => {
    await announce(d.db);
    await h.live.reload();
  };

  app.post("/admin/settings/:section", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    const section = (req.params as { section: string }).section;
    const keys = SECTIONS[section];
    if (!keys) return h.back(reply, "/admin/settings", { kind: "bad", text: "No such settings." });
    const back = `/admin/settings#${section}`;
    const f = h.form(req);
    if (section === "dns" && h.live.base.dnsProvider === "challtestsrv") return h.back(reply, back, { kind: "bad", text: "DNS is set in .env on this platform." });

    // What the form asks for; an empty secret box keeps the secret there.
    const values = new Map<SettingKey, string>();
    for (const key of keys) {
      const given = String(f[key] ?? "");
      if (!given.trim()) continue;
      const v = SETTINGS[key].check(given);
      if (typeof v !== "string") return h.back(reply, back, { kind: "bad", text: v.error });
      const current = String(d.config[key as keyof Config] ?? "");
      if (v !== current) values.set(key, v);
    }
    if (section === "dns" && (values.get("dnsProvider") ?? d.config.dnsProvider) === "cloudflare" && !String(f.cloudflareZoneId ?? "").trim()) {
      const token = values.get("cloudflareApiToken") ?? d.config.cloudflareApiToken;
      if (!token) return h.back(reply, back, { kind: "bad", text: "Cloudflare needs an API token." });
      try {
        const zone = await findCloudflareZone(token, d.config.rootDomain);
        if (zone.id !== d.config.cloudflareZoneId) values.set("cloudflareZoneId", zone.id);
      } catch (e) {
        return h.back(reply, back, { kind: "bad", text: `${(e as Error).message}` });
      }
    }
    if (!values.size) return h.back(reply, back, { kind: "ok", text: "Nothing changed." });
    for (const [key, v] of values) await saveSetting(d.db, d.config.sessionSecret, s.user.id, key, v);
    // Which settings changed, never their values (the audit log is no place for a token).
    await audit(d.db, { actor: s.user.id, action: "settings.update", target: section, ip: req.ip,
      metadata: Object.fromEntries([...values].map(([k, v]) => [k, SETTINGS[k].secret ? "(secret)" : v])) });
    await changed();
    const next = section === "dns" ? " Test it on Setup checks." : section === "mail" ? " Send a test email to check it." : "";
    return h.back(reply, back, { kind: "ok", text: `Saved: ${[...values.keys()].map((k) => SETTINGS[k].env).join(", ")}.${next}` });
  });

  app.post("/admin/settings/clear", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    const key = String(h.form(req).key ?? "");
    if (!isSettingKey(key)) return h.back(reply, "/admin/settings", { kind: "bad", text: "No such setting." });
    await clearSetting(d.db, key);
    await audit(d.db, { actor: s.user.id, action: "settings.clear", target: key, ip: req.ip });
    await changed();
    return h.back(reply, "/admin/settings", { kind: "ok", text: `${SETTINGS[key].env} comes from .env again.` });
  });

  app.post("/admin/settings/test-mail", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    if (!(await hit(d.db, `mail:${s.user.email.toLowerCase()}`, LIMITS.mail)).ok) return h.back(reply, "/admin/settings#mail", { kind: "bad", text: "Too many emails in the last hour; try later." });
    try {
      await d.mail({ to: s.user.email, subject: `Test email from ${d.config.rootDomain}`, text: `This is a test from the ${d.config.rootDomain} dashboard. Email works.\n` });
    } catch (e) {
      return h.back(reply, "/admin/settings#mail", { kind: "bad", text: `Sending failed: ${(e as Error).message}`.slice(0, 250) });
    }
    return h.back(reply, "/admin/settings#mail", { kind: "ok", text: d.config.smtpUrl ? `Sent to ${s.user.email}. Check the inbox (and spam).` : "No SMTP address is set, so it was only written to the dashboard's log." });
  });
}
