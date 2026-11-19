/**
 * Admin > Settings: the platform's credentials and choices that used to need .env and a
 * restart: the Cloudflare token and zone, the SMTP server, the Let's Encrypt account
 * email, staging or production, and the weekly certificate limit. Saved values win over
 * .env and reach every process at once (lib/settings.ts).
 *
 * Guarded more than other admin pages: the `settings.manage` permission, two-step sign-in
 * (adminGuard), and sudo mode (identity confirmed within the last minutes) to open the
 * page and to save. Secrets are never shown back, only their last characters.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { smtpOf, type Config } from "../config.js";
import { findCloudflareZone } from "../dns/providers.js";
import { audit } from "../lib/audit.js";
import { hit, LIMITS } from "../lib/limits.js";
import { DEFAULT_PORT, isSmtpSecurity, joinFrom, SMTP_PRESETS, SMTP_SECURITIES, smtpPort, splitFrom, testSmtp, type Smtp, type SmtpSecurity } from "../lib/mail.js";
import { announce, clearSetting, isSettingKey, LE_PRODUCTION, LE_STAGING, LEGACY_SMTP_URL, masked, saveSetting, SETTINGS, type SettingKey, type Stored } from "../lib/settings.js";
import { adminGuard } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { badge, csrfField, field, formSection, html, icon, pageHead, panel, when, type Html } from "./html.js";
import type { Session } from "./session.js";

const SECTIONS: Record<string, SettingKey[]> = {
  dns: ["dnsProvider", "cloudflareApiToken", "cloudflareZoneId"],
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
    const clearForms = html`${[...stored.keys()].filter((key) => (key as string) !== LEGACY_SMTP_URL).map((key) => html`<form id="clear-${key}" method="post" action="/admin/settings/clear" data-confirm="Stop using the value set here and go back to .env's?">${csrfField(s.csrf)}<input type="hidden" name="key" value="${key}"></form>`)}`;
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

      ${mailPanel(s, source, stored.has(LEGACY_SMTP_URL as SettingKey))}

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


  const SECURITY_TEXT: Record<SmtpSecurity, [string, string]> = {
    ssl: ["SSL/TLS", "Encrypted from the start. Usually port 465."],
    starttls: ["STARTTLS", "Starts plain, then encrypts. Usually port 587."],
    none: ["None", "Not encrypted. Port 25, trusted networks only."],
  };

  /** Admin > Settings > Email: the SMTP server in parts, the sender, and a test with the values in the form. */
  const mailPanel = (s: Session, source: (key: SettingKey) => Html, legacy: boolean) => {
    const c = d.config;
    const from = splitFrom(c.mailFrom);
    const security = c.smtpSecurity;
    const preset = SMTP_PRESETS.find((p) => p.host === c.smtpHost);
    return html`<form method="post" action="/admin/settings/mail" id="mail" data-smtp>${csrfField(s.csrf)}${panel({ title: "Email", sub: "Confirmation links, password resets, security notices and the admins' daily alert." }, html`
      ${legacy ? html`<div class="callout info">${icon("info")}<div><b>Saved as one SMTP address by an earlier version</b><p>Its parts are shown below. Saving this form stores them separately.</p></div></div>` : ""}
      ${formSection("Provider", "Pick yours to fill in the server details, or enter them yourself.", html`
        ${field({ id: "smtpPreset", label: "Email provider", control: html`<select id="smtpPreset" class="w-md" data-smtp-preset>
          <option value="">Other / custom</option>
          ${SMTP_PRESETS.map((p) => html`<option value="${p.id}" data-host="${p.host}" data-port="${p.port}" data-security="${p.security}" data-user="${p.user ?? ""}" data-note="${p.note}"${preset?.id === p.id ? " selected" : ""}>${p.name}</option>`)}</select>
          <p class="help" id="smtp-preset-note">${preset?.note ?? ""}</p>` })}`)}
      ${formSection("Server", "Where the platform connects to send email.", html`
        ${field({ id: "smtpHost", label: "SMTP host", help: html`A server name like <code>smtp.example.com</code>. Leave empty to send no email (messages only go to the log).`, control: html`<input id="smtpHost" name="smtpHost" value="${c.smtpHost}" autocomplete="off" spellcheck="false" maxlength="253" placeholder="smtp.example.com">${source("smtpHost")}` })}
        <div class="field"><span class="label" id="smtpSecurity-label">Security</span>
          <div class="options" role="radiogroup" aria-labelledby="smtpSecurity-label">${SMTP_SECURITIES.map((v) => html`<label class="option"><input type="radio" name="smtpSecurity" value="${v}" data-port="${DEFAULT_PORT[v]}"${v === security ? " checked" : ""}>
            <b>${SECURITY_TEXT[v][0]}</b><span>${SECURITY_TEXT[v][1]}</span></label>`)}</div>${source("smtpSecurity")}</div>
        ${field({ id: "smtpPort", label: "Port", help: "Filled in from the security; change it only if your provider says so.", control: html`<input id="smtpPort" name="smtpPort" type="number" min="1" max="65535" class="w-sm" value="${smtpPort({ port: c.smtpPort, security: c.smtpSecurity })}">${source("smtpPort")}` })}`)}
      ${formSection("Sign-in", "The account used to sign in to the server. Leave both empty for a relay that needs no sign-in.", html`
        ${field({ id: "smtpUser", label: "Username", help: "Often your full email address.", control: html`<input id="smtpUser" name="smtpUser" value="${c.smtpUser}" autocomplete="off" spellcheck="false" maxlength="254">${source("smtpUser")}` })}
        ${field({ id: "smtpPassword", label: "Password", help: c.smtpPassword ? "Leave empty to keep the saved password." : "Some providers call it an app password or SMTP key.", control: html`<div class="input-group"><input id="smtpPassword" type="password" name="smtpPassword" autocomplete="new-password" maxlength="500" placeholder="${c.smtpPassword ? "Unchanged" : ""}"><button type="button" class="addon reveal" data-reveal="smtpPassword" aria-label="Show password">Show</button></div>
          ${c.smtpPassword ? html`<label class="inline-check"><input type="checkbox" name="clearSmtpPassword" value="1"> Remove the saved password</label>` : ""}${source("smtpPassword")}` })}`)}
      ${formSection("Sender", "Who emails come from. Many providers only send from an address they have verified.", html`<div class="form-grid">
        ${field({ id: "mailFromName", label: "Sender name", control: html`<input id="mailFromName" name="mailFromName" value="${from.name}" maxlength="100" placeholder="Nova">` })}
        ${field({ id: "mailFromEmail", label: "Sender email", control: html`<input id="mailFromEmail" name="mailFromEmail" type="email" value="${from.email}" maxlength="200" placeholder="no-reply@${c.rootDomain}">` })}</div>${source("mailFrom")}`)}
      ${formSection("Test", "Sends one email with the values above, before you save them, so you can check them first.", html`
        ${field({ id: "testTo", label: "Send the test to", control: html`<div class="row tight"><input id="testTo" name="testTo" type="email" value="${s.user.email}" class="w-md" style="flex:1"><button formaction="/admin/settings/test-mail" formnovalidate>${icon("check", 16)} Send test email</button></div>` })}`)}`,
      html`<button class="primary">Save email settings</button>`)}</form>`;
  };

  /** The SMTP settings a mail form asks for, over the ones in use; a message when something is wrong. */
  const mailFromForm = (f: Record<string, string>): { smtp: Smtp; from: string } | { error: string } => {
    const c = d.config;
    const host = String(f.smtpHost ?? "").trim();
    const security = String(f.smtpSecurity ?? c.smtpSecurity);
    if (!isSmtpSecurity(security)) return { error: "Choose SSL/TLS, STARTTLS or None." };
    let port = 0;
    if (host) {
      const h = SETTINGS.smtpHost.check(host);
      if (typeof h !== "string") return h;
      const rawPort = String(f.smtpPort ?? "").trim() || String(DEFAULT_PORT[security]);
      const p = SETTINGS.smtpPort.check(rawPort);
      if (typeof p !== "string") return p;
      port = Number(p);
    }
    const user = String(f.smtpUser ?? "").trim();
    if (user.length > 254) return { error: "The username is too long." };
    const given = String(f.smtpPassword ?? "");
    const password = f.clearSmtpPassword === "1" ? "" : given || c.smtpPassword;
    if (password.length > 500) return { error: "The password is too long." };
    const email = String(f.mailFromEmail ?? "").trim();
    if (!/^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/.test(email)) return { error: "The sender email is not an email address." };
    return { smtp: { host: host.toLowerCase(), port, security, user, password }, from: joinFrom(String(f.mailFromName ?? "").slice(0, 100), email) };
  };

  app.get("/admin/settings", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    return page(req, reply, s);
  });

  const changed_ = async () => {
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
    await changed_();
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
    await changed_();
    return h.back(reply, "/admin/settings", { kind: "ok", text: `${SETTINGS[key].env} comes from .env again.` });
  });

  app.post("/admin/settings/mail", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    const back = "/admin/settings#mail";
    const asked = mailFromForm(h.form(req));
    if ("error" in asked) return h.back(reply, back, { kind: "bad", text: asked.error });
    const c = d.config;
    const { smtp, from } = asked;
    const next: [SettingKey, string][] = [
      ["smtpHost", smtp.host], ["smtpPort", String(smtpPort(smtp))], ["smtpSecurity", smtp.security],
      ["smtpUser", smtp.user], ["smtpPassword", smtp.password], ["mailFrom", from],
    ];
    const now: Record<string, string> = { smtpHost: c.smtpHost, smtpPort: String(smtpPort({ port: c.smtpPort, security: c.smtpSecurity })), smtpSecurity: c.smtpSecurity, smtpUser: c.smtpUser, smtpPassword: c.smtpPassword, mailFrom: c.mailFrom };
    const changed = next.filter(([k, v]) => now[k] !== v);
    const legacy = (await h.live.stored()).some((x) => (x.key as string) === LEGACY_SMTP_URL);
    if (!changed.length && !legacy) return h.back(reply, back, { kind: "ok", text: "Nothing changed." });
    // With an address from an earlier version, every part is written out before it goes.
    for (const [key, v] of legacy ? next : changed) await saveSetting(d.db, d.config.sessionSecret, s.user.id, key, v);
    if (legacy) await d.db.query("DELETE FROM settings WHERE key = $1", [LEGACY_SMTP_URL]);
    await audit(d.db, { actor: s.user.id, action: "settings.update", target: "mail", ip: req.ip,
      metadata: Object.fromEntries(changed.map(([k, v]) => [k, SETTINGS[k].secret ? "(secret)" : v])) });
    await changed_();
    return h.back(reply, back, { kind: "ok", text: smtp.host ? `Email settings saved: sending through ${smtp.host}:${smtpPort(smtp)} as ${from}.` : "Email settings saved. No SMTP host, so emails are only written to the log." });
  });

  app.post("/admin/settings/test-mail", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    const back = "/admin/settings#mail";
    const f = h.form(req);
    const to = String(f.testTo ?? "").trim() || s.user.email;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) return h.back(reply, back, { kind: "bad", text: "Send the test to an email address." });
    // From the settings page's form (values not saved yet), or with what is saved.
    const asked = f.smtpHost !== undefined ? mailFromForm(f) : smtpOf(d.config) ? { smtp: smtpOf(d.config)!, from: d.config.mailFrom } : { error: "Enter the SMTP host first." };
    if ("error" in asked) return h.back(reply, back, { kind: "bad", text: asked.error });
    if (!asked.smtp.host) return h.back(reply, back, { kind: "bad", text: "Enter the SMTP host first." });
    if (!(await hit(d.db, `mail:${s.user.email.toLowerCase()}`, LIMITS.mail)).ok) return h.back(reply, back, { kind: "bad", text: "Too many emails in the last hour; try later." });
    try {
      await (d.testSmtp ?? testSmtp)(asked.smtp, asked.from, to, `This is a test from the ${d.config.rootDomain} dashboard, sent through ${asked.smtp.host}:${smtpPort(asked.smtp)}. Email works.\n`, `Test email from ${d.config.rootDomain}`);
    } catch (e) {
      await audit(d.db, { actor: s.user.id, action: "settings.test_mail", target: asked.smtp.host, ip: req.ip, metadata: { ok: false } });
      return h.back(reply, back, { kind: "bad", text: `The test failed: ${(e as Error).message}`.slice(0, 290) });
    }
    await audit(d.db, { actor: s.user.id, action: "settings.test_mail", target: asked.smtp.host, ip: req.ip, metadata: { ok: true } });
    return h.back(reply, back, { kind: "ok", text: `Sent to ${to} through ${asked.smtp.host}. Check the inbox (and spam).${f.smtpHost !== undefined ? " Save the settings to keep them." : ""}` });
  });
}
