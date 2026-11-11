/**
 * Admin > Settings: the platform's credentials and choices that used to need .env and a
 * restart: the Cloudflare token and zone, the SMTP address, the Let's Encrypt account
 * email, staging or production, and the weekly certificate limit. Saved values win over
 * .env and reach every process at once (lib/settings.ts).
 *
 * Guarded more than other admin pages: the `settings.manage` permission, two-step sign-in
 * turned on, and the admin's password again on every save. Secrets are never shown back.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.js";
import { findCloudflareZone } from "../dns/providers.js";
import { audit } from "../lib/audit.js";
import { hit, LIMITS } from "../lib/limits.js";
import { verifySecret } from "../lib/secrets.js";
import { announce, clearSetting, isSettingKey, LE_PRODUCTION, LE_STAGING, masked, saveSetting, SETTINGS, type SettingKey, type Stored } from "../lib/settings.js";
import { adminGuard, adminTabs } from "./admin.js";
import type { DashDeps, Helpers } from "./app.js";
import { csrfField, html, when, type Html } from "./html.js";
import type { Session } from "./session.js";

const SECTIONS: Record<string, SettingKey[]> = {
  dns: ["dnsProvider", "cloudflareApiToken", "cloudflareZoneId"],
  mail: ["smtpUrl", "mailFrom"],
  acme: ["acmeEmail", "acmeDirectoryUrl", "certWeeklyLimit"],
};

export function settingsRoutes(app: FastifyInstance, d: DashDeps, h: Helpers) {
  const admin = adminGuard(h);

  /** Settings pages need two-step sign-in on: an admin's password alone should not reach the DNS token. */
  const guard = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = admin(req, reply, "settings.manage");
    if (!s) return null;
    if (!s.user.totp) {
      void h.render(req, reply, "Settings", html`${adminTabs(req, s)}<div class="card notice"><h1>Turn on two-step sign-in first</h1>
        <p>Settings hold the platform's credentials (the Cloudflare token, the email password), so changing them needs two-step sign-in on your account.</p>
        <p><a class="btn primary" href="/account">Set it up on the Account page</a></p></div>`, null, req.method === "GET" ? 200 : 403);
      return null;
    }
    return s;
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
        return html`<span class="dim">Set here${st.updated_by ? ` by ${st.updated_by}` : ""}, ${when(st.updated_at)}${SETTINGS[key].secret ? html` · <code>${masked(key, st.value)}</code>` : ""}.</span>
          <form class="inline" method="post" action="/admin/settings/clear" data-confirm="Stop using the value set here${env ? " and go back to .env's" : ""}?">${csrfField(s.csrf)}<input type="hidden" name="key" value="${key}"><button>Use .env's value</button></form>`;
      }
      return env ? html`<span class="dim">From .env${SETTINGS[key].secret ? html` · <code>${masked(key, env)}</code>` : ""}.</span>` : html`<span class="dim">Not set.</span>`;
    };
    const password = (id: string) => html`<label for="${id}">Your password, to confirm</label><input id="${id}" type="password" name="password" required autocomplete="current-password">`;
    const testsOnly = base.dnsProvider === "challtestsrv";
    const custom = !!base.acmeDirectoryUrl && base.acmeDirectoryUrl !== LE_PRODUCTION && base.acmeDirectoryUrl !== LE_STAGING;

    return h.render(req, reply, "Settings", html`${adminTabs(req, s)}<div class="card"><h1>Settings</h1>
      <p class="dim">What is saved here wins over .env and takes effect everywhere within seconds, with no restart. Secrets are stored encrypted and never shown again; leave a secret's box empty to keep the one there.
      Not here: the database, SESSION_SECRET, the domain, ports and proxies (set with <span class="mono">./setup.sh</span>), and TURN's secrets.</p></div>

      <div class="card" id="dns"><h2>DNS (Cloudflare)</h2>
      ${testsOnly ? html`<p class="dim">This platform uses a test DNS server (DNS_PROVIDER=challtestsrv in .env), so this is not changed here.</p>` : html`
      <form method="post" action="/admin/settings/dns">${csrfField(s.csrf)}
        <label for="dnsProvider">Provider</label><select id="dnsProvider" name="dnsProvider">
          <option value="cloudflare"${c.dnsProvider === "cloudflare" ? " selected" : ""}>Cloudflare</option>
          <option value="memory"${c.dnsProvider === "memory" ? " selected" : ""}>None (station names are not published)</option></select>
        <p>${source("dnsProvider")}</p>
        <label for="cloudflareApiToken">API token</label><input id="cloudflareApiToken" type="password" name="cloudflareApiToken" autocomplete="off" placeholder="${c.cloudflareApiToken ? "unchanged" : "paste the token"}">
        <p>${source("cloudflareApiToken")}</p>
        <label for="cloudflareZoneId">Zone ID (leave empty to find it from the token)</label><input id="cloudflareZoneId" name="cloudflareZoneId" autocomplete="off" value="${c.cloudflareZoneId}" maxlength="32">
        <p>${source("cloudflareZoneId")}</p>
        ${password("pw-dns")}
        <div class="row"><button class="primary">Save</button><a href="/admin/setup">Test the connection on Setup</a></div></form>`}</div>

      <div class="card" id="mail"><h2>Email</h2>
      <form method="post" action="/admin/settings/mail">${csrfField(s.csrf)}
        <label for="smtpUrl">SMTP address, e.g. smtps://user:password@smtp.example.com:465</label><input id="smtpUrl" type="password" name="smtpUrl" autocomplete="off" placeholder="${c.smtpUrl ? "unchanged" : "smtps://…"}">
        <p>${source("smtpUrl")}</p>
        <label for="mailFrom">Sender</label><input id="mailFrom" name="mailFrom" value="${c.mailFrom}" maxlength="200">
        <p>${source("mailFrom")}</p>
        ${password("pw-mail")}
        <div class="row"><button class="primary">Save</button></div></form>
      <form method="post" action="/admin/settings/test-mail">${csrfField(s.csrf)}<div class="row"><button>Send a test email to ${s.user.email}</button></div></form></div>

      <div class="card" id="acme"><h2>Certificates (Let's Encrypt)</h2>
      <form method="post" action="/admin/settings/acme">${csrfField(s.csrf)}
        <label for="acmeEmail">Account email (Let's Encrypt writes here about expiring certificates)</label><input id="acmeEmail" type="email" name="acmeEmail" value="${c.acmeEmail}">
        <p>${source("acmeEmail")}</p>
        ${custom ? html`<p class="dim">The certificate authority is set in .env (${base.acmeDirectoryUrl}), so staging or production is not chosen here.</p>` : html`
        <label for="acmeDirectoryUrl">Certificates</label><select id="acmeDirectoryUrl" name="acmeDirectoryUrl">
          <option value="${LE_STAGING}"${c.acmeDirectoryUrl === LE_STAGING ? " selected" : ""}>Staging (test certificates; browsers warn)</option>
          <option value="${LE_PRODUCTION}"${c.acmeDirectoryUrl === LE_PRODUCTION ? " selected" : ""}>Production (real certificates)</option></select>
        <p>${source("acmeDirectoryUrl")}</p>`}
        <label for="certWeeklyLimit">New certificates per 7 days (Let's Encrypt's limit for the domain)</label><input id="certWeeklyLimit" type="number" name="certWeeklyLimit" min="1" max="99999" value="${c.certWeeklyLimit}">
        <p>${source("certWeeklyLimit")}</p>
        ${password("pw-acme")}
        <div class="row"><button class="primary">Save</button></div></form></div>`, h.takeFlash(req, reply));
  };

  app.get("/admin/settings", async (req, reply) => {
    const s = guard(req, reply);
    if (!s) return reply;
    return page(req, reply, s);
  });

  const confirmed = async (s: Session, password: unknown): Promise<string | null> => {
    if (!(await hit(d.db, `reauth:${s.user.id}`, LIMITS.login)).ok) return "Too many tries; wait 10 minutes.";
    const hash = (await d.db.query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [s.user.id])).rows[0]?.password_hash;
    return hash && (await verifySecret(hash, String(password ?? ""))) ? null : "Your password is not right.";
  };

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
    const wrong = await confirmed(s, f.password);
    if (wrong) return h.back(reply, back, { kind: "bad", text: wrong });
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
    const next = section === "dns" ? " Test it on the Setup page." : section === "mail" ? " Send a test email to check it." : "";
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
