/**
 * `app.ROOT_DOMAIN`: the customer dashboard (spec section 1) and the admin dashboard
 * (section 2), rendered on the server. Plain forms, a CSRF token on each, secure
 * session cookies, HSTS and a strict CSP.
 */

import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import QRCode from "qrcode";
import type { Config } from "../config.js";
import type { Db } from "../db/db.js";
import type { DnsManager } from "../dns/dns.js";
import { audit } from "../lib/audit.js";
import { forget, hit, LIMITS } from "../lib/limits.js";
import type { Mailer } from "../lib/mail.js";
import { checkName, fqdnOf, normaliseLabel } from "../lib/names.js";
import { decrypt, dummyHash, encrypt, hashSecret, newToken, newTotpSecret, tokenHash, totpUri, verifySecret, verifyTotp } from "../lib/secrets.js";
import * as subs from "../lib/subdomains.js";
import { adminRoutes } from "./admin.js";
import { APP_JS, bytes, csrfField, html, page, raw, when, type Html } from "./html.js";
import { COOKIE, csrfOk, endSession, loadSession, preToken, startSession, type Session } from "./session.js";

export interface DashDeps {
  db: Db;
  dns: DnsManager;
  config: Config;
  mail: Mailer;
  /** The addresses a name has on the public internet (the setup page; tests replace it). */
  lookup?: (name: string) => Promise<string[]>;
}

type Form = Record<string, string>;
export type Flash = { kind: "ok" | "bad"; text: string } | null;

declare module "fastify" {
  interface FastifyRequest {
    session: Session | null;
  }
}

export const MIN_PASSWORD = 10;
const OFFLINE_MINUTES = 10;

export function buildDashboard(d: DashDeps): FastifyInstance {
  const app = Fastify({ trustProxy: d.config.trustedProxies, logger: false, bodyLimit: 32 * 1024 });
  void app.register(cookie);
  void app.register(formbody);
  const secure = d.config.dashboardUrl.startsWith("https://");
  const host = new URL(d.config.dashboardUrl).host;
  const ctx = (): subs.Ctx => ({ db: d.db, dns: d.dns, rootDomain: d.config.rootDomain, limit: d.config.subdomainLimit });

  app.decorateRequest("session", null);
  app.addHook("onRequest", async (req, reply) => {
    reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    reply.header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "same-origin");
    reply.header("Cache-Control", "no-store");
    req.session = await loadSession(d.db, req.cookies[COOKIE]);
  });
  app.addHook("preHandler", async (req, reply) => {
    if (req.method !== "POST") return;
    if (!csrfOk(req, req.session, host)) {
      return reply.status(403).type("text/html").send(page({ title: "Refused", rootDomain: d.config.rootDomain }, html`<div class="card"><h1>That form has expired</h1><p>Go back, reload the page and try again.</p></div>`));
    }
  });

  // ------------------------------------------------------------------ helpers

  const render = (req: FastifyRequest, reply: FastifyReply, title: string, body: Html, flash: Flash = null, status = 200) => {
    const s = req.session && !req.session.needsTotp ? req.session : null;
    return reply.status(status).type("text/html; charset=utf-8").send(page({ title, user: s?.user, csrf: s?.csrf, flash, rootDomain: d.config.rootDomain, path: req.url }, body));
  };
  const form = (req: FastifyRequest): Form => (req.body ?? {}) as Form;
  const pre = (req: FastifyRequest, reply: FastifyReply) => csrfField(req.session?.csrf ?? preToken(req, reply, secure));
  const signedIn = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = req.session;
    if (!s) {
      void reply.redirect("/login");
      return null;
    }
    if (s.needsTotp) {
      void reply.redirect("/login/totp");
      return null;
    }
    return s;
  };
  const back = (reply: FastifyReply, to: string, flash: Flash) => {
    if (flash) reply.setCookie("nova_flash", `${flash.kind}:${flash.text}`, { path: "/", httpOnly: true, sameSite: "lax", secure, maxAge: 60 });
    return reply.redirect(to);
  };
  const takeFlash = (req: FastifyRequest, reply: FastifyReply): Flash => {
    const v = req.cookies.nova_flash;
    if (!v) return null;
    reply.clearCookie("nova_flash", { path: "/" });
    const [kind, ...rest] = v.split(":");
    return { kind: kind === "ok" ? "ok" : "bad", text: rest.join(":").slice(0, 300) };
  };

  async function mailLink(userId: number, email: string, kind: "verify" | "reset") {
    const r = await hit(d.db, `mail:${email.toLowerCase()}`, LIMITS.mail);
    if (!r.ok) return;
    const token = newToken();
    const hours = kind === "verify" ? 48 : 1;
    await d.db.query("INSERT INTO email_tokens (token_hash, user_id, kind, expires_at) VALUES ($1, $2, $3, now() + make_interval(hours => $4))", [tokenHash(token), userId, kind, hours]);
    const link = `${d.config.dashboardUrl}/${kind === "verify" ? "verify" : "reset"}?token=${token}`;
    await d.mail({
      to: email,
      subject: kind === "verify" ? `Confirm your email for ${d.config.rootDomain}` : `Reset your ${d.config.rootDomain} password`,
      text: kind === "verify"
        ? `Open this link to confirm your email address (it works for 48 hours):\n\n${link}\n`
        : `Someone asked to reset your password. If it was you, open this link within an hour:\n\n${link}\n\nIf not, ignore this email.`,
    }).catch(() => undefined);
  }

  async function useToken(token: string, kind: "verify" | "reset"): Promise<number | null> {
    const r = await d.db.query<{ user_id: number }>(
      "UPDATE email_tokens SET used_at = now() WHERE token_hash = $1 AND kind = $2 AND used_at IS NULL AND expires_at > now() RETURNING user_id",
      [tokenHash(String(token ?? "")), kind]);
    return r.rows[0]?.user_id ?? null;
  }

  app.get("/static/app.js", async (_req, reply) => reply.type("text/javascript").header("Cache-Control", "max-age=300").send(APP_JS));
  app.get("/healthz", async () => ({ ok: true }));

  // ------------------------------------------------------------------ sign up, in and out

  const signupForm = (req: FastifyRequest, reply: FastifyReply, email = "", flash: Flash = null, status = 200) =>
    render(req, reply, "Create account", html`<div class="card"><h1>Create an account</h1>
      <p class="dim">For station owners: claim your station's address, then paste its access code into Nova.</p>
      <form method="post" action="/signup">${pre(req, reply)}
        <label for="email">Email</label><input id="email" type="email" name="email" value="${email}" required autocomplete="email">
        <label for="password">Password (${MIN_PASSWORD} characters or more)</label><input id="password" type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password">
        <div class="row"><button class="primary">Create account</button><a href="/login">I have an account</a></div>
      </form></div>`, flash, status);

  app.get("/signup", async (req, reply) => signupForm(req, reply));
  app.post("/signup", async (req, reply) => {
    const f = form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    if (!(await hit(d.db, `signup:${req.ip}`, LIMITS.signup)).ok) return signupForm(req, reply, email, { kind: "bad", text: "Too many new accounts from here; try later." }, 429);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return signupForm(req, reply, email, { kind: "bad", text: "That is not an email address." }, 400);
    if (String(f.password ?? "").length < MIN_PASSWORD) return signupForm(req, reply, email, { kind: "bad", text: `The password needs ${MIN_PASSWORD} characters or more.` }, 400);
    const role = d.config.adminEmails.includes(email) ? "admin" : "user";
    const r = await d.db.query<{ id: number }>("INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id",
      [email, await hashSecret(String(f.password)), role]);
    if (!r.rows[0]) return signupForm(req, reply, email, { kind: "bad", text: "There is already an account with that email. Sign in, or reset the password." }, 409);
    const id = r.rows[0].id;
    await audit(d.db, { actor: id, action: "user.signup", target: email, ip: req.ip });
    await mailLink(id, email, "verify");
    await startSession(d.db, reply, id, false, req.ip, secure);
    return back(reply, "/", { kind: "ok", text: `Welcome. We sent a link to ${email}: open it to confirm your address, then claim your station.` });
  });

  const loginForm = (req: FastifyRequest, reply: FastifyReply, email = "", flash: Flash = null, status = 200) =>
    render(req, reply, "Sign in", html`<div class="card"><h1>Sign in</h1>
      <form method="post" action="/login">${pre(req, reply)}
        <label for="email">Email</label><input id="email" type="email" name="email" value="${email}" required autocomplete="username">
        <label for="password">Password</label><input id="password" type="password" name="password" required autocomplete="current-password">
        <div class="row"><button class="primary">Sign in</button><a href="/forgot">Forgot the password?</a></div>
      </form></div>`, flash, status);

  app.get("/login", async (req, reply) => loginForm(req, reply, "", takeFlash(req, reply)));
  app.post("/login", async (req, reply) => {
    const f = form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    for (const key of [`login:ip:${req.ip}`, `login:email:${email}`]) {
      const r = await hit(d.db, key, LIMITS.login);
      if (!r.ok) return loginForm(req, reply, email, { kind: "bad", text: `Too many attempts; try again in ${Math.ceil(r.retryAfter / 60)} minutes.` }, 429);
    }
    const u = (await d.db.query<{ id: number; password_hash: string; status: string; totp_secret_enc: string | null }>(
      "SELECT id, password_hash, status, totp_secret_enc FROM users WHERE lower(email) = $1", [email])).rows[0];
    const ok = await verifySecret(u?.password_hash ?? (await dummyHash()), String(f.password ?? ""));
    if (!u || !ok) return loginForm(req, reply, email, { kind: "bad", text: "Wrong email or password." }, 401);
    if (u.status !== "active") return loginForm(req, reply, email, { kind: "bad", text: "This account is suspended." }, 403);
    await forget(d.db, `login:email:${email}`);
    await endSession(d.db, reply, req.session);
    await startSession(d.db, reply, u.id, !!u.totp_secret_enc, req.ip, secure);
    return reply.redirect(u.totp_secret_enc ? "/login/totp" : "/");
  });

  app.get("/login/totp", async (req, reply) => {
    if (!req.session?.needsTotp) return reply.redirect("/");
    return render(req, reply, "Two-step sign-in", html`<div class="card"><h1>Enter the code from your authenticator app</h1>
      <form method="post" action="/login/totp">${csrfField(req.session.csrf)}
        <label for="code">6-digit code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required pattern="[0-9 ]{6,7}">
        <div class="row"><button class="primary">Continue</button></div></form></div>`);
  });
  app.post("/login/totp", async (req, reply) => {
    const s = req.session;
    if (!s?.needsTotp) return reply.redirect("/");
    if (!(await hit(d.db, `totp:${s.user.id}`, LIMITS.totp)).ok) return render(req, reply, "Two-step sign-in", html`<div class="card"><p>Too many tries; wait 10 minutes.</p></div>`, null, 429);
    const enc = (await d.db.query("SELECT totp_secret_enc FROM users WHERE id = $1", [s.user.id])).rows[0]?.totp_secret_enc;
    if (!enc || !verifyTotp(decrypt(d.config.sessionSecret, enc), form(req).code)) {
      return render(req, reply, "Two-step sign-in", html`<div class="card"><h1>That code is not right</h1><p><a href="/login/totp">Try again</a></p></div>`, { kind: "bad", text: "Wrong code." }, 401);
    }
    await d.db.query("UPDATE sessions SET needs_totp = false WHERE token_hash = $1", [s.tokenHash]);
    return reply.redirect("/");
  });

  app.post("/logout", async (req, reply) => {
    await endSession(d.db, reply, req.session);
    return reply.redirect("/login");
  });

  // ------------------------------------------------------------------ email links

  app.get("/verify", async (req, reply) => {
    const id = await useToken(String((req.query as Form).token), "verify");
    if (!id) return render(req, reply, "Link expired", html`<div class="card"><h1>This link has expired or was used</h1><p>Sign in and ask for a new one.</p></div>`, null, 400);
    await d.db.query("UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [id]);
    return back(reply, req.session ? "/" : "/login", { kind: "ok", text: "Your email address is confirmed." });
  });
  app.post("/verify/resend", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    if (!s.user.verified) await mailLink(s.user.id, s.user.email, "verify");
    return back(reply, "/", { kind: "ok", text: `A new link is on its way to ${s.user.email}.` });
  });

  app.get("/forgot", async (req, reply) => render(req, reply, "Reset password", html`<div class="card"><h1>Reset your password</h1>
    <form method="post" action="/forgot">${pre(req, reply)}<label for="email">Email</label><input id="email" type="email" name="email" required>
    <div class="row"><button class="primary">Send a reset link</button></div></form></div>`));
  app.post("/forgot", async (req, reply) => {
    const email = String(form(req).email ?? "").trim().toLowerCase();
    const u = (await d.db.query<{ id: number }>("SELECT id FROM users WHERE lower(email) = $1 AND status = 'active'", [email])).rows[0];
    if (u) await mailLink(u.id, email, "reset");
    // The same answer either way: no telling which emails have accounts.
    return render(req, reply, "Reset password", html`<div class="card"><h1>Check your email</h1><p>If ${email} has an account, a reset link is on its way. It works for an hour.</p></div>`);
  });
  app.get("/reset", async (req, reply) => render(req, reply, "New password", html`<div class="card"><h1>Choose a new password</h1>
    <form method="post" action="/reset">${pre(req, reply)}<input type="hidden" name="token" value="${(req.query as Form).token ?? ""}">
    <label for="password">New password (${MIN_PASSWORD} characters or more)</label><input id="password" type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password">
    <div class="row"><button class="primary">Save</button></div></form></div>`));
  app.post("/reset", async (req, reply) => {
    const f = form(req);
    if (String(f.password ?? "").length < MIN_PASSWORD) return render(req, reply, "New password", html`<div class="card"><p>The password needs ${MIN_PASSWORD} characters or more. <a href="javascript:history.back()">Back</a></p></div>`, null, 400);
    const id = await useToken(f.token, "reset");
    if (!id) return render(req, reply, "Link expired", html`<div class="card"><h1>This link has expired or was used</h1><p><a href="/forgot">Ask for a new one.</a></p></div>`, null, 400);
    await d.db.query("UPDATE users SET password_hash = $2, email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [id, await hashSecret(f.password)]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1", [id]); // sign out everywhere
    await audit(d.db, { actor: id, action: "user.password_reset", ip: req.ip });
    return back(reply, "/login", { kind: "ok", text: "Password changed. Sign in with the new one." });
  });

  // ------------------------------------------------------------------ account: password, 2FA

  app.get("/account", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    let setup: Html | string = "";
    if (s.pendingTotpEnc) {
      const secret = decrypt(d.config.sessionSecret, s.pendingTotpEnc);
      const qr = await QRCode.toDataURL(totpUri(secret, s.user.email, d.config.rootDomain), { margin: 1, width: 200 });
      setup = html`<p>Scan this with an authenticator app (or type the key), then enter the code it shows.</p>
        <img src="${qr}" alt="QR code for the authenticator app" width="200" height="200"><p class="dim">Key: <code>${secret}</code></p>
        <form method="post" action="/account/totp/confirm">${csrfField(s.csrf)}<label for="code">Code</label><input id="code" name="code" inputmode="numeric" required>
        <div class="row"><button class="primary">Turn on</button></div></form>`;
    }
    return render(req, reply, "Account", html`<div class="card"><h1>Account</h1><div class="grid"><span class="dim">Email</span><span>${s.user.email}
      ${s.user.verified ? html`<span class="chip ok">confirmed</span>` : html`<span class="chip bad">not confirmed</span> <form class="inline" method="post" action="/verify/resend">${csrfField(s.csrf)}<button>Send the link again</button></form>`}</span></div></div>
      <div class="card"><h2>Two-step sign-in</h2>
      ${s.user.totp ? html`<p class="ok">On. Signing in asks for a code from your authenticator app.</p>
        <form method="post" action="/account/totp/disable">${csrfField(s.csrf)}<label for="off">A current code, to turn it off</label><input id="off" name="code" inputmode="numeric" required><div class="row"><button class="danger">Turn off</button></div></form>`
        : s.pendingTotpEnc ? setup
        : html`<p class="dim">Off. Turn it on to need a code from an authenticator app as well as the password.</p><form method="post" action="/account/totp/start">${csrfField(s.csrf)}<button class="primary">Set up</button></form>`}</div>
      <div class="card"><h2>Change password</h2><form method="post" action="/account/password">${csrfField(s.csrf)}
        <label for="cur">Current password</label><input id="cur" type="password" name="current" required autocomplete="current-password">
        <label for="new">New password</label><input id="new" type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password">
        <div class="row"><button class="primary">Change</button></div></form></div>`, takeFlash(req, reply));
  });
  app.post("/account/totp/start", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    await d.db.query("UPDATE sessions SET pending_totp_enc = $2 WHERE token_hash = $1", [s.tokenHash, encrypt(d.config.sessionSecret, newTotpSecret())]);
    return reply.redirect("/account");
  });
  app.post("/account/totp/confirm", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s?.pendingTotpEnc) return reply.redirect("/account");
    if (!verifyTotp(decrypt(d.config.sessionSecret, s.pendingTotpEnc), form(req).code)) return back(reply, "/account", { kind: "bad", text: "That code is not right; try the newest one." });
    await d.db.query("UPDATE users SET totp_secret_enc = $2 WHERE id = $1", [s.user.id, s.pendingTotpEnc]);
    await d.db.query("UPDATE sessions SET pending_totp_enc = NULL WHERE token_hash = $1", [s.tokenHash]);
    await audit(d.db, { actor: s.user.id, action: "user.totp_on", ip: req.ip });
    return back(reply, "/account", { kind: "ok", text: "Two-step sign-in is on." });
  });
  app.post("/account/totp/disable", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const enc = (await d.db.query("SELECT totp_secret_enc FROM users WHERE id = $1", [s.user.id])).rows[0]?.totp_secret_enc;
    if (!enc || !verifyTotp(decrypt(d.config.sessionSecret, enc), form(req).code)) return back(reply, "/account", { kind: "bad", text: "That code is not right." });
    await d.db.query("UPDATE users SET totp_secret_enc = NULL WHERE id = $1", [s.user.id]);
    await audit(d.db, { actor: s.user.id, action: "user.totp_off", ip: req.ip });
    return back(reply, "/account", { kind: "ok", text: "Two-step sign-in is off." });
  });
  app.post("/account/password", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const f = form(req);
    const hash = (await d.db.query("SELECT password_hash FROM users WHERE id = $1", [s.user.id])).rows[0].password_hash;
    if (!(await verifySecret(hash, f.current))) return back(reply, "/account", { kind: "bad", text: "The current password is wrong." });
    if (String(f.password ?? "").length < MIN_PASSWORD) return back(reply, "/account", { kind: "bad", text: `The new password needs ${MIN_PASSWORD} characters or more.` });
    await d.db.query("UPDATE users SET password_hash = $2 WHERE id = $1", [s.user.id, await hashSecret(f.password)]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [s.user.id, s.tokenHash]);
    await audit(d.db, { actor: s.user.id, action: "user.password_change", ip: req.ip });
    return back(reply, "/account", { kind: "ok", text: "Password changed; other sign-ins were ended." });
  });

  // ------------------------------------------------------------------ names

  app.get("/names/check", async (req, reply) => {
    const r = await hit(d.db, `names:${req.ip}`, LIMITS.nameCheck);
    if (!r.ok) return reply.status(429).header("Retry-After", String(r.retryAfter)).send({ state: "limited", message: "Too many checks." });
    const label = normaliseLabel(String((req.query as Form).label ?? ""), d.config.rootDomain);
    const c = await checkName(d.db, label);
    return { ...c, fqdn: fqdnOf(label, d.config.rootDomain) };
  });

  // ------------------------------------------------------------------ my stations

  const codeOnce = (req: FastifyRequest, reply: FastifyReply, label: string, code: string, title: string) =>
    render(req, reply, title, html`<div class="card"><h1>${title}</h1>
      <p>The access code for <b>${fqdnOf(label, d.config.rootDomain)}</b>:</p>
      <p><span class="code">${code}</span> <button type="button" data-copy="${code}">Copy</button></p>
      <p class="bad"><b>Store it now.</b> It is shown only this once; we keep only a scrambled copy. If it is lost, make a new one (the old one then stops working).</p>
      <p>In Nova: Settings → Remote Connections → Hostname <b>${label}</b>, Access code as above, then Start Server.</p>
      <p><a class="btn primary" href="/">I have stored it</a></p></div>`);

  app.get("/", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT s.id, s.label, s.status, st.last_seen_at, st.app_version FROM subdomains s JOIN studios st ON st.subdomain_id = s.id
        WHERE s.user_id = $1 ORDER BY s.label`, [s.user.id])).rows;
    const room = rows.length < d.config.subdomainLimit;
    return render(req, reply, "My stations", html`
      ${!s.user.verified ? html`<div class="card notice"><b>Confirm your email</b> to claim a station. We sent a link to ${s.user.email}. <form class="inline" method="post" action="/verify/resend">${csrfField(s.csrf)}<button>Send the link again</button></form></div>` : ""}
      <div class="card"><h1>My stations</h1>
      ${rows.length ? html`<table><tr><th>Address</th><th>Status</th><th class="wide-only">Last seen</th><th class="wide-only"></th></tr>${rows.map((r) => html`<tr>
        <td><a href="/stations/${r.id}">${fqdnOf(r.label, d.config.rootDomain)}</a></td>
        <td>${statusChip(r.status, r.last_seen_at)}</td><td class="wide-only">${when(r.last_seen_at)}</td><td class="wide-only"><a href="/stations/${r.id}">Manage</a></td></tr>`)}</table>`
        : html`<div class="empty"><p>No station yet. Claim an address like <b>kfm.${d.config.rootDomain}</b>, then enter its access code in Nova.</p></div>`}
      ${room && s.user.verified ? html`<p class="row"${rows.length ? "" : raw(' style="justify-content:center"')}><a class="btn primary" href="/stations/new">Claim a station address</a></p>` : room ? "" : html`<p class="dim row">Your plan allows ${d.config.subdomainLimit} station${d.config.subdomainLimit === 1 ? "" : "s"}.</p>`}
      </div>`, takeFlash(req, reply));
  });

  app.get("/stations/new", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    return render(req, reply, "Claim an address", html`<div class="card"><h1>Claim your station's address</h1>
      <form method="post" action="/stations">${csrfField(s.csrf)}
        <label for="label">Name</label><div class="row" style="margin-top:0;gap:8px;flex-wrap:nowrap"><input id="label" name="label" required autocomplete="off" spellcheck="false" placeholder="kfm" maxlength="63" style="max-width:260px">
        <span class="dim">.${d.config.rootDomain}</span></div><div id="name-state" aria-live="polite"></div>
        <p class="dim">3–63 lowercase letters, digits and hyphens; not starting or ending with a hyphen.</p>
        <div class="row"><button class="primary">Claim</button><a href="/">Cancel</a></div></form></div>`, takeFlash(req, reply));
  });
  app.post("/stations", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const label = normaliseLabel(form(req).label, d.config.rootDomain);
    try {
      const { accessCode } = await subs.claim(ctx(), { id: s.user.id, ip: req.ip }, label);
      return codeOnce(req, reply, label, accessCode, "Your station's address is yours");
    } catch (e) {
      if (e instanceof subs.SubdomainError) return back(reply, "/stations/new", { kind: "bad", text: e.message });
      throw e;
    }
  });

  async function ownStation(req: FastifyRequest, reply: FastifyReply, s: Session) {
    const id = Number((req.params as { id: string }).id);
    const row = (await d.db.query(
      `SELECT s.id, s.label, s.status, s.user_id, s.created_at, st.id AS studio_id, st.last_ip, st.last_port, st.last_seen_at, st.app_version
         FROM subdomains s JOIN studios st ON st.subdomain_id = s.id WHERE s.id = $1`, [id])).rows[0];
    if (!row || (row.user_id !== s.user.id && s.user.role !== "admin")) {
      void render(req, reply, "Not found", html`<div class="card"><h1>No such station</h1></div>`, null, 404);
      return null;
    }
    return row;
  }

  app.get("/stations/:id", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const st = await ownStation(req, reply, s);
    if (!st) return reply;
    const cert = (await d.db.query("SELECT status, expires_at, error FROM certificates WHERE subdomain_id = $1 AND status IN ('pending', 'issued', 'failed') ORDER BY created_at DESC LIMIT 1", [st.id])).rows[0];
    const usage = (await d.db.query("SELECT coalesce(sum(bytes_relayed), 0)::bigint AS b, coalesce(sum(sessions), 0)::int AS n FROM turn_usage WHERE studio_id = $1 AND day >= date_trunc('month', current_date)", [st.studio_id])).rows[0];
    const url = `https://${fqdnOf(st.label, d.config.rootDomain)}${st.last_port && st.last_port !== 443 ? `:${st.last_port}` : ""}`;
    return render(req, reply, st.label, html`<p><a href="/">← My stations</a></p><div class="card"><h1>${fqdnOf(st.label, d.config.rootDomain)}</h1>
      <div class="grid">
        <span class="dim">Address for presenters</span><span><code>${url}</code> <button type="button" data-copy="${url}">Copy</button></span>
        <span class="dim">Status</span><span>${statusChip(st.status, st.last_seen_at)}</span>
        <span class="dim">Last address</span><span>${st.last_ip ? `${st.last_ip}${st.last_port ? ` port ${st.last_port}` : ""}` : "—"}</span>
        <span class="dim">Last seen</span><span>${when(st.last_seen_at)}</span>
        <span class="dim">Nova version</span><span>${st.app_version ?? "—"}</span>
        <span class="dim">Certificate</span><span>${!cert ? "None yet (Nova asks for one when it starts its server)" : cert.status === "issued" ? html`<span class="ok">Issued</span>, until ${when(cert.expires_at)}` : cert.status === "pending" ? "Being issued…" : html`<span class="bad">Failed</span> <span class="dim">${cert.error ?? ""}</span>`}</span>
        <span class="dim">Audio relay this month</span><span>${bytes(Number(usage.b))} in ${usage.n} session${usage.n === 1 ? "" : "s"}</span>
      </div></div>
      ${st.status === "suspended" ? html`<div class="card bad">This station is suspended by the platform. Contact support.</div>` : html`
      <div class="cols"><div class="card"><h2>Rename</h2><p class="dim">The old name is held for 30 days and then released. Nova picks up the new name on its next check-in (within 5 minutes) and gets a new certificate.</p>
        <form method="post" action="/stations/${st.id}/rename" data-confirm="Rename ${st.label}? Presenters will need the new address.">${csrfField(s.csrf)}
          <label for="label">New name</label><input id="label" name="label" required autocomplete="off" maxlength="63"><div id="name-state" aria-live="polite"></div>
          <div class="row"><button>Rename</button></div></form></div>
      <div class="card"><h2>Access code</h2><p class="dim">Make a new code if the old one may have leaked. The old code, and every Nova signed in with it, stop working at once; enter the new code in Nova.</p>
        <form method="post" action="/stations/${st.id}/regenerate" data-confirm="Make a new access code? Nova will need it entered again.">${csrfField(s.csrf)}<button>Make a new access code</button></form></div></div>`}
      <div class="card danger"><h2>Delete</h2><p class="dim">Removes the address, its certificate and every sign-in; the name is held for 30 days.</p>
        <form method="post" action="/stations/${st.id}/delete">${csrfField(s.csrf)}<label for="confirm">Type <b>${st.label}</b> to confirm</label><input id="confirm" name="confirm" required autocomplete="off">
        <div class="row"><button class="danger">Delete this station</button></div></form></div>`, takeFlash(req, reply));
  });

  const action = (name: string, run: (s: Session, id: number, f: Form, req: FastifyRequest, reply: FastifyReply) => Promise<unknown>) =>
    app.post(`/stations/:id/${name}`, async (req, reply) => {
      const s = signedIn(req, reply);
      if (!s) return reply;
      const st = await ownStation(req, reply, s);
      if (!st) return reply;
      try {
        return await run(s, st.id, form(req), req, reply);
      } catch (e) {
        if (e instanceof subs.SubdomainError) return back(reply, `/stations/${st.id}`, { kind: "bad", text: e.message });
        throw e;
      }
    });
  const actor = (s: Session, req: FastifyRequest): subs.Actor => ({ id: s.user.id, ip: req.ip, admin: s.user.role === "admin" });

  action("rename", async (s, id, f, req, reply) => {
    const r = await subs.rename(ctx(), actor(s, req), id, normaliseLabel(f.label, d.config.rootDomain));
    return back(reply, `/stations/${id}`, { kind: "ok", text: `Renamed to ${fqdnOf(r.to, d.config.rootDomain)}. ${r.from} is held for 30 days.` });
  });
  action("regenerate", async (s, id, _f, req, reply) => {
    const code = await subs.regenerate(ctx(), actor(s, req), id);
    const label = (await d.db.query("SELECT label FROM subdomains WHERE id = $1", [id])).rows[0].label;
    return codeOnce(req, reply, label, code, "A new access code");
  });
  action("delete", async (s, id, f, req, reply) => {
    const label = (await d.db.query("SELECT label FROM subdomains WHERE id = $1", [id])).rows[0].label;
    if (String(f.confirm ?? "").trim().toLowerCase() !== label) return back(reply, `/stations/${id}`, { kind: "bad", text: "Type the name exactly to delete." });
    await subs.remove(ctx(), actor(s, req), id);
    return back(reply, "/", { kind: "ok", text: `${fqdnOf(label, d.config.rootDomain)} is deleted.` });
  });

  adminRoutes(app, d, { render, form, back, takeFlash, signedIn, actor, ctx });

  app.setNotFoundHandler((req, reply) => render(req, reply, "Not found", html`<div class="card"><h1>Not found</h1><p><a href="/">Home</a></p></div>`, null, 404));
  app.setErrorHandler((err, req, reply) => {
    console.error("dashboard error:", err);
    return render(req, reply, "Error", html`<div class="card"><h1>Something went wrong</h1><p>Try again in a moment.</p></div>`, null, 500);
  });
  return app;
}

export function statusChip(status: string, lastSeen: Date | null): Html {
  if (status === "suspended") return html`<span class="chip bad">suspended</span>`;
  const online = lastSeen && Date.now() - new Date(lastSeen).getTime() < OFFLINE_MINUTES * 60_000;
  return online ? html`<span class="chip ok">online</span>` : html`<span class="chip">offline</span>`;
}

export type Helpers = {
  render: (req: FastifyRequest, reply: FastifyReply, title: string, body: Html, flash?: Flash, status?: number) => FastifyReply;
  form: (req: FastifyRequest) => Form;
  back: (reply: FastifyReply, to: string, flash: Flash) => FastifyReply;
  takeFlash: (req: FastifyRequest, reply: FastifyReply) => Flash;
  signedIn: (req: FastifyRequest, reply: FastifyReply) => Session | null;
  actor: (s: Session, req: FastifyRequest) => subs.Actor;
  ctx: () => subs.Ctx;
};
