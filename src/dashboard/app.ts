/**
 * `app.ROOT_DOMAIN`: the customer dashboard (spec section 1) and the admin console
 * (section 2), rendered on the server. Plain forms, a CSRF token on each, secure session
 * cookies, HSTS and a strict CSP, sudo mode before sensitive changes.
 */

import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import QRCode from "qrcode";
import { billingOn, billingState, BillingError, confirm, plansForSale, startCheckout } from "../billing/billing.js";
import { formatMoney, PROVIDER_INFO } from "../billing/gateways.js";
import type { Config } from "../config.js";
import type { Db } from "../db/db.js";
import { transaction } from "../db/db.js";
import type { DnsManager } from "../dns/dns.js";
import { audit } from "../lib/audit.js";
import { forget, hit, LIMITS } from "../lib/limits.js";
import type { Mailer } from "../lib/mail.js";
import { checkName, fqdnOf, normaliseLabel } from "../lib/names.js";
import { presenterPort } from "../api/studio.js";
import { allowance, stationWord } from "../lib/plans.js";
import { ALL_PERMISSIONS, can, isStaff } from "../lib/rbac.js";
import { decrypt, dummyHash, encrypt, hashSecret, newToken, newTotpSecret, tokenHash, totpUri, verifySecret, verifyTotp } from "../lib/secrets.js";
import { LiveConfig } from "../lib/settings.js";
import * as subs from "../lib/subdomains.js";
import { adminRoutes } from "./admin.js";
import { peopleRoutes } from "./admin-people.js";
import { settingsRoutes } from "./admin-settings.js";
import { billingAdminRoutes } from "./admin-billing.js";
import { APP_JS, badge, bytes, csrfField, day, emptyState, facts, field, html, icon, page, pageHead, panel, when, type Html } from "./html.js";
import { cookieNames, csrfOk, elevate, endSession, loadSession, preToken, startSession, SUDO_MINUTES, type Session } from "./session.js";

export interface DashDeps {
  db: Db;
  dns: DnsManager;
  config: Config;
  mail: Mailer;
  /** The addresses a name has on the public internet (the setup page; tests replace it). */
  lookup?: (name: string) => Promise<string[]>;
  /** The settings saved in Admin > Settings (main.ts shares one with the DNS manager and mailer). */
  live?: LiveConfig;
  /** Payment providers' APIs (tests replace the network). */
  fetch?: typeof fetch;
}

type Form = Record<string, string>;
export type Flash = { kind: "ok" | "bad"; text: string } | null;

declare module "fastify" {
  interface FastifyRequest {
    session: Session | null;
  }
}

export const MIN_PASSWORD = 10;
export const MAX_PASSWORD = 200;
const OFFLINE_MINUTES = 10;

/** "Chrome on macOS", from a User-Agent; good enough to recognise one's own devices. */
export function deviceOf(ua: string | null | undefined): string {
  const s = ua ?? "";
  const browser = /Edg\//.test(s) ? "Edge" : /OPR\//.test(s) ? "Opera" : /Firefox\//.test(s) ? "Firefox" : /Chrome\//.test(s) ? "Chrome" : /Safari\//.test(s) ? "Safari" : s ? "A browser" : "Unknown device";
  const os = /iPhone|iPad/.test(s) ? "iOS" : /Android/.test(s) ? "Android" : /Windows/.test(s) ? "Windows" : /Mac OS X|Macintosh/.test(s) ? "macOS" : /Linux/.test(s) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

/** A password we accept: long enough, not too long (hashing cost), not the email. */
function passwordProblem(password: string, email: string): string | null {
  if (password.length < MIN_PASSWORD) return `Use ${MIN_PASSWORD} characters or more.`;
  if (password.length > MAX_PASSWORD) return `Use ${MAX_PASSWORD} characters or fewer.`;
  const local = email.toLowerCase().split("@")[0];
  if (local.length >= 4 && password.toLowerCase().includes(local)) return "Do not use your email address in the password.";
  if (/^(.)\1+$/.test(password)) return "Choose a password that is not one repeated character.";
  return null;
}

export function buildDashboard(d: DashDeps): FastifyInstance {
  const app = Fastify({ trustProxy: d.config.trustedProxies, logger: false, bodyLimit: 32 * 1024 });
  void app.register(cookie);
  void app.register(formbody);
  const secure = d.config.dashboardUrl.startsWith("https://");
  const names = cookieNames(secure);
  const host = new URL(d.config.dashboardUrl).host;
  const ctx = (): subs.Ctx => ({ db: d.db, dns: d.dns, rootDomain: d.config.rootDomain, limit: d.config.subdomainLimit, edgeIp: d.config.edgeIp });
  const live = d.live ?? new LiveConfig(d.config, d.db, { dns: d.dns });
  const billingDeps = () => ({ db: d.db, config: d.config, mail: d.mail, fetch: d.fetch });

  app.decorateRequest("session", null);
  app.addHook("onRequest", async (req, reply) => {
    reply.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
    reply.header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "same-origin");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
    reply.header("Cross-Origin-Resource-Policy", "same-origin");
    reply.header("Cache-Control", "no-store");
    req.session = await loadSession(d.db, req.cookies[names.sid]);
  });
  app.addHook("preHandler", async (req, reply) => {
    if (req.method !== "POST") return;
    if (!csrfOk(req, req.session, host, secure)) {
      return reply.status(403).type("text/html").send(page({ title: "Refused", rootDomain: d.config.rootDomain },
        panel({}, html`<h1>This form has expired</h1><p class="dim">Go back, reload the page and try again.</p>`)));
    }
  });

  // ------------------------------------------------------------------ helpers

  const render = async (req: FastifyRequest, reply: FastifyReply, title: string, body: Html, flash: Flash = null, status = 200) => {
    const s = req.session && !req.session.needsTotp ? req.session : null;
    const billing = s ? await billingOn(d.db) : false;
    return reply.status(status).type("text/html; charset=utf-8").send(page({ title, user: s?.user, csrf: s?.csrf, flash, rootDomain: d.config.rootDomain, path: req.url, billing }, body));
  };
  const form = (req: FastifyRequest): Form => (req.body ?? {}) as Form;
  const pre = (req: FastifyRequest, reply: FastifyReply) => csrfField(req.session?.csrf ?? preToken(req, reply, secure));
  const signedIn = (req: FastifyRequest, reply: FastifyReply): Session | null => {
    const s = req.session;
    if (!s) {
      void reply.redirect(`/login${req.method === "GET" && req.url !== "/" ? `?next=${encodeURIComponent(req.url)}` : ""}`);
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
  /** Only an address on this site (no "//host", no scheme) is somewhere to go back to. */
  const safeNext = (v: unknown, fallback = "/") => {
    const s = String(v ?? "");
    return /^\/(?![/\\])[\w\-./?=&%#]*$/.test(s) ? s : fallback;
  };

  /**
   * Sudo mode: true when this session confirmed its identity within the last few minutes.
   * Otherwise the person is sent to confirm it, then back to `next` (a page, never a POST).
   */
  const requireSudo = (req: FastifyRequest, reply: FastifyReply, s: Session, next: string): boolean => {
    if (s.elevated) return true;
    if (req.method === "POST") void back(reply, `/sudo?next=${encodeURIComponent(next)}`, { kind: "bad", text: "Confirm it is you, then make the change again." });
    else void reply.redirect(`/sudo?next=${encodeURIComponent(next)}`);
    return false;
  };

  /** A security notice to the account's own address (best effort). */
  const notify = (to: string, subject: string, text: string) =>
    d.mail({ to, subject: `[${d.config.rootDomain}] ${subject}`, text: `${text}\n\nIf this was not you, reset your password now: ${d.config.dashboardUrl}/forgot\n` }).catch(() => undefined);

  /** An email link: confirm the address, reset the password, or (an admin made the account) choose one. */
  async function mailLink(userId: number, email: string, kind: "verify" | "reset" | "invite"): Promise<boolean> {
    const r = await hit(d.db, `mail:${email.toLowerCase()}`, LIMITS.mail);
    if (!r.ok) return false;
    const token = newToken();
    const hours = kind === "reset" ? 1 : kind === "invite" ? 72 : 48;
    await d.db.query("INSERT INTO email_tokens (token_hash, user_id, kind, expires_at) VALUES ($1, $2, $3, now() + make_interval(hours => $4))",
      [tokenHash(token), userId, kind === "verify" ? "verify" : "reset", hours]);
    const link = `${d.config.dashboardUrl}/${kind === "verify" ? "verify" : "reset"}?token=${token}`;
    const text = kind === "verify"
      ? `Open this link to confirm your email address (it works for 48 hours):\n\n${link}\n`
      : kind === "invite"
        ? `An account was made for you on ${d.config.rootDomain}. Open this link within 3 days to choose your password:\n\n${link}\n`
        : `Someone asked to reset your password. If it was you, open this link within an hour:\n\n${link}\n\nIf not, ignore this email.`;
    const subject = kind === "verify" ? `Confirm your email for ${d.config.rootDomain}` : kind === "invite" ? `Your ${d.config.rootDomain} account` : `Reset your ${d.config.rootDomain} password`;
    return d.mail({ to: email, subject, text }).then(() => true, () => false);
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

  const authCard = (title: string, lead: Html | string, body: Html | string, links?: Html | string) =>
    html`<section class="card"><h1>${title}</h1>${lead ? html`<p class="lead">${lead}</p>` : ""}${body}${links ? html`<div class="auth-links">${links}</div>` : ""}</section>`;

  const signupForm = (req: FastifyRequest, reply: FastifyReply, email = "", flash: Flash = null, status = 200) =>
    render(req, reply, "Create account", authCard("Create your account", "Claim your station's address, then connect Nova to it.", html`
      <form method="post" action="/signup">${pre(req, reply)}
        ${field({ id: "email", label: "Email", control: html`<input id="email" type="email" name="email" value="${email}" required autocomplete="email" maxlength="254">` })}
        ${field({ id: "password", label: "Password", help: `${MIN_PASSWORD} characters or more.`, control: html`<input id="password" type="password" name="password" required minlength="${MIN_PASSWORD}" maxlength="${MAX_PASSWORD}" autocomplete="new-password">` })}
        <button class="primary">Create account</button></form>`, html`<span class="dim">Have an account?</span><a href="/login">Sign in</a>`), flash, status);

  app.get("/signup", async (req, reply) => signupForm(req, reply));
  app.post("/signup", async (req, reply) => {
    const f = form(req);
    const email = String(f.email ?? "").trim().toLowerCase();
    if (!(await hit(d.db, `signup:${req.ip}`, LIMITS.signup)).ok) return signupForm(req, reply, email, { kind: "bad", text: "Too many new accounts from here; try later." }, 429);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) return signupForm(req, reply, email, { kind: "bad", text: "That is not an email address." }, 400);
    const weak = passwordProblem(String(f.password ?? ""), email);
    if (weak) return signupForm(req, reply, email, { kind: "bad", text: weak }, 400);
    const hash = await hashSecret(String(f.password));
    // The very first account is the super admin; ADMIN_EMAILS (optional) become admins with every permission.
    const made = await transaction(d.db, async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(7466022)"); // two first sign-ups at once: one wins
      const first = !(await tx.query("SELECT 1 FROM users LIMIT 1")).rowCount;
      const role = first ? "superadmin" : d.config.adminEmails.includes(email) ? "admin" : "user";
      const r = await tx.query<{ id: number }>("INSERT INTO users (email, password_hash, role, permissions) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING id",
        [email, hash, role, role === "admin" ? ALL_PERMISSIONS : []]);
      return r.rows[0] ? { id: r.rows[0].id, role } : null;
    });
    if (!made) return signupForm(req, reply, email, { kind: "bad", text: "There is already an account with that email. Sign in, or reset the password." }, 409);
    const id = made.id;
    if (made.role === "superadmin") await audit(d.db, { actor: id, action: "user.superadmin", target: email, ip: req.ip, metadata: { first: true } });
    await audit(d.db, { actor: id, action: "user.signup", target: email, ip: req.ip });
    await mailLink(id, email, "verify");
    await startSession(d.db, reply, id, false, req.ip, secure, String(req.headers["user-agent"] ?? ""));
    return back(reply, made.role === "user" ? "/" : "/account", {
      kind: "ok",
      text: made.role === "superadmin" ? "Welcome. You are the super admin. Turn on two-step sign-in now: the admin console needs it." : `Welcome. We sent a link to ${email}: open it to confirm your address, then claim your station.`,
    });
  });

  const loginForm = (req: FastifyRequest, reply: FastifyReply, email = "", flash: Flash = null, status = 200) =>
    render(req, reply, "Sign in", authCard("Sign in", "Welcome back.", html`
      <form method="post" action="/login">${pre(req, reply)}<input type="hidden" name="next" value="${safeNext((req.query as Form).next ?? form(req).next)}">
        ${field({ id: "email", label: "Email", control: html`<input id="email" type="email" name="email" value="${email}" required autocomplete="username" maxlength="254">` })}
        ${field({ id: "password", label: "Password", control: html`<input id="password" type="password" name="password" required autocomplete="current-password" maxlength="${MAX_PASSWORD}">` })}
        <button class="primary">Sign in</button></form>`, html`<a href="/forgot">Forgot your password?</a><a href="/signup">Create an account</a>`), flash, status);

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
    const password = String(f.password ?? "").slice(0, MAX_PASSWORD);
    const ok = await verifySecret(u?.password_hash ?? (await dummyHash()), password);
    if (!u || !ok) return loginForm(req, reply, email, { kind: "bad", text: "Wrong email or password." }, 401);
    if (u.status !== "active") return loginForm(req, reply, email, { kind: "bad", text: "This account is suspended." }, 403);
    await forget(d.db, `login:email:${email}`);
    await endSession(d.db, reply, req.session, secure);
    await startSession(d.db, reply, u.id, !!u.totp_secret_enc, req.ip, secure, String(req.headers["user-agent"] ?? ""));
    if (!u.totp_secret_enc) await signedInNow(u.id, req.ip);
    const next = safeNext(f.next);
    return reply.redirect(u.totp_secret_enc ? `/login/totp${next !== "/" ? `?next=${encodeURIComponent(next)}` : ""}` : next);
  });

  async function signedInNow(id: number, ip: string) {
    await d.db.query("UPDATE users SET last_login_at = now(), last_login_ip = $2 WHERE id = $1", [id, ip]);
    await audit(d.db, { actor: id, action: "user.login", ip });
  }

  app.get("/login/totp", async (req, reply) => {
    if (!req.session?.needsTotp) return reply.redirect("/");
    return render(req, reply, "Two-step sign-in", authCard("Two-step sign-in", "Enter the 6-digit code from your authenticator app.", html`
      <form method="post" action="/login/totp">${csrfField(req.session.csrf)}<input type="hidden" name="next" value="${safeNext((req.query as Form).next)}">
        ${field({ id: "code", label: "Code", control: html`<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required pattern="[0-9 ]{6,7}" maxlength="7" autofocus>` })}
        <button class="primary">Verify</button></form>`, html`<span></span><form method="post" action="/logout">${csrfField(req.session.csrf)}<button class="ghost sm">Use another account</button></form>`));
  });
  app.post("/login/totp", async (req, reply) => {
    const s = req.session;
    if (!s?.needsTotp) return reply.redirect("/");
    if (!(await hit(d.db, `totp:${s.user.id}`, LIMITS.totp)).ok) return render(req, reply, "Two-step sign-in", authCard("Too many tries", "Wait 10 minutes, then try again.", ""), null, 429);
    const enc = (await d.db.query("SELECT totp_secret_enc FROM users WHERE id = $1", [s.user.id])).rows[0]?.totp_secret_enc;
    if (!enc || !verifyTotp(decrypt(d.config.sessionSecret, enc), form(req).code)) {
      return render(req, reply, "Two-step sign-in", authCard("That code is not right", "Codes change every 30 seconds; use the newest one.", html`<a class="btn primary" href="/login/totp">Try again</a>`), { kind: "bad", text: "Wrong code." }, 401);
    }
    await d.db.query("UPDATE sessions SET needs_totp = false, elevated_until = now() + make_interval(mins => $2) WHERE token_hash = $1", [s.tokenHash, SUDO_MINUTES]);
    await forget(d.db, `totp:${s.user.id}`);
    await signedInNow(s.user.id, req.ip);
    return reply.redirect(safeNext(form(req).next));
  });

  app.post("/logout", async (req, reply) => {
    await endSession(d.db, reply, req.session, secure);
    return reply.redirect("/login");
  });

  // ------------------------------------------------------------------ sudo mode

  app.get("/sudo", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const next = safeNext((req.query as Form).next);
    return render(req, reply, "Confirm it is you", html`${pageHead({ title: "Confirm it is you", sub: `This is a sensitive area. Confirm your identity to continue; you will not be asked again for ${SUDO_MINUTES} minutes.` })}
      <div style="max-width:480px">${panel({}, html`<form method="post" action="/sudo">${csrfField(s.csrf)}<input type="hidden" name="next" value="${next}">
        ${field({ id: "sudo-email", label: "Account", control: html`<input id="sudo-email" value="${s.user.email}" disabled>` })}
        ${field({ id: "password", label: "Password", control: html`<input id="password" type="password" name="password" required autocomplete="current-password" maxlength="${MAX_PASSWORD}" autofocus>` })}
        ${s.user.totp ? field({ id: "code", label: "Authenticator code", control: html`<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required pattern="[0-9 ]{6,7}" maxlength="7">` }) : ""}
        <div class="row"><button class="primary">${icon("lock", 16)} Confirm</button><a class="btn ghost" href="/">Cancel</a></div></form>`)}</div>`, takeFlash(req, reply));
  });
  app.post("/sudo", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const f = form(req);
    const next = safeNext(f.next);
    const again = (text: string) => back(reply, `/sudo?next=${encodeURIComponent(next)}`, { kind: "bad", text });
    if (!(await hit(d.db, `sudo:${s.user.id}`, LIMITS.login)).ok) return again("Too many tries; wait 10 minutes.");
    const u = (await d.db.query<{ password_hash: string; totp_secret_enc: string | null }>("SELECT password_hash, totp_secret_enc FROM users WHERE id = $1", [s.user.id])).rows[0];
    if (!u || !(await verifySecret(u.password_hash, String(f.password ?? "").slice(0, MAX_PASSWORD)))) {
      await audit(d.db, { actor: s.user.id, action: "user.sudo_failed", ip: req.ip });
      return again("That password is not right.");
    }
    if (u.totp_secret_enc && !verifyTotp(decrypt(d.config.sessionSecret, u.totp_secret_enc), f.code)) return again("That code is not right; use the newest one.");
    await elevate(d.db, s);
    await forget(d.db, `sudo:${s.user.id}`);
    await audit(d.db, { actor: s.user.id, action: "user.sudo", ip: req.ip });
    return reply.redirect(next);
  });

  // ------------------------------------------------------------------ email links

  app.get("/verify", async (req, reply) => {
    const id = await useToken(String((req.query as Form).token), "verify");
    if (!id) return render(req, reply, "Link expired", authCard("This link has expired", "It was used already, or is too old. Sign in and ask for a new one.", html`<a class="btn primary" href="/login">Sign in</a>`), null, 400);
    await d.db.query("UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [id]);
    return back(reply, req.session ? "/" : "/login", { kind: "ok", text: "Your email address is confirmed." });
  });
  app.post("/verify/resend", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    if (!s.user.verified) await mailLink(s.user.id, s.user.email, "verify");
    return back(reply, "/", { kind: "ok", text: `A new link is on its way to ${s.user.email}.` });
  });

  app.get("/forgot", async (req, reply) => render(req, reply, "Reset password", authCard("Reset your password", "We will email you a link to choose a new one.", html`
    <form method="post" action="/forgot">${pre(req, reply)}${field({ id: "email", label: "Email", control: html`<input id="email" type="email" name="email" required autocomplete="email">` })}
    <button class="primary">Send reset link</button></form>`, html`<a href="/login">Back to sign in</a><span></span>`)));
  app.post("/forgot", async (req, reply) => {
    const email = String(form(req).email ?? "").trim().toLowerCase();
    const u = (await d.db.query<{ id: number }>("SELECT id FROM users WHERE lower(email) = $1 AND status = 'active'", [email])).rows[0];
    if (u) await mailLink(u.id, email, "reset");
    // The same answer either way: no telling which emails have accounts.
    return render(req, reply, "Reset password", authCard("Check your email", html`If ${email} has an account, a reset link is on its way. It works for an hour.`, html`<a class="btn primary" href="/login">Back to sign in</a>`));
  });
  app.get("/reset", async (req, reply) => render(req, reply, "New password", authCard("Choose a new password", "You will be signed out everywhere else.", html`
    <form method="post" action="/reset">${pre(req, reply)}<input type="hidden" name="token" value="${(req.query as Form).token ?? ""}">
    ${field({ id: "password", label: "New password", help: `${MIN_PASSWORD} characters or more.`, control: html`<input id="password" type="password" name="password" required minlength="${MIN_PASSWORD}" maxlength="${MAX_PASSWORD}" autocomplete="new-password">` })}
    <button class="primary">Save password</button></form>`)));
  app.post("/reset", async (req, reply) => {
    const f = form(req);
    const password = String(f.password ?? "");
    if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) return render(req, reply, "New password", authCard("Choose another password", `Use ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`, html`<a class="btn primary" href="/reset?token=${f.token ?? ""}">Back</a>`), null, 400);
    const id = await useToken(f.token, "reset");
    if (!id) return render(req, reply, "Link expired", authCard("This link has expired", "It was used already, or is too old.", html`<a class="btn primary" href="/forgot">Ask for a new one</a>`), null, 400);
    const email = (await d.db.query<{ email: string }>("SELECT email FROM users WHERE id = $1", [id])).rows[0].email;
    const weak = passwordProblem(password, email);
    if (weak) return render(req, reply, "New password", authCard("Choose another password", weak, html`<a class="btn primary" href="/forgot">Ask for a new link</a>`), null, 400);
    await d.db.query("UPDATE users SET password_hash = $2, email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1", [id, await hashSecret(password)]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1", [id]); // sign out everywhere
    await audit(d.db, { actor: id, action: "user.password_reset", ip: req.ip });
    void notify(email, "Your password was changed", `The password of your ${d.config.rootDomain} account was changed with a reset link, from ${req.ip}.`);
    return back(reply, "/login", { kind: "ok", text: "Password changed. Sign in with the new one." });
  });

  // ------------------------------------------------------------------ account and security

  app.get("/account", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const me = (await d.db.query<{ created_at: Date; last_login_at: Date | null; last_login_ip: string | null }>("SELECT created_at, last_login_at, last_login_ip FROM users WHERE id = $1", [s.user.id])).rows[0];
    const sessions = (await d.db.query<{ id: number; ip: string | null; user_agent: string | null; created_at: Date; last_seen_at: Date; current: boolean }>(
      "SELECT id, ip, user_agent, created_at, last_seen_at, token_hash = $2 AS current FROM sessions WHERE user_id = $1 AND expires_at > now() AND NOT needs_totp ORDER BY current DESC, last_seen_at DESC",
      [s.user.id, s.tokenHash])).rows;
    let totp: Html;
    if (s.user.totp) {
      totp = html`<div class="switch-row"><div>${badge("ok", "On")} <span class="dim">Signing in asks for a code from your authenticator app.</span></div></div>
        <form method="post" action="/account/totp/disable" style="margin-top:16px">${csrfField(s.csrf)}
          ${field({ id: "off", label: "Current code, to turn it off", help: isStaff(s.user) ? "Admins need two-step sign-in: without it the admin console is closed to you." : "", control: html`<input id="off" class="w-sm" name="code" inputmode="numeric" required maxlength="7">` })}
          <div class="row"><button class="danger">Turn off two-step sign-in</button></div></form>`;
    } else if (s.pendingTotpEnc) {
      const secret = decrypt(d.config.sessionSecret, s.pendingTotpEnc);
      const qr = await QRCode.toDataURL(totpUri(secret, s.user.email, d.config.rootDomain), { margin: 1, width: 200 });
      totp = html`<ol style="padding-left:18px;margin:0 0 16px"><li>Scan this QR code with an authenticator app (1Password, Google Authenticator, Authy…), or type the key.</li><li>Enter the 6-digit code it shows.</li></ol>
        <div class="row tight" style="align-items:flex-start;gap:24px"><img src="${qr}" alt="QR code for the authenticator app" width="168" height="168" style="border-radius:8px;border:1px solid var(--line);background:#fff">
        <div style="flex:1;min-width:220px"><p class="dim small">Key: <code>${secret}</code></p>
        <form method="post" action="/account/totp/confirm">${csrfField(s.csrf)}${field({ id: "code", label: "Code", control: html`<input id="code" class="w-sm" name="code" inputmode="numeric" required maxlength="7" autocomplete="one-time-code">` })}
        <div class="row"><button class="primary">Turn on</button></div></form></div></div>`;
    } else {
      totp = html`<div class="switch-row"><div>${badge("neutral", "Off")} <span class="dim">Add a code from an authenticator app to your password.</span></div>
        <form method="post" action="/account/totp/start">${csrfField(s.csrf)}<button class="primary">Set up two-step sign-in</button></form></div>`;
    }
    return render(req, reply, "Account & security", html`${pageHead({ title: "Account & security", sub: "Your sign-in, two-step sign-in and the devices signed in to this account." })}
      ${isStaff(s.user) && !s.user.totp ? html`<div class="callout warn">${icon("alert")}<div><b>Two-step sign-in is required for admins</b><p>Set it up below. Until then the admin console stays closed.</p></div></div>` : ""}
      ${panel({ title: "Profile" }, facts([
        ["Email", html`${s.user.email} ${s.user.verified ? badge("ok", "Confirmed") : html`${badge("warn", "Not confirmed")} <form class="inline" method="post" action="/verify/resend">${csrfField(s.csrf)}<button class="sm">Resend link</button></form>`}`],
        ["Role", s.user.role === "superadmin" ? "Super admin" : s.user.role === "admin" ? "Admin" : "Station owner"],
        ["Member since", day(me.created_at)],
        ["Last sign-in", me.last_login_at ? `${when(me.last_login_at)}${me.last_login_ip ? ` from ${me.last_login_ip}` : ""}` : "—"],
      ]))}
      ${panel({ title: "Two-step sign-in", sub: "A second step at sign-in and before sensitive changes." }, totp)}
      ${panel({ title: "Password", sub: "Changing it signs out every other device." }, html`<form method="post" action="/account/password">${csrfField(s.csrf)}<div class="form-grid">
        ${field({ id: "cur", label: "Current password", control: html`<input id="cur" type="password" name="current" required autocomplete="current-password" maxlength="${MAX_PASSWORD}">` })}
        ${field({ id: "new", label: "New password", help: `${MIN_PASSWORD} characters or more.`, control: html`<input id="new" type="password" name="password" required minlength="${MIN_PASSWORD}" maxlength="${MAX_PASSWORD}" autocomplete="new-password">` })}</div>
        <div class="row"><button class="primary">Change password</button></div></form>`)}
      ${panel({ title: "Signed-in devices", sub: "End any you do not recognise.", flush: true, actions: sessions.length > 1 ? html`<form method="post" action="/account/sessions/others">${csrfField(s.csrf)}<button class="sm danger">Sign out all others</button></form>` : "" },
        html`<div class="table-wrap"><table><tr><th>Device</th><th>IP address</th><th>Signed in</th><th>Last active</th><th class="actions"></th></tr>${sessions.map((x) => html`<tr>
          <td><b>${deviceOf(x.user_agent)}</b>${x.current ? html` ${badge("accent", "This device")}` : ""}</td><td>${x.ip ?? "—"}</td><td>${when(x.created_at)}</td><td>${when(x.last_seen_at)}</td>
          <td class="actions">${x.current ? "" : html`<form method="post" action="/account/sessions/${x.id}/end">${csrfField(s.csrf)}<button class="sm">Sign out</button></form>`}</td></tr>`)}</table></div>`)}`, takeFlash(req, reply));
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
    void notify(s.user.email, "Two-step sign-in is on", "Two-step sign-in was turned on for your account.");
    return back(reply, "/account", { kind: "ok", text: "Two-step sign-in is on." });
  });
  app.post("/account/totp/disable", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    if (!(await hit(d.db, `totp:${s.user.id}`, LIMITS.totp)).ok) return back(reply, "/account", { kind: "bad", text: "Too many tries; wait 10 minutes." });
    const enc = (await d.db.query("SELECT totp_secret_enc FROM users WHERE id = $1", [s.user.id])).rows[0]?.totp_secret_enc;
    if (!enc || !verifyTotp(decrypt(d.config.sessionSecret, enc), form(req).code)) return back(reply, "/account", { kind: "bad", text: "That code is not right." });
    await d.db.query("UPDATE users SET totp_secret_enc = NULL WHERE id = $1", [s.user.id]);
    await audit(d.db, { actor: s.user.id, action: "user.totp_off", ip: req.ip });
    void notify(s.user.email, "Two-step sign-in was turned off", `Two-step sign-in was turned off for your account, from ${req.ip}.`);
    return back(reply, "/account", { kind: "ok", text: "Two-step sign-in is off." });
  });
  app.post("/account/password", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const f = form(req);
    if (!(await hit(d.db, `sudo:${s.user.id}`, LIMITS.login)).ok) return back(reply, "/account", { kind: "bad", text: "Too many tries; wait 10 minutes." });
    const hash = (await d.db.query("SELECT password_hash FROM users WHERE id = $1", [s.user.id])).rows[0].password_hash;
    if (!(await verifySecret(hash, String(f.current ?? "").slice(0, MAX_PASSWORD)))) return back(reply, "/account", { kind: "bad", text: "The current password is wrong." });
    const weak = passwordProblem(String(f.password ?? ""), s.user.email);
    if (weak) return back(reply, "/account", { kind: "bad", text: weak });
    await d.db.query("UPDATE users SET password_hash = $2 WHERE id = $1", [s.user.id, await hashSecret(f.password)]);
    await d.db.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [s.user.id, s.tokenHash]);
    await audit(d.db, { actor: s.user.id, action: "user.password_change", ip: req.ip });
    void notify(s.user.email, "Your password was changed", `The password of your ${d.config.rootDomain} account was changed from ${req.ip}. Other devices were signed out.`);
    return back(reply, "/account", { kind: "ok", text: "Password changed; other devices were signed out." });
  });
  app.post("/account/sessions/:id/end", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const id = Number((req.params as { id: string }).id);
    const r = await d.db.query("DELETE FROM sessions WHERE id = $1 AND user_id = $2 AND token_hash <> $3", [Number.isSafeInteger(id) ? id : -1, s.user.id, s.tokenHash]);
    if (r.rowCount) await audit(d.db, { actor: s.user.id, action: "user.session_end", ip: req.ip });
    return back(reply, "/account", { kind: "ok", text: r.rowCount ? "That device is signed out." : "That device was already signed out." });
  });
  app.post("/account/sessions/others", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const r = await d.db.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [s.user.id, s.tokenHash]);
    await audit(d.db, { actor: s.user.id, action: "user.sessions_end", ip: req.ip, metadata: { count: r.rowCount } });
    return back(reply, "/account", { kind: "ok", text: `Signed out ${r.rowCount} other device${r.rowCount === 1 ? "" : "s"}.` });
  });

  // ------------------------------------------------------------------ names

  app.get("/names/check", async (req, reply) => {
    const r = await hit(d.db, `names:${req.ip}`, LIMITS.nameCheck);
    if (!r.ok) return reply.status(429).header("Retry-After", String(r.retryAfter)).send({ state: "limited", message: "Too many checks." });
    const label = normaliseLabel(String((req.query as Form).label ?? ""), d.config.rootDomain);
    const c = await checkName(d.db, label);
    return { ...c, fqdn: fqdnOf(label, d.config.rootDomain) };
  });

  // ------------------------------------------------------------------ stations

  const codeOnce = (req: FastifyRequest, reply: FastifyReply, label: string, code: string, title: string) =>
    render(req, reply, title, html`${pageHead({ title, sub: html`The access code for <b>${fqdnOf(label, d.config.rootDomain)}</b>.` })}
      <div style="max-width:720px">${panel({}, html`
        <div class="callout warn">${icon("key")}<div><b>Store it now: it is shown only this once.</b><p>We keep only a scrambled copy. If it is lost, make a new one (the old one then stops working).</p></div></div>
        <div class="copyline"><span class="code">${code}</span><button type="button" data-copy="${code}">${icon("copy", 16)} Copy</button></div>
        <h3 style="margin:24px 0 8px;font-size:14px">Connect Nova</h3>
        <ol style="margin:0;padding-left:20px;color:var(--ink-2)"><li>In Nova, open <b>Settings → Remote Connections</b>.</li><li>Hostname: <code>${label}</code></li><li>Access code: the code above, then <b>Start Server</b>.</li></ol>`,
        html`<a class="btn primary" href="/">I have stored it</a>`)}</div>`);

  app.get("/", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const rows = (await d.db.query(
      `SELECT s.id, s.label, s.status, st.last_seen_at, st.app_version, st.last_ip FROM subdomains s JOIN studios st ON st.subdomain_id = s.id
        WHERE s.user_id = $1 ORDER BY s.label`, [s.user.id])).rows;
    const a = await allowance(d.db, s.user.id, d.config.subdomainLimit);
    const room = rows.length < a.limit;
    const billing = await billingOn(d.db);
    const limitText = `${a.custom ? "Your account allows" : a.plan ? `Your ${a.plan} plan allows` : "Your plan allows"} ${stationWord(a.limit)}.`;
    const claim = room && s.user.verified ? html`<a class="btn primary" href="/stations/new">${icon("plus", 16)} Claim a station address</a>` : "";
    return render(req, reply, "Stations", html`${pageHead({ title: "Stations", sub: html`${limitText} ${rows.length} in use.${a.expiresAt ? ` Paid until ${day(a.expiresAt)}.` : ""}`, actions: html`${claim}${!room && billing ? html`<a class="btn" href="/billing">Upgrade plan</a>` : ""}` })}
      ${!s.user.verified ? html`<div class="callout warn">${icon("alert")}<div><b>Confirm your email to claim a station</b><p>We sent a link to ${s.user.email}.</p></div><form method="post" action="/verify/resend" style="margin-left:auto">${csrfField(s.csrf)}<button class="sm">Send the link again</button></form></div>` : ""}
      ${a.lapsed ? html`<div class="callout info">${icon("info")}<div><b>Your ${a.lapsed} plan has ended</b><p>You are on the default plan again. ${billing ? html`<a href="/billing">Renew it</a> to get its limit back.` : ""}</p></div></div>` : ""}
      ${rows.length ? panel({ flush: true }, html`<div class="table-wrap"><table><tr><th>Address</th><th>Status</th><th class="wide-only">Last seen</th><th class="wide-only">Nova</th><th class="actions"></th></tr>${rows.map((r) => html`<tr>
          <td><a href="/stations/${r.id}"><b>${fqdnOf(r.label, d.config.rootDomain)}</b></a></td>
          <td>${statusChip(r.status, r.last_seen_at)}</td><td class="wide-only">${when(r.last_seen_at)}</td><td class="wide-only">${r.app_version ?? "—"}</td><td class="actions"><a class="btn sm" href="/stations/${r.id}">Manage</a></td></tr>`)}</table></div>`)
        : panel({}, emptyState("No station yet", html`Claim an address like <b>kfm.${d.config.rootDomain}</b>, then enter its access code in Nova.`, claim))}`, takeFlash(req, reply));
  });

  app.get("/stations/new", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    return render(req, reply, "Claim an address", html`${pageHead({ title: "Claim a station address", back: { href: "/", text: "Stations" }, sub: "Presenters use this address to reach your studio." })}
      <div style="max-width:640px">${panel({}, html`<form method="post" action="/stations">${csrfField(s.csrf)}
        ${field({ id: "label", label: "Name", help: "3–63 lowercase letters, digits and hyphens; not starting or ending with a hyphen.",
          control: html`<div class="input-group"><input id="label" name="label" required autocomplete="off" spellcheck="false" placeholder="kfm" maxlength="63"><span class="addon">.${d.config.rootDomain}</span></div><div id="name-state" aria-live="polite"></div>` })}
        <div class="row"><button class="primary">Claim address</button><a class="btn ghost" href="/">Cancel</a></div></form>`)}</div>`, takeFlash(req, reply));
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

  /** The station, if `s` owns it or may see (GET) or change (POST) every station. */
  async function ownStation(req: FastifyRequest, reply: FastifyReply, s: Session) {
    const id = Number((req.params as { id: string }).id);
    const row = Number.isSafeInteger(id) ? (await d.db.query(
      `SELECT s.id, s.label, s.status, s.user_id, s.created_at, st.id AS studio_id, st.last_ip, st.last_port, st.via, st.last_seen_at, st.app_version, u.email AS owner
         FROM subdomains s JOIN studios st ON st.subdomain_id = s.id JOIN users u ON u.id = s.user_id WHERE s.id = $1`, [id])).rows[0] : undefined;
    const staff = can(s.user, req.method === "GET" ? "stations.view" : "stations.manage");
    if (!row || (row.user_id !== s.user.id && !staff)) {
      void render(req, reply, "Not found", html`${pageHead({ title: "No such station", back: { href: "/", text: "Stations" } })}`, null, 404);
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
    const fqdn = fqdnOf(st.label, d.config.rootDomain);
    // Through the edge, presenters use a port the edge serves, not the station's own.
    const port = presenterPort(d.config, st.via, st.last_port);
    const url = `https://${fqdn}${port !== 443 ? `:${port}` : ""}`;
    const mine = st.user_id === s.user.id;
    const manage = can(s.user, "stations.manage");
    const fromAdmin = !mine && can(s.user, "stations.view");
    const blocked = st.status === "suspended" && !manage;
    const certText = !cert ? html`<span class="dim">None yet. Nova asks for one when it starts its server.</span>` : cert.status === "issued" ? html`${badge("ok", "Issued")} <span class="dim">until ${day(cert.expires_at)}</span>` : cert.status === "pending" ? badge("info", "Being issued") : html`${badge("bad", "Failed")} <span class="dim">${cert.error ?? ""}</span>`;
    return render(req, reply, st.label, html`${pageHead({ title: fqdn, back: fromAdmin ? { href: "/admin/stations", text: "All stations" } : { href: "/", text: "Stations" },
        meta: html`${statusChip(st.status, st.last_seen_at)}${fromAdmin ? html`<span>Owner: ${can(s.user, "users.view") ? html`<a href="/admin/users/${st.user_id}">${st.owner}</a>` : st.owner}</span>` : ""}` })}
      ${st.status === "suspended" ? html`<div class="callout bad">${icon("alert")}<div><b>This station is suspended by the platform</b><p>${manage ? "Its address does not resolve and Nova's requests are refused." : "Contact support to restore it."}</p></div></div>` : ""}
      <div class="split"><div>
      ${panel({ title: "Overview" }, facts([
        ["Address for presenters", html`<div class="copyline"><code>${url}</code><button type="button" class="sm" data-copy="${url}">${icon("copy", 14)} Copy</button></div>`],
        ["Reached", st.via === "tunnel" && d.config.edgeIp ? "Through the edge (no open port at the station)" : "Directly"],
        ["Last address", st.last_ip ? `${st.last_ip}${st.last_port ? ` port ${st.last_port}` : ""}` : "—"],
        ["Last seen", when(st.last_seen_at)],
        ["Nova version", st.app_version ?? "—"],
        ["Certificate", certText],
        ["Audio relay this month", `${bytes(Number(usage.b))} in ${usage.n} session${usage.n === 1 ? "" : "s"}`],
        ["Created", day(st.created_at)],
      ]))}
      ${blocked ? "" : html`
      ${panel({ title: "Rename", sub: "The old name is held for 30 days. Nova picks up the new name within 5 minutes and gets a new certificate." }, html`
        <form method="post" action="/stations/${st.id}/rename" data-confirm="Rename ${st.label}? Presenters will need the new address.">${csrfField(s.csrf)}
          ${field({ id: "label", label: "New name", control: html`<div class="input-group"><input id="label" name="label" required autocomplete="off" maxlength="63" spellcheck="false"><span class="addon">.${d.config.rootDomain}</span></div><div id="name-state" aria-live="polite"></div>` })}
          <div class="row"><button>Rename station</button></div></form>`)}
      ${panel({ title: "Access code", sub: "Make a new code if the old one may have leaked. The old code, and every Nova signed in with it, stop working at once." },
        html`<form method="post" action="/stations/${st.id}/regenerate" data-confirm="Make a new access code? Nova will need it entered again.">${csrfField(s.csrf)}<button>${icon("key", 16)} Make a new access code</button></form>`)}`}
      ${panel({ title: "Delete station", tone: "danger", sub: "Removes the address, its certificate and every sign-in. The name is held for 30 days." }, html`
        <form method="post" action="/stations/${st.id}/delete">${csrfField(s.csrf)}${field({ id: "confirm", label: `Type ${st.label} to confirm`, control: html`<input id="confirm" class="w-md" name="confirm" required autocomplete="off">` })}
        <div class="row"><button class="danger-solid">Delete this station</button></div></form>`)}
      </div><div>
      ${manage ? panel({ title: "Administration", sub: "Visible to admins only." }, html`
        <form method="post" action="/admin/stations/${st.id}/${st.status === "active" ? "suspend" : "unsuspend"}" data-confirm="${st.status === "active" ? "Suspend" : "Restore"} ${st.label}?">${csrfField(s.csrf)}<input type="hidden" name="back" value="/stations/${st.id}">
          <button class="${st.status === "active" ? "danger" : "primary"}" style="width:100%">${st.status === "active" ? "Suspend station" : "Restore station"}</button></form>
        <form method="post" action="/stations/${st.id}/transfer" data-confirm="Give ${st.label} to someone else? Its access code is replaced and Nova is signed out." style="margin-top:20px">${csrfField(s.csrf)}
          ${field({ id: "to", label: "Move to another owner", help: "A new access code is made for the new owner (shown once) and the old one stops working.", control: html`<input id="to" name="email" type="email" required autocomplete="off" placeholder="owner@example.com">` })}
          <div class="row"><button>Move station</button></div></form>`) : ""}
      </div></div>`, takeFlash(req, reply));
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
  const actor = (s: Session, req: FastifyRequest): subs.Actor => ({ id: s.user.id, ip: req.ip, admin: can(s.user, "stations.manage") });

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
  action("transfer", async (s, id, f, req, reply) => {
    const r = await subs.transfer(ctx(), actor(s, req), id, String(f.email ?? ""));
    return codeOnce(req, reply, r.label, r.accessCode, `${fqdnOf(r.label, d.config.rootDomain)} now belongs to ${r.to}`);
  });

  // ------------------------------------------------------------------ billing (station owners)

  const billingClosed = (req: FastifyRequest, reply: FastifyReply) =>
    render(req, reply, "Billing", html`${pageHead({ title: "Billing" })}${panel({}, emptyState("Billing is not available", "Plans are assigned by the platform's administrators."))}`, null, 404);

  app.get("/billing", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const b = await billingState(d.db, d.config.sessionSecret);
    if (!b.ready || !b.provider) return billingClosed(req, reply);
    const a = await allowance(d.db, s.user.id, d.config.subdomainLimit);
    const me = (await d.db.query<{ plan_id: number | null; plan_expires_at: Date | null }>("SELECT plan_id, plan_expires_at FROM users WHERE id = $1", [s.user.id])).rows[0];
    const used = Number((await d.db.query("SELECT count(*) AS n FROM subdomains WHERE user_id = $1", [s.user.id])).rows[0].n);
    const plans = await plansForSale(d.db);
    const history = (await d.db.query("SELECT reference, plan_name, amount_minor, currency, status, created_at, paid_at, period_end FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50", [s.user.id])).rows;
    const cancelled = (req.query as Form).cancelled;
    const active = (id: number) => me.plan_id === id && (!me.plan_expires_at || me.plan_expires_at > new Date());
    return render(req, reply, "Billing", html`${pageHead({ title: "Billing", sub: html`Payments are handled securely by ${PROVIDER_INFO[b.provider].name}. Card details never reach this platform.` })}
      ${cancelled ? html`<div class="callout info">${icon("info")}<div><b>Checkout was cancelled</b><p>Nothing was charged. Choose a plan whenever you are ready.</p></div></div>` : ""}
      ${!b.providers[b.provider].live ? html`<div class="callout warn">${icon("alert")}<div><b>Test mode</b><p>Payments use the provider's test environment: no real money moves.</p></div></div>` : ""}
      <div class="stats">
        <div class="stat"><span>Current plan</span><b>${a.custom ? "Custom" : a.plan || "Default"}</b><small>${stationWord(a.limit)}</small></div>
        <div class="stat"><span>Stations in use</span><b>${used} <span>of ${a.limit}</span></b></div>
        <div class="stat"><span>${a.expiresAt ? "Paid until" : "Renewal"}</span><b>${a.expiresAt ? day(a.expiresAt) : "—"}</b><small>${a.expiresAt ? "Renew any time; time left is kept." : "No end date"}</small></div>
      </div>
      ${a.custom ? html`<div class="callout info">${icon("info")}<div><b>Your limit was set by an administrator</b><p>Buying a plan does not change it while that limit is in place.</p></div></div>` : ""}
      ${panel({ title: "Plans", sub: "Each payment covers one period. Renewing early adds to the time you have left." }, plans.length ? html`<div class="plans">${plans.map((p) => html`
        <div class="plan${active(p.id) ? " current" : ""}"><div class="row tight" style="justify-content:space-between"><h3>${p.name}</h3>${active(p.id) ? badge("accent", "Current") : ""}</div>
          ${p.description ? html`<p class="dim small">${p.description}</p>` : ""}
          <div class="price">${formatMoney(Number(p.price_minor), p.currency)} <small>/ ${p.period}</small></div>
          <ul><li>${icon("check", 15)} ${stationWord(p.station_limit)}</li><li>${icon("shield", 15)} Certificates and DNS included</li></ul>
          ${s.user.verified ? html`<form method="post" action="/billing/checkout">${csrfField(s.csrf)}<input type="hidden" name="plan" value="${p.id}"><button class="${active(p.id) ? "" : "primary"}">${active(p.id) ? "Renew" : "Choose"} ${p.name}</button></form>` : html`<p class="dim small">Confirm your email to buy a plan.</p>`}
        </div>`)}</div>` : emptyState("No plans for sale", "Check back later."))}
      ${panel({ title: "Payment history", flush: true }, history.length ? html`<div class="table-wrap"><table><tr><th>Date</th><th>Plan</th><th class="num">Amount</th><th>Status</th><th>Covers until</th><th>Reference</th></tr>${history.map((h) => html`<tr>
        <td>${when(h.created_at)}</td><td>${h.plan_name}</td><td class="num">${formatMoney(Number(h.amount_minor), h.currency)}</td><td>${paymentBadge(h.status)}</td><td>${day(h.period_end)}</td><td><code>${h.reference}</code></td></tr>`)}</table></div>`
        : html`<div class="card-body"><p class="dim" style="margin:0">No payments yet.</p></div>`)}`, takeFlash(req, reply));
  });

  app.post("/billing/checkout", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    if (!s.user.verified) return back(reply, "/billing", { kind: "bad", text: "Confirm your email first." });
    if (!(await hit(d.db, `checkout:${s.user.id}`, { max: 10, seconds: 3600 })).ok) return back(reply, "/billing", { kind: "bad", text: "Too many checkouts started; try again later." });
    try {
      const { url } = await startCheckout(billingDeps(), { id: s.user.id, email: s.user.email, ip: req.ip }, Number(form(req).plan));
      const where = new URL(url).hostname;
      return render(req, reply, "Secure checkout", html`<div style="max-width:520px;margin:40px auto">${panel({}, html`<div class="empty"><div class="empty-ic">${icon("lock", 22)}</div>
        <h3>Taking you to secure checkout</h3><p>You will pay on <b>${where}</b>, then come back here.</p>
        <a class="btn primary" href="${url}" data-autoredirect rel="noreferrer">Continue to checkout ${icon("ext", 15)}</a></div>`)}</div>`);
    } catch (e) {
      if (e instanceof BillingError) return back(reply, "/billing", { kind: "bad", text: e.message });
      throw e;
    }
  });

  app.get("/billing/return", async (req, reply) => {
    const s = signedIn(req, reply);
    if (!s) return reply;
    const ref = String((req.query as Form).ref ?? "");
    const mine = (await d.db.query("SELECT 1 FROM payments WHERE reference = $1 AND user_id = $2", [ref, s.user.id])).rowCount;
    if (!mine) return back(reply, "/billing", { kind: "bad", text: "No such payment." });
    let p = null;
    try {
      p = await confirm(billingDeps(), ref);
    } catch {
      // The provider could not be asked just now; the worker asks again shortly.
    }
    const status = p?.status ?? "pending";
    const body = status === "paid"
      ? html`<div class="empty"><div class="empty-ic" style="background:var(--ok-soft);color:var(--ok)">${icon("check", 22)}</div><h3>Payment received</h3>
          <p>Your <b>${p!.plan_name}</b> plan is active${p!.period_end ? ` until ${day(p!.period_end)}` : ""}.</p><a class="btn primary" href="/">Go to your stations</a></div>`
      : status === "pending"
        ? html`<div class="empty"><div class="empty-ic">${icon("activity", 22)}</div><h3>Confirming your payment</h3><p>This usually takes a few seconds. Your plan starts as soon as the provider confirms it.</p><a class="btn" href="/billing/return?ref=${ref}">Check again</a></div>`
        : html`<div class="empty"><div class="empty-ic" style="background:var(--bad-soft);color:var(--bad)">${icon("alert", 22)}</div><h3>The payment did not go through</h3><p>Nothing was charged for this attempt.</p><a class="btn primary" href="/billing">Back to billing</a></div>`;
    return render(req, reply, "Payment", html`<div style="max-width:560px;margin:40px auto">${panel({}, body)}</div>`);
  });

  const helpers: Helpers = { render, form, back, takeFlash, signedIn, actor, ctx, mailLink, codeOnce, live, requireSudo, notify, billingDeps };
  adminRoutes(app, d, helpers);
  peopleRoutes(app, d, helpers);
  settingsRoutes(app, d, helpers);
  billingAdminRoutes(app, d, helpers);

  app.setNotFoundHandler((req, reply) => render(req, reply, "Not found", req.session && !req.session.needsTotp
    ? html`${pageHead({ title: "Page not found" })}${panel({}, html`<p class="dim">There is nothing at this address.</p><a class="btn" href="/">Go home</a>`)}`
    : authCard("Page not found", "There is nothing at this address.", html`<a class="btn primary" href="/">Go home</a>`), null, 404));
  app.setErrorHandler((err, req, reply) => {
    console.error("dashboard error:", err);
    return render(req, reply, "Error", panel({}, html`<h1>Something went wrong</h1><p class="dim">Try again in a moment.</p>`), null, 500);
  });
  return app;
}

export function statusChip(status: string, lastSeen: Date | null): Html {
  if (status === "suspended") return badge("bad", "Suspended");
  const online = lastSeen && Date.now() - new Date(lastSeen).getTime() < OFFLINE_MINUTES * 60_000;
  return online ? badge("ok", "Online") : badge("neutral", "Offline");
}

export function paymentBadge(status: string): Html {
  return status === "paid" ? badge("ok", "Paid") : status === "pending" ? badge("info", "Pending") : status === "failed" ? badge("bad", "Failed") : badge("neutral", "Abandoned");
}

export type Helpers = {
  render: (req: FastifyRequest, reply: FastifyReply, title: string, body: Html, flash?: Flash, status?: number) => Promise<FastifyReply>;
  form: (req: FastifyRequest) => Form;
  back: (reply: FastifyReply, to: string, flash: Flash) => FastifyReply;
  takeFlash: (req: FastifyRequest, reply: FastifyReply) => Flash;
  signedIn: (req: FastifyRequest, reply: FastifyReply) => Session | null;
  actor: (s: Session, req: FastifyRequest) => subs.Actor;
  ctx: () => subs.Ctx;
  mailLink: (userId: number, email: string, kind: "verify" | "reset" | "invite") => Promise<boolean>;
  /** A page showing a station's access code, once. */
  codeOnce: (req: FastifyRequest, reply: FastifyReply, label: string, code: string, title: string) => Promise<FastifyReply>;
  live: LiveConfig;
  /** Sudo mode: true if identity was confirmed recently; otherwise redirects to confirm it. */
  requireSudo: (req: FastifyRequest, reply: FastifyReply, s: Session, next: string) => boolean;
  /** A security notice to an account's own address. */
  notify: (to: string, subject: string, text: string) => Promise<unknown>;
  billingDeps: () => { db: Db; config: Config; mail: Mailer; fetch?: typeof fetch };
};
