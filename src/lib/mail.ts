/**
 * Email: verification links, password resets, the admins' daily alert. Sent through the
 * SMTP server in the settings (host, port, security, username, password); without a host
 * (development) each message is printed instead. Never logs a password or an access code
 * (none is ever mailed).
 */

import nodemailer from "nodemailer";

export interface Mail {
  to: string;
  subject: string;
  text: string;
}

export type Mailer = (m: Mail) => Promise<void>;

/** ssl: TLS from the first byte (465). starttls: plain, then upgraded, required (587). none: no TLS (25; not recommended). */
export type SmtpSecurity = "ssl" | "starttls" | "none";
export const SMTP_SECURITIES: SmtpSecurity[] = ["ssl", "starttls", "none"];
export const isSmtpSecurity = (v: unknown): v is SmtpSecurity => SMTP_SECURITIES.includes(v as SmtpSecurity);
export const DEFAULT_PORT: Record<SmtpSecurity, number> = { ssl: 465, starttls: 587, none: 25 };

export interface Smtp {
  host: string;
  /** 0: the security's usual port. */
  port: number;
  security: SmtpSecurity;
  user: string;
  password: string;
}

export const smtpPort = (s: Pick<Smtp, "port" | "security">) => s.port || DEFAULT_PORT[s.security];

/** Well-known providers: what the settings page fills in when one is picked. */
export const SMTP_PRESETS: { id: string; name: string; host: string; security: SmtpSecurity; port: number; user?: string; note: string }[] = [
  { id: "gmail", name: "Gmail / Google Workspace", host: "smtp.gmail.com", security: "ssl", port: 465, note: "Use an app password (Google Account > Security > App passwords), not your normal password." },
  { id: "m365", name: "Microsoft 365 / Outlook", host: "smtp.office365.com", security: "starttls", port: 587, note: "SMTP AUTH must be allowed for the mailbox in the Microsoft 365 admin centre." },
  { id: "ses", name: "Amazon SES", host: "email-smtp.us-east-1.amazonaws.com", security: "starttls", port: 587, note: "Change the region in the host to yours. Use SMTP credentials from the SES console, not your AWS keys." },
  { id: "mailgun", name: "Mailgun", host: "smtp.mailgun.org", security: "starttls", port: 587, note: "The username is the SMTP login of your domain (postmaster@…)." },
  { id: "postmark", name: "Postmark", host: "smtp.postmarkapp.com", security: "starttls", port: 587, note: "The username and password are both your Server API token." },
  { id: "sendgrid", name: "SendGrid", host: "smtp.sendgrid.net", security: "starttls", port: 587, user: "apikey", note: "The username is the word apikey; the password is an API key." },
  { id: "brevo", name: "Brevo (Sendinblue)", host: "smtp-relay.brevo.com", security: "starttls", port: 587, note: "Use the SMTP key from Brevo's SMTP & API page." },
  { id: "zoho", name: "Zoho Mail", host: "smtp.zoho.com", security: "ssl", port: 465, note: "Use an application-specific password if two-factor sign-in is on." },
];

/**
 * An SMTP_URL (smtp:// or smtps://user:password@host:port), the older single-value form,
 * split into its parts. Null when it is not one.
 */
export function parseSmtpUrl(url: string): Smtp | null {
  if (!url.trim()) return null;
  try {
    const u = new URL(url.trim());
    if (u.protocol !== "smtp:" && u.protocol !== "smtps:") return null;
    const port = u.port ? Number(u.port) : 0;
    // smtp:// on 25 was plain; on any other port nodemailer upgraded when offered, so STARTTLS.
    const security: SmtpSecurity = u.protocol === "smtps:" ? "ssl" : port === 25 ? "none" : "starttls";
    return { host: u.hostname, port, security, user: decodeURIComponent(u.username), password: decodeURIComponent(u.password) };
  } catch {
    return null;
  }
}

export function transportOptions(s: Smtp) {
  return {
    host: s.host,
    port: smtpPort(s),
    secure: s.security === "ssl",
    requireTLS: s.security === "starttls",
    ignoreTLS: s.security === "none",
    auth: s.user ? { user: s.user, pass: s.password } : undefined,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  };
}

export function makeMailer(smtp: Smtp | null, from: string): Mailer {
  if (!smtp?.host) {
    return async (m) => {
      console.log(`[mail] to=${m.to} subject=${JSON.stringify(m.subject)}\n${m.text}\n`);
    };
  }
  const transport = nodemailer.createTransport(transportOptions(smtp));
  return async (m) => {
    await transport.sendMail({ from, to: m.to, subject: m.subject, text: m.text });
  };
}

/** What went wrong, in words an admin can act on. */
export function explainSmtpError(e: unknown, s: Smtp): string {
  const err = e as { code?: string; responseCode?: number; message?: string; response?: string };
  const where = `${s.host}:${smtpPort(s)}`;
  const msg = String(err.message ?? e);
  const code = err.code ?? "";
  if (code === "EAUTH" || err.responseCode === 535 || err.responseCode === 534) {
    return `The server refused the username or password (${(err.response ?? msg).slice(0, 120)}). Check them; Gmail and others need an app password.`;
  }
  if (/wrong version number|ssl3_get_record|packet length too long|unknown protocol/i.test(msg)) {
    return `The secure connection failed at ${where}: the security does not match the port. Use SSL/TLS with 465, STARTTLS with 587.`;
  }
  if (/greeting never received/i.test(msg)) {
    return `${where} answered but never greeted: it probably expects SSL/TLS (try 465 with SSL/TLS).`;
  }
  if (code === "EDNS" || /ENOTFOUND|EAI_AGAIN/.test(msg)) return `There is no server called ${s.host}. Check the host.`;
  if (/ECONNREFUSED/.test(msg)) return `${where} refused the connection. Check the host and port.`;
  if (code === "ETIMEDOUT" || /timeout|ETIMEDOUT/i.test(msg)) {
    return `No answer from ${where}. Check the host and port, and that this machine may connect out on port ${smtpPort(s)} (many cloud hosts block 25).`;
  }
  if (/STARTTLS/i.test(msg)) return `${where} does not offer STARTTLS. Choose SSL/TLS (465) or, only on a trusted network, None.`;
  if (/self.signed|certificate|CERT_/i.test(msg)) return `The server's certificate is not trusted (${msg.slice(0, 120)}).`;
  if (code === "EENVELOPE" || err.responseCode === 550 || err.responseCode === 553 || err.responseCode === 554) {
    return `The server would not send it: ${(err.response ?? msg).slice(0, 160)}. The sender address may not be allowed for this account.`;
  }
  return msg.slice(0, 200);
}

/** Connect, sign in and send one message with these settings (not necessarily saved). Throws an explained Error. */
export async function testSmtp(s: Smtp, from: string, to: string, text: string, subject: string): Promise<void> {
  const t = nodemailer.createTransport(transportOptions(s));
  try {
    await t.verify();
    await t.sendMail({ from, to, subject, text });
  } catch (e) {
    throw new Error(explainSmtpError(e, s));
  } finally {
    t.close();
  }
}

/** A mailer whose transport can be replaced (the SMTP settings changed in the dashboard). */
export type SwitchableMailer = Mailer & { set(next: Mailer): void };

export function switchableMailer(initial: Mailer): SwitchableMailer {
  let current = initial;
  const m = ((x: Mail) => current(x)) as SwitchableMailer;
  m.set = (next) => {
    current = next;
  };
  return m;
}

/** "Name <email>" split; a bare address has no name. */
export function splitFrom(from: string): { name: string; email: string } {
  const m = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(from);
  return m ? { name: m[1].trim(), email: m[2].trim() } : { name: "", email: from.trim() };
}

export function joinFrom(name: string, email: string): string {
  const n = name.replace(/["<>\r\n]/g, "").trim();
  return n ? `${n} <${email.trim()}>` : email.trim();
}
