/**
 * Email: verification links, password resets, the admins' daily alert. Sent through
 * SMTP_URL; without it (development) each message is printed instead. Never logs a
 * password or an access code (none is ever mailed).
 */

import nodemailer from "nodemailer";

export interface Mail {
  to: string;
  subject: string;
  text: string;
}

export type Mailer = (m: Mail) => Promise<void>;

export function makeMailer(smtpUrl: string, from: string): Mailer {
  if (!smtpUrl) {
    return async (m) => {
      console.log(`[mail] to=${m.to} subject=${JSON.stringify(m.subject)}\n${m.text}\n`);
    };
  }
  const transport = nodemailer.createTransport(smtpUrl);
  return async (m) => {
    await transport.sendMail({ from, to: m.to, subject: m.subject, text: m.text });
  };
}
