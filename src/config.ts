import { isIP } from "node:net";
import { isSmtpSecurity, parseSmtpUrl, type Smtp, type SmtpSecurity } from "./lib/mail.js";

/**
 * Everything the platform is told by its environment (see .env.example). Read once;
 * a missing required value stops the process with a plain message.
 */

export interface Config {
  rootDomain: string;
  databaseUrl: string;
  /** "cloudflare" in production; "memory" keeps records in this process (development, tests);
   *  "challtestsrv" is Pebble's challenge server (end-to-end certificate tests). */
  dnsProvider: "cloudflare" | "memory" | "challtestsrv";
  challTestSrvUrl: string;
  cloudflareApiToken: string;
  cloudflareZoneId: string;
  acmeDirectoryUrl: string;
  acmeEmail: string;
  /** Pebble (tests) serves its directory with its own certificate authority. */
  acmeCaBundle: string;
  turnSharedSecret: string;
  /** The secret coturn also accepts during a rotation (not used to sign). */
  turnSharedSecretPrevious: string;
  turnHost: string;
  turnUsageToken: string;
  /** The tunnel's edge (Nova's docs/TUNNEL.md): its public address. A station reached
   *  through it is pointed here (A/AAAA). "" when the platform runs no edge: then stations
   *  are only ever reached directly and nothing else here changes. */
  edgeIp: string;
  /** Where stations dial it over QUIC (UDP), "host:port"; edge.ROOT_DOMAIN:443 by default. */
  edgeHost: string;
  /** The TCP ports presenters reach it on (EDGE_PORTS, "443,25433" by default). Behind a
   *  reverse proxy that keeps 443 (Nginx Proxy Manager) it is 25433 alone. Told to stations,
   *  so the address they give out names a port the edge serves. */
  edgePorts: number[];
  /** Shared only between the edge and the API: the edge checks stations' tokens and
   *  fetches its certificate with it (/internal/edge/...). */
  edgeToken: string;
  sessionSecret: string;
  /** The SMTP server; "" sends nothing (each message is printed to the log). */
  smtpHost: string;
  /** 0: the security's usual port (465, 587, 25). */
  smtpPort: number;
  smtpSecurity: SmtpSecurity;
  smtpUser: string;
  smtpPassword: string;
  mailFrom: string;
  /** Proxies whose X-Forwarded-For is believed (comma-separated addresses). */
  trustedProxies: string[];
  apiPort: number;
  dashboardPort: number;
  /** Public base address of the dashboard, for links in emails. */
  dashboardUrl: string;
  subdomainLimit: number;
  /** Let's Encrypt: new certificates per registered domain per 7 days. */
  certWeeklyLimit: number;
  adminEmails: string[];
  /** Development only: the probe may reach private addresses (tests on one machine). */
  allowPrivateProbe: boolean;
  /** Development only: a DNS-01 check the worker waits on (Pebble's challenge server). */
  dnsCheckResolver: string;
}

function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v !== undefined && v !== "") return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`${name} is not set (see .env.example)`);
}

const list = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);
const ports = (v: string) => {
  const found = list(v).map(Number);
  if (!found.length || found.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw new Error("EDGE_PORTS must be ports, comma separated, e.g. 443,25433");
  return found;
};

/**
 * SMTP_HOST, SMTP_PORT, SMTP_SECURITY, SMTP_USER and SMTP_PASSWORD; or the older SMTP_URL
 * (smtps://user:password@host:465), split into the same parts.
 */
function smtpFromEnv(): Pick<Config, "smtpHost" | "smtpPort" | "smtpSecurity" | "smtpUser" | "smtpPassword"> {
  const fromUrl: Smtp | null = parseSmtpUrl(env("SMTP_URL", ""));
  if (env("SMTP_URL", "") && !fromUrl) throw new Error("SMTP_URL must look like smtps://user:password@smtp.example.com:465 (or use SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD)");
  const security = env("SMTP_SECURITY", fromUrl?.security ?? "");
  if (security && !isSmtpSecurity(security)) throw new Error("SMTP_SECURITY must be ssl, starttls or none");
  const port = env("SMTP_PORT", fromUrl?.port ? String(fromUrl.port) : "0");
  if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) throw new Error("SMTP_PORT must be a port number");
  return {
    smtpHost: env("SMTP_HOST", fromUrl?.host ?? ""),
    smtpPort: Number(port),
    // Without a choice: SSL/TLS on 465, STARTTLS anywhere else.
    smtpSecurity: (security || (port === "0" || port === "465" ? "ssl" : "starttls")) as SmtpSecurity,
    smtpUser: env("SMTP_USER", fromUrl?.user ?? ""),
    smtpPassword: env("SMTP_PASSWORD", fromUrl?.password ?? ""),
  };
}

/** The SMTP part of the configuration, for the mailer; null when no server is set. */
export const smtpOf = (c: Config): Smtp | null =>
  c.smtpHost ? { host: c.smtpHost, port: c.smtpPort, security: c.smtpSecurity, user: c.smtpUser, password: c.smtpPassword } : null;

export function loadConfig(): Config {
  const rootDomain = env("ROOT_DOMAIN").toLowerCase().replace(/\.$/, "");
  if (env("EDGE_IP", "") && !isIP(env("EDGE_IP", ""))) throw new Error("EDGE_IP must be the edge's public address (an IP address)");
  const dnsProvider = env("DNS_PROVIDER", "cloudflare") as Config["dnsProvider"];
  if (!["cloudflare", "memory", "challtestsrv"].includes(dnsProvider)) throw new Error("DNS_PROVIDER must be cloudflare, memory or challtestsrv");
  return {
    rootDomain,
    databaseUrl: env("DATABASE_URL"),
    dnsProvider,
    challTestSrvUrl: env("CHALLTESTSRV_URL", "http://127.0.0.1:8055"),
    // Either here or in Admin > Settings: without both, DNS changes fail with a plain reason.
    cloudflareApiToken: env("CLOUDFLARE_API_TOKEN", ""),
    cloudflareZoneId: env("CLOUDFLARE_ZONE_ID", ""),
    acmeDirectoryUrl: env("ACME_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory"),
    acmeEmail: env("ACME_EMAIL"),
    acmeCaBundle: env("ACME_CA_BUNDLE", ""),
    turnSharedSecret: env("TURN_SHARED_SECRET"),
    turnSharedSecretPrevious: env("TURN_SHARED_SECRET_PREVIOUS", ""),
    turnHost: env("TURN_HOST", `turn.${rootDomain}`),
    turnUsageToken: env("TURN_USAGE_TOKEN", ""),
    edgeIp: env("EDGE_IP", ""),
    edgeHost: env("EDGE_HOST", `edge.${rootDomain}:443`),
    edgePorts: ports(env("EDGE_PORTS", "443,25433")),
    edgeToken: env("EDGE_TOKEN", ""),
    sessionSecret: env("SESSION_SECRET"),
    ...smtpFromEnv(),
    mailFrom: env("MAIL_FROM", `Nova <no-reply@${rootDomain}>`),
    trustedProxies: list(env("TRUSTED_PROXIES", "127.0.0.1,::1")),
    apiPort: Number(env("API_PORT", "8080")),
    dashboardPort: Number(env("DASHBOARD_PORT", "8081")),
    dashboardUrl: env("DASHBOARD_URL", `https://app.${rootDomain}`).replace(/\/$/, ""),
    subdomainLimit: Number(env("SUBDOMAIN_LIMIT", "1")),
    certWeeklyLimit: Number(env("CERT_WEEKLY_LIMIT", "50")),
    adminEmails: list(env("ADMIN_EMAILS", "")).map((e) => e.toLowerCase()),
    allowPrivateProbe: env("ALLOW_PRIVATE_PROBE", "false") === "true",
    dnsCheckResolver: env("DNS_CHECK_RESOLVER", ""),
  };
}
