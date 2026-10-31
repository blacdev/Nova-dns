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
  sessionSecret: string;
  smtpUrl: string;
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

export function loadConfig(): Config {
  const rootDomain = env("ROOT_DOMAIN").toLowerCase().replace(/\.$/, "");
  const dnsProvider = env("DNS_PROVIDER", "cloudflare") as Config["dnsProvider"];
  if (!["cloudflare", "memory", "challtestsrv"].includes(dnsProvider)) throw new Error("DNS_PROVIDER must be cloudflare, memory or challtestsrv");
  return {
    rootDomain,
    databaseUrl: env("DATABASE_URL"),
    dnsProvider,
    challTestSrvUrl: env("CHALLTESTSRV_URL", "http://127.0.0.1:8055"),
    cloudflareApiToken: dnsProvider === "cloudflare" ? env("CLOUDFLARE_API_TOKEN") : env("CLOUDFLARE_API_TOKEN", ""),
    cloudflareZoneId: dnsProvider === "cloudflare" ? env("CLOUDFLARE_ZONE_ID") : env("CLOUDFLARE_ZONE_ID", ""),
    acmeDirectoryUrl: env("ACME_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory"),
    acmeEmail: env("ACME_EMAIL"),
    acmeCaBundle: env("ACME_CA_BUNDLE", ""),
    turnSharedSecret: env("TURN_SHARED_SECRET"),
    turnSharedSecretPrevious: env("TURN_SHARED_SECRET_PREVIOUS", ""),
    turnHost: env("TURN_HOST", `turn.${rootDomain}`),
    turnUsageToken: env("TURN_USAGE_TOKEN", ""),
    sessionSecret: env("SESSION_SECRET"),
    smtpUrl: env("SMTP_URL", ""),
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
