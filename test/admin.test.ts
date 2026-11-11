/** Admin control: the super admin, permissions, sudo mode, plans, managing people and stations, settings. */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { LightMyRequestResponse } from "fastify";
import { buildDashboard } from "../src/dashboard/app.js";
import type { Db } from "../src/db/db.js";
import type { Mail } from "../src/lib/mail.js";
import { totpAt } from "../src/lib/secrets.js";
import { LiveConfig } from "../src/lib/settings.js";
import { freshDb, platform } from "./helpers.js";

let db: Db;
let app: ReturnType<typeof buildDashboard>;
let p: ReturnType<typeof platform>;
let live: LiveConfig;
const mails: Mail[] = [];
const PW = "correct horse battery";

beforeAll(async () => {
  db = await freshDb();
  p = platform(db, { dashboardUrl: "http://app.example.test" });
  live = new LiveConfig(p.config, db, { dns: p.dns });
  app = buildDashboard({ db, dns: p.dns, config: p.config, live, mail: async (m) => { mails.push(m); } });
});
afterAll(async () => {
  await app.close();
  await db.end();
});

/** A browser: keeps cookies, finds the form token, sends forms from this site. */
export class Browser {
  cookies = new Map<string, string>();
  totp = "";
  constructor(public ip: string, public email = "") {}
  private keep(r: LightMyRequestResponse) {
    for (const c of r.cookies) {
      if (c.value === "" || (c.maxAge !== undefined && c.maxAge <= 0)) this.cookies.delete(c.name);
      else this.cookies.set(c.name, c.value);
    }
    return r;
  }
  private get cookie() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async get(url: string) {
    return this.keep(await app.inject({ method: "GET", url, headers: { cookie: this.cookie }, remoteAddress: this.ip }));
  }
  /** `form` may hold repeated fields (checkboxes) as arrays. */
  async post(url: string, form: Record<string, string | string[]>, from = url) {
    const body = new URLSearchParams();
    if (!form._csrf) {
      const page = await this.get(from);
      body.append("_csrf", /name="_csrf" value="([^"]+)"/.exec(page.body)?.[1] ?? "");
    }
    for (const [k, v] of Object.entries(form)) for (const x of [v].flat()) body.append(k, x);
    return this.keep(await app.inject({ method: "POST", url, payload: body.toString(),
      headers: { cookie: this.cookie, "content-type": "application/x-www-form-urlencoded", origin: "http://app.example.test" }, remoteAddress: this.ip }));
  }
  /** The flash message the next page shows. */
  async flash(url: string) {
    const t = /class="flash \w+" role="status">[\s\S]*?<span>([^<]*)</.exec((await this.get(url)).body)?.[1] ?? "";
    return t.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  }
  /** Turn on two-step sign-in (admins need it). */
  async enable2fa() {
    await this.post("/account/totp/start", {}, "/account");
    this.totp = /Key: <code>([A-Z2-7]+)</.exec((await this.get("/account")).body)![1];
    await this.post("/account/totp/confirm", { code: totpAt(this.totp) }, "/account");
  }
  /** Sudo mode ends (as if 10 minutes passed). */
  async sudoExpires() {
    await db.query("UPDATE sessions s SET elevated_until = now() - interval '1 minute' FROM users u WHERE u.id = s.user_id AND u.email = $1", [this.email]);
  }
  async sudo(next = "/") {
    return this.post("/sudo", { password: PW, code: totpAt(this.totp), next }, "/sudo");
  }
}

const idOf = async (email: string) => (await db.query<{ id: number }>("SELECT id FROM users WHERE email = $1", [email])).rows[0].id;
const roleOf = async (email: string) => (await db.query<{ role: string; permissions: string[] }>("SELECT role, permissions FROM users WHERE email = $1", [email])).rows[0];
const sign = async (email: string, ip: string) => {
  const b = new Browser(ip, email);
  await b.post("/signup", { email, password: PW });
  await db.query("UPDATE users SET email_verified_at = now() WHERE email = $1", [email]);
  return b;
};

const chief = new Browser("203.0.113.1", "chief@example.test");
let owner: Browser;
let helper: Browser;

describe("the super admin", () => {
  it("is the first account made; later ones are station owners", async () => {
    await chief.post("/signup", { email: "chief@example.test", password: PW });
    owner = await sign("owner@example.test", "203.0.113.2");
    helper = await sign("helper@example.test", "203.0.113.3");
    expect((await roleOf("chief@example.test")).role).toBe("superadmin");
    expect((await roleOf("owner@example.test")).role).toBe("user");
    expect((await owner.get("/admin")).statusCode).toBe(404);
    // Exactly one, whatever happens.
    await expect(db.query("UPDATE users SET role = 'superadmin' WHERE email = 'owner@example.test'")).rejects.toThrow();
  });

  it("needs two-step sign-in before the console opens", async () => {
    expect((await chief.get("/admin")).body).toContain("Two-step sign-in required");
    expect((await chief.get("/admin/users")).body).not.toContain("owner@example.test");
    await chief.enable2fa();
    expect((await chief.get("/admin")).body).toContain("You are the super admin");
  });

  it("gives an admin only the permissions ticked, in sudo mode", async () => {
    const id = await idOf("helper@example.test");
    // Sudo mode has run out: the change is refused and the super admin is asked to confirm.
    await chief.sudoExpires();
    const r = await chief.post(`/admin/users/${id}/role`, { role: "admin", perm: ["stations.view", "users.view", "nonsense"] }, `/admin/users/${id}`);
    expect(r.headers.location).toMatch(/^\/sudo\?next=/);
    expect((await roleOf("helper@example.test")).role).toBe("user");
    // A wrong code does not confirm it.
    await chief.post("/sudo", { password: PW, code: "000000", next: "/" }, "/sudo");
    expect((await chief.post(`/admin/users/${id}/role`, { role: "admin", perm: ["users.view"] }, `/admin/users/${id}`)).headers.location).toMatch(/^\/sudo/);
    await chief.sudo();
    await chief.post(`/admin/users/${id}/role`, { role: "admin", perm: ["stations.view", "users.view", "nonsense"] }, `/admin/users/${id}`);
    expect(await roleOf("helper@example.test")).toEqual({ role: "admin", permissions: ["stations.view", "users.view"] });
    expect(mails.some((m) => m.to === "helper@example.test" && m.subject.includes("Your access changed"))).toBe(true);

    await helper.enable2fa();
    const nav = (await helper.get("/admin")).body;
    expect(nav).toContain('href="/admin/stations"');
    expect(nav).not.toContain('href="/admin/settings"');
    expect((await helper.get("/admin/stations")).statusCode).toBe(200);
    for (const page of ["/admin/plans", "/admin/names", "/admin/settings", "/admin/setup", "/admin/audit", "/admin/billing"]) expect((await helper.get(page)).statusCode, page).toBe(403);
  });

  it("is the only one who changes roles, and no admin acts on another admin", async () => {
    const chiefId = await idOf("chief@example.test");
    const ownerId = await idOf("owner@example.test");
    await db.query("UPDATE users SET permissions = $2 WHERE email = $1", ["helper@example.test", ["users.view", "users.manage", "stations.view"]]);
    await helper.post(`/admin/users/${ownerId}/role`, { role: "admin", perm: ["settings.manage"] }, `/admin/users/${ownerId}`);
    expect((await roleOf("owner@example.test")).role).toBe("user");
    await helper.post(`/admin/users/${chiefId}/suspend`, {}, `/admin/users/${chiefId}`);
    expect((await db.query("SELECT status FROM users WHERE id = $1", [chiefId])).rows[0].status).toBe("active");
    expect(await helper.flash(`/admin/users/${chiefId}`)).toContain("Only the super admin");
    await helper.post(`/admin/users/${ownerId}/suspend`, {}, `/admin/users/${ownerId}`);
    expect((await db.query("SELECT status FROM users WHERE id = $1", [ownerId])).rows[0].status).toBe("suspended");
    await helper.post(`/admin/users/${ownerId}/unsuspend`, {}, `/admin/users/${ownerId}`);
    owner = new Browser("203.0.113.2", "owner@example.test");
    await owner.post("/login", { email: "owner@example.test", password: PW }, "/login");
  });
});

describe("plans", () => {
  it("limit stations: the default plan, a person's plan, and their own limit", async () => {
    // No plan yet: SUBDOMAIN_LIMIT (1).
    await owner.post("/stations", { label: "one" }, "/stations/new");
    await owner.post("/stations", { label: "two" }, "/stations/new");
    expect(await owner.flash("/stations/new")).toContain("plan allows 1 station");

    await chief.post("/admin/plans", { name: "Free", limit: "1", default: "1" }, "/admin/plans/new");
    await chief.post("/admin/plans", { name: "Pro", limit: "3", price: "19.99", currency: "USD", period: "month" }, "/admin/plans/new");
    await chief.post("/admin/plans", { name: "pro", limit: "9" }, "/admin/plans/new");
    expect(await chief.flash("/admin/plans/new")).toContain("already a plan called pro");
    expect((await db.query("SELECT price_minor, currency FROM plans WHERE name = 'Pro'")).rows[0]).toEqual({ price_minor: 1999, currency: "USD" });
    expect((await owner.get("/")).body).toContain("Your Free plan allows 1 station");

    const pro = (await db.query("SELECT id FROM plans WHERE name = 'Pro'")).rows[0].id;
    const ownerId = await idOf("owner@example.test");
    await chief.post(`/admin/users/${ownerId}/plan`, { plan: String(pro), limit: "" }, `/admin/users/${ownerId}`);
    await owner.post("/stations", { label: "two" }, "/stations/new");
    await owner.post("/stations", { label: "three" }, "/stations/new");
    await owner.post("/stations", { label: "four" }, "/stations/new");
    expect(await owner.flash("/stations/new")).toContain("plan allows 3 stations");
    expect((await db.query("SELECT count(*)::int AS n FROM subdomains WHERE user_id = $1", [ownerId])).rows[0].n).toBe(3);

    // Their own limit wins over the plan.
    await chief.post(`/admin/users/${ownerId}/plan`, { plan: String(pro), limit: "4" }, `/admin/users/${ownerId}`);
    await owner.post("/stations", { label: "four" }, "/stations/new");
    expect((await db.query("SELECT count(*)::int AS n FROM subdomains WHERE user_id = $1", [ownerId])).rows[0].n).toBe(4);
    expect((await owner.get("/")).body).toContain("Your account allows 4 stations");

    // Only one default plan; a bad price is refused.
    await chief.post("/admin/plans", { name: "Starter", limit: "2", default: "1" }, "/admin/plans/new");
    expect((await db.query("SELECT name FROM plans WHERE is_default")).rows.map((r) => r.name)).toEqual(["Starter"]);
    await chief.post("/admin/plans", { name: "Odd", limit: "2", price: "12.345", currency: "USD" }, "/admin/plans/new");
    expect(await chief.flash("/admin/plans/new")).toContain("like 19.99");
  });

  it("are changed by those allowed to only", async () => {
    expect((await helper.post("/admin/plans", { name: "Sneaky", limit: "99" }, "/admin/stations")).statusCode).toBe(403);
    expect((await db.query("SELECT 1 FROM plans WHERE name = 'Sneaky'")).rowCount).toBe(0);
  });
});

describe("people and stations", () => {
  it("adds a person, who chooses a password from the emailed link", async () => {
    await chief.post("/admin/users", { email: "new@example.test", plan: "" }, "/admin/users");
    const mail = mails.find((m) => m.to === "new@example.test")!;
    expect(mail.subject).toContain("account");
    const link = new URL(/https?:\/\/\S+/.exec(mail.text)![0]);
    const b = new Browser("203.0.113.9");
    await b.post("/reset", { token: link.searchParams.get("token")!, password: "a brand new password" }, `/reset${link.search}`);
    const r = await b.post("/login", { email: "new@example.test", password: "a brand new password" }, "/login");
    expect(r.headers.location).toBe("/");
  });

  it("creates a station for someone, then moves it, replacing its access code", async () => {
    const r = await chief.post("/admin/stations", { email: "new@example.test", label: "gift" }, "/admin/stations");
    expect(r.body).toContain("gift.example.test is created");
    const first = /class="code">([0-9A-Z-]+)</.exec(r.body)![1];
    const sd = (await db.query("SELECT sd.id, st.id AS studio FROM subdomains sd JOIN studios st ON st.subdomain_id = sd.id WHERE label = 'gift'")).rows[0];
    await db.query("INSERT INTO studio_tokens (studio_id, token_hash, expires_at) VALUES ($1, 'h', now() + interval '1 day')", [sd.studio]);

    // The owner's limit applies to a move: owner has 4 of 4.
    await chief.post(`/stations/${sd.id}/transfer`, { email: "owner@example.test" }, `/stations/${sd.id}`);
    expect(await chief.flash(`/stations/${sd.id}`)).toContain("Raise their limit");
    const moved = await chief.post(`/stations/${sd.id}/transfer`, { email: "chief@example.test" }, `/stations/${sd.id}`);
    expect(moved.body).toContain("now belongs to chief@example.test");
    const second = /class="code">([0-9A-Z-]+)</.exec(moved.body)![1];
    expect(second).not.toBe(first);
    expect((await db.query("SELECT revoked_at FROM studio_tokens WHERE studio_id = $1", [sd.studio])).rows[0].revoked_at).not.toBeNull();
    // An admin who may only look cannot move it.
    expect((await helper.post(`/stations/${sd.id}/transfer`, { email: "new@example.test" }, `/stations/${sd.id}`)).statusCode).toBe(404);
    expect((await helper.get(`/stations/${sd.id}`)).statusCode).toBe(200);
  });

  it("deletes a person with their stations, in sudo mode", async () => {
    const id = await idOf("owner@example.test");
    await chief.sudoExpires();
    expect((await chief.get(`/admin/users/${id}`)).body).toContain("Confirm it is you to continue");
    await chief.post(`/admin/users/${id}/delete`, { confirm: "owner@example.test" }, `/admin/users/${id}`);
    expect((await db.query("SELECT 1 FROM users WHERE id = $1", [id])).rowCount).toBe(1);
    await chief.sudo();
    await chief.post(`/admin/users/${id}/delete`, { confirm: "nope" }, `/admin/users/${id}`);
    expect((await db.query("SELECT 1 FROM users WHERE id = $1", [id])).rowCount).toBe(1);
    await chief.post(`/admin/users/${id}/delete`, { confirm: "owner@example.test" }, `/admin/users/${id}`);
    expect((await db.query("SELECT 1 FROM users WHERE id = $1", [id])).rowCount).toBe(0);
    expect((await db.query("SELECT 1 FROM subdomains WHERE label IN ('one', 'two', 'three', 'four')")).rowCount).toBe(0);
    expect((await db.query("SELECT 1 FROM name_cooldowns WHERE label = 'one'")).rowCount).toBe(1);
    const auditPage = (await chief.get("/admin/audit")).body;
    for (const a of ["user.role", "user.sudo", "plan.create", "user.plan", "subdomain.transfer", "user.delete"]) expect(auditPage).toContain(a);
  });
});

describe("account security", () => {
  it("lists signed-in devices and ends them", async () => {
    const other = new Browser("203.0.113.50", "new@example.test");
    await other.post("/login", { email: "new@example.test", password: "a brand new password" }, "/login");
    const me = new Browser("203.0.113.51", "new@example.test");
    await me.post("/login", { email: "new@example.test", password: "a brand new password" }, "/login");
    const page = (await me.get("/account")).body;
    expect(page).toContain("This device");
    expect(page).toContain("203.0.113.50");
    await me.post("/account/sessions/others", {}, "/account");
    expect((await other.get("/")).headers.location).toMatch(/^\/login/);
    expect((await me.get("/")).statusCode).toBe(200);
  });

  it("refuses weak passwords and sends a notice when one changes", async () => {
    const b = new Browser("203.0.113.52", "new@example.test");
    await b.post("/login", { email: "new@example.test", password: "a brand new password" }, "/login");
    await b.post("/account/password", { current: "a brand new password", password: "aaaaaaaaaaaa" }, "/account");
    expect(await b.flash("/account")).toContain("not one repeated character");
    await b.post("/account/password", { current: "a brand new password", password: "another long password" }, "/account");
    expect(mails.some((m) => m.to === "new@example.test" && m.subject.includes("password was changed"))).toBe(true);
  });

  it("only goes back to addresses on this site after sign-in", async () => {
    const b = new Browser("203.0.113.53");
    const r = await b.post("/login", { email: "new@example.test", password: "another long password", next: "//evil.example/x" }, "/login");
    expect(r.headers.location).toBe("/");
  });
});

describe("settings", () => {
  it("need sudo mode", async () => {
    await chief.sudoExpires();
    const r = await chief.get("/admin/settings");
    expect(r.headers.location).toBe("/sudo?next=%2Fadmin%2Fsettings");
    expect((await chief.post("/admin/settings/mail", { mailFrom: "x@example.test" }, "/admin/users")).headers.location).toMatch(/^\/sudo/);
    expect(p.config.mailFrom).not.toBe("x@example.test");
  });

  it("store credentials encrypted, take effect at once, and go back to .env", async () => {
    await chief.sudo("/admin/settings");
    expect((await chief.get("/admin/settings")).body).toContain("Cloudflare credentials");

    await chief.post("/admin/settings/mail", { smtpUrl: "smtps://mailer:s3cret-pass@smtp.example.test:465", mailFrom: "Radio <hi@example.test>" }, "/admin/settings");
    expect(p.config.smtpUrl).toBe("smtps://mailer:s3cret-pass@smtp.example.test:465");
    expect(p.config.mailFrom).toBe("Radio <hi@example.test>");
    const raw = JSON.stringify((await db.query("SELECT * FROM settings")).rows) + JSON.stringify((await db.query("SELECT * FROM audit_log")).rows);
    expect(raw).not.toContain("s3cret-pass");
    const page = (await chief.get("/admin/settings")).body;
    expect(page).not.toContain("s3cret-pass");
    expect(page).toContain("smtps://mailer:••••@smtp.example.test:465");

    // Cloudflare: the DNS provider changes without a restart.
    expect(p.dns.providerName).toBe("memory");
    await chief.post("/admin/settings/dns", { dnsProvider: "cloudflare", cloudflareApiToken: "x".repeat(40), cloudflareZoneId: "a".repeat(32) }, "/admin/settings");
    expect(p.config.cloudflareZoneId).toBe("a".repeat(32));
    expect(p.dns.providerName).toBe("cloudflare");
    // Another process (a fresh LiveConfig over the same database) sees the same.
    const other = { ...p.config, dnsProvider: "memory" as const, cloudflareApiToken: "", cloudflareZoneId: "", smtpUrl: "" };
    await new LiveConfig(other, db).reload();
    expect(other.cloudflareApiToken).toBe("x".repeat(40));

    await chief.post("/admin/settings/clear", { key: "dnsProvider" }, "/admin/settings");
    expect(p.dns.providerName).toBe("memory");

    await chief.post("/admin/settings/acme", { acmeEmail: "not an email" }, "/admin/settings");
    expect(await chief.flash("/admin/settings")).toContain("not an email address");
  });

  it("are not for admins without the permission", async () => {
    expect((await helper.post("/admin/settings/mail", { mailFrom: "x@example.test" }, "/admin/stations")).statusCode).toBe(403);
  });

  it("the super admin hands over the role", async () => {
    const id = await idOf("helper@example.test");
    await chief.post(`/admin/users/${id}/superadmin`, {}, `/admin/users/${id}`);
    expect((await roleOf("helper@example.test")).role).toBe("superadmin");
    expect((await roleOf("chief@example.test")).role).toBe("admin");
    expect((await roleOf("chief@example.test")).permissions).toContain("billing.manage");
  });
});
