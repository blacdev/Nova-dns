import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { LightMyRequestResponse } from "fastify";
import { buildDashboard } from "../src/dashboard/app.js";
import type { Db } from "../src/db/db.js";
import type { Mail } from "../src/lib/mail.js";
import { totpAt } from "../src/lib/secrets.js";
import { freshDb, platform } from "./helpers.js";

let db: Db;
let app: ReturnType<typeof buildDashboard>;
let p: ReturnType<typeof platform>;
const mails: Mail[] = [];

beforeAll(async () => {
  db = await freshDb();
  p = platform(db, { adminEmails: ["boss@example.test"], dashboardUrl: "http://app.example.test" });
  app = buildDashboard({ db, dns: p.dns, config: p.config, mail: async (m) => { mails.push(m); } });
});
afterAll(async () => {
  await app.close();
  await db.end();
});

/** A browser: keeps cookies, finds the form token, sends forms from this site. */
class Browser {
  cookies = new Map<string, string>();
  constructor(public ip = "198.51.100.1") {}
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
  async post(url: string, form: Record<string, string>, { from = url, csrf = true, origin = "http://app.example.test" } = {}) {
    if (csrf && !form._csrf) {
      const page = await this.get(from);
      form._csrf = /name="_csrf" value="([^"]+)"/.exec(page.body)?.[1] ?? "";
    }
    return this.keep(await app.inject({ method: "POST", url, payload: new URLSearchParams(form).toString(),
      headers: { cookie: this.cookie, "content-type": "application/x-www-form-urlencoded", origin }, remoteAddress: this.ip }));
  }
}

const linkIn = (m: Mail) => new URL(/https?:\/\/\S+/.exec(m.text)![0]);

describe("an owner's way through", () => {
  const b = new Browser();
  it("signs up, confirms the email, and is told to", async () => {
    const r = await b.post("/signup", { email: "Owner@Example.test", password: "correct horse battery" });
    expect(r.statusCode).toBe(302);
    expect((await b.get("/")).body).toContain("Confirm your email");
    const mail = mails.find((m) => m.to === "owner@example.test")!;
    expect(mail.subject).toContain("Confirm");
    const link = linkIn(mail);
    expect((await b.get(link.pathname + link.search)).statusCode).toBe(302);
    expect((await b.get("/")).body).toContain("Claim a station address");
    // A link works once.
    expect((await b.get(link.pathname + link.search)).statusCode).toBe(400);
  });

  it("checks names live as they are typed", async () => {
    const check = async (l: string) => (await b.get(`/names/check?label=${l}`)).json();
    expect(await check("KFM")).toMatchObject({ state: "available", label: "kfm", fqdn: "kfm.example.test" });
    expect((await check("api")).state).toBe("reserved");
    expect((await check("-x")).state).toBe("invalid");
  });

  let stationId = "";
  it("claims a name and sees the access code exactly once", async () => {
    const r = await b.post("/stations", { label: "kfm" }, { from: "/stations/new" });
    expect(r.statusCode).toBe(200);
    const code = /class="code">([0-9A-Z-]+)</.exec(r.body)?.[1];
    expect(code).toMatch(/^([0-9A-Z]{4}-){5}[0-9A-Z]{4}$/);
    expect(r.headers["cache-control"]).toBe("no-store");
    const list = await b.get("/");
    expect(list.body).toContain("kfm.example.test");
    stationId = /href="\/stations\/(\d+)"/.exec(list.body)![1];
    const detail = await b.get(`/stations/${stationId}`);
    expect(detail.body).toContain("Offline");
    expect(detail.body).not.toContain(code!);
    // Nowhere in the database either, only its hash.
    expect(JSON.stringify((await db.query("SELECT * FROM studios")).rows)).not.toContain(code!.replace(/-/g, ""));
  });

  it("is held to the plan limit", async () => {
    const r = await b.post("/stations", { label: "second" }, { from: "/stations/new" });
    expect(r.statusCode).toBe(302);
    expect((await b.get("/stations/new")).body).toContain("plan allows 1");
  });

  it("renames, regenerates and deletes", async () => {
    let r = await b.post(`/stations/${stationId}/rename`, { label: "kfm-fm" }, { from: `/stations/${stationId}` });
    expect((await b.get(`/stations/${stationId}`)).body).toContain("kfm-fm.example.test");
    r = await b.post(`/stations/${stationId}/regenerate`, {}, { from: `/stations/${stationId}` });
    expect(r.body).toContain("A new access code");
    r = await b.post(`/stations/${stationId}/delete`, { confirm: "wrong" }, { from: `/stations/${stationId}` });
    expect((await b.get(`/stations/${stationId}`)).body).toContain("Type the name exactly");
    r = await b.post(`/stations/${stationId}/delete`, { confirm: "kfm-fm" }, { from: `/stations/${stationId}` });
    expect(r.statusCode).toBe(302);
    expect((await b.get("/")).body).toContain("No station yet");
    expect((await b.get("/names/check?label=kfm-fm")).json().state).toBe("cooldown");
  });

  it("turns on two-step sign-in, and then needs a code", async () => {
    await b.post("/account/totp/start", {}, { from: "/account" });
    const page = await b.get("/account");
    const secret = /Key: <code>([A-Z2-7]+)</.exec(page.body)![1];
    expect(page.body).toContain("data:image/png;base64");
    await b.post("/account/totp/confirm", { code: totpAt(secret) }, { from: "/account" });
    expect((await b.get("/account")).body).toContain("Two-step sign-in is on");
    await b.post("/logout", {}, { from: "/account" });

    const c = new Browser("198.51.100.2");
    const r = await c.post("/login", { email: "owner@example.test", password: "correct horse battery" }, { from: "/login" });
    expect(r.headers.location).toBe("/login/totp");
    expect((await c.get("/")).headers.location).toBe("/login/totp"); // not in yet
    expect((await c.post("/login/totp", { code: "000000" }, { from: "/login/totp" })).statusCode).toBe(401);
    await c.post("/login/totp", { code: totpAt(secret) }, { from: "/login/totp" });
    expect((await c.get("/")).statusCode).toBe(200);
  });
});

describe("protection", () => {
  it("refuses a form without its token, or from another site", async () => {
    const b = new Browser("198.51.100.3");
    await b.post("/signup", { email: "x@example.test", password: "correct horse battery" });
    expect((await b.post("/stations/new", { label: "evil" }, { csrf: false })).statusCode).toBe(403);
    expect((await b.post("/stations", { label: "evil" }, { from: "/stations/new", origin: "https://evil.example" })).statusCode).toBe(403);
  });

  it("does not tell which emails have accounts, and limits sign-in attempts", async () => {
    const b = new Browser("198.51.100.4");
    const a = await b.post("/forgot", { email: "nobody@example.test" });
    const c = await b.post("/forgot", { email: "owner@example.test" });
    expect(a.body.replace(/\S+@example\.test/g, "")).toBe(c.body.replace(/\S+@example\.test/g, ""));
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await b.post("/login", { email: "owner@example.test", password: "nope" }, { from: "/login" })).statusCode;
    expect(last).toBe(429);
  });

  it("sends secure headers", async () => {
    const r = await new Browser().get("/login");
    expect(r.headers["strict-transport-security"]).toContain("max-age=");
    expect(r.headers["content-security-policy"]).toContain("script-src 'self'");
    expect(r.body).not.toMatch(/<script>(?!<\/script>)/);
  });
});

describe("admin", () => {
  it("is for admins only; sees, suspends and restores", async () => {
    const owner = new Browser("198.51.100.5");
    await owner.post("/signup", { email: "station@example.test", password: "correct horse battery" });
    await db.query("UPDATE users SET email_verified_at = now() WHERE email = 'station@example.test'");
    await owner.post("/stations", { label: "radio1" }, { from: "/stations/new" });
    expect((await owner.get("/admin")).statusCode).toBe(404);

    const boss = new Browser("198.51.100.6");
    await boss.post("/signup", { email: "boss@example.test", password: "correct horse battery" });
    // Admins need two-step sign-in before the console opens.
    expect((await boss.get("/admin")).body).toContain("Two-step sign-in required");
    await boss.post("/account/totp/start", {}, { from: "/account" });
    const secret = /Key: <code>([A-Z2-7]+)</.exec((await boss.get("/account")).body)![1];
    await boss.post("/account/totp/confirm", { code: totpAt(secret) }, { from: "/account" });
    for (const page of ["/admin", "/admin/users", "/admin/stations", "/admin/names", "/admin/plans", "/admin/billing", "/admin/certificates", "/admin/turn", "/admin/audit", "/admin/operations"]) {
      expect((await boss.get(page)).statusCode, page).toBe(200);
    }
    const list = await boss.get("/admin/stations?q=radio1");
    const id = /\/admin\/stations\/(\d+)\/suspend/.exec(list.body)![1];
    await boss.post(`/admin/stations/${id}/suspend`, {}, { from: "/admin/stations" });
    expect((await db.query("SELECT status FROM subdomains WHERE id = $1", [id])).rows[0].status).toBe("suspended");
    expect((await owner.get(`/stations/${id}`)).body).toContain("suspended by the platform");
    await boss.post(`/admin/stations/${id}/unsuspend`, {}, { from: "/admin/stations" });
    // Blocked names.
    await boss.post("/admin/names", { label: "rude", kind: "blocked", reason: "profanity" }, { from: "/admin/names" });
    expect((await owner.get("/names/check?label=rude")).json().message).toContain("not allowed");
    // The audit log shows it all.
    const auditPage = (await boss.get("/admin/audit")).body;
    for (const a of ["subdomain.create", "subdomain.suspend", "subdomain.unsuspend", "name.blocked"]) expect(auditPage).toContain(a);
  });
});
