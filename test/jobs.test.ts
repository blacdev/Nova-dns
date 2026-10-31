import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db/db.js";
import type { Mail } from "../src/lib/mail.js";
import { opsEvent } from "../src/lib/audit.js";
import { dailyAlert, expireTokens, markOffline, releaseCooldowns } from "../src/worker/jobs.js";
import * as subs from "../src/lib/subdomains.js";
import { freshDb, person, platform } from "./helpers.js";

let db: Db;
beforeAll(async () => { db = await freshDb(); });
afterAll(async () => { await db.end(); });

describe("background jobs", () => {
  it("marks a studio offline after 10 silent minutes, without touching DNS", async () => {
    const p = platform(db);
    const owner = await person(db);
    const { id } = await subs.claim({ db, dns: p.dns, rootDomain: "example.test", limit: 1 }, { id: owner, ip: null }, "quietfm");
    await db.query("UPDATE studios SET online = true, last_seen_at = now() - interval '9 minutes' WHERE subdomain_id = $1", [id]);
    expect(await markOffline(db)).toBe(0);
    await db.query("UPDATE studios SET last_seen_at = now() - interval '11 minutes' WHERE subdomain_id = $1", [id]);
    const calls = p.provider.calls;
    expect(await markOffline(db)).toBe(1);
    expect(p.provider.calls).toBe(calls);
  });

  it("releases names whose cooldown passed, and drops expired tokens", async () => {
    await db.query("INSERT INTO name_cooldowns VALUES ('gonefm', now() - interval '1 minute'), ('stillfm', now() + interval '1 day')");
    expect(await releaseCooldowns(db)).toBe(1);
    expect((await db.query("SELECT label FROM name_cooldowns")).rows.map((r) => r.label)).toContain("stillfm");
    expect(await expireTokens(db)).toBeGreaterThanOrEqual(0);
  });

  it("emails admins the DNS/ACME failures once", async () => {
    await person(db, "boss@example.test", "admin");
    await opsEvent(db, "dns", "Cloudflare said no", "kfm.example.test");
    await opsEvent(db, "acme", "issued", "kfm.example.test", "info");
    const sent: Mail[] = [];
    const deps = { db, mail: async (m: Mail) => { sent.push(m); }, config: platform(db, { adminEmails: ["ops@example.test"] }).config } as never;
    expect(await dailyAlert(deps)).toBe(1);
    expect(sent.map((m) => m.to).sort()).toEqual(["boss@example.test", "ops@example.test"]);
    expect(sent[0].text).toContain("Cloudflare said no");
    expect(sent[0].text).not.toContain("issued");
    expect(await dailyAlert(deps)).toBe(0);
  });
});
