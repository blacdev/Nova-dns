import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db/db.js";
import { checkName, coolDown, formError, normaliseLabel } from "../src/lib/names.js";
import { canonicalCode, decrypt, encrypt, newAccessCode, totpAt, turnCredential, verifyTotp } from "../src/lib/secrets.js";
import { hit } from "../src/lib/limits.js";
import { isPublicAddress } from "../src/lib/net.js";
import { freshDb } from "./helpers.js";
import { createHmac } from "node:crypto";

describe("name rules", () => {
  it("normalises to a lowercase label", () => {
    expect(normaliseLabel("  KFM ", "example.test")).toBe("kfm");
    expect(normaliseLabel("https://Kfm.Example.test/", "example.test")).toBe("kfm");
  });
  it.each([
    ["kfm", null], ["k-fm", null], ["a1b", null],
    ["ab", "At least 3"], ["-kfm", "Only lowercase"], ["kfm-", "Only lowercase"], ["k_fm", "Only lowercase"],
    ["xn--abc", "xn--"], ["ab--cd", "double hyphen"], ["a".repeat(64), "At most 63"],
  ])("%s", (label, error) => {
    const got = formError(label);
    if (error === null) expect(got).toBeNull();
    else expect(got).toContain(error);
  });
});

describe("names in the database", () => {
  let db: Db;
  beforeAll(async () => { db = await freshDb(); });
  afterAll(async () => { await db.end(); });

  it("knows reserved, blocked, cooling and taken names", async () => {
    expect((await checkName(db, "api")).state).toBe("reserved");
    await db.query("INSERT INTO reserved_names (label, kind) VALUES ('badword', 'blocked')");
    expect((await checkName(db, "badword")).message).toContain("not allowed");
    await coolDown(db, "oldfm");
    expect((await checkName(db, "oldfm")).state).toBe("cooldown");
    expect((await checkName(db, "kfm")).state).toBe("available");
  });

  it("counts rate limits in fixed windows", async () => {
    const lim = { max: 2, seconds: 60 };
    expect((await hit(db, "t:a", lim)).ok).toBe(true);
    expect((await hit(db, "t:a", lim)).ok).toBe(true);
    const third = await hit(db, "t:a", lim);
    expect(third.ok).toBe(false);
    expect(third.retryAfter).toBeGreaterThan(50);
  });
});

describe("secrets", () => {
  it("makes 24-character Crockford access codes, forgiving to type", () => {
    const code = newAccessCode();
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){5}$/);
    expect(canonicalCode(code.toLowerCase().replace(/-/g, " "))).toBe(code.replace(/-/g, ""));
    expect(canonicalCode("o0-il")).toBe("0011");
  });
  it("encrypts TOTP secrets and checks codes with one step of slack", () => {
    const enc = encrypt("k", "JBSWY3DPEHPK3PXP");
    expect(enc).not.toContain("JBSWY3");
    expect(decrypt("k", enc)).toBe("JBSWY3DPEHPK3PXP");
    // RFC 6238's SHA-1 test vector (secret "12345678901234567890", T = 59 s): 287082.
    expect(totpAt("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59_000)).toBe("287082");
    const now = Date.now();
    expect(verifyTotp("JBSWY3DPEHPK3PXP", totpAt("JBSWY3DPEHPK3PXP", now - 30_000), now)).toBe(true);
    expect(verifyTotp("JBSWY3DPEHPK3PXP", totpAt("JBSWY3DPEHPK3PXP", now - 90_000), now)).toBe(false);
  });
  it("signs TURN credentials the coturn way", () => {
    const { username, credential } = turnCredential("s3cret", "studio-1", 6 * 3600, 1_700_000_000_000);
    expect(username).toBe(`${1_700_000_000 + 21600}:studio-1`);
    expect(credential).toBe(createHmac("sha1", "s3cret").update(username).digest("base64"));
  });
  it("tells public addresses from private ones", () => {
    for (const ip of ["10.1.2.3", "192.168.1.1", "127.0.0.1", "100.64.0.9", "172.20.0.1", "169.254.1.1", "::1", "fd00::1"]) expect(isPublicAddress(ip)).toBe(false);
    for (const ip of ["8.8.8.8", "2606:4700::1111"]) expect(isPublicAddress(ip)).toBe(true);
  });
});
