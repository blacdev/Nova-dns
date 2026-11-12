import { createServer } from "node:https";
import { createHmac } from "node:crypto";
import acme from "acme-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApi } from "../src/api/app.js";
import type { Db } from "../src/db/db.js";
import * as subs from "../src/lib/subdomains.js";
import { freshDb, person, platform } from "./helpers.js";

let db: Db;
let p: ReturnType<typeof platform>;
let api: ReturnType<typeof buildApi>;
const ctx = () => ({ db, dns: p.dns, rootDomain: "example.test", limit: 1 });

beforeAll(async () => {
  db = await freshDb();
  p = platform(db);
  api = buildApi(p.deps);
});
afterAll(async () => {
  await api.close();
  await db.end();
});

const post = (url: string, payload: unknown, token?: string, ip = "198.51.100.20") =>
  api.inject({ method: "POST", url, payload: payload as object, remoteAddress: ip, headers: token ? { authorization: `Bearer ${token}` } : {} });
const get = (url: string, token?: string) => api.inject({ method: "GET", url, headers: token ? { authorization: `Bearer ${token}` } : {} });

async function station(label: string) {
  const owner = await person(db);
  const { id, accessCode } = await subs.claim(ctx(), { id: owner, ip: null }, label);
  return { owner, id, accessCode };
}

let nextIp = 1;
async function registered(label: string) {
  const s = await station(label);
  const r = await post("/v1/studio/register", { hostname: `${label}.example.test`, access_code: s.accessCode, install_id: "install-1", app_version: "0.1.0" }, undefined, `192.0.2.${nextIp++}`);
  expect(r.statusCode).toBe(200);
  return { ...s, ...(r.json() as { studio_token: string; studio_id: string; fqdn: string }) };
}

describe("3.1 register", () => {
  it("gives a 30-day token for the right code, and the contract's errors otherwise", async () => {
    const s = await station("kfm");
    const ok = await post("/v1/studio/register", { hostname: "KFM", access_code: s.accessCode.toLowerCase(), install_id: "i", app_version: "1" });
    expect(ok.statusCode).toBe(200);
    const body = ok.json();
    expect(body).toMatchObject({ fqdn: "kfm.example.test" });
    expect(body.studio_token).toMatch(/^[\w-]{43}$/);
    const days = (Date.parse(body.token_expires_at) - Date.now()) / 86400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(body.token_expires_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);

    const wrong = await post("/v1/studio/register", { hostname: "kfm", access_code: "WRONG", install_id: "i" });
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json()).toEqual({ error: { code: "invalid_credentials", message: expect.any(String) } });
    const none = await post("/v1/studio/register", { hostname: "nosuch", access_code: "X", install_id: "i" });
    expect(none.statusCode).toBe(404);
    expect(none.json().error.code).toBe("hostname_not_found");
    // Only a hash of the token is kept.
    const kept = await db.query("SELECT token_hash FROM studio_tokens");
    expect(kept.rows.every((r) => !String(r.token_hash).includes(body.studio_token))).toBe(true);
  });

  it("limits attempts per hostname", async () => {
    await station("busyfm");
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await post("/v1/studio/register", { hostname: "busyfm", access_code: "X" }, undefined, `203.0.113.${i}`)).statusCode;
    expect(last).toBe(429);
  });
});

describe("3.2 DNS update", () => {
  it("points the name at the caller, calls the provider only on a change, and returns the current FQDN", async () => {
    const s = await registered("ddnsfm");
    const calls = p.provider.calls;
    const first = await post("/v1/ddns/update", { ip_override: null, port: 25433 }, s.studio_token, "198.51.100.7");
    expect(first.json()).toEqual({ ip: "198.51.100.7", changed: true, dns_status: "propagated", fqdn: "ddnsfm.example.test", via: "direct" });
    expect(p.provider.get("ddnsfm.example.test", "A")).toEqual(["198.51.100.7"]);
    const again = await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.7");
    expect(again.json().changed).toBe(false);
    expect(p.provider.calls - calls).toBeLessThanOrEqual(2); // the A record (and clearing a stale AAAA), once
    // An override, then IPv6: AAAA replaces A.
    expect((await post("/v1/ddns/update", { ip_override: "198.51.100.9", port: 25433 }, s.studio_token)).json().ip).toBe("198.51.100.9");
    await post("/v1/ddns/update", { ip_override: "2001:db8::5", port: 25433 }, s.studio_token);
    expect(p.provider.get("ddnsfm.example.test", "AAAA")).toEqual(["2001:db8::5"]);
    expect(p.provider.get("ddnsfm.example.test", "A")).toEqual([]);
    const row = (await db.query("SELECT last_ip, last_port, online FROM studios st JOIN subdomains s ON s.id = st.subdomain_id WHERE s.label = 'ddnsfm'")).rows[0];
    expect(row).toEqual({ last_ip: "2001:db8::5", last_port: 25433, online: true });
  });

  it("reports pending when the provider fails, and retries later", async () => {
    const s = await registered("flakyfm");
    p.provider.failNext = 10;
    expect((await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.30")).json().dns_status).toBe("pending");
    p.provider.failNext = 0;
    expect(await p.dns.retryPending()).toBeGreaterThanOrEqual(1);
    expect(p.provider.get("flakyfm.example.test", "A")).toEqual(["198.51.100.30"]);
    expect((await db.query("SELECT count(*)::int AS n FROM ops_events WHERE kind = 'dns'")).rows[0].n).toBeGreaterThan(0);
  });

  it("never touches the platform's own names", async () => {
    await expect(p.dns.pointAt("api.example.test", "198.51.100.1")).rejects.toThrow(/protected/);
    await expect(p.dns.pointAt("example.test", "198.51.100.1")).rejects.toThrow(/protected/);
    await expect(p.dns.pointAt("a.b.example.test", "198.51.100.1")).rejects.toThrow(/protected/);
  });
});

describe("3.3 certificates", () => {
  it("accepts a CSR naming only the station, and refuses any other name", async () => {
    const s = await registered("certfm");
    const [, other] = await acme.crypto.createCsr({ commonName: "evil.example.test" });
    const refused = await post("/v1/cert/csr", { csr_pem: other.toString() }, s.studio_token);
    expect(refused.statusCode).toBe(400);
    expect(refused.json().error.code).toBe("invalid_csr");
    const [, extra] = await acme.crypto.createCsr({ commonName: "certfm.example.test", altNames: ["certfm.example.test", "x.example.test"] });
    expect((await post("/v1/cert/csr", { csr_pem: extra.toString() }, s.studio_token)).statusCode).toBe(400);
    const [, good] = await acme.crypto.createCsr({ commonName: "certfm.example.test", altNames: ["certfm.example.test"] });
    const ok = await post("/v1/cert/csr", { csr_pem: good.toString() }, s.studio_token);
    expect(ok.statusCode).toBe(202);
    expect(ok.json()).toEqual({ status: "pending" });
    expect((await get("/v1/cert", s.studio_token)).json()).toEqual({ status: "pending" });
  });
});

describe("3.4 reachability", () => {
  it("calls the studio's probe with its name and checks the install id", async () => {
    const s = await registered("probefm");
    const [key, csr] = await acme.crypto.createCsr({ commonName: "probefm.example.test" });
    void csr;
    // A stand-in studio: any certificate is accepted (self-signed during setup).
    const selfSigned = await selfSignedCert(key.toString());
    const studio = createServer({ key, cert: selfSigned }, (req, res) => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ install_id: req.headers.host?.startsWith("probefm.example.test") ? "install-1" : "other" }));
    });
    await new Promise<void>((r) => studio.listen(0, "127.0.0.1", () => r()));
    const port = (studio.address() as { port: number }).port;
    await post("/v1/ddns/update", { ip_override: "127.0.0.1", port }, s.studio_token);
    const r = (await post("/v1/reachability/probe", { port }, s.studio_token)).json();
    expect(r.reachable).toBe(true);
    expect(r.latency_ms).toBeGreaterThanOrEqual(0);
    // One a 10 s per studio.
    expect((await post("/v1/reachability/probe", { port }, s.studio_token)).statusCode).toBe(429);
    studio.close();
  });

  it("never probes a private address in production", async () => {
    const q = platform(db, { allowPrivateProbe: false });
    const api2 = buildApi(q.deps);
    const s = await registered("privfm");
    await post("/v1/ddns/update", { ip_override: "10.0.0.5", port: 25433 }, s.studio_token);
    const r = await api2.inject({ method: "POST", url: "/v1/reachability/probe", payload: { port: 25433 }, headers: { authorization: `Bearer ${s.studio_token}` } });
    expect(r.json()).toMatchObject({ reachable: false, error: expect.stringContaining("not a public") });
    await api2.close();
  });
});

describe("3.5 ICE servers", () => {
  it("returns STUN and 6-hour TURN credentials in coturn's scheme", async () => {
    const s = await registered("icefm");
    const r = (await get("/v1/ice-servers", s.studio_token)).json();
    expect(r.ttl_seconds).toBe(21600);
    expect(r.ice_servers[0]).toEqual({ urls: ["stun:turn.example.test:3478"] });
    const turn = r.ice_servers[1];
    expect(turn.urls).toEqual(["turn:turn.example.test:3478?transport=udp", "turns:turn.example.test:443?transport=tcp"]);
    const [expiry, studioId] = turn.username.split(":");
    expect(studioId).toBe(s.studio_id);
    expect(Number(expiry) - Date.now() / 1000).toBeGreaterThan(21590);
    expect(turn.credential).toBe(createHmac("sha1", "turn-secret").update(turn.username).digest("base64"));
  });
});

describe("dashboard actions as the studio sees them", () => {
  it("rename: the next heartbeat brings the new name; the old one cools down and leaves DNS", async () => {
    const s = await registered("renamefm");
    await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.40");
    await subs.rename(ctx(), { id: s.owner, ip: null }, s.id, "renamefm-fm");
    expect(p.provider.get("renamefm.example.test", "A")).toEqual([]);
    expect(p.provider.get("renamefm-fm.example.test", "A")).toEqual(["198.51.100.40"]);
    const beat = (await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.40")).json();
    expect(beat.fqdn).toBe("renamefm-fm.example.test");
    const other = await person(db);
    await expect(subs.claim(ctx(), { id: other, ip: null }, "renamefm")).rejects.toThrow(/recently released/);
  });

  it("regenerate: the old code and every token stop at once", async () => {
    const s = await registered("regenfm");
    const code = await subs.regenerate(ctx(), { id: s.owner, ip: null }, s.id);
    expect((await get("/v1/ice-servers", s.studio_token)).statusCode).toBe(401);
    expect((await post("/v1/studio/register", { hostname: "regenfm", access_code: s.accessCode }, undefined, "192.0.2.200")).statusCode).toBe(401);
    expect((await post("/v1/studio/register", { hostname: "regenfm", access_code: code }, undefined, "192.0.2.201")).statusCode).toBe(200);
  });

  it("suspend: DNS goes, the API and the relay answer 403", async () => {
    const s = await registered("suspfm");
    await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.50");
    await subs.setSuspended(ctx(), { id: s.owner, ip: null, admin: true }, s.id, true);
    expect(p.provider.get("suspfm.example.test", "A")).toEqual([]);
    for (const r of [await get("/v1/ice-servers", s.studio_token), await post("/v1/ddns/update", { port: 1 }, s.studio_token)]) {
      expect(r.statusCode).toBe(403);
      expect(r.json().error.code).toBe("suspended");
    }
    expect((await post("/v1/studio/register", { hostname: "suspfm", access_code: s.accessCode }, undefined, "192.0.2.202")).json().error.code).toBe("suspended");
    await subs.setSuspended(ctx(), { id: s.owner, ip: null, admin: true }, s.id, false);
    expect(p.provider.get("suspfm.example.test", "A")).toEqual(["198.51.100.50"]);
  });

  it("delete: DNS, tokens and the name all go; the name cools down", async () => {
    const s = await registered("delfm");
    await post("/v1/ddns/update", { port: 25433 }, s.studio_token, "198.51.100.60");
    await subs.remove(ctx(), { id: s.owner, ip: null }, s.id);
    expect(p.provider.get("delfm.example.test", "A")).toEqual([]);
    expect((await get("/v1/ice-servers", s.studio_token)).statusCode).toBe(401);
    expect((await db.query("SELECT 1 FROM name_cooldowns WHERE label = 'delfm' AND available_after > now() + interval '29 days'")).rowCount).toBe(1);
  });

  it("two people racing for one name: exactly one gets it", async () => {
    const people = await Promise.all(Array.from({ length: 8 }, () => person(db)));
    const results = await Promise.allSettled(people.map((id) => subs.claim(ctx(), { id, ip: null }, "racefm")));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect((await db.query("SELECT count(*)::int AS n FROM subdomains WHERE label = 'racefm'")).rows[0].n).toBe(1);
  });

  it("keeps to the plan limit", async () => {
    const owner = await person(db);
    await subs.claim(ctx(), { id: owner, ip: null }, "onefm");
    await expect(subs.claim(ctx(), { id: owner, ip: null }, "twofm")).rejects.toThrow(/plan allows 1/);
  });

  it("logs every action", async () => {
    const actions = (await db.query("SELECT DISTINCT action FROM audit_log")).rows.map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(["subdomain.create", "subdomain.rename", "subdomain.regenerate_code", "subdomain.suspend", "subdomain.delete"]));
  });
});

describe("TURN usage from the coturn host", () => {
  it("adds up bytes and sessions per studio and day, with its own token", async () => {
    const s = await registered("usagefm");
    const send = (token: string) => api.inject({ method: "POST", url: "/internal/turn-usage", headers: { authorization: `Bearer ${token}` },
      payload: { records: [{ studio_id: s.studio_id, day: "2026-10-31", bytes: 1000, sessions: 1 }] } });
    expect((await send("wrong")).statusCode).toBe(401);
    await send("usage-token");
    await send("usage-token");
    expect((await db.query("SELECT bytes_relayed::int AS b, sessions FROM turn_usage WHERE studio_id = $1", [s.studio_id])).rows[0]).toEqual({ b: 2000, sessions: 2 });
  });
});

async function selfSignedCert(keyPem: string): Promise<string> {
  const { X509CertificateGenerator, PemConverter } = await import("@peculiar/x509");
  const { webcrypto, createPrivateKey, createPublicKey } = await import("node:crypto");
  const priv = createPrivateKey(keyPem);
  const der = priv.export({ format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(priv).export({ format: "der", type: "spki" });
  const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const keys = {
    privateKey: await webcrypto.subtle.importKey("pkcs8", der, alg, true, ["sign"]),
    publicKey: await webcrypto.subtle.importKey("spki", pubDer, alg, true, ["verify"]),
  };
  const cert = await X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=localhost", notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 86400_000), keys, signingAlgorithm: alg });
  return PemConverter.encode(cert.rawData, "CERTIFICATE");
}

describe("the tunnel's edge (Nova's docs/TUNNEL.md)", () => {
  // A second platform on the same database, running an edge.
  let edged: ReturnType<typeof platform>;
  let edgeApi: ReturnType<typeof buildApi>;
  beforeAll(() => {
    edged = platform(db, { edgeIp: "203.0.113.50", edgeHost: "edge.example.test:443" });
    edgeApi = buildApi(edged.deps);
  });
  afterAll(async () => {
    await edgeApi.close();
  });
  const on = (url: string, payload: unknown, token?: string, ip = "198.51.100.30") =>
    edgeApi.inject({ method: "POST", url, payload: payload as object, remoteAddress: ip, headers: token ? { authorization: `Bearer ${token}` } : {} });

  it("is offered at registration only while the platform runs one", async () => {
    const plain = await registered("noedgefm");
    expect(plain).not.toHaveProperty("tunnel");
    const s = await station("edgefm");
    const r = await on("/v1/studio/register", { hostname: "edgefm", access_code: s.accessCode, install_id: "i", app_version: "0.2.27" });
    expect(r.json().tunnel).toEqual({ edge: "edge.example.test:443", server_name: "edge.example.test", ports: [443, 25433] });
  });

  it("behind a proxy that keeps 443, the offer names the edge's own ports", async () => {
    const proxied = buildApi(platform(db, { edgeIp: "203.0.113.50", edgeHost: "edge.example.test:4433", edgePorts: [25433] }).deps);
    const s = await station("proxiedfm");
    const r = await proxied.inject({ method: "POST", url: "/v1/studio/register", remoteAddress: "192.0.2.93",
      payload: { hostname: "proxiedfm", access_code: s.accessCode } });
    expect(r.json().tunnel).toEqual({ edge: "edge.example.test:4433", server_name: "edge.example.test", ports: [25433] });
    await proxied.close();
  });

  it("via tunnel points the name at the edge and keeps the station's own address for the probe", async () => {
    const s = await station("viafm");
    const token = (await on("/v1/studio/register", { hostname: "viafm", access_code: s.accessCode }, undefined, "192.0.2.90")).json().studio_token;
    const through = await on("/v1/ddns/update", { port: 25433, via: "tunnel" }, token, "198.51.100.44");
    expect(through.json()).toMatchObject({ ip: "198.51.100.44", via: "tunnel", fqdn: "viafm.example.test" });
    expect(edged.provider.get("viafm.example.test", "A")).toEqual(["203.0.113.50"]);
    const row = async () => (await db.query("SELECT last_ip, via FROM studios st JOIN subdomains s ON s.id = st.subdomain_id WHERE s.label = 'viafm'")).rows[0];
    expect(await row()).toEqual({ last_ip: "198.51.100.44", via: "tunnel" });
    // Back to direct: the name follows the station again.
    await on("/v1/ddns/update", { port: 25433, via: "direct" }, token, "198.51.100.44");
    expect(edged.provider.get("viafm.example.test", "A")).toEqual(["198.51.100.44"]);
    expect((await row()).via).toBe("direct");
    // Nonsense is refused; and a platform without an edge stays direct whatever is asked.
    expect((await on("/v1/ddns/update", { port: 25433, via: "sideways" }, token)).statusCode).toBe(400);
    const plain = await registered("plainviafm");
    const asked = await post("/v1/ddns/update", { port: 25433, via: "tunnel" }, plain.studio_token, "198.51.100.45");
    expect(asked.json().via).toBe("direct");
    expect(p.provider.get("plainviafm.example.test", "A")).toEqual(["198.51.100.45"]);
  });

  it("checks a station's token for the edge, with the edge's own token", async () => {
    const s = await station("authfm");
    const token = (await on("/v1/studio/register", { hostname: "authfm", access_code: s.accessCode }, undefined, "192.0.2.91")).json().studio_token;
    const ask = (studioToken: string, edgeToken = "edge-token") => on("/internal/edge/auth", { token: studioToken }, edgeToken);
    expect((await ask(token, "wrong")).statusCode).toBe(401);
    expect((await ask(token)).json()).toMatchObject({ ok: true, fqdn: "authfm.example.test" });
    expect((await ask("not-a-token")).json()).toMatchObject({ ok: false, code: "invalid_token" });
    await subs.setSuspended(ctx(), { id: s.owner, ip: null, admin: true }, s.id, true);
    expect((await ask(token)).json()).toMatchObject({ ok: false, code: "suspended" });
  });

  it("hands the edge its certificate with the edge's token only", async () => {
    const cert = (token: string) => edgeApi.inject({ method: "GET", url: "/internal/edge-cert", headers: { authorization: `Bearer ${token}` } });
    expect((await cert("usage-token")).statusCode).toBe(401); // coturn's token is not the edge's
    expect((await cert("edge-token")).statusCode).toBe(404); // not issued yet
    await db.query("INSERT INTO platform_certs (name, key_enc, cert_pem) VALUES ('edge', $1, 'CERT') ON CONFLICT (name) DO UPDATE SET cert_pem = 'CERT'",
      [(await import("../src/lib/secrets.js")).encrypt("session-secret", "KEY")]);
    expect((await cert("edge-token")).json()).toMatchObject({ cert_pem: "CERT", key_pem: "KEY" });
  });

  it("restored or renamed, a station that comes in through the edge stays pointed at the edge", async () => {
    const s = await station("keepfm");
    const token = (await on("/v1/studio/register", { hostname: "keepfm", access_code: s.accessCode }, undefined, "192.0.2.92")).json().studio_token;
    await on("/v1/ddns/update", { port: 25433, via: "tunnel" }, token, "198.51.100.61");
    const c = { ...ctx(), dns: edged.dns, edgeIp: "203.0.113.50" };
    await subs.setSuspended(c, { id: s.owner, ip: null, admin: true }, s.id, true);
    expect(edged.provider.get("keepfm.example.test", "A")).toEqual([]);
    await subs.setSuspended(c, { id: s.owner, ip: null, admin: true }, s.id, false);
    expect(edged.provider.get("keepfm.example.test", "A")).toEqual(["203.0.113.50"]);
    await subs.rename(c, { id: s.owner, ip: null }, s.id, "keptfm");
    expect(edged.provider.get("keptfm.example.test", "A")).toEqual(["203.0.113.50"]);
  });

  it("edge is the platform's name: no station may take it", async () => {
    const owner = await person(db);
    await expect(subs.claim(ctx(), { id: owner, ip: null }, "edge")).rejects.toThrow();
  });
});
