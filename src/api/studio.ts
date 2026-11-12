/**
 * The studio API (spec section 3; the same contract Nova's client speaks,
 * `nova/remote/client.py`). Every call but register needs a studio token, and a token
 * reaches exactly one studio and its one subdomain.
 */

import { connect as tlsConnect } from "node:tls";
import { isIP } from "node:net";
import * as x509 from "@peculiar/x509";
import type { Db } from "../db/db.js";
import { transaction } from "../db/db.js";
import type { DnsManager } from "../dns/dns.js";
import { opsEvent } from "../lib/audit.js";
import { ApiError, badRequest, forbidden, notFound, tooMany, unauthorized } from "../lib/errors.js";
import { hit, LIMITS } from "../lib/limits.js";
import { fqdnOf, normaliseLabel } from "../lib/names.js";
import { canonicalCode, dummyHash, newToken, tokenHash, turnCredential, verifySecret } from "../lib/secrets.js";
import { isPublicAddress } from "../lib/net.js";
import type { Config } from "../config.js";

export const TOKEN_DAYS = 30;
export const ICE_TTL = 6 * 3600;

export interface Studio {
  studioId: string;
  subdomainId: number;
  label: string;
  fqdn: string;
  installId: string | null;
  lastIp: string | null;
}

export interface Deps {
  db: Db;
  dns: DnsManager;
  config: Config;
  metrics: Metrics;
  /** Payment providers' APIs (tests replace the network). */
  fetch?: typeof fetch;
}

export class Metrics {
  counters = new Map<string, number>();
  add(name: string, by = 1) {
    this.counters.set(name, (this.counters.get(name) ?? 0) + by);
  }
}

const stamp = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

// ---------------------------------------------------------------- 3.1 register

export async function register(d: Deps, body: Record<string, unknown>, ip: string) {
  const label = normaliseLabel(String(body.hostname ?? ""), d.config.rootDomain);
  const code = canonicalCode(String(body.access_code ?? ""));
  if (!label || !code) throw badRequest("hostname and access_code are required");
  for (const key of [`register:ip:${ip}`, `register:host:${label}`]) {
    const r = await hit(d.db, key, LIMITS.register);
    if (!r.ok) throw tooMany(r.retryAfter);
  }
  const row = (await d.db.query<{ studio_id: string; access_code_hash: string; sub_status: string; user_status: string; label: string }>(
    `SELECT st.id AS studio_id, st.access_code_hash, s.status AS sub_status, u.status AS user_status, s.label
       FROM subdomains s JOIN studios st ON st.subdomain_id = s.id JOIN users u ON u.id = s.user_id
      WHERE s.label = $1`, [label])).rows[0];
  if (!row) {
    await verifySecret(await dummyHash(), code); // the same time as a real check
    throw new ApiError(404, "hostname_not_found", "There is no station with that hostname.");
  }
  if (!(await verifySecret(row.access_code_hash, code))) throw new ApiError(401, "invalid_credentials", "The access code is wrong.");
  if (row.sub_status !== "active" || row.user_status !== "active") throw forbidden("This station is suspended.", "suspended");
  const token = newToken();
  const expires = new Date(Date.now() + TOKEN_DAYS * 86400_000);
  await d.db.query("INSERT INTO studio_tokens (studio_id, token_hash, expires_at) VALUES ($1, $2, $3)", [row.studio_id, tokenHash(token), expires]);
  await d.db.query("UPDATE studios SET install_id = $2, app_version = $3 WHERE id = $1",
    [row.studio_id, String(body.install_id ?? "").slice(0, 100) || null, String(body.app_version ?? "").slice(0, 50) || null]);
  d.metrics.add("studio_registrations_total");
  return { studio_token: token, token_expires_at: stamp(expires), fqdn: fqdnOf(row.label, d.config.rootDomain), studio_id: row.studio_id,
    ...tunnelOffer(d) };
}

/** The tunnel's edge, offered to every station while the platform runs one (Nova's
 *  docs/TUNNEL.md): where to dial (QUIC), the name on the edge's certificate, and the TCP
 *  ports presenters reach it on (so the station gives out an address the edge serves). */
export function tunnelOffer(d: Deps): { tunnel?: { edge: string; server_name: string; ports: number[] } } {
  if (!d.config.edgeIp) return {};
  return { tunnel: { edge: d.config.edgeHost, server_name: `edge.${d.config.rootDomain}`, ports: d.config.edgePorts } };
}

/** The UDP port stations dial the edge on (EDGE_HOST's port; 443 when it names none). */
export function edgeQuicPort(d: Deps): number {
  const port = Number(/:(\d+)$/.exec(d.config.edgeHost)?.[1] ?? 443);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : 443;
}

/**
 * The port in a station's address for presenters: its own server port when reached
 * directly; through the edge, a port the edge serves (the station's own if the edge
 * serves it, else 443, else the first). Nova works it out the same way
 * (nova/remote/studio.py, snapshot).
 */
export function presenterPort(config: { edgeIp: string; edgePorts: number[] }, via: string | null, ownPort: number | null): number {
  const own = ownPort ?? 25433;
  if (via !== "tunnel" || !config.edgeIp) return own;
  const served = config.edgePorts.length ? config.edgePorts : [443, 25433];
  return served.includes(own) ? own : served.includes(443) ? 443 : served[0];
}

// ---------------------------------------------------------------- who is calling

export async function studioFor(d: Deps, authorization: string | undefined): Promise<Studio> {
  const given = /^Bearer\s+(.+)$/i.exec(authorization ?? "")?.[1]?.trim();
  if (!given) throw unauthorized("A studio token is required.");
  const row = (await d.db.query<{ studio_id: string; subdomain_id: number; label: string; sub_status: string; user_status: string; install_id: string | null; last_ip: string | null }>(
    `SELECT st.id AS studio_id, s.id AS subdomain_id, s.label, s.status AS sub_status, u.status AS user_status, st.install_id, st.last_ip
       FROM studio_tokens t JOIN studios st ON st.id = t.studio_id JOIN subdomains s ON s.id = st.subdomain_id JOIN users u ON u.id = s.user_id
      WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now()`, [tokenHash(given)])).rows[0];
  if (!row) throw unauthorized();
  if (row.sub_status !== "active" || row.user_status !== "active") throw forbidden("This station is suspended.", "suspended");
  return { studioId: row.studio_id, subdomainId: row.subdomain_id, label: row.label, fqdn: fqdnOf(row.label, d.config.rootDomain), installId: row.install_id, lastIp: row.last_ip };
}

// ---------------------------------------------------------------- 3.2 DNS update / heartbeat

export async function ddnsUpdate(d: Deps, s: Studio, body: Record<string, unknown>, sourceIp: string) {
  const override = body.ip_override;
  let ip = sourceIp.replace(/^::ffff:/, "");
  if (override !== null && override !== undefined && override !== "") {
    if (typeof override !== "string" || !isIP(override)) throw badRequest("ip_override must be an IP address");
    ip = override;
  }
  const port = Number(body.port ?? 25433);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw badRequest("port must be 1-65535");
  // "tunnel": the station is reached through the edge, so its name points there. The
  // station's own address is still kept (last_ip): the probe tests the direct way with it.
  const asked = body.via ?? "direct";
  if (asked !== "direct" && asked !== "tunnel") throw badRequest('via must be "direct" or "tunnel"');
  const via = asked === "tunnel" && d.config.edgeIp ? "tunnel" : "direct";
  const set = await d.dns.pointAt(s.fqdn, via === "tunnel" ? d.config.edgeIp : ip);
  if (set.changed) d.metrics.add("dns_updates_total");
  await d.db.query("UPDATE studios SET last_ip = $2, last_port = $3, last_seen_at = now(), online = true, via = $4 WHERE id = $1",
    [s.studioId, ip, port, via]);
  // The edge's offer, now, on every heartbeat: a station learns a changed edge address or
  // ports within minutes, without signing in again. null when the platform runs no edge.
  return { ip, changed: set.changed, dns_status: set.ok ? "propagated" : "pending", fqdn: s.fqdn, via,
    tunnel: tunnelOffer(d).tunnel ?? null };
}

// ---------------------------------------------------------------- the tunnel's edge

/**
 * The edge asks whether a station's token is good when the station dials in, and again
 * every few minutes while it stays (a renamed, suspended or deleted station is let go).
 * The same checks as every studio call (`studioFor`); the answer is the line the edge
 * sends the station (Nova's docs/TUNNEL.md).
 */
export async function edgeAuth(d: Deps, body: Record<string, unknown>) {
  const token = String(body.token ?? "");
  try {
    const s = await studioFor(d, `Bearer ${token}`);
    return { ok: true, fqdn: s.fqdn, studio_id: s.studioId };
  } catch (e) {
    if (e instanceof ApiError && e.status < 500) {
      // An unknown or expired token: the station signs in to the platform again and dials back.
      return { ok: false, code: e.code === "suspended" ? "suspended" : "invalid_token", message: e.message };
    }
    throw e;
  }
}

// ---------------------------------------------------------------- 3.3 certificates

/** The names a CSR asks for, after checking its signature. */
export async function csrNames(pem: string): Promise<string[]> {
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem);
  } catch {
    throw badRequest("csr_pem is not a certificate signing request", "invalid_csr");
  }
  if (!(await csr.verify())) throw badRequest("the CSR's signature does not verify", "invalid_csr");
  const names = new Set<string>();
  for (const cn of csr.subjectName.getField("CN")) names.add(cn.toLowerCase());
  const san = csr.extensions.find((e) => e instanceof x509.SubjectAlternativeNameExtension) as x509.SubjectAlternativeNameExtension | undefined;
  for (const n of san?.names.items ?? []) {
    if (n.type !== "dns") throw badRequest("the CSR may name only the station's address", "invalid_csr");
    names.add(n.value.toLowerCase());
  }
  return [...names];
}

export async function submitCsr(d: Deps, s: Studio, body: Record<string, unknown>) {
  const pem = String(body.csr_pem ?? "");
  const names = await csrNames(pem);
  if (names.length === 0 || names.some((n) => n !== s.fqdn)) {
    throw badRequest(`the CSR must name only ${s.fqdn}`, "invalid_csr");
  }
  await transaction(d.db, async (tx) => {
    // A newer request replaces one still waiting; an issued certificate stays until the new one is out.
    await tx.query("UPDATE certificates SET status = 'superseded' WHERE subdomain_id = $1 AND status = 'pending'", [s.subdomainId]);
    const renews = await tx.query<{ id: number }>("SELECT id FROM certificates WHERE subdomain_id = $1 AND status = 'issued' AND fqdn = $2 ORDER BY issued_at DESC LIMIT 1", [s.subdomainId, s.fqdn]);
    await tx.query("INSERT INTO certificates (subdomain_id, fqdn, status, csr_pem, renews_id) VALUES ($1, $2, 'pending', $3, $4)",
      [s.subdomainId, s.fqdn, pem, renews.rows[0]?.id ?? null]);
  });
  await d.db.query("NOTIFY cert_queue");
  return { status: "pending" };
}

export async function currentCertificate(d: Deps, s: Studio) {
  const row = (await d.db.query<{ status: string; cert_pem: string | null; chain_pem: string | null; expires_at: Date | null; serial: string | null; error: string | null }>(
    `SELECT status, cert_pem, chain_pem, expires_at, serial, error FROM certificates
      WHERE subdomain_id = $1 AND status IN ('pending', 'issued', 'failed') ORDER BY created_at DESC LIMIT 1`, [s.subdomainId])).rows[0];
  if (!row) throw notFound("No certificate has been requested for this station.", "no_certificate");
  if (row.status === "issued") {
    return { status: "issued", cert_pem: row.cert_pem, chain_pem: row.chain_pem, expires_at: row.expires_at ? stamp(row.expires_at) : null, serial: row.serial };
  }
  return row.status === "failed" ? { status: "failed", error: row.error } : { status: "pending" };
}

// ---------------------------------------------------------------- 3.4 reachability

export async function probe(d: Deps, s: Studio, body: Record<string, unknown>) {
  const r = await hit(d.db, `probe:${s.studioId}`, LIMITS.probe);
  if (!r.ok) throw tooMany(r.retryAfter);
  const port = Number(body.port ?? 25433);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw badRequest("port must be 1-65535");
  const ip = s.lastIp;
  if (!ip) return { reachable: false, latency_ms: null, error: "No address yet: the studio has not sent a DNS update." };
  // Never a door into private networks.
  if (!d.config.allowPrivateProbe && !isPublicAddress(ip)) return { reachable: false, latency_ms: null, error: "The studio's address is not a public one." };
  await d.db.query("UPDATE studios SET last_probe_at = now() WHERE id = $1", [s.studioId]);
  const got = await fetchProbe(ip, port, s.fqdn);
  if (got.error) return { reachable: false, latency_ms: null, error: got.error };
  const ok = got.installId !== null && got.installId === s.installId;
  return { reachable: ok, latency_ms: ok ? got.ms : null, error: ok ? null : "Something answered, but it is not this studio." };
}

/** GET https://<fqdn>:<port>/.well-known/studio-probe, sent to `ip` (any certificate accepted). */
export function fetchProbe(ip: string, port: number, fqdn: string, timeoutMs = 5000): Promise<{ installId: string | null; ms: number; error?: string }> {
  const started = Date.now();
  return new Promise((resolve) => {
    let data = Buffer.alloc(0);
    let done = false;
    const finish = (out: { installId: string | null; ms: number; error?: string }) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(out);
    };
    const sock = tlsConnect({ host: ip, port, servername: fqdn, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      sock.write(`GET /.well-known/studio-probe HTTP/1.1\r\nHost: ${fqdn}:${port}\r\nAccept: application/json\r\nConnection: close\r\nUser-Agent: nova-platform-probe\r\n\r\n`);
    });
    sock.setTimeout(timeoutMs, () => finish({ installId: null, ms: 0, error: `No answer within ${timeoutMs / 1000} s (is the port forwarded?).` }));
    sock.on("data", (c) => {
      data = Buffer.concat([data, c]);
      if (data.length > 65536) finish({ installId: null, ms: 0, error: "The answer was too large." });
    });
    sock.on("error", (e) => finish({ installId: null, ms: 0, error: `Could not connect: ${e.message}` }));
    sock.on("end", () => {
      const text = data.toString("utf8");
      const [head, ...rest] = text.split("\r\n\r\n");
      if (!/^HTTP\/1\.[01] 200/.test(head)) return finish({ installId: null, ms: 0, error: `The studio answered ${head.split("\r\n")[0] || "nothing"}.` });
      const body = /transfer-encoding:\s*chunked/i.test(head) ? dechunk(rest.join("\r\n\r\n")) : rest.join("\r\n\r\n");
      try {
        finish({ installId: String((JSON.parse(body) as { install_id?: unknown }).install_id ?? "") || null, ms: Date.now() - started });
      } catch {
        finish({ installId: null, ms: 0, error: "The answer was not the studio's." });
      }
    });
  });
}

function dechunk(s: string): string {
  let out = "";
  let rest = s;
  for (;;) {
    const nl = rest.indexOf("\r\n");
    const n = parseInt(rest.slice(0, nl), 16);
    if (!n) return out;
    out += rest.slice(nl + 2, nl + 2 + n);
    rest = rest.slice(nl + 2 + n + 2);
  }
}

// ---------------------------------------------------------------- 3.5 ICE servers

export function iceServers(d: Deps, s: Studio) {
  const { username, credential } = turnCredential(d.config.turnSharedSecret, s.studioId, ICE_TTL);
  const host = d.config.turnHost;
  return {
    ice_servers: [
      { urls: [`stun:${host}:3478`] },
      { urls: [`turn:${host}:3478?transport=udp`, `turns:${host}:443?transport=tcp`], username, credential },
    ],
    ttl_seconds: ICE_TTL,
  };
}

// ---------------------------------------------------------------- TURN usage (from the coturn host)

export async function recordTurnUsage(d: Deps, body: Record<string, unknown>) {
  const rows = Array.isArray(body.records) ? body.records : [];
  let n = 0;
  for (const r of rows as Record<string, unknown>[]) {
    const studio = String(r.studio_id ?? "");
    const day = String(r.day ?? "");
    if (!/^[0-9a-f-]{36}$/i.test(studio) || !/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    await d.db.query(
      `INSERT INTO turn_usage (studio_id, day, bytes_relayed, sessions) VALUES ($1, $2, $3, $4)
       ON CONFLICT (studio_id, day) DO UPDATE SET bytes_relayed = turn_usage.bytes_relayed + EXCLUDED.bytes_relayed,
         sessions = turn_usage.sessions + EXCLUDED.sessions`,
      [studio, day, Math.max(0, Math.floor(Number(r.bytes) || 0)), Math.max(0, Math.floor(Number(r.sessions) || 0))]);
    n++;
  }
  d.metrics.add("turn_usage_records_total", n);
  return { ok: true, recorded: n };
}

export async function logProbeFailure(d: Deps, s: Studio, error: string) {
  await opsEvent(d.db, "probe", error, s.fqdn, "info");
}
