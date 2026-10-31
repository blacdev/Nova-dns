/**
 * `api.ROOT_DOMAIN`: the studio API (`/v1/...`), the coturn host's usage endpoint,
 * health and metrics. JSON only; every error is `{"error": {"code", "message"}}`.
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { decrypt, sameString } from "../lib/secrets.js";
import { ApiError, unauthorized } from "../lib/errors.js";
import * as studio from "./studio.js";
import type { Deps } from "./studio.js";

type Body = Record<string, unknown>;

export function buildApi(d: Deps): FastifyInstance {
  const app = Fastify({
    // X-Forwarded-For is believed only from the reverse proxy (spec 3.2).
    trustProxy: d.config.trustedProxies,
    bodyLimit: 64 * 1024,
    logger: false,
  });

  app.addHook("onRequest", async (_req, reply) => {
    reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    reply.header("Cache-Control", "no-store");
  });
  app.addHook("onResponse", async (req, reply) => {
    d.metrics.add(`http_requests_total{route="${req.routeOptions.url ?? "unknown"}",status="${reply.statusCode}"}`);
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof ApiError) {
      for (const [k, v] of Object.entries(err.headers)) reply.header(k, v);
      return reply.status(err.status).send(err.body());
    }
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status < 500) return reply.status(status).send({ error: { code: "invalid_request", message: (err as Error).message } });
    console.error("api error:", err);
    return reply.status(500).send({ error: { code: "internal", message: "Something went wrong on the platform." } });
  });
  app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: { code: "not_found", message: "No such endpoint." } }));

  const body = (req: FastifyRequest): Body => (req.body && typeof req.body === "object" ? (req.body as Body) : {});
  const who = (req: FastifyRequest) => studio.studioFor(d, req.headers.authorization);

  app.post("/v1/studio/register", async (req) => studio.register(d, body(req), req.ip));
  app.post("/v1/ddns/update", async (req) => studio.ddnsUpdate(d, await who(req), body(req), req.ip));
  app.post("/v1/cert/csr", async (req, reply) => reply.status(202).send(await studio.submitCsr(d, await who(req), body(req))));
  app.get("/v1/cert", async (req) => studio.currentCertificate(d, await who(req)));
  app.post("/v1/reachability/probe", async (req) => studio.probe(d, await who(req), body(req)));
  app.get("/v1/ice-servers", async (req) => studio.iceServers(d, await who(req)));

  // The coturn host reports relayed bytes and sessions per studio (deploy/turn/usage-shipper).
  app.post("/internal/turn-usage", async (req) => {
    const given = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    if (!d.config.turnUsageToken || !sameString(given, d.config.turnUsageToken)) throw unauthorized("Not allowed.", "forbidden");
    return studio.recordTurnUsage(d, body(req));
  });

  // The coturn host fetches turn.<root>'s certificate (issued by the worker).
  app.get("/internal/turn-cert", async (req, reply) => {
    const given = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    if (!d.config.turnUsageToken || !sameString(given, d.config.turnUsageToken)) throw unauthorized("Not allowed.", "forbidden");
    const row = (await d.db.query<{ key_enc: string; cert_pem: string | null; expires_at: Date | null }>("SELECT key_enc, cert_pem, expires_at FROM platform_certs WHERE name = 'turn'")).rows[0];
    if (!row?.cert_pem) return reply.status(404).send({ error: { code: "not_ready", message: "Not issued yet." } });
    return { cert_pem: row.cert_pem, key_pem: decrypt(d.config.sessionSecret, row.key_enc), expires_at: row.expires_at };
  });

  app.get("/healthz", async (_req, reply) => {
    try {
      await d.db.query("SELECT 1");
      return { ok: true };
    } catch {
      return reply.status(503).send({ ok: false });
    }
  });
  app.get("/metrics", async (_req, reply) => {
    reply.type("text/plain; version=0.0.4");
    return metricsText(d);
  });
  return app;
}

/** Prometheus text: this process's counters, and totals read from the database. */
export async function metricsText(d: Deps): Promise<string> {
  const lines: string[] = [];
  for (const [name, value] of d.metrics.counters) lines.push(`nova_${name} ${value}`);
  const q = async (sql: string) => Number((await d.db.query(sql)).rows[0]?.n ?? 0);
  lines.push(`nova_studios_online ${await q("SELECT count(*) AS n FROM studios WHERE online")}`);
  lines.push(`nova_subdomains ${await q("SELECT count(*) AS n FROM subdomains")}`);
  lines.push(`nova_certificates_issued_7d ${await q("SELECT count(*) AS n FROM certificates WHERE issued_at > now() - interval '7 days' AND renews_id IS NULL")}`);
  lines.push(`nova_certificates_pending ${await q("SELECT count(*) AS n FROM certificates WHERE status = 'pending'")}`);
  lines.push(`nova_turn_bytes_today ${await q("SELECT coalesce(sum(bytes_relayed), 0) AS n FROM turn_usage WHERE day = current_date")}`);
  return lines.join("\n") + "\n";
}
