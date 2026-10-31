/**
 * TURN usage, from the coturn host to the platform (spec section 6). Runs beside coturn
 * (`node dist/main.js turn-usage`): follows coturn's log, adds up relayed bytes and
 * sessions per studio per day, and posts them to the API's /internal/turn-usage every
 * minute. The studio id comes from the credential's username, "<expiry>:<studio_id>".
 *
 * Lines it reads (coturn with `verbose`):
 *   ...: session 0001: usage: realm=<...>, username=<1793494455:STUDIO>, rp=31, rb=3788, sp=31, sb=3012
 *   ...: session 0001: closed (2nd stage), user <1793494455:STUDIO> realm <...> ...
 * Bytes are the client side's received + sent; each closed session counts once.
 */

import { closeSync, existsSync, openSync, readFileSync, readSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const USAGE = /^(\d{4}-\d{2}-\d{2})\S*:? session \S+: usage: .*username=<\d+:([0-9a-f-]{36})>.*\brb=(\d+), sp=\d+, sb=(\d+)/i;
const CLOSED = /^(\d{4}-\d{2}-\d{2})\S*:? session \S+: closed \(2nd stage\), user <\d+:([0-9a-f-]{36})>/i;

export interface UsageRecord {
  studio_id: string;
  day: string;
  bytes: number;
  sessions: number;
}

/** Add up a batch of log lines. */
export function tally(lines: string[]): UsageRecord[] {
  const by = new Map<string, UsageRecord>();
  const get = (day: string, studio: string) => {
    const key = `${studio}|${day}`;
    let r = by.get(key);
    if (!r) by.set(key, (r = { studio_id: studio.toLowerCase(), day, bytes: 0, sessions: 0 }));
    return r;
  };
  for (const line of lines) {
    const u = USAGE.exec(line);
    if (u && !line.includes("peer usage:")) {
      get(u[1], u[2]).bytes += Number(u[3]) + Number(u[4]);
      continue;
    }
    const c = CLOSED.exec(line);
    if (c) get(c[1], c[2]).sessions += 1;
  }
  return [...by.values()];
}

/** Follow a log file (surviving rotation) and ship totals every `everyMs`. */
export function ship(opts: { logFile: string; apiBase: string; token: string; everyMs?: number }) {
  let offset = 0;
  let carry = "";
  try {
    offset = statSync(opts.logFile).size; // start at the end: earlier lines were shipped before
  } catch {
    offset = 0;
  }
  const pending: string[] = [];
  const read = () => {
    let size: number;
    try {
      size = statSync(opts.logFile).size;
    } catch {
      return;
    }
    if (size < offset) offset = 0; // rotated
    if (size === offset) return;
    const fd = openSync(opts.logFile, "r");
    try {
      const buf = Buffer.alloc(size - offset);
      readSync(fd, buf, 0, buf.length, offset);
      offset = size;
      const text = carry + buf.toString("utf8");
      const lines = text.split("\n");
      carry = lines.pop() ?? "";
      pending.push(...lines);
    } finally {
      closeSync(fd);
    }
  };
  const send = async () => {
    read();
    if (!pending.length) return;
    const records = tally(pending.splice(0));
    if (!records.length) return;
    try {
      const res = await fetch(`${opts.apiBase.replace(/\/$/, "")}/internal/turn-usage`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${opts.token}` },
        body: JSON.stringify({ records }), signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`status ${res.status}`);
    } catch (e) {
      console.error(`turn-usage: could not send (${(e as Error).message}); will retry`);
      // Put them back as synthetic lines is lossy; keep the totals and retry next time.
      retry.push(...records);
    }
  };
  const retry: UsageRecord[] = [];
  const flushRetry = async () => {
    if (!retry.length) return;
    const records = retry.splice(0);
    const res = await fetch(`${opts.apiBase.replace(/\/$/, "")}/internal/turn-usage`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${opts.token}` },
      body: JSON.stringify({ records }), signal: AbortSignal.timeout(10_000),
    }).catch(() => null);
    if (!res?.ok) retry.push(...records);
  };
  const timer = setInterval(() => void flushRetry().then(send), opts.everyMs ?? 60_000);
  return { stop: () => clearInterval(timer), tick: () => flushRetry().then(send) };
}

/**
 * Keep coturn's certificate (turn.<root>, issued by the platform's worker) current: fetch
 * it every hour, write fullchain.pem and privkey.pem when it changed, and send coturn
 * SIGUSR2 so it reloads them (`reloadPid`, coturn's process id; 1 when the shipper shares
 * coturn's process namespace, as in deploy/turn/docker-compose.yml).
 */
export function keepTurnCert(opts: { apiBase: string; token: string; dir: string; reloadPid?: number; everyMs?: number }) {
  const run = async () => {
    try {
      const res = await fetch(`${opts.apiBase.replace(/\/$/, "")}/internal/turn-cert`, {
        headers: { Authorization: `Bearer ${opts.token}` }, signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) return;
      const got = (await res.json()) as { cert_pem: string; key_pem: string };
      const certFile = join(opts.dir, "fullchain.pem");
      if (existsSync(certFile) && readFileSync(certFile, "utf8") === got.cert_pem) return;
      writeFileSync(join(opts.dir, "privkey.pem"), got.key_pem, { mode: 0o600 });
      writeFileSync(certFile, got.cert_pem);
      if (opts.reloadPid) process.kill(opts.reloadPid, "SIGUSR2");
      console.log("turn certificate updated");
    } catch (e) {
      console.error(`turn certificate: ${(e as Error).message}`);
    }
  };
  void run();
  const timer = setInterval(() => void run(), opts.everyMs ?? 3600_000);
  return { stop: () => clearInterval(timer), run };
}
