/**
 * DNS manager (spec section 4). Providers implement `upsertRecord` / `deleteRecord`;
 * the manager adds what every provider needs:
 *
 * - **Protected names**: the platform's own records (the zone apex, `api`, `app`,
 *   `turn`, and any reserved name) can never be touched through a studio flow.
 * - **Only on a change**: what the provider holds is mirrored in `dns_records`, so a
 *   heartbeat with the same address does not call the provider.
 * - **Retries** with backoff; a failure is logged for admins and the record is marked
 *   `pending` (the worker tries again).
 */

import type { Db, Queryable } from "../db/db.js";
import { opsEvent } from "../lib/audit.js";

export type RecordType = "A" | "AAAA" | "TXT";

export interface DnsProvider {
  readonly name: string;
  /** Create or replace the record (name, type) with exactly this value. Returns the provider's id. */
  upsertRecord(name: string, type: RecordType, value: string, ttl: number): Promise<string | null>;
  /** Remove the record (name, type); with `value`, only that one (TXT records can be several). */
  deleteRecord(name: string, type: RecordType, value?: string): Promise<void>;
  /** Try the provider out for real (read, write, the right zone) and say what is wrong in plain words. */
  check?(rootDomain: string): Promise<DnsCheckStep[]>;
}

/** One line of a setup check: `ok` null means "could not tell", which is not a failure. */
export interface DnsCheckStep {
  name: string;
  ok: boolean | null;
  detail: string;
}

export const STUDIO_TTL = 60;
const PLATFORM_LABELS = new Set(["api", "app", "turn", "www", "_acme-challenge"]);

export class DnsManager {
  constructor(private db: Db, private provider: DnsProvider, private rootDomain: string, private sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))) {}

  get providerName() {
    return this.provider.name;
  }

  /** The provider's own setup check; null when it has none (memory, tests). */
  async check(): Promise<DnsCheckStep[] | null> {
    return this.provider.check ? this.provider.check(this.rootDomain) : null;
  }

  /** Whether a studio flow may touch this name: `<label>.<root>` or its ACME challenge only. */
  async allowed(name: string): Promise<boolean> {
    const root = `.${this.rootDomain}`;
    if (!name.endsWith(root)) return false;
    const rest = name.slice(0, -root.length).split(".");
    const label = rest[0] === "_acme-challenge" ? rest[1] : rest[0];
    if (rest.length > (rest[0] === "_acme-challenge" ? 2 : 1) || !label || PLATFORM_LABELS.has(label)) return false;
    const reserved = await this.db.query("SELECT 1 FROM reserved_names WHERE label = $1 AND kind = 'reserved'", [label]);
    return reserved.rowCount === 0;
  }

  private async retry<T>(what: string, target: string, work: () => Promise<T>): Promise<T> {
    let last: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt) await this.sleep(500 * 2 ** (attempt - 1) * (1 + Math.random() / 2));
      try {
        return await work();
      } catch (e) {
        last = e;
      }
    }
    await opsEvent(this.db, "dns", `${what} failed: ${(last as Error)?.message ?? last}`, target);
    throw last;
  }

  /**
   * Point `name` at `ip` (an A or AAAA record by the address's kind), replacing what was
   * there. Returns whether the provider was called (the address changed) and whether it
   * now holds the record.
   */
  async pointAt(name: string, ip: string): Promise<{ changed: boolean; ok: boolean }> {
    if (!(await this.allowed(name))) throw new Error(`refusing to change a protected name: ${name}`);
    const type: RecordType = ip.includes(":") ? "AAAA" : "A";
    const other: RecordType = type === "A" ? "AAAA" : "A";
    const now = await this.db.query<{ value: string; status: string }>("SELECT value, status FROM dns_records WHERE name = $1 AND type = $2", [name, type]);
    const same = now.rows.length === 1 && now.rows[0].value === ip && now.rows[0].status === "ok";
    if (same) return { changed: false, ok: true };
    try {
      const id = await this.retry(`set ${type} ${name}`, name, () => this.provider.upsertRecord(name, type, ip, STUDIO_TTL));
      await this.db.query("DELETE FROM dns_records WHERE name = $1 AND type = $2", [name, type]);
      await this.db.query("INSERT INTO dns_records (name, type, value, provider_id, status) VALUES ($1, $2, $3, $4, 'ok')", [name, type, ip, id]);
      // An address of the other kind left over from before would send some browsers astray.
      await this.remove(name, other).catch(() => undefined);
      return { changed: true, ok: true };
    } catch {
      await this.db.query("DELETE FROM dns_records WHERE name = $1 AND type = $2", [name, type]);
      await this.db.query("INSERT INTO dns_records (name, type, value, status) VALUES ($1, $2, $3, 'pending')", [name, type, ip]);
      return { changed: true, ok: false };
    }
  }

  /** Remove a station name's address records (delete, rename, suspend). */
  async removeName(name: string): Promise<void> {
    if (!(await this.allowed(name))) throw new Error(`refusing to change a protected name: ${name}`);
    for (const type of ["A", "AAAA"] as const) await this.remove(name, type);
  }

  private async remove(name: string, type: RecordType): Promise<void> {
    const held = await this.db.query("SELECT 1 FROM dns_records WHERE name = $1 AND type = $2", [name, type]);
    if (!held.rowCount && type !== "A") return;
    await this.retry(`remove ${type} ${name}`, name, () => this.provider.deleteRecord(name, type));
    await this.db.query("DELETE FROM dns_records WHERE name = $1 AND type = $2", [name, type]);
  }

  /** The DNS-01 challenge record for a station name. */
  async setChallenge(fqdn: string, value: string): Promise<void> {
    const name = `_acme-challenge.${fqdn}`;
    if (!(await this.allowed(name))) throw new Error(`refusing to change a protected name: ${name}`);
    await this.retry(`set TXT ${name}`, fqdn, () => this.provider.upsertRecord(name, "TXT", value, STUDIO_TTL));
  }

  /** The challenge for one of the platform's own names (turn.<root>): worker only, never a studio flow. */
  async setPlatformChallenge(label: "turn", value: string): Promise<void> {
    const name = `_acme-challenge.${label}.${this.rootDomain}`;
    await this.retry(`set TXT ${name}`, name, () => this.provider.upsertRecord(name, "TXT", value, STUDIO_TTL));
  }

  async clearPlatformChallenge(label: "turn", value: string): Promise<void> {
    const name = `_acme-challenge.${label}.${this.rootDomain}`;
    await this.retry(`remove TXT ${name}`, name, () => this.provider.deleteRecord(name, "TXT", value)).catch(() => undefined);
  }

  async clearChallenge(fqdn: string, value: string): Promise<void> {
    const name = `_acme-challenge.${fqdn}`;
    if (!(await this.allowed(name))) return;
    await this.retry(`remove TXT ${name}`, fqdn, () => this.provider.deleteRecord(name, "TXT", value)).catch(() => undefined);
  }

  /** Records left `pending` by a failure: try them again (the worker calls this). */
  async retryPending(): Promise<number> {
    const rows = await this.db.query<{ name: string; value: string }>("SELECT name, value FROM dns_records WHERE status = 'pending'");
    let done = 0;
    for (const r of rows.rows) {
      const got = await this.pointAt(r.name, r.value).catch(() => ({ ok: false }));
      if (got.ok) done++;
    }
    return done;
  }
}

/** What a name holds, as this platform last set it (for status pages). */
export async function heldAddress(db: Queryable, name: string): Promise<{ value: string; status: string } | null> {
  const r = await db.query<{ value: string; status: string }>("SELECT value, status FROM dns_records WHERE name = $1 AND type IN ('A', 'AAAA') ORDER BY updated_at DESC LIMIT 1", [name]);
  return r.rows[0] ?? null;
}
