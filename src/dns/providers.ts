/**
 * DNS providers: Cloudflare (production), memory (development and tests) and
 * Pebble's challenge test server (end-to-end certificate tests, `challtestsrv`).
 */

import { randomBytes } from "node:crypto";
import type { Config } from "../config.js";
import type { DnsCheckStep, DnsProvider, RecordType } from "./dns.js";

// ---------------------------------------------------------------- Cloudflare

interface CfRecord { id: string; name: string; type: string; content: string }
interface CfZone { name: string; status: string; name_servers?: string[] }
interface CfAnswer<T> { status: number; ok: boolean; result?: T; errors: string }

export class CloudflareProvider implements DnsProvider {
  readonly name = "cloudflare";
  constructor(private token: string, private zoneId: string, private base = "https://api.cloudflare.com/client/v4") {}

  /** One request about this zone; never throws for an answer Cloudflare gave. */
  private async ask<T>(method: string, path: string, body?: unknown): Promise<CfAnswer<T>> {
    const res = await fetch(`${this.base}/zones/${this.zoneId}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    const json = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T; errors?: { message: string }[] };
    return { status: res.status, ok: res.ok && json.success !== false, result: json.result, errors: (json.errors ?? []).map((e) => e.message).join("; ") };
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const a = await this.ask<T>(method, path, body);
    if (!a.ok) throw new Error(`Cloudflare ${method} ${path.split("?")[0]}: ${a.status} ${a.errors}`);
    return a.result as T;
  }

  /**
   * The setup check behind the dashboard's "Test the Cloudflare connection": can the
   * token read this zone, can it write to it (a TXT record made and removed), and is the
   * zone the one ROOT_DOMAIN lives in. The wording matches docs/cloudflare-setup.md.
   */
  async check(rootDomain: string): Promise<DnsCheckStep[]> {
    const steps: DnsCheckStep[] = [];
    const guide = "See the setup guide";
    let read: CfAnswer<CfRecord[]>;
    try {
      read = await this.ask<CfRecord[]>("GET", "/dns_records?per_page=1");
    } catch (e) {
      return [{ name: "Reach Cloudflare", ok: false, detail: `Cloudflare could not be reached from this machine (${(e as Error).message}). Check its internet connection and try again.` }];
    }
    if (!read.ok) {
      const detail =
        read.status === 401 || (read.status === 400 && /header|token|authoriz/i.test(read.errors))
          ? `Cloudflare did not accept the token. It may be copied incompletely, deleted, or be the Global API Key. ${guide}, step 5.`
          : read.status === 403
            ? `The token may not use this domain. It was made for another domain, or the Zone ID is another domain's. ${guide}, steps 4 and 5.`
            : read.status === 404 || read.status === 400
              ? `Cloudflare does not know this Zone ID. Copy the Zone ID again (not the Account ID). ${guide}, step 4.`
              : `Cloudflare answered ${read.status}: ${read.errors || "no reason given"}.`;
      return [{ name: "Read the domain's records", ok: false, detail }];
    }
    steps.push({ name: "Read the domain's records", ok: true, detail: "The token and the Zone ID belong together." });

    const zone = await this.ask<CfZone>("GET", "").catch(() => null);
    let zoneName = zone?.ok ? zone.result?.name ?? "" : "";

    const probe = `_nova-setup-check.${rootDomain}`;
    const made = await this.ask<CfRecord>("POST", "/dns_records", { type: "TXT", name: probe, content: `"nova-${randomBytes(6).toString("hex")}"`, ttl: 60, proxied: false })
      .catch((e) => ({ status: 0, ok: false, result: undefined, errors: (e as Error).message }) as CfAnswer<CfRecord>);
    if (made.ok && made.result) {
      await this.ask("DELETE", `/dns_records/${made.result.id}`).catch(() => undefined);
      // Cloudflare puts a name from outside the zone under the zone's own name: that shows a wrong zone.
      if (!zoneName && made.result.name !== probe && made.result.name.startsWith(`${probe}.`)) zoneName = made.result.name.slice(probe.length + 1);
      steps.push({ name: "Change the domain's records", ok: true, detail: "A test record was added and removed." });
    } else {
      steps.push({
        name: "Change the domain's records", ok: false,
        detail: made.status === 403 || made.status === 401
          ? `The token can read but not change records. Create a new one from the "Edit zone DNS" template. ${guide}, step 5.`
          : `Cloudflare refused a test record (${made.status}: ${made.errors || "no reason given"}).`,
      });
    }

    if (zoneName) {
      const inside = rootDomain === zoneName || rootDomain.endsWith(`.${zoneName}`);
      steps.push({
        name: "The Zone ID is this domain's", ok: inside,
        detail: inside ? `The zone is ${zoneName}.` : `This Zone ID belongs to ${zoneName}, but the platform's domain is ${rootDomain}. Copy the Zone ID of the right domain. ${guide}, step 4.`,
      });
    } else {
      steps.push({ name: "The Zone ID is this domain's", ok: null, detail: "The token may not read the zone's details, so this could not be checked. That is not a problem by itself." });
    }
    if (zone?.ok && zone.result) {
      const active = zone.result.status === "active";
      steps.push({
        name: "The domain is active at Cloudflare", ok: active,
        detail: active ? "Cloudflare answers for this domain." : `The domain is not active at Cloudflare yet (status: ${zone.result.status}). At your registrar, set the nameservers to ${(zone.result.name_servers ?? []).join(" and ") || "the two Cloudflare gave you"}, then wait. ${guide}, step 3.`,
      });
    }
    return steps;
  }

  private find(name: string, type: RecordType) {
    return this.call<CfRecord[]>("GET", `/dns_records?type=${type}&name=${encodeURIComponent(name)}&per_page=100`);
  }

  async upsertRecord(name: string, type: RecordType, value: string, ttl: number): Promise<string | null> {
    const content = type === "TXT" ? `"${value}"` : value;
    const found = await this.find(name, type);
    if (type === "TXT") {
      // A TXT name can hold several values (two challenges at once): add, never replace.
      const same = found.find((r) => r.content.replace(/^"|"$/g, "") === value);
      if (same) return same.id;
      return (await this.call<CfRecord>("POST", "/dns_records", { type, name, content, ttl, proxied: false })).id;
    }
    const [keep, ...extra] = found;
    for (const r of extra) await this.call("DELETE", `/dns_records/${r.id}`);
    if (keep) {
      if (keep.content === value) return keep.id;
      return (await this.call<CfRecord>("PUT", `/dns_records/${keep.id}`, { type, name, content, ttl, proxied: false })).id;
    }
    return (await this.call<CfRecord>("POST", "/dns_records", { type, name, content, ttl, proxied: false })).id;
  }

  async deleteRecord(name: string, type: RecordType, value?: string): Promise<void> {
    for (const r of await this.find(name, type)) {
      if (value !== undefined && r.content.replace(/^"|"$/g, "") !== value) continue;
      await this.call("DELETE", `/dns_records/${r.id}`);
    }
  }
}

// ---------------------------------------------------------------- memory

/** Keeps records in this process (development, tests). `records` shows what is "published". */
export class MemoryProvider implements DnsProvider {
  readonly name = "memory";
  records = new Map<string, string[]>();
  failNext = 0;
  calls = 0;

  private tick() {
    this.calls++;
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("memory provider: failing as asked");
    }
  }

  async upsertRecord(name: string, type: RecordType, value: string): Promise<string> {
    this.tick();
    const key = `${type} ${name}`;
    if (type === "TXT") this.records.set(key, [...new Set([...(this.records.get(key) ?? []), value])]);
    else this.records.set(key, [value]);
    return key;
  }

  async deleteRecord(name: string, type: RecordType, value?: string): Promise<void> {
    this.tick();
    const key = `${type} ${name}`;
    if (value === undefined) this.records.delete(key);
    else this.records.set(key, (this.records.get(key) ?? []).filter((v) => v !== value));
  }

  get(name: string, type: RecordType): string[] {
    return this.records.get(`${type} ${name}`) ?? [];
  }
}

// ---------------------------------------------------------------- Pebble's challenge server

/** pebble-challtestsrv's management API: the DNS Pebble checks DNS-01 against (tests only). */
export class ChallTestSrvProvider implements DnsProvider {
  readonly name = "challtestsrv";
  constructor(private base = "http://127.0.0.1:8055") {}

  private async post(path: string, body: unknown) {
    const res = await fetch(`${this.base}${path}`, { method: "POST", body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`challtestsrv ${path}: ${res.status}`);
  }

  async upsertRecord(name: string, type: RecordType, value: string): Promise<string | null> {
    const host = `${name}.`;
    if (type === "TXT") await this.post("/set-txt", { host, value });
    else await this.post(type === "A" ? "/add-a" : "/add-aaaa", { host, addresses: [value] });
    return null;
  }

  async deleteRecord(name: string, type: RecordType): Promise<void> {
    const host = `${name}.`;
    if (type === "TXT") await this.post("/clear-txt", { host });
    else await this.post(type === "A" ? "/clear-a" : "/clear-aaaa", { host });
  }
}

// ---------------------------------------------------------------- not set up yet

/** Cloudflare chosen, but its token or zone is missing: every change fails with a plain reason. */
export class UnconfiguredProvider implements DnsProvider {
  readonly name = "cloudflare";
  private why = "Cloudflare is not set up yet: add the API token in Admin > Settings.";
  async upsertRecord(): Promise<string | null> {
    throw new Error(this.why);
  }
  async deleteRecord(): Promise<void> {
    throw new Error(this.why);
  }
  async check(): Promise<DnsCheckStep[]> {
    return [{ name: "Cloudflare API token", ok: false, detail: "No token or Zone ID yet. Add them in Admin > Settings (the guide below shows where to get them)." }];
  }
}

/** The provider the settings ask for. */
export function providerFor(c: Config): DnsProvider {
  if (c.dnsProvider === "cloudflare") return c.cloudflareApiToken && c.cloudflareZoneId ? new CloudflareProvider(c.cloudflareApiToken, c.cloudflareZoneId) : new UnconfiguredProvider();
  if (c.dnsProvider === "challtestsrv") return new ChallTestSrvProvider(c.challTestSrvUrl);
  return new MemoryProvider();
}

/** The Cloudflare zone holding `domain` (itself or a parent), as setup.sh finds it. */
export async function findCloudflareZone(token: string, domain: string, base = "https://api.cloudflare.com/client/v4"): Promise<{ id: string; name: string }> {
  let name = domain;
  while (name.includes(".")) {
    const res = await fetch(`${base}/zones?name=${encodeURIComponent(name)}`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(res.status === 401 || res.status === 400 || res.status === 403
      ? "Cloudflare did not accept the token. It may be copied incompletely, or be the Global API Key."
      : `Cloudflare answered ${res.status}.`);
    const json = (await res.json().catch(() => ({}))) as { result?: { id: string; name: string }[] };
    const zone = json.result?.find((z) => z.name === name);
    if (zone && /^[0-9a-f]{32}$/.test(zone.id)) return zone;
    name = name.slice(name.indexOf(".") + 1);
  }
  throw new Error(`The token cannot see a zone for ${domain}. It may be for another domain; or type the Zone ID yourself.`);
}
