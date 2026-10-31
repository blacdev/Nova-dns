/**
 * DNS providers: Cloudflare (production), memory (development and tests) and
 * Pebble's challenge test server (end-to-end certificate tests, `challtestsrv`).
 */

import type { DnsProvider, RecordType } from "./dns.js";

// ---------------------------------------------------------------- Cloudflare

interface CfRecord { id: string; name: string; type: string; content: string }

export class CloudflareProvider implements DnsProvider {
  readonly name = "cloudflare";
  constructor(private token: string, private zoneId: string, private base = "https://api.cloudflare.com/client/v4") {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}/zones/${this.zoneId}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    const json = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T; errors?: { message: string }[] };
    if (!res.ok || json.success === false) {
      throw new Error(`Cloudflare ${method} ${path.split("?")[0]}: ${res.status} ${(json.errors ?? []).map((e) => e.message).join("; ")}`);
    }
    return json.result as T;
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

  private check() {
    this.calls++;
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("memory provider: failing as asked");
    }
  }

  async upsertRecord(name: string, type: RecordType, value: string): Promise<string> {
    this.check();
    const key = `${type} ${name}`;
    if (type === "TXT") this.records.set(key, [...new Set([...(this.records.get(key) ?? []), value])]);
    else this.records.set(key, [value]);
    return key;
  }

  async deleteRecord(name: string, type: RecordType, value?: string): Promise<void> {
    this.check();
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
