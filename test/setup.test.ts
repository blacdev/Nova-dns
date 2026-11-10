import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildDashboard } from "../src/dashboard/app.js";
import { markdown } from "../src/dashboard/markdown.js";
import type { Db } from "../src/db/db.js";
import { DnsManager } from "../src/dns/dns.js";
import { CloudflareProvider } from "../src/dns/providers.js";
import { freshDb, person, testConfig } from "./helpers.js";

describe("the guide's Markdown", () => {
  it("renders what the guides use, and escapes the rest", () => {
    const out = markdown([
      "# Title", "", "A **bold** word, `a <b>` and [a link](https://example.com/x?a=1&b=2).", "second line.", "",
      "1. One", "   still one.", "2. Two", "", "   ```", "   run <this>", "   ```", "",
      "- a", "- **b `c`.** d", "", "> **Note** this.", "", "| A | B |", "| --- | --- |", "| `x` | y |", "",
      "<script>alert(1)</script> [bad](javascript:alert(1))",
    ].join("\n")).value;
    expect(out).toContain('<h1 id="title">Title</h1>');
    expect(out).toContain("<p>A <strong>bold</strong> word, <code>a &lt;b&gt;</code> and <a href=\"https://example.com/x?a=1&amp;b=2\" target=\"_blank\" rel=\"noopener noreferrer\">a link</a>. second line.</p>");
    expect(out).toContain("<ol><li>One still one.</li><li><p>Two</p>\n<pre><code>run &lt;this&gt;</code></pre></li></ol>");
    expect(out).toContain("<ul><li>a</li><li><strong>b <code>c</code>.</strong> d</li></ul>");
    expect(out).toContain("<blockquote><p><strong>Note</strong> this.</p></blockquote>");
    expect(out).toContain("<table><tr><th>A</th><th>B</th></tr><tr><td><code>x</code></td><td>y</td></tr></table>");
    expect(out).not.toContain("<script>");
    expect(out).not.toContain('href="javascript');
  });

  it("renders the Cloudflare guide with nothing left over", () => {
    const out = markdown(readFileSync(new URL("../docs/cloudflare-setup.md", import.meta.url), "utf8")).value;
    expect(out).toContain('<h2 id="step-5-create-the-api-token">');
    expect(out.match(/<h2 /g)!.length).toBeGreaterThanOrEqual(10);
    const text = out.replace(/<pre>[\s\S]*?<\/pre>|<code>[\s\S]*?<\/code>/g, "");
    expect(text).not.toMatch(/\*\*|```|\]\(|^\s*\|/m);
    expect(text).not.toMatch(/<p>\s*(#|\d+\. |- |> )/);
  });
});

// ------------------------------------------------------------------ a stand-in for Cloudflare's API

interface Fake { token: string; canWrite: boolean; zone: { id: string; name: string; status: string }; zoneReadable: boolean; records: Map<string, { name: string; content: string }>; }
const fake: Fake = { token: "good-token", canWrite: true, zone: { id: "z".repeat(32), name: "example.test", status: "active" }, zoneReadable: true, records: new Map() };
let server: Server;
let base = "";

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const send = (status: number, result: unknown, error?: string) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify({ success: status < 400, result, errors: error ? [{ message: error }] : [] }));
      };
      const path = new URL(req.url!, "http://x").pathname;
      if (req.headers.authorization !== `Bearer ${fake.token}`) return send(401, null, "Invalid API Token");
      const m = /^\/zones\/([^/]+)(\/dns_records(?:\/(.+))?)?$/.exec(path);
      if (!m) return send(404, null, "no route");
      if (m[1] !== fake.zone.id) return send(m[1].length === 32 ? 403 : 404, null, "Authentication error");
      if (!m[2]) return fake.zoneReadable ? send(200, { ...fake.zone, name_servers: ["anna.ns.cloudflare.com", "bob.ns.cloudflare.com"] }) : send(403, null, "Authentication error");
      if (req.method === "GET") return send(200, []);
      if (!fake.canWrite) return send(403, null, "Authentication error");
      if (req.method === "POST") {
        const r = JSON.parse(body) as { name: string; content: string };
        // Like Cloudflare: a name from outside the zone lands under the zone's own name.
        const name = r.name.endsWith(fake.zone.name) ? r.name : `${r.name}.${fake.zone.name}`;
        const id = `r${fake.records.size + 1}`;
        fake.records.set(id, { name, content: r.content });
        return send(200, { id, name, type: "TXT", content: r.content });
      }
      if (req.method === "DELETE") {
        fake.records.delete(m[3]);
        return send(200, { id: m[3] });
      }
      return send(405, null, "no");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => new Promise((r) => server.close(r)));

const check = (root = "example.test", token = "good-token", zone = fake.zone.id) => new CloudflareProvider(token, zone, base).check(root);
const reset = () => Object.assign(fake, { canWrite: true, zoneReadable: true, zone: { id: "z".repeat(32), name: "example.test", status: "active" } });

describe("the Cloudflare connection test", () => {
  it("passes with a token that may edit the right, active zone, and leaves nothing behind", async () => {
    reset();
    const steps = await check();
    expect(steps.map((s) => s.ok)).toEqual([true, true, true, true]);
    expect(fake.records.size).toBe(0);
    // A subdomain of the zone as the platform's domain is fine too.
    expect((await check("radio.example.test")).every((s) => s.ok)).toBe(true);
  });

  it("says in plain words what is wrong", async () => {
    reset();
    expect((await check("example.test", "typo"))[0]).toMatchObject({ ok: false, detail: expect.stringContaining("did not accept the token") });
    expect((await check("example.test", "good-token", "y".repeat(32)))[0]).toMatchObject({ ok: false, detail: expect.stringContaining("may not use this domain") });
    expect((await check("example.test", "good-token", "short"))[0]).toMatchObject({ ok: false, detail: expect.stringContaining("does not know this Zone ID") });

    fake.canWrite = false;
    expect((await check()).find((s) => s.ok === false)).toMatchObject({ detail: expect.stringContaining("can read but not change") });
    reset();

    fake.zone.status = "pending";
    expect((await check()).at(-1)).toMatchObject({ ok: false, detail: expect.stringContaining("anna.ns.cloudflare.com and bob.ns.cloudflare.com") });
    reset();

    expect((await check("other.test")).find((s) => s.ok === false)).toMatchObject({ detail: expect.stringContaining("belongs to example.test") });
    // Even when the token may not read the zone's details, the test record gives a wrong zone away.
    fake.zoneReadable = false;
    expect((await check("other.test")).find((s) => s.ok === false)).toMatchObject({ detail: expect.stringContaining("belongs to example.test") });
    expect((await check()).map((s) => s.ok)).toEqual([true, true, null]);
    expect(fake.records.size).toBe(0);

    const down = await new CloudflareProvider("good-token", fake.zone.id, "http://127.0.0.1:1").check("example.test");
    expect(down[0]).toMatchObject({ ok: false, detail: expect.stringContaining("could not be reached") });
  });
});

// ------------------------------------------------------------------ the dashboard's Setup page

describe("Admin > Setup", () => {
  let db: Db;
  afterAll(() => db?.end());

  async function signedIn(over: Parameters<typeof testConfig>[0], provider?: CloudflareProvider) {
    db ??= await freshDb();
    const config = testConfig({ adminEmails: ["boss@example.test"], ...over });
    const { MemoryProvider } = await import("../src/dns/providers.js");
    const dns = new DnsManager(db, provider ?? new MemoryProvider(), config.rootDomain, async () => undefined);
    const app = buildDashboard({ db, dns, config, mail: async () => undefined, lookup: async (n) => (n.startsWith("turn.") ? [] : ["203.0.113.9"]) });
    const email = `boss${Math.random().toString(36).slice(2, 8)}@example.test`;
    const who = await person(db, email, "admin");
    const { startSession } = await import("../src/dashboard/session.js");
    const cookies = new Map<string, string>();
    const reply = { setCookie: (k: string, v: string) => cookies.set(k, v) };
    await (startSession as unknown as (...a: unknown[]) => Promise<unknown>)(db, reply, who, false, "198.51.100.9", false);
    return { app, cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; ") };
  }

  it("shows the guide with this platform's domain, what is unfinished, and the test's result", async () => {
    reset();
    const { app, cookie } = await signedIn({ dnsProvider: "cloudflare", rootDomain: "example.test" }, new CloudflareProvider("good-token", fake.zone.id, base));
    const page = await app.inject({ method: "GET", url: "/admin/setup", headers: { cookie } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("Setting up Cloudflare for Nova");
    expect(page.body).toContain("kfm.example.test");
    expect(page.body).not.toContain("yourdomain.com");
    expect(page.body).toContain("test certificates");
    expect(page.body).toContain("Test the Cloudflare connection");

    const csrf = /name="_csrf" value="([^"]+)"/.exec(page.body)![1];
    const post = (c: string) => app.inject({ method: "POST", url: "/admin/setup/check", payload: `_csrf=${encodeURIComponent(csrf)}`,
      headers: { cookie: c, "content-type": "application/x-www-form-urlencoded", origin: "http://app.example.test" } });
    const ok = await post(cookie);
    expect(ok.statusCode).toBe(200);
    expect(ok.body).toContain("Cloudflare: working");
    expect(ok.body).toContain("Points to 203.0.113.9");
    expect(ok.body).toContain("<b>turn.example.test</b><br><span class=\"bad\">Not found on the internet");

    fake.canWrite = false;
    const bad = await post(cookie);
    expect(bad.body).toContain("Cloudflare: something needs fixing");
    expect(bad.body).toContain("can read but not change records");
    reset();
    await app.close();
  });

  it("without Cloudflare, says so on the overview and still shows the guide", async () => {
    const { app, cookie } = await signedIn({ dnsProvider: "memory" });
    const overview = await app.inject({ method: "GET", url: "/admin", headers: { cookie } });
    expect(overview.body).toContain("Setup not finished");
    expect(overview.body).toContain("station names are not published");
    const page = await app.inject({ method: "GET", url: "/admin/setup", headers: { cookie } });
    expect(page.body).toContain("Station names are not published on the internet");
    expect(page.body).toContain("Check the platform&#39;s addresses");
    await app.close();
  });
});
