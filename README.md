# Nova platform

The central service behind Nova's **Remote Studio**: station owners claim a subdomain
(`kfm.ROOT_DOMAIN`), the platform keeps it pointed at their studio PC, issues its HTTPS
certificate, and hands out STUN/TURN credentials so presenters' audio always connects.

It is a phone book (DNS), a certificate front-end and an audio relay of last resort. It
never sees the studio's interface or audio: presenters' browsers connect straight to Nova,
or, for a station that opens no port, through the **edge**, which passes their connection
on still encrypted (TLS ends in Nova). Only TURN relays audio, when a direct connection fails.

| Part | Address | What |
| --- | --- | --- |
| API | `api.ROOT_DOMAIN` | the studio contract Nova speaks (`/v1/...`), health, metrics |
| Dashboard | `app.ROOT_DOMAIN` | owners: account, claim/rename/regenerate/delete; admins |
| Worker | (no address) | certificates (ACME DNS-01), renewals, DNS retries, cleanup, alerts |
| coturn | `turn.ROOT_DOMAIN` | STUN/TURN on its own host, with a usage shipper |
| Edge (optional) | `edge.ROOT_DOMAIN` | the tunnel for stations that open no port: QUIC from stations, presenters passed down by name (Rust, `edge/`) |

Stack: TypeScript on Node 22, Fastify, PostgreSQL 16, acme-client, coturn, Caddy, Docker
Compose. DNS: Cloudflare (the free plan is enough).

**New to Cloudflare?** [docs/cloudflare-setup.md](docs/cloudflare-setup.md) goes from "I
have a domain" to a working setup, step by step, with no DNS knowledge needed. Admins
see the same guide in the dashboard under **Admin > Setup**, next to a button that tests
the Cloudflare connection.

## Deploy

**The quick way: `./setup.sh`.** It asks for the domain, the DNS provider (Cloudflare, or
`memory` without Cloudflare: then station names and their certificates do not work, the
dashboard and the TURN relay do), Let's Encrypt staging or production, the admins and
email, and whether this machine takes ports 80/443 itself (Caddy) or sits behind your own
reverse proxy such as Nginx Proxy Manager (then it opens the API and dashboard on ports
8080/8081 and leaves Caddy out). It makes every secret, writes `.env`, starts the
containers and prints what to do next (DNS records, the proxy hosts, the TURN values, the
line for Nova's `remote/config.json`). `./setup.sh turn` does the TURN host: on a cloud
server (`TURN_EXTERNAL_IP=PUBLIC/PRIVATE` behind 1:1 NAT), or on your own network behind
your router, beside Nova: then it also takes the Nova server's LAN address
(`TURN_ALLOWED_PEER_IP`, the one private address the relay may reach; every other stays
refused), a small port range to forward (`TURN_MIN_PORT`/`TURN_MAX_PORT`, 40000-40999 by
default there, clear of the ports Windows gives Nova) and a TLS port off 443
(`TURN_TLS_PORT`, 5349), and prints the port forwards to make.
`--dry-run` writes the files and shows the commands without starting anything. Run it
again to change an answer; secrets are kept.

For Cloudflare it asks only for the API token: it finds the zone id itself (when
`ROOT_DOMAIN` is a subdomain, the parent's zone), tests that the token can read and change
the zone's records (one test record, added and removed), says in plain words what is wrong
if not, and offers to add the `api` and `app` records (never changing one that exists).
This part needs `curl`.

**`./setup.sh check`** changes nothing and tests a setup that is already there: the
settings, the Cloudflare token, the platform's DNS records, the containers, and whether
the API and dashboard answer from the internet. The dashboard's **Admin > Setup** page
shows the same things to admins: what is unfinished (no DNS provider, test certificates,
no email), the Cloudflare test, and the guide.

By hand:

**Platform host** (one machine is enough to start):

```bash
cp .env.example .env        # fill in every value (see the comments in it)
docker compose up -d --build
```

Caddy gets certificates for `api.` and `app.` by itself; point their DNS records (and the
apex, if you use it) at this host first. The first account made in the dashboard is
the super admin (see below).

### Admins, plans and settings

- **The first account made is the super admin.** It may do everything, and is the only
  one who makes other accounts admins and chooses what each admin may do (Admin > People >
  a person > Role and permissions): see people, manage people, see or manage every
  station, names, plans, settings, logs. Only the super admin acts on another admin's
  account, and it can hand its role to an admin. `ADMIN_EMAILS` (optional) still makes
  admins with every permission at sign-up. On an existing platform, the first migration
  after this change makes its first admin (or else its first account) the super admin.
- **Plans** (Admin > Plans) set how many stations a person may have; one is the default.
  On a person's page an admin picks their plan or sets their own limit, which wins.
  Without plans, `SUBDOMAIN_LIMIT` applies.
- **People and stations**: admins add people (they get an email to choose a password),
  confirm emails, send reset links, turn off a lost second factor, suspend, delete; create
  a station for someone and move a station to another owner (its access code is replaced).
- **Settings** (Admin > Settings): the Cloudflare token and zone, the SMTP address and
  sender, the Let's Encrypt email, staging or production, and the weekly certificate
  limit, without editing `.env` or restarting. Saved values win over `.env`, are stored
  encrypted (key from `SESSION_SECRET`), are never shown again, and reach every process
  within seconds. Changing them needs the `settings.manage` permission, two-step sign-in,
  and sudo mode (below). The database, `SESSION_SECRET`, the domain, ports, proxies and
  TURN's secrets stay in `.env`.

### Payments (optional, off by default)

Admin > Payments lets station owners buy plans with **Stripe**, **Paystack** or
**Flutterwave**. Nothing depends on it: with payments off, admins assign plans by hand.

1. Give at least one plan a price, currency and period (Admin > Plans > a plan).
2. Choose the provider, paste its secret key (and, for Stripe, the webhook signing
   secret; for Flutterwave, the secret hash), and press **Test connection**. Each provider
   keeps its own keys, encrypted, so you can switch between them. Test keys take test
   payments, live keys real ones; the page says which is in use.
3. Add the webhook address shown there (`https://api.ROOT_DOMAIN/v1/billing/webhook/<provider>`)
   in the provider's dashboard.
4. Turn payments on. Owners then see **Billing**, pick a plan, pay on the provider's own
   checkout page (card details never reach this platform) and come back.

A payment counts only when the provider's API confirms it, for the exact amount and
currency; webhooks are signature-checked, handled once each, and only trigger that check.
The worker asks again about pending payments every 10 minutes. Each payment covers one
month or year (renewing early adds to the time left); owners get an email 3 days before
it ends, and afterwards they are on the default plan again (their stations stay).

### Security

- Admins must use two-step sign-in; the admin console stays closed until it is on.
- **Sudo mode**: settings, payment keys, roles, handing over the super admin role,
  turning off someone's second factor and deleting people need the password (and code)
  confirmed within the last 10 minutes.
- Sessions: `__Host-` cookies over HTTPS; 2 hours idle for admins, 12 for owners, 7 days at
  most; every account sees its signed-in devices and can end them.
- Email notices on password changes, two-step sign-in changes and role changes.
- Strict CSP, no inline script, HSTS, `X-Frame-Options: DENY`, COOP/CORP, rate limits on
  sign-in, sudo, two-step codes, emails and checkouts; every change in the audit log.

**TURN host** (its own machine: it is bandwidth-heavy and needs a public address):

```bash
cd deploy/turn
cp ../../.env.example .env  # TURN_SHARED_SECRET, TURN_HOST, API_BASE, TURN_USAGE_TOKEN
docker compose up -d
```

Open UDP/TCP 3478, TCP 443 and UDP 49152-65535. Point `turn.ROOT_DOMAIN` at this host.
The shipper fetches `turn.ROOT_DOMAIN`'s certificate from the platform (the worker issues
it by DNS-01) and reloads coturn (SIGUSR2); it also reports relayed bytes and sessions per
studio.

**Edge host** (optional; its own machine, like TURN: Nova's docs/TUNNEL.md). Stations
behind a router that forwards nothing, or an internet provider that shares one address
among many customers, dial out to it; presenters reach them through it. Nova uses it by
itself when the platform's probe cannot reach a station directly.

```bash
cd deploy/edge
cp ../../.env.example .env  # EDGE_API_BASE, EDGE_TOKEN
docker compose up -d --build
```

Open UDP 443 (stations) and TCP 443 and 25433 (presenters). Point `edge.ROOT_DOMAIN` at
this host, and on the platform set `EDGE_IP` to its address and the same `EDGE_TOKEN`; the
worker then issues `edge.ROOT_DOMAIN`'s certificate, which the edge fetches and keeps
current. Every presenter's page and live-link message goes through it: put it near the
stations. It limits connections per presenter address (96) and in total (8192), and
checks each signed-in station again every 5 minutes (a suspended or renamed one is let
go). Its tests: `cd edge && cargo test`.

**Rotating the TURN secret**: set the new value as `TURN_SHARED_SECRET` everywhere and the
old one as `TURN_SHARED_SECRET_PREVIOUS` on the TURN host (coturn accepts both). After 6
hours (the credentials' lifetime) remove the previous one.

**Nova**: each Nova install must know the same domain. Build Nova with
`ROOT_DOMAIN` set to yours, or put `{"root_domain": "...", "api_base": "https://api..."}`
in `<Nova Data>/remote/config.json`.

**Before going live with Let's Encrypt**: test with the staging directory (the default in
`.env.example`); Let's Encrypt allows 50 new certificates per registered domain per 7
days, so for many stations ask for a rate-limit increase and/or add `ROOT_DOMAIN` to the
Public Suffix List. Every issued name appears in public Certificate Transparency logs.

## Develop

```bash
npm install
npm test            # needs PostgreSQL's binaries (initdb) on PATH or in /usr/lib/postgresql,
                    # or TEST_DATABASE_URL; Pebble tests run when pebble is installed:
                    #   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
                    #   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
npm run typecheck
npm run build && node dist/main.js all   # everything in one process (DNS_PROVIDER=memory)
```

Roles: `node dist/main.js migrate | api | dashboard | worker | all | turn-usage`.

## The studio API (shared with Nova; must match exactly)

JSON over HTTPS. Errors are `{"error": {"code", "message"}}`. Authenticated calls send
`Authorization: Bearer <studio_token>`; a token reaches one studio and its one subdomain.

| Call | Notes |
| --- | --- |
| `POST /v1/studio/register` `{hostname, access_code, install_id, app_version}` | 200 `{studio_token, token_expires_at, fqdn, studio_id, tunnel?}` (`tunnel: {edge, server_name}` while the edge runs); 401 `invalid_credentials`, 403 `suspended`, 404 `hostname_not_found`; 10 tries / 10 min per IP and per hostname; tokens 30 days, kept as hashes |
| `POST /v1/ddns/update` `{ip_override, port, via?}` | the heartbeat; A or AAAA, TTL 60, provider called only on a change; `{ip, changed, dns_status, fqdn, via}` (always the current FQDN). `via: "tunnel"` points the name at the edge (`EDGE_IP`) while `ip` stays the station's own (the probe uses it); without an edge it is always `direct` |
| `POST /v1/cert/csr` `{csr_pem}` | 202 `{status: "pending"}`; the CSR may name only the studio's FQDN |
| `GET /v1/cert` | `{status, cert_pem, chain_pem, expires_at, serial}` |
| `POST /v1/reachability/probe` `{port}` | `{reachable, latency_ms, error}`; 1 per 10 s; never into private networks |
| `GET /v1/ice-servers` | STUN + TURN, coturn REST credentials valid 6 h |

The edge's own calls, with `EDGE_TOKEN`: `POST /internal/edge/auth {token}` (is a station's
token good: `{ok, fqdn}` or `{ok: false, code: invalid_token | suspended, message}`) and
`GET /internal/edge-cert` (edge.ROOT_DOMAIN's certificate and key; 404 until issued).

**The edge's protocol** (shared with Nova's `apps/tunnel`; must match exactly): QUIC, ALPN
`nova-tunnel/1`. A station opens one stream and sends `{"v":1,"token":...}` as a line; the
edge answers `{"ok":true,"fqdn":...}` or `{"ok":false,"code","message"}` (`try_later`
when the API cannot be asked) and keeps the stream open. For each presenter the edge reads
the first TLS record, finds the station by its SNI name, opens a stream to it and writes a
PROXY v2 header (the presenter's address), the record, then copies both ways.

## How it is built

| Where | What |
| --- | --- |
| `src/api/` | the studio API (`studio.ts`), Fastify app, metrics |
| `src/dashboard/` | customer pages (`app.ts`), admin pages (`admin.ts`), sessions and CSRF, the guides' Markdown |
| `docs/` | guides for people setting the platform up (also shown in the dashboard) |
| `src/lib/` | name rules, access codes and secrets, rate limits, audit, subdomain actions |
| `src/dns/` | DNS manager (protected names, only-on-change, retries) and providers |
| `src/acme/` | certificates by DNS-01, ARI renewals, the weekly-limit queue, revocation |
| `src/worker/` | background jobs, each with its own advisory lock |
| `src/turn/` | the coturn host's usage shipper and certificate keeper |
| `edge/` | the tunnel's edge (Rust: quinn, rustls), its tests and Dockerfile |
| `src/db/migrations/` | the schema (additive files) |
| `deploy/` | Caddy, coturn config and its Compose file, the edge's Compose file |

Choices made where the spec left room:

- **Claiming needs a confirmed email address**, so names cannot be squatted by throwaway
  sign-ups.
- **Renewals reuse the studio's stored CSR**: the platform renews by itself at the CA's
  suggested time (ARI) or with 30 days left, and Nova picks the new certificate up; the
  studio's key never changes hands.
- **The DNS status is "propagated" once Cloudflare accepted the record** (Cloudflare
  serves it from its authoritative servers at once); "pending" means the provider failed
  and the worker is retrying.
- **The probe accepts any certificate** (as the spec says) but refuses private and
  reserved addresses, so it can never be used to reach into the platform's network.

## What was verified, and how

**The edge (2026-11-12, Linux, one computer):** `cd edge && cargo test` (9 tests: a
presenter reaches their station on both ports with their own address, forty at once each
get their own bytes back, plain http and unknown names are closed, the platform decides
who signs in and the API out of reach gives `try_later`, a renamed station is let go but
not for an API hiccup, a newer sign-in takes over, the per-address limit, the certificate
from the API). Then end to end with the real API (PostgreSQL 16, `EDGE_IP` set), the real
edge and a real Nova engine with its `nova-tunnel` (blacdev/Nova 0.2.27): Nova registered
and was offered the edge, its name was pointed at the edge (`studios.via = tunnel`), the
edge checked its token with the API, and an HTTPS request for `kfm.example.test` through
the edge was answered by Nova itself (its install id); suspending the station in the
database made the edge let it go at its next re-check, refuse it when it dialled back, and
Nova said "This station is suspended". Not verified: the Docker image (no Docker daemon
here; `cargo build --release --locked`, which it runs, succeeds), a real certificate from
Let's Encrypt for edge.ROOT_DOMAIN, real networks.

On a Linux machine with a real PostgreSQL 16, Pebble (Let's Encrypt's test CA) with its
challenge DNS server, coturn 4.6.1, and a real Nova engine:

- 59 automated tests (`npm test`), including: the racing claim (exactly one of eight
  wins), register/DNS/CSR/probe/ICE against the contract, rename / regenerate / suspend /
  delete as the studio sees them, certificates issued, renewed with ARI and revoked
  through Pebble, the weekly-limit queue, the dashboard driven like a browser (cookies,
  CSRF, email links, TOTP), and coturn's real log lines.
- coturn: credentials from `/v1/ice-servers` relayed audio with no loss; credentials
  signed with the previous secret were still accepted (rotation); expired credentials were
  refused; relaying to 127.0.0.1 was refused (403 Forbidden IP).
- End to end with Nova: signed up and claimed `kfm` in the dashboard (live check showed
  "reserved" for `api`, "available" for `kfm`); entered the code in Nova; within 12 s Nova
  was registered, DNS pointed at it, Pebble had issued its certificate by DNS-01 and the
  probe reached it. Renamed to `kfm-fm`: Nova took the new name on its next check-in and
  served a new certificate within 10 s. A new access code: Nova at once showed "Access
  code rejected". The admin suspended the station; the audit log showed every step.

Not verified here:

- **Cloudflare** for real (the provider, the connection test and `setup.sh`'s Cloudflare
  steps are tested against a stand-in with its API shape only) and **Let's
  Encrypt** for real (Pebble is its test CA; staging is the next step).
- **The Docker images**: the Compose files validate, but Docker Hub refused the image pull
  in the build environment (rate limited), so the images were not built there.
- **TURN over the internet** (only on one machine) and **email delivery** (messages were
  printed, no SMTP server).
