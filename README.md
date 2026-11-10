# Nova platform

The central service behind Nova's **Remote Studio**: station owners claim a subdomain
(`kfm.ROOT_DOMAIN`), the platform keeps it pointed at their studio PC, issues its HTTPS
certificate, and hands out STUN/TURN credentials so presenters' audio always connects.

It is a phone book (DNS), a certificate front-end and an audio relay of last resort. It
never carries the studio's interface or audio itself (only TURN does, when a direct
connection fails): presenters' browsers connect straight to Nova.

| Part | Address | What |
| --- | --- | --- |
| API | `api.ROOT_DOMAIN` | the studio contract Nova speaks (`/v1/...`), health, metrics |
| Dashboard | `app.ROOT_DOMAIN` | owners: account, claim/rename/regenerate/delete; admins |
| Worker | (no address) | certificates (ACME DNS-01), renewals, DNS retries, cleanup, alerts |
| coturn | `turn.ROOT_DOMAIN` | STUN/TURN on its own host, with a usage shipper |

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
apex, if you use it) at this host first. The first person to sign up with an address in
`ADMIN_EMAILS` is an admin.

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
| `POST /v1/studio/register` `{hostname, access_code, install_id, app_version}` | 200 `{studio_token, token_expires_at, fqdn, studio_id}`; 401 `invalid_credentials`, 403 `suspended`, 404 `hostname_not_found`; 10 tries / 10 min per IP and per hostname; tokens 30 days, kept as hashes |
| `POST /v1/ddns/update` `{ip_override, port}` | the heartbeat; A or AAAA, TTL 60, provider called only on a change; `{ip, changed, dns_status, fqdn}` (always the current FQDN) |
| `POST /v1/cert/csr` `{csr_pem}` | 202 `{status: "pending"}`; the CSR may name only the studio's FQDN |
| `GET /v1/cert` | `{status, cert_pem, chain_pem, expires_at, serial}` |
| `POST /v1/reachability/probe` `{port}` | `{reachable, latency_ms, error}`; 1 per 10 s; never into private networks |
| `GET /v1/ice-servers` | STUN + TURN, coturn REST credentials valid 6 h |

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
| `src/db/migrations/` | the schema (additive files) |
| `deploy/` | Caddy, coturn config and its Compose file |

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
