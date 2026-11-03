#!/usr/bin/env bash
# Set up the Nova platform on this machine, step by step.
#
#   ./setup.sh             asks what to set up
#   ./setup.sh platform    the API, dashboard, worker and database (docker-compose.yml)
#   ./setup.sh turn        the TURN relay (deploy/turn), on a machine with a public address
#   ./setup.sh --dry-run   writes the settings files and shows the commands, starts nothing
#
# It writes .env (and deploy/turn/.env) from your answers, makes every secret itself, and
# starts the containers. Run it again to change an answer: what you gave before is the
# default. Needs Docker with the compose plugin, and openssl (or /dev/urandom).
set -euo pipefail

cd "$(dirname "$0")"
HERE=$(pwd)
DRY=0
MODE=""
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    platform|turn) MODE="$a" ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
fail() { printf '\033[31m  x %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- answers and secrets

declare -A OLD=()
load_old() { # KEY=VALUE lines of an existing settings file become the defaults
  local file=$1 line key
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key=${line%%=*}
    OLD[$key]=${line#*=}
  done < "$file"
}
old() { printf '%s' "${OLD[$1]:-${2:-}}"; }

ask() { # ask VAR "question" default
  local var=$1 q=$2 def=${3:-} reply
  if [ -n "$def" ]; then read -r -p "  $q [$def]: " reply || true; else read -r -p "  $q: " reply || true; fi
  printf -v "$var" '%s' "${reply:-$def}"
}
ask_required() {
  local var=$1
  while :; do
    ask "$@"
    [ -n "${!var}" ] && return 0
    warn "This one is needed."
  done
}
choose() { # choose VAR "question" default option...
  local var=$1 q=$2 def=$3; shift 3
  local opts="$*" reply
  while :; do
    read -r -p "  $q ($opts) [$def]: " reply || true
    reply=${reply:-$def}
    for o in "$@"; do [ "$reply" = "$o" ] && { printf -v "$var" '%s' "$reply"; return 0; }; done
    warn "Answer one of: $opts"
  done
}
secret() { # secret BYTES: hex, no characters that need quoting anywhere
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"; else head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}
keep_or_new() { local v; v=$(old "$1"); [ -n "$v" ] && [ "$v" != "change-me" ] && printf '%s' "$v" || secret "$2"; }

write_env() { # write_env FILE: the KEY=VALUE pairs in ENV_ORDER, private to this user
  local file=$1 tmp
  tmp=$(mktemp)
  {
    echo "# Written by setup.sh on $(date -u +%Y-%m-%d). Keep it private; never commit it."
    for k in "${ENV_ORDER[@]}"; do printf '%s=%s\n' "$k" "${ENV[$k]}"; done
  } > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$file"
  note "Wrote $file (readable by you only)."
}

run() { # show a command, and run it unless --dry-run
  printf '  $ %s\n' "$*"
  [ "$DRY" = 1 ] || "$@"
}

need_docker() {
  command -v docker >/dev/null 2>&1 || fail "Docker is not installed: https://docs.docker.com/engine/install/"
  docker compose version >/dev/null 2>&1 || fail "Docker's compose plugin is missing (docker compose version failed)."
  if [ "$DRY" = 0 ] && ! docker info >/dev/null 2>&1; then
    fail "Docker is installed but not running, or this user may not use it (try sudo, or add yourself to the docker group)."
  fi
}

resolves_to() { getent ahosts "$1" 2>/dev/null | awk 'NR==1 {print $1}'; }

# ---------------------------------------------------------------- the platform

setup_platform() {
  bold "The Nova platform: API, dashboard, worker and database"
  load_old .env
  need_docker

  bold "1. Your domain"
  note "Stations get <name>.DOMAIN; the API is api.DOMAIN, the dashboard app.DOMAIN, TURN turn.DOMAIN."
  ask_required ROOT_DOMAIN "Domain" "$(old ROOT_DOMAIN)"
  ROOT_DOMAIN=${ROOT_DOMAIN,,}; ROOT_DOMAIN=${ROOT_DOMAIN%.}

  bold "2. DNS for station names"
  note "cloudflare: station names and their certificates work (needs a Cloudflare API token"
  note "            with Zone.DNS:Edit on this domain, and the zone's id)."
  note "memory:     no Cloudflare. Station names are NOT published and their certificates"
  note "            fail; the dashboard and the TURN relay still work."
  choose DNS_PROVIDER "DNS provider" "$(old DNS_PROVIDER cloudflare)" cloudflare memory
  CLOUDFLARE_API_TOKEN=""; CLOUDFLARE_ZONE_ID=""
  if [ "$DNS_PROVIDER" = cloudflare ]; then
    ask_required CLOUDFLARE_API_TOKEN "Cloudflare API token" "$(old CLOUDFLARE_API_TOKEN)"
    ask_required CLOUDFLARE_ZONE_ID "Cloudflare zone id" "$(old CLOUDFLARE_ZONE_ID)"
  else
    warn "Memory DNS: station names will not resolve on the internet. Fine for the relay; not for names."
  fi

  bold "3. Certificates (Let's Encrypt)"
  ask_required ACME_EMAIL "Email for Let's Encrypt notices" "$(old ACME_EMAIL "ops@$ROOT_DOMAIN")"
  local was_prod=staging
  [ "$(old ACME_DIRECTORY_URL)" = "https://acme-v02.api.letsencrypt.org/directory" ] && was_prod=production
  note "Start with staging (test certificates, generous limits); switch to production once it works."
  choose ACME_MODE "Let's Encrypt" "$was_prod" staging production
  if [ "$ACME_MODE" = production ]; then
    ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
  else
    ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
  fi

  bold "4. People and email"
  ask_required ADMIN_EMAILS "Admin email(s), comma separated (they become admins when they sign up)" "$(old ADMIN_EMAILS)"
  note "Email sends sign-up confirmations and password resets, e.g. smtps://user:pass@smtp.example.com:465"
  ask SMTP_URL "SMTP address (empty: emails are only written to the dashboard's log)" "$(old SMTP_URL)"
  [ -n "$SMTP_URL" ] || warn "No email: find confirmation links with: docker compose logs dashboard | grep -A3 '\[mail\]'"

  bold "5. In front of the API and dashboard"
  note "caddy:  this machine takes ports 80 and 443 and gets certificates by itself."
  note "proxy:  your own reverse proxy (Nginx Proxy Manager...) already has 80/443 and forwards"
  note "        api.$ROOT_DOMAIN and app.$ROOT_DOMAIN to this machine's ports."
  local was_front=caddy
  [ -f docker-compose.proxy.yml ] && was_front=proxy
  choose FRONT "Front" "$was_front" caddy proxy
  API_PORT=8080; DASHBOARD_PORT=8081; TRUSTED_PROXIES=172.28.0.10
  if [ "$FRONT" = proxy ]; then
    ask_required PROXY_IP "Your proxy's IP address, as this machine sees it" "$(old PROXY_IP)"
    ask_required API_PORT "Port for the API on this machine" "$(old API_PORT 8080)"
    ask_required DASHBOARD_PORT "Port for the dashboard on this machine" "$(old DASHBOARD_PORT 8081)"
    # Docker may show the proxy's connections as coming from the bridge's gateway.
    TRUSTED_PROXIES="$PROXY_IP,172.28.0.1"
  fi

  bold "6. Secrets"
  POSTGRES_PASSWORD=$(keep_or_new POSTGRES_PASSWORD 24)
  SESSION_SECRET=$(keep_or_new SESSION_SECRET 48)
  TURN_SHARED_SECRET=$(keep_or_new TURN_SHARED_SECRET 32)
  TURN_USAGE_TOKEN=$(keep_or_new TURN_USAGE_TOKEN 32)
  note "Made (or kept) the database password, the session secret and the TURN secrets."
  [ -n "$(old SESSION_SECRET)" ] || note "Keep .env safe: a new SESSION_SECRET signs everyone out."

  declare -gA ENV=(
    [ROOT_DOMAIN]=$ROOT_DOMAIN [DASHBOARD_URL]="https://app.$ROOT_DOMAIN"
    [POSTGRES_PASSWORD]=$POSTGRES_PASSWORD
    [DATABASE_URL]="postgres://nova:$POSTGRES_PASSWORD@postgres:5432/nova"
    [DNS_PROVIDER]=$DNS_PROVIDER [CLOUDFLARE_API_TOKEN]=$CLOUDFLARE_API_TOKEN [CLOUDFLARE_ZONE_ID]=$CLOUDFLARE_ZONE_ID
    [ACME_DIRECTORY_URL]=$ACME_DIRECTORY_URL [ACME_EMAIL]=$ACME_EMAIL [CERT_WEEKLY_LIMIT]=$(old CERT_WEEKLY_LIMIT 50)
    [TURN_SHARED_SECRET]=$TURN_SHARED_SECRET [TURN_SHARED_SECRET_PREVIOUS]=$(old TURN_SHARED_SECRET_PREVIOUS)
    [TURN_HOST]="turn.$ROOT_DOMAIN" [TURN_USAGE_TOKEN]=$TURN_USAGE_TOKEN [API_BASE]="https://api.$ROOT_DOMAIN"
    [SESSION_SECRET]=$SESSION_SECRET [SMTP_URL]=$SMTP_URL [MAIL_FROM]="$(old MAIL_FROM "Nova <no-reply@$ROOT_DOMAIN>")"
    [ADMIN_EMAILS]=$ADMIN_EMAILS [SUBDOMAIN_LIMIT]=$(old SUBDOMAIN_LIMIT 1)
    [TRUSTED_PROXIES]=$TRUSTED_PROXIES [API_PORT]=$API_PORT [DASHBOARD_PORT]=$DASHBOARD_PORT
    [PROXY_IP]=${PROXY_IP:-}
  )
  ENV_ORDER=(ROOT_DOMAIN DASHBOARD_URL POSTGRES_PASSWORD DATABASE_URL DNS_PROVIDER CLOUDFLARE_API_TOKEN
    CLOUDFLARE_ZONE_ID ACME_DIRECTORY_URL ACME_EMAIL CERT_WEEKLY_LIMIT TURN_SHARED_SECRET
    TURN_SHARED_SECRET_PREVIOUS TURN_HOST TURN_USAGE_TOKEN API_BASE SESSION_SECRET SMTP_URL MAIL_FROM
    ADMIN_EMAILS SUBDOMAIN_LIMIT TRUSTED_PROXIES API_PORT DASHBOARD_PORT PROXY_IP)
  if [ -f .env ] && [ -n "$(old POSTGRES_PASSWORD)" ] && [ "$(old POSTGRES_PASSWORD)" != "$POSTGRES_PASSWORD" ]; then
    warn "The database password changed; an existing database keeps its old one. Keep the old .env if it has data."
  fi
  write_env .env

  local compose=(docker compose -f docker-compose.yml)
  local services=()
  if [ "$FRONT" = proxy ]; then
    cat > docker-compose.proxy.yml <<YAML
# Written by setup.sh: the platform behind your own reverse proxy (no Caddy).
# Forward https://api.$ROOT_DOMAIN to this machine's port $API_PORT and
# https://app.$ROOT_DOMAIN to port $DASHBOARD_PORT.
services:
  api:
    ports: ["$API_PORT:$API_PORT"]
  dashboard:
    ports: ["$DASHBOARD_PORT:$DASHBOARD_PORT"]
YAML
    note "Wrote docker-compose.proxy.yml (the two ports, no Caddy)."
    compose+=(-f docker-compose.proxy.yml)
    services=(postgres migrate api dashboard worker)
  else
    rm -f docker-compose.proxy.yml
  fi

  bold "7. DNS records you make at your DNS provider"
  local a
  for name in "api.$ROOT_DOMAIN" "app.$ROOT_DOMAIN"; do
    a=$(resolves_to "$name" || true)
    note "$name -> ${a:-(not found yet)}   should be this site's public IP"
  done
  note "turn.$ROOT_DOMAIN -> the TURN machine's public IP (./setup.sh turn there)"

  bold "8. Starting"
  run "${compose[@]}" config --quiet
  run "${compose[@]}" up -d --build "${services[@]}"
  if [ "$DRY" = 0 ]; then
    note "Waiting for the API to answer..."
    local ok=0
    for _ in $(seq 1 60); do
      if "${compose[@]}" exec -T api node -e "fetch('http://127.0.0.1:'+(process.env.API_PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" >/dev/null 2>&1; then ok=1; break; fi
      sleep 3
    done
    [ "$ok" = 1 ] && note "The API is up." || warn "The API did not answer within 3 minutes: ${compose[*]} logs api migrate"
  fi

  bold "Next"
  if [ "$FRONT" = proxy ]; then
    note "In Nginx Proxy Manager, two proxy hosts, each with a Let's Encrypt certificate and Force SSL:"
    note "  api.$ROOT_DOMAIN -> http://<this machine's IP>:$API_PORT"
    note "  app.$ROOT_DOMAIN -> http://<this machine's IP>:$DASHBOARD_PORT"
  else
    note "Ports 80 and 443 must reach this machine (port forward them on your router/firewall)."
  fi
  note "Sign up at https://app.$ROOT_DOMAIN with an admin email."
  note "On the TURN machine: ./setup.sh turn, with these values:"
  note "  TURN_SHARED_SECRET=$TURN_SHARED_SECRET"
  note "  TURN_USAGE_TOKEN=$TURN_USAGE_TOKEN"
  note "  API_BASE=https://api.$ROOT_DOMAIN   TURN_HOST=turn.$ROOT_DOMAIN"
  note "In Nova, put this in <Nova Data>/remote/config.json, then restart Nova:"
  note "  {\"root_domain\": \"$ROOT_DOMAIN\", \"api_base\": \"https://api.$ROOT_DOMAIN\"}"
  note "Later, the same command again: ${compose[*]} up -d --build ${services[*]}"
}

# ---------------------------------------------------------------- the TURN relay

setup_turn() {
  bold "The TURN relay (coturn): carries presenters' audio when a direct path fails"
  note "It needs a machine with a PUBLIC address (a small cloud server is ideal), not one"
  note "behind a home router: it refuses to relay into private networks by design."
  load_old .env
  load_old deploy/turn/.env
  need_docker

  ask_required ROOT_DOMAIN "Domain (as on the platform)" "$(old ROOT_DOMAIN)"
  ROOT_DOMAIN=${ROOT_DOMAIN,,}; ROOT_DOMAIN=${ROOT_DOMAIN%.}
  ask_required TURN_HOST "This relay's name" "$(old TURN_HOST "turn.$ROOT_DOMAIN")"
  ask_required API_BASE "The platform's API" "$(old API_BASE "https://api.$ROOT_DOMAIN")"
  note "The next two come from the platform's .env (setup.sh printed them)."
  ask_required TURN_SHARED_SECRET "TURN_SHARED_SECRET" "$(old TURN_SHARED_SECRET)"
  ask_required TURN_USAGE_TOKEN "TURN_USAGE_TOKEN" "$(old TURN_USAGE_TOKEN)"
  note "Cloud servers behind 1:1 NAT (AWS, Google, Oracle...) see a private address on the"
  note "machine and a public one outside: give both as PUBLIC/PRIVATE. Empty if the public"
  note "address is on the machine itself."
  ask TURN_EXTERNAL_IP "External IP (PUBLIC/PRIVATE)" "$(old TURN_EXTERNAL_IP)"

  declare -gA ENV=(
    [TURN_HOST]=$TURN_HOST [API_BASE]=$API_BASE [TURN_SHARED_SECRET]=$TURN_SHARED_SECRET
    [TURN_SHARED_SECRET_PREVIOUS]=$(old TURN_SHARED_SECRET_PREVIOUS) [TURN_USAGE_TOKEN]=$TURN_USAGE_TOKEN
    [TURN_EXTERNAL_IP]=$TURN_EXTERNAL_IP [ROOT_DOMAIN]=$ROOT_DOMAIN
  )
  ENV_ORDER=(ROOT_DOMAIN TURN_HOST API_BASE TURN_SHARED_SECRET TURN_SHARED_SECRET_PREVIOUS TURN_USAGE_TOKEN TURN_EXTERNAL_IP)
  write_env deploy/turn/.env

  local a
  a=$(resolves_to "$TURN_HOST" || true)
  note "$TURN_HOST -> ${a:-(not found yet)}   should be this machine's public IP"

  run docker compose -f deploy/turn/docker-compose.yml config --quiet
  run docker compose -f deploy/turn/docker-compose.yml up -d --build

  bold "Next"
  note "Open on this machine's firewall (and the cloud provider's): UDP+TCP 3478, TCP 443,"
  note "UDP 49152-65535."
  note "Logs: docker compose -f deploy/turn/docker-compose.yml logs -f"
}

# ---------------------------------------------------------------- start

if [ -z "$MODE" ]; then
  bold "What should this machine run?"
  note "platform: the API, dashboard, worker and database"
  note "turn:     the audio relay (needs its own public address)"
  note "both:     everything on one machine with a public address"
  choose MODE "Set up" platform platform turn both
fi
[ "$DRY" = 1 ] && note "(dry run: settings files are written, nothing is started)"
case "$MODE" in
  platform) setup_platform ;;
  turn) setup_turn ;;
  both) setup_platform; OLD=(); setup_turn ;;
esac
cd "$HERE"
