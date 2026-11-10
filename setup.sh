#!/usr/bin/env bash
# Set up the Nova platform on this machine, step by step.
#
#   ./setup.sh             asks what to set up
#   ./setup.sh platform    the API, dashboard, worker and database (docker-compose.yml)
#   ./setup.sh turn        the TURN relay (deploy/turn), on a machine with a public address
#   ./setup.sh check       tests an existing setup: Cloudflare, DNS records, containers, the API
#   ./setup.sh --dry-run   writes the settings files and shows the commands, starts nothing
#
# It writes .env (and deploy/turn/.env) from your answers, makes every secret itself, and
# starts the containers. Run it again to change an answer: what you gave before is the
# default. Needs Docker with the compose plugin, and openssl (or /dev/urandom); with curl
# it also tests your Cloudflare token and can add the platform's DNS records for you.
# New to Cloudflare? docs/cloudflare-setup.md goes through it step by step.
set -euo pipefail

cd "$(dirname "$0")"
HERE=$(pwd)
DRY=0
MODE=""
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    platform|turn|both|check) MODE="$a" ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
fail() { printf '\033[31m  x %s\033[0m\n' "$*" >&2; exit 1; }
good() { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
PROBLEMS=0
bad() { printf '\033[31m  ✗ %s\033[0m\n' "$*"; PROBLEMS=$((PROBLEMS + 1)); }

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

INPUT_ENDED=0 # set once there is nothing more to read (answers piped in ran out)
ask() { # ask VAR "question" default
  local var=$1 q=$2 def=${3:-} reply=""
  if [ -n "$def" ]; then read -r -p "  $q [$def]: " reply || INPUT_ENDED=1; else read -r -p "  $q: " reply || INPUT_ENDED=1; fi
  reply=${reply#"${reply%%[![:space:]]*}"}; reply=${reply%"${reply##*[![:space:]]}"}
  printf -v "$var" '%s' "${reply:-$def}"
}
ask_required() {
  local var=$1
  while :; do
    ask "$@"
    [ -n "${!var}" ] && return 0
    [ "$INPUT_ENDED" = 1 ] && fail "No answer for \"$2\", and nothing more to read."
    warn "This one is needed."
  done
}
ask_secret() { # like ask_required, but a saved value is offered without being shown
  local var=$1 q=$2 def=${3:-} reply=""
  while :; do
    if [ -n "$def" ]; then read -r -p "  $q [Enter keeps the saved one]: " reply || INPUT_ENDED=1; else read -r -p "  $q: " reply || INPUT_ENDED=1; fi
    reply=${reply//[[:space:]]/}
    printf -v "$var" '%s' "${reply:-$def}"
    [ -n "${!var}" ] && return 0
    [ "$INPUT_ENDED" = 1 ] && fail "No answer for \"$q\", and nothing more to read."
    warn "This one is needed."
  done
}
ask_domain() { # ask_domain VAR "question" default: a bare domain name, tidied (no https://, no path)
  local var=$1 v
  while :; do
    ask_required "$@"
    v=${!var,,}; v=${v#*://}; v=${v%%/*}; v=${v%.}
    if [[ "$v" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]]; then printf -v "$var" '%s' "$v"; return 0; fi
    [ "$INPUT_ENDED" = 1 ] && fail "\"$v\" is not a domain name."
    warn "That does not look like a domain name. Give it like: myradiohost.com"
  done
}
choose() { # choose VAR "question" default option...
  local var=$1 q=$2 def=$3; shift 3
  local opts="$*" reply
  while :; do
    reply=""
    read -r -p "  $q ($opts) [$def]: " reply || INPUT_ENDED=1
    reply=${reply:-$def}; reply=${reply,,}
    for o in "$@"; do [ "$reply" = "$o" ] && { printf -v "$var" '%s' "$reply"; return 0; }; done
    [ "$INPUT_ENDED" = 1 ] && fail "\"$reply\" is not one of: $opts"
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

# ---------------------------------------------------------------- Cloudflare
# The same checks as the dashboard's Admin > Setup page, with the same wording as
# docs/cloudflare-setup.md. Everything here needs curl and CLOUDFLARE_API_TOKEN.

CF_API=${NOVA_CF_API:-https://api.cloudflare.com/client/v4}
CF_GUIDE="docs/cloudflare-setup.md"
CF_BODY=""; CF_STATUS=""; CF_OK=0
CF_ZONE_ID=""; CF_ZONE_NAME=""

cf() { # cf METHOD PATH [JSON]: fills CF_BODY and CF_STATUS; true when Cloudflare said yes
  local method=$1 path=$2 data=${3:-} out
  local args=(-sS -m 20 -X "$method" -H "Content-Type: application/json" -w '\n%{http_code}')
  [ -n "$data" ] && args+=(--data "$data")
  # The token goes to curl through a config on a pipe, so it never shows in the process list.
  out=$(curl "${args[@]}" -K <(printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN") "$CF_API$path" 2>/dev/null) || { CF_BODY=""; CF_STATUS=000; return 1; }
  CF_STATUS=${out##*$'\n'}; CF_BODY=${out%$'\n'*}
  [[ "$CF_STATUS" == 2* ]] && printf '%s' "$CF_BODY" | grep -q '"success"[[:space:]]*:[[:space:]]*true'
}
cf_field() { # the first "KEY": "VALUE" in the last answer
  printf '%s' "$CF_BODY" | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -n 1 | sed 's/^[^:]*:[[:space:]]*"\(.*\)"$/\1/' || true
}
cf_refused() { # say why the last request failed, in the guide's words
  case "$CF_STATUS" in
    000) warn "Cloudflare could not be reached from this machine. Check its internet connection." ;;
    401) warn "Cloudflare did not accept the token. It may be copied incompletely, deleted, or be"
         warn "the Global API Key. See $CF_GUIDE, step 5." ;;
    403) warn "The token may not use this domain. It was made for another domain, or the Zone ID"
         warn "is another domain's. See $CF_GUIDE, steps 4 and 5." ;;
    400|404)
      if printf '%s' "$CF_BODY" | grep -qiE 'token|authoriz|header'; then
        warn "Cloudflare did not accept the token. Paste all of it. See $CF_GUIDE, step 5."
      else
        warn "Cloudflare does not know this Zone ID. Copy the Zone ID again (not the Account ID)."
        warn "See $CF_GUIDE, step 4."
      fi ;;
    *) warn "Cloudflare answered $CF_STATUS: $(cf_field message)" ;;
  esac
}
cf_find_zone() { # cf_find_zone DOMAIN: the zone holding it (itself or a parent) -> CF_ZONE_ID, CF_ZONE_NAME
  local name=$1
  CF_ZONE_ID=""; CF_ZONE_NAME=""
  while [[ "$name" == *.* ]]; do
    if cf GET "/zones?name=$name"; then
      if printf '%s' "$CF_BODY" | grep -q "\"name\"[[:space:]]*:[[:space:]]*\"$name\""; then
        CF_ZONE_ID=$(cf_field id); CF_ZONE_NAME=$name
        [[ "$CF_ZONE_ID" =~ ^[0-9a-f]{32}$ ]] && return 0
        CF_ZONE_ID=""
      fi
    else
      return 1 # the token itself was refused: looking further up will not help
    fi
    name=${name#*.}
  done
  return 1
}
cf_verify() { # may the token read and change this zone's records, and is the zone the right, active one?
  local zone=$CLOUDFLARE_ZONE_ID probe="_nova-setup-check.$ROOT_DOMAIN" id got status servers
  if ! cf GET "/zones/$zone/dns_records?per_page=1"; then cf_refused; return 1; fi
  good "The token and the Zone ID belong together."
  if cf GET "/zones/$zone"; then
    got=$(cf_field name); status=$(cf_field status)
    if [ -n "$got" ] && [ "$got" != "$ROOT_DOMAIN" ] && [[ "$ROOT_DOMAIN" != *".$got" ]]; then
      warn "This Zone ID belongs to $got, but your domain is $ROOT_DOMAIN. Copy the Zone ID of"
      warn "the right domain. See $CF_GUIDE, step 4."
      return 1
    fi
    if [ -n "$status" ] && [ "$status" != active ]; then
      servers=$(printf '%s' "$CF_BODY" | grep -o '"name_servers"[[:space:]]*:[[:space:]]*\[[^]]*\]' | grep -o '"[a-z0-9.-]*\.[a-z]*"' | tr -d '"' | paste -sd' ' - || true)
      warn "The domain is not active at Cloudflare yet (status: $status). At your registrar, set"
      warn "the nameservers to: ${servers:-the two Cloudflare gave you}. Then wait: certificates"
      warn "cannot be issued until it is active. See $CF_GUIDE, step 3."
    else
      good "The domain is active at Cloudflare."
    fi
  fi
  if [ "$DRY" = 1 ]; then note "(dry run: not adding a test record)"; return 0; fi
  if cf POST "/zones/$zone/dns_records" "{\"type\":\"TXT\",\"name\":\"$probe\",\"content\":\"\\\"nova-$(secret 6)\\\"\",\"ttl\":60}"; then
    id=$(cf_field id); got=$(cf_field name)
    [ -z "$id" ] || cf DELETE "/zones/$zone/dns_records/$id" || true
    if [ -n "$got" ] && [ "$got" != "$probe" ]; then
      warn "This Zone ID belongs to ${got#"$probe".}, but your domain is $ROOT_DOMAIN. Copy the"
      warn "Zone ID of the right domain. See $CF_GUIDE, step 4."
      return 1
    fi
    good "The token can change the domain's records (a test record was added and removed)."
  elif [ "$CF_STATUS" = 403 ] || [ "$CF_STATUS" = 401 ]; then
    warn "The token can read but not change records. Create a new one from the \"Edit zone DNS\""
    warn "template. See $CF_GUIDE, step 5."
    return 1
  else
    warn "Cloudflare refused a test record ($CF_STATUS: $(cf_field message))."
    return 1
  fi
}
cf_point() { # cf_point NAME IP: add the record if it is missing; never change one that is there
  local name=$1 ip=$2 type=A have
  [[ "$ip" == *:* ]] && type=AAAA
  if ! cf GET "/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=$type&name=$name"; then
    warn "Could not look up $name at Cloudflare; add it yourself: $type $name -> $ip (grey cloud)."
    return 0
  fi
  have=$(cf_field content)
  if [ "$have" = "$ip" ]; then
    good "$name already points to $ip."
  elif [ -n "$have" ]; then
    warn "$name points to $have, not $ip. Left as it is: change it at Cloudflare if that is wrong."
  elif [ "$DRY" = 1 ]; then
    note "(dry run) would add: $type $name -> $ip"
  elif cf POST "/zones/$CLOUDFLARE_ZONE_ID/dns_records" "{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":false}"; then
    good "Added $name -> $ip (grey cloud, DNS only)."
  else
    warn "Cloudflare did not add $name ($CF_STATUS: $(cf_field message)). Add it yourself: $type $name -> $ip."
  fi
}
public_ip() { curl -s -m 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' || true; }

# ---------------------------------------------------------------- the platform

setup_platform() {
  bold "The Nova platform: API, dashboard, worker and database"
  load_old .env
  need_docker

  bold "1. Your domain"
  note "Stations get <name>.DOMAIN; the API is api.DOMAIN, the dashboard app.DOMAIN, TURN turn.DOMAIN."
  ask_domain ROOT_DOMAIN "Domain" "$(old ROOT_DOMAIN)"

  bold "2. DNS for station names"
  note "cloudflare: station names and their certificates work. The free Cloudflare plan is"
  note "            enough. You need an API token that may edit this domain's DNS."
  note "            Never done this? $CF_GUIDE goes through it step by step."
  note "memory:     no Cloudflare. Station names are NOT published and their certificates"
  note "            fail; the dashboard and the TURN relay still work."
  choose DNS_PROVIDER "DNS provider" "$(old DNS_PROVIDER cloudflare)" cloudflare memory
  CLOUDFLARE_API_TOKEN=""; CLOUDFLARE_ZONE_ID=""; CF_OK=0
  if [ "$DNS_PROVIDER" = cloudflare ]; then
    local again
    while :; do
      ask_secret CLOUDFLARE_API_TOKEN "Cloudflare API token" "$(old CLOUDFLARE_API_TOKEN)"
      if ! command -v curl >/dev/null 2>&1; then
        ask_required CLOUDFLARE_ZONE_ID "Cloudflare Zone ID" "$(old CLOUDFLARE_ZONE_ID)"
        warn "curl is not installed, so the token was not tested. Later: ./setup.sh check"
        break
      fi
      note "Asking Cloudflare about $ROOT_DOMAIN..."
      if cf_find_zone "$ROOT_DOMAIN"; then
        good "Found $CF_ZONE_NAME at Cloudflare; its Zone ID is $CF_ZONE_ID."
        CLOUDFLARE_ZONE_ID=$CF_ZONE_ID
      elif [ "$CF_STATUS" = 200 ] || [ "$CF_STATUS" = 403 ]; then
        note "This token cannot look the Zone ID up. It is on the domain's Overview page at"
        note "Cloudflare, lower right, under API ($CF_GUIDE, step 4)."
        ask_required CLOUDFLARE_ZONE_ID "Cloudflare Zone ID" "$(old CLOUDFLARE_ZONE_ID)"
      else
        CLOUDFLARE_ZONE_ID=$(old CLOUDFLARE_ZONE_ID)
      fi
      if [ -n "$CLOUDFLARE_ZONE_ID" ] && cf_verify; then CF_OK=1; break; fi
      [ -n "$CLOUDFLARE_ZONE_ID" ] || cf_refused
      [ "$INPUT_ENDED" = 1 ] && again=no || choose again "Enter the token again" yes yes no
      if [ "$again" = no ]; then
        [ -n "$CLOUDFLARE_ZONE_ID" ] || ask_required CLOUDFLARE_ZONE_ID "Cloudflare Zone ID" "$(old CLOUDFLARE_ZONE_ID)"
        warn "Going on with these values. Station names will not work until this is fixed;"
        warn "test again any time with: ./setup.sh check"
        break
      fi
    done
  else
    warn "Memory DNS: station names will not resolve on the internet. Fine for the relay; not for names."
  fi

  bold "3. Certificates (Let's Encrypt)"
  while :; do
    ask_required ACME_EMAIL "Email for Let's Encrypt notices" "$(old ACME_EMAIL "ops@$ROOT_DOMAIN")"
    [[ "$ACME_EMAIL" == ?*@?*.?* ]] && break
    [ "$INPUT_ENDED" = 1 ] && fail "\"$ACME_EMAIL\" is not an email address."
    warn "That does not look like an email address."
  done
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

  bold "7. The platform's own DNS records"
  local a name ip="" add=no names=("api.$ROOT_DOMAIN" "app.$ROOT_DOMAIN")
  [ "$MODE" = both ] && names+=("turn.$ROOT_DOMAIN")
  if [ "$CF_OK" = 1 ]; then
    note "${names[*]} must point at this site's public IP address."
    choose add "Check them at Cloudflare, and add the missing ones" yes yes no
  fi
  if [ "$add" = yes ]; then
    ask ip "This site's public IP" "$(public_ip)"
    if [ -n "$ip" ]; then
      for name in "${names[@]}"; do cf_point "$name" "$ip"; done
    else
      warn "No address given: add the records yourself ($CF_GUIDE, step 6)."
    fi
  else
    for name in "${names[@]}"; do
      a=$(resolves_to "$name" || true)
      note "$name -> ${a:-(not found yet)}   should be this site's public IP"
    done
    note "Add them at your DNS provider as A records, DNS only ($CF_GUIDE, step 6)."
  fi
  [ "$MODE" = both ] || note "turn.$ROOT_DOMAIN -> the TURN machine's public IP (add it by hand; then ./setup.sh turn there)"

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
  note "Sign up at https://app.$ROOT_DOMAIN with an admin email. Admin > Setup there shows"
  note "what is unfinished, the Cloudflare guide, and a button that tests the connection."
  [ "$ACME_MODE" = staging ] && note "Certificates are test ones for now: once a station works, run this again and choose production."
  note "To test this setup at any time: ./setup.sh check"
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
  note "It runs either on a cloud server with its own public address, or on your own"
  note "network behind your router (beside Nova), with a few ports forwarded to it."
  load_old .env
  load_old deploy/turn/.env
  need_docker

  ask_domain ROOT_DOMAIN "Domain (as on the platform)" "$(old ROOT_DOMAIN)"
  ask_required TURN_HOST "This relay's name" "$(old TURN_HOST "turn.$ROOT_DOMAIN")"
  ask_required API_BASE "The platform's API" "$(old API_BASE "https://api.$ROOT_DOMAIN")"
  note "The next two come from the platform's .env (setup.sh printed them)."
  ask_required TURN_SHARED_SECRET "TURN_SHARED_SECRET" "$(old TURN_SHARED_SECRET)"
  ask_required TURN_USAGE_TOKEN "TURN_USAGE_TOKEN" "$(old TURN_USAGE_TOKEN)"
  local was_where=cloud
  [ -n "$(old TURN_ALLOWED_PEER_IP)" ] && was_where=home
  note "cloud: a server with its own public address (or 1:1 NAT, as AWS, Google, Oracle)."
  note "home:  this machine is on your network behind your router, like the Nova server."
  choose WHERE "Where is this relay" "$was_where" cloud home
  TURN_ALLOWED_PEER_IP=""
  if [ "$WHERE" = home ]; then
    note "Your public IP and this machine's LAN IP, as PUBLIC/PRIVATE (e.g. 203.0.113.7/192.168.1.40)."
    ask_required TURN_EXTERNAL_IP "External IP (PUBLIC/PRIVATE)" "$(old TURN_EXTERNAL_IP)"
    note "The relay refuses every private address except the Nova server's: give its LAN IP"
    note "(the computer Nova runs on; several, comma separated)."
    ask_required TURN_ALLOWED_PEER_IP "Nova server's LAN IP" "$(old TURN_ALLOWED_PEER_IP)"
    note "A small port range to forward, away from the ports Windows gives Nova (49152 and up)."
    ask_required TURN_MIN_PORT "First relay port" "$(old TURN_MIN_PORT 40000)"
    ask_required TURN_MAX_PORT "Last relay port" "$(old TURN_MAX_PORT 40999)"
    note "TURN over TLS needs its own port when 443 already goes to your proxy."
    ask_required TURN_TLS_PORT "TLS port" "$(old TURN_TLS_PORT 5349)"
  else
    note "Machines behind 1:1 NAT see a private address on the machine and a public one"
    note "outside: give both as PUBLIC/PRIVATE. Empty if the public address is on the machine."
    ask TURN_EXTERNAL_IP "External IP (PUBLIC/PRIVATE)" "$(old TURN_EXTERNAL_IP)"
    TURN_MIN_PORT=$(old TURN_MIN_PORT 49152); TURN_MAX_PORT=$(old TURN_MAX_PORT 65535); TURN_TLS_PORT=$(old TURN_TLS_PORT 443)
  fi
  if ! [ "$TURN_MIN_PORT" -lt "$TURN_MAX_PORT" ] 2>/dev/null; then
    fail "The first relay port must be a number below the last one."
  fi

  declare -gA ENV=(
    [TURN_HOST]=$TURN_HOST [API_BASE]=$API_BASE [TURN_SHARED_SECRET]=$TURN_SHARED_SECRET
    [TURN_SHARED_SECRET_PREVIOUS]=$(old TURN_SHARED_SECRET_PREVIOUS) [TURN_USAGE_TOKEN]=$TURN_USAGE_TOKEN
    [TURN_EXTERNAL_IP]=$TURN_EXTERNAL_IP [ROOT_DOMAIN]=$ROOT_DOMAIN [TURN_ALLOWED_PEER_IP]=$TURN_ALLOWED_PEER_IP
    [TURN_MIN_PORT]=$TURN_MIN_PORT [TURN_MAX_PORT]=$TURN_MAX_PORT [TURN_TLS_PORT]=$TURN_TLS_PORT
  )
  ENV_ORDER=(ROOT_DOMAIN TURN_HOST API_BASE TURN_SHARED_SECRET TURN_SHARED_SECRET_PREVIOUS TURN_USAGE_TOKEN TURN_EXTERNAL_IP
    TURN_ALLOWED_PEER_IP TURN_MIN_PORT TURN_MAX_PORT TURN_TLS_PORT)
  write_env deploy/turn/.env

  local a
  a=$(resolves_to "$TURN_HOST" || true)
  note "$TURN_HOST -> ${a:-(not found yet)}   should be this machine's public IP"

  run docker compose -f deploy/turn/docker-compose.yml config --quiet
  # Recreated every time: the relay reads its config only as it starts.
  run docker compose -f deploy/turn/docker-compose.yml up -d --build --force-recreate

  bold "Next"
  if [ "$WHERE" = home ]; then
    local lan=${TURN_EXTERNAL_IP#*/}
    note "On your router (OPNsense: Firewall > NAT > Port Forward), to $lan:"
    note "  UDP and TCP 3478"
    note "  UDP $TURN_MIN_PORT-$TURN_MAX_PORT"
    note "  TCP $TURN_TLS_PORT (optional: TURN over TLS)"
    note "And this machine's own firewall, if it has one: the same ports."
    note "If your public IP changes, run ./setup.sh turn again with the new one."
  else
    note "Open on this machine's firewall (and the cloud provider's): UDP+TCP 3478,"
    note "TCP $TURN_TLS_PORT, UDP $TURN_MIN_PORT-$TURN_MAX_PORT."
  fi
  note "Logs: docker compose -f deploy/turn/docker-compose.yml logs -f"
}

# ---------------------------------------------------------------- check

setup_check() {
  bold "Checking this platform's setup"
  [ -f .env ] || fail "There is no .env here yet: run ./setup.sh first."
  load_old .env
  ROOT_DOMAIN=$(old ROOT_DOMAIN); DNS_PROVIDER=$(old DNS_PROVIDER cloudflare)
  CLOUDFLARE_API_TOKEN=$(old CLOUDFLARE_API_TOKEN); CLOUDFLARE_ZONE_ID=$(old CLOUDFLARE_ZONE_ID)
  local key a name code

  bold "Settings (.env)"
  for key in ROOT_DOMAIN DATABASE_URL POSTGRES_PASSWORD SESSION_SECRET TURN_SHARED_SECRET ACME_EMAIL; do
    [ -n "$(old "$key")" ] && [ "$(old "$key")" != change-me ] || bad "$key is not set."
  done
  [ "$PROBLEMS" = 0 ] && good "The values that must be set are set."
  [ -n "$ROOT_DOMAIN" ] || fail "Without ROOT_DOMAIN nothing else can be checked."
  if [ "$(old ACME_DIRECTORY_URL)" = "https://acme-v02.api.letsencrypt.org/directory" ]; then
    good "Certificates come from Let's Encrypt (production)."
  else
    warn "Certificates are test certificates (staging): browsers warn about them. Run ./setup.sh and choose production once a station works."
  fi
  [ -n "$(old SMTP_URL)" ] && good "Email is sent through your SMTP server." || warn "No SMTP address: confirmation links are only written to the dashboard's log."
  [ -n "$(old ADMIN_EMAILS)" ] && good "Admins: $(old ADMIN_EMAILS)" || bad "ADMIN_EMAILS is empty: nobody becomes an admin."

  bold "DNS for station names"
  if [ "$DNS_PROVIDER" != cloudflare ]; then
    bad "DNS_PROVIDER is $DNS_PROVIDER: station names are not published. Run ./setup.sh and choose cloudflare ($CF_GUIDE)."
  elif ! command -v curl >/dev/null 2>&1; then
    warn "curl is not installed, so Cloudflare was not tested. The dashboard can: Admin > Setup."
  elif [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
    bad "CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID is empty. Run ./setup.sh ($CF_GUIDE)."
  elif cf_verify; then
    :
  else
    PROBLEMS=$((PROBLEMS + 1))
  fi

  bold "The platform's own addresses"
  for name in "api.$ROOT_DOMAIN" "app.$ROOT_DOMAIN" "$(old TURN_HOST "turn.$ROOT_DOMAIN")"; do
    a=$(resolves_to "$name" || true)
    if [ -n "$a" ]; then
      good "$name -> $a   (check that this is the right machine's public address)"
    else
      bad "$name is not found. Add an A record for it, DNS only ($CF_GUIDE, step 6)."
    fi
  done

  bold "Containers"
  local compose=(docker compose -f docker-compose.yml) want=(postgres api dashboard worker) running svc
  if [ -f docker-compose.proxy.yml ]; then compose+=(-f docker-compose.proxy.yml); else want+=(caddy); fi
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    warn "Docker is not available to this user, so the containers were not checked."
  else
    running=$("${compose[@]}" ps --services --status running 2>/dev/null || true)
    for svc in "${want[@]}"; do
      printf '%s\n' "$running" | grep -qx "$svc" && good "$svc is running." || bad "$svc is not running: ${compose[*]} logs $svc"
    done
    if printf '%s\n' "$running" | grep -qx api; then
      if "${compose[@]}" exec -T api node -e "fetch('http://127.0.0.1:'+(process.env.API_PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" >/dev/null 2>&1; then
        good "The API answers on this machine."
      else
        bad "The API does not answer: ${compose[*]} logs api migrate"
      fi
    fi
  fi

  bold "From the internet"
  if command -v curl >/dev/null 2>&1; then
    for name in "api.$ROOT_DOMAIN" "app.$ROOT_DOMAIN"; do
      code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "https://$name/healthz" 2>/dev/null || true)
      [ "$code" = 200 ] && good "https://$name answers." || bad "https://$name does not answer ($([ "${code:-000}" = 000 ] && echo "no reply" || echo "it said $code")). Check its DNS record, ports 80/443 and the proxy in front."
    done
  else
    warn "curl is not installed, so this was not checked."
  fi

  if [ "$PROBLEMS" = 0 ]; then
    bold "All good."
  else
    bold "$PROBLEMS thing(s) to fix: see the red lines above."
    exit 1
  fi
}

# ---------------------------------------------------------------- start

if [ -z "$MODE" ]; then
  bold "What should this machine run?"
  note "platform: the API, dashboard, worker and database"
  note "turn:     the audio relay (needs its own public address)"
  note "both:     everything on one machine with a public address"
  note "check:    change nothing; test a setup that is already there"
  choose MODE "Set up" platform platform turn both check
fi
[ "$DRY" = 1 ] && note "(dry run: settings files are written, nothing is started)"
case "$MODE" in
  platform) setup_platform ;;
  turn) setup_turn ;;
  both) setup_platform; OLD=(); setup_turn ;;
  check) setup_check ;;
esac
cd "$HERE"
