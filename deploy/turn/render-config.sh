#!/bin/sh
# Render turnserver.conf from the environment: TURN_SHARED_SECRET, TURN_HOST and,
# during a rotation, TURN_SHARED_SECRET_PREVIOUS. TURN_EXTERNAL_IP (PUBLIC/PRIVATE) for a
# host behind 1:1 NAT (most cloud servers) or a home router: coturn then hands out the
# public address. On a home network beside Nova (behind the same router):
#   TURN_ALLOWED_PEER_IP  the Nova server's LAN address(es), comma separated: the one
#                         private address the relay may send audio to (all others stay
#                         refused, see the template);
#   TURN_MIN_PORT/MAX_PORT the relay's port range (default 49152-65535), small enough to
#                         forward and clear of the ports the Nova server uses itself;
#   TURN_TLS_PORT         TURN over TLS (default 443; 5349 when 443 is taken, e.g. by a proxy).
set -eu
: "${TURN_SHARED_SECRET:?set TURN_SHARED_SECRET}"
: "${TURN_HOST:?set TURN_HOST}"
if [ -n "${TURN_SHARED_SECRET_PREVIOUS:-}" ]; then
  TURN_PREVIOUS_SECRET_LINE="static-auth-secret=${TURN_SHARED_SECRET_PREVIOUS}"
else
  TURN_PREVIOUS_SECRET_LINE=""
fi
if [ -n "${TURN_EXTERNAL_IP:-}" ]; then
  TURN_EXTERNAL_IP_LINE="external-ip=${TURN_EXTERNAL_IP}"
else
  TURN_EXTERNAL_IP_LINE=""
fi
TURN_MIN_PORT=${TURN_MIN_PORT:-49152}
TURN_MAX_PORT=${TURN_MAX_PORT:-65535}
TURN_TLS_PORT=${TURN_TLS_PORT:-443}
for p in "$TURN_MIN_PORT" "$TURN_MAX_PORT" "$TURN_TLS_PORT"; do
  case "$p" in ''|*[!0-9]*) echo "render-config: ports must be numbers (got '$p')" >&2; exit 1 ;; esac
done
if [ "$TURN_MIN_PORT" -ge "$TURN_MAX_PORT" ]; then
  echo "render-config: TURN_MIN_PORT must be below TURN_MAX_PORT" >&2; exit 1
fi
export TURN_PREVIOUS_SECRET_LINE TURN_EXTERNAL_IP_LINE TURN_MIN_PORT TURN_MAX_PORT TURN_TLS_PORT
here=$(dirname "$0")
sed -e "s|\${TURN_SHARED_SECRET}|${TURN_SHARED_SECRET}|" \
    -e "s|\${TURN_PREVIOUS_SECRET_LINE}|${TURN_PREVIOUS_SECRET_LINE}|" \
    -e "s|\${TURN_EXTERNAL_IP_LINE}|${TURN_EXTERNAL_IP_LINE}|" \
    -e "s|\${TURN_MIN_PORT}|${TURN_MIN_PORT}|" \
    -e "s|\${TURN_MAX_PORT}|${TURN_MAX_PORT}|" \
    -e "s|\${TURN_TLS_PORT}|${TURN_TLS_PORT}|" \
    -e "s|\${TURN_HOST}|${TURN_HOST}|g" "$here/turnserver.conf.template" > "${1:-/etc/coturn/turnserver.conf}"
# The Nova server beside it on the same private network: allowed, before every private
# range the template refuses (coturn lets allowed-peer-ip win over denied-peer-ip).
out=${1:-/etc/coturn/turnserver.conf}
for ip in $(printf '%s' "${TURN_ALLOWED_PEER_IP:-}" | tr ',' ' '); do
  printf 'allowed-peer-ip=%s\n' "$ip" >> "$out"
done
