#!/bin/sh
# Render turnserver.conf from the environment: TURN_SHARED_SECRET, TURN_HOST and,
# during a rotation, TURN_SHARED_SECRET_PREVIOUS.
set -eu
: "${TURN_SHARED_SECRET:?set TURN_SHARED_SECRET}"
: "${TURN_HOST:?set TURN_HOST}"
if [ -n "${TURN_SHARED_SECRET_PREVIOUS:-}" ]; then
  TURN_PREVIOUS_SECRET_LINE="static-auth-secret=${TURN_SHARED_SECRET_PREVIOUS}"
else
  TURN_PREVIOUS_SECRET_LINE=""
fi
export TURN_PREVIOUS_SECRET_LINE
here=$(dirname "$0")
sed -e "s|\${TURN_SHARED_SECRET}|${TURN_SHARED_SECRET}|" \
    -e "s|\${TURN_PREVIOUS_SECRET_LINE}|${TURN_PREVIOUS_SECRET_LINE}|" \
    -e "s|\${TURN_HOST}|${TURN_HOST}|g" "$here/turnserver.conf.template" > "${1:-/etc/coturn/turnserver.conf}"
