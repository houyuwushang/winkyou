#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${WINK_RELAY_IP:?set WINK_RELAY_IP to the public IPv4 address clients should use for TURN}"

exec "${ROOT}/bin/wink-relay" \
  --listen "${WINK_RELAY_LISTEN:-${WINK_RELAY_IP}:3478}" \
  --realm "${WINK_REALM:-winkyou}" \
  --users "${WINK_TURN_USERS:-winkdemo:winkdemo-pass}" \
  --relay-ip "${WINK_RELAY_IP}"
