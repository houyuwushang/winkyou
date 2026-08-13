#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${WINK_COORD_TLS_CERT:?set WINK_COORD_TLS_CERT to the coordinator certificate path}"
: "${WINK_COORD_TLS_KEY:?set WINK_COORD_TLS_KEY to the coordinator private-key path}"

if [[ -n "${WINK_AUTH_KEY:-}" && -n "${WINK_COORD_AUTH_KEY_FILE:-}" ]]; then
  echo "set only one of WINK_AUTH_KEY or WINK_COORD_AUTH_KEY_FILE" >&2
  exit 1
fi
if [[ -z "${WINK_AUTH_KEY:-}" && -z "${WINK_COORD_AUTH_KEY_FILE:-}" ]]; then
  echo "set WINK_COORD_AUTH_KEY_FILE to a one-line deployment secret file" >&2
  exit 1
fi

args=(
  --listen "${WINK_COORD_LISTEN:-:50051}"
  --network-cidr "${WINK_NETWORK_CIDR:-10.42.0.0/24}"
  --lease-ttl "${WINK_LEASE_TTL:-30s}"
  --tls-cert "${WINK_COORD_TLS_CERT}"
  --tls-key "${WINK_COORD_TLS_KEY}"
  --store-backend "${WINK_STORE_BACKEND:-memory}"
)

if [[ -n "${WINK_COORD_AUTH_KEY_FILE:-}" ]]; then
  args+=(--auth-key-file "${WINK_COORD_AUTH_KEY_FILE}")
else
  echo "warning: WINK_AUTH_KEY is deprecated because it exposes the secret in process arguments; use WINK_COORD_AUTH_KEY_FILE" >&2
  args+=(--auth-key "${WINK_AUTH_KEY}")
fi

if [[ -n "${WINK_SQLITE_PATH:-}" ]]; then
  args+=(--sqlite-path "${WINK_SQLITE_PATH}")
fi

exec "${ROOT}/bin/wink-coordinator" "${args[@]}"
