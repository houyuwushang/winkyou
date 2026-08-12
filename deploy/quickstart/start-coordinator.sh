#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${WINK_AUTH_KEY:?set WINK_AUTH_KEY to a random deployment secret}"
: "${WINK_COORD_TLS_CERT:?set WINK_COORD_TLS_CERT to the coordinator certificate path}"
: "${WINK_COORD_TLS_KEY:?set WINK_COORD_TLS_KEY to the coordinator private-key path}"

args=(
  --listen "${WINK_COORD_LISTEN:-:50051}"
  --network-cidr "${WINK_NETWORK_CIDR:-10.42.0.0/24}"
  --lease-ttl "${WINK_LEASE_TTL:-30s}"
  --auth-key "${WINK_AUTH_KEY}"
  --tls-cert "${WINK_COORD_TLS_CERT}"
  --tls-key "${WINK_COORD_TLS_KEY}"
  --store-backend "${WINK_STORE_BACKEND:-memory}"
)

if [[ -n "${WINK_SQLITE_PATH:-}" ]]; then
  args+=(--sqlite-path "${WINK_SQLITE_PATH}")
fi

exec "${ROOT}/bin/wink-coordinator" "${args[@]}"
