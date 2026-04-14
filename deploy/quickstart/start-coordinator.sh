#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

args=(
  --listen "${WINK_COORD_LISTEN:-:50051}"
  --network-cidr "${WINK_NETWORK_CIDR:-10.42.0.0/24}"
  --lease-ttl "${WINK_LEASE_TTL:-30s}"
  --auth-key "${WINK_AUTH_KEY:-wink-demo-key}"
  --store-backend "${WINK_STORE_BACKEND:-memory}"
)

if [[ -n "${WINK_SQLITE_PATH:-}" ]]; then
  args+=(--sqlite-path "${WINK_SQLITE_PATH}")
fi

exec "${ROOT}/bin/wink-coordinator" "${args[@]}"
