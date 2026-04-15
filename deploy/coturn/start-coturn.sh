#!/usr/bin/env bash
# deploy/coturn/start-coturn.sh - Start coturn relay for WinkYou
# Usage: EXTERNAL_IP=<your-ip> bash deploy/coturn/start-coturn.sh

set -euo pipefail

EXTERNAL_IP="${EXTERNAL_IP:-${WINK_RELAY_IP:-}}"

if [ -z "$EXTERNAL_IP" ]; then
  echo "Error: EXTERNAL_IP or WINK_RELAY_IP must be set" >&2
  echo "Usage: EXTERNAL_IP=203.0.113.10 bash $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$SCRIPT_DIR/turnserver.conf"

if [ ! -f "$CONF" ]; then
  echo "Error: $CONF not found" >&2
  exit 1
fi

TMPCONF="$(mktemp)"
trap "rm -f '$TMPCONF'" EXIT

sed "s/<EXTERNAL_IP>/$EXTERNAL_IP/g" "$CONF" > "$TMPCONF"

echo "=== coturn configuration ==="
echo "  External IP:   $EXTERNAL_IP"
echo "  Listen port:   3478/udp"
echo "  Relay ports:   49152-65535/udp"
echo "  Realm:         winkyou"
echo ""
echo "Ensure firewall allows:"
echo "  - UDP 3478"
echo "  - UDP 49152-65535"
echo "==========================="

cd "$SCRIPT_DIR"
docker-compose up -d
echo "coturn started. Check logs: docker-compose -f $SCRIPT_DIR/docker-compose.yml logs -f"
