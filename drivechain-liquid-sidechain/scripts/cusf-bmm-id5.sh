#!/usr/bin/env bash
# cusf-bmm-id5.sh — Minimal reliable BMM driver for Liquid/Elements ID 5
# Uses the *exact* proven host buf one-liner from liquid-side-status.sh + e2e grpc_curl pattern.
# Bypasses all Python f-string / subprocess fragility on this Mac (arm64 + homebrew buf).
# Usage: ./cusf-bmm-id5.sh [height] [critical_hex] [value_sats=1000]
set -euo pipefail

LIQUID_ID=5
HEIGHT="${1:-1}"
CRITICAL="${2:-0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206}"
VALUE="${3:-1000}"
PREV_BYTES="0000000000000000000000000000000000000000000000000000000000000000"

# Robust LOCAL_DEV discovery (exact copy from status.sh)
if [ -z "${LOCAL_DEV:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CANDIDATES=(
    "/Volumes/T705/code/drivechain-wallet-dev/local-dev"
    "$SCRIPT_DIR/../../../drivechain-wallet-dev/local-dev"
    "$(dirname "$SCRIPT_DIR")/../drivechain-wallet-dev/local-dev"
    "$HOME/drivechain-wallet-dev/local-dev"
  )
  for c in "${CANDIDATES[@]}"; do
    if [ -f "$c/docker-compose.local-minimal.yml" ]; then
      LOCAL_DEV="$c"; break
    fi
  done
fi
LOCAL_DEV="${LOCAL_DEV:-/Volumes/T705/code/drivechain-wallet-dev/local-dev}"
COMPOSE_FILE="${COMPOSE_FILE:-$LOCAL_DEV/docker-compose.local-minimal.yml}"

PAYLOAD='{"sidechainId":'"$LIQUID_ID"',"valueSats":{"value":'"$VALUE"'},"height":'"$HEIGHT"',"criticalHash":{"value":"'"$CRITICAL"'"},"prevBytes":{"value":"'"$PREV_BYTES"'"}}'

echo "=== CUSF CreateBmmCriticalDataTransaction ID${LIQUID_ID} (real critical from live elementsd) ==="
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Height: $HEIGHT"
echo "Critical: ${CRITICAL}"
echo "Payload: $PAYLOAD"
echo ""

( command -v buf >/dev/null && buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d "$PAYLOAD" http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>&1 \
  || docker compose -f "$COMPOSE_FILE" run --rm --pull=never buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d "$PAYLOAD" http://enforcer:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>&1 ) | cat

echo ""
echo "=== End BMM call (check for txid or exact 'broadcast deposit transaction failed' string) ==="
