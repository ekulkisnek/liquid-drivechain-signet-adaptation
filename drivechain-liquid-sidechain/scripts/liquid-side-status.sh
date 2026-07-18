#!/usr/bin/env bash
printf '%s\n' 'ERROR: quarantined legacy slot-5/regtest launcher. This fork supports only Elements Drivechain (-chain=elements), BIP300 slot 24. See the repository README.md.' >&2
exit 64

# liquid-side-status.sh — Quick status + evidence for Liquid/Elements ID 5 on drivechain signet.
# Pure CUSF queries (no fed). Run anytime stack is up.
set -euo pipefail

# Robust discovery of the drivechain local-dev dir (works from anywhere in the repo)
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
      LOCAL_DEV="$c"
      break
    fi
  done
fi
LOCAL_DEV="${LOCAL_DEV:-/Volumes/T705/code/drivechain-wallet-dev/local-dev}"
COMPOSE_FILE="${COMPOSE_FILE:-$LOCAL_DEV/docker-compose.local-minimal.yml}"
LIQUID_ID=5

echo "=== Liquid/Elements Sidechain ID $LIQUID_ID Status (native CUSF) ==="
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Stack: $COMPOSE_FILE"

# Health
docker compose -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -E 'mainchain|enforcer' || true

MAIN_H=$(docker exec private-drivechain-local-mainchain-1 \
  drivechain-cli -signet -rpccookiefile=/data/signet/.cookie getblockcount 2>/dev/null || echo '?')
echo "Mainchain height: $MAIN_H"

echo ""
echo "GetSidechains (ID $LIQUID_ID excerpt):"
( command -v buf >/dev/null && buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d '{}' http://127.0.0.1:50051/cusf.mainchain.v1.ValidatorService/GetSidechains 2>/dev/null \
  || docker compose -f "$COMPOSE_FILE" run --rm --pull=never buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d '{}' http://enforcer:50051/cusf.mainchain.v1.ValidatorService/GetSidechains 2>/dev/null ) \
  | jq --argjson id "$LIQUID_ID" '.sidechains[]? | select(.sidechainNumber == $id) | {sidechainNumber, proposalHeight, activationHeight, voteCount, title: .declaration.v0.title}' || echo "(no jq or query failed)"

echo ""
echo "GetTwoWayPegData (ID $LIQUID_ID, empty until first deposits+BMMs):"
( command -v buf >/dev/null && buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d "{\"sidechainId\":$LIQUID_ID}" http://127.0.0.1:50051/cusf.mainchain.v1.ValidatorService/GetTwoWayPegData 2>/dev/null \
  || docker compose -f "$COMPOSE_FILE" run --rm --pull=never buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge \
  -d "{\"sidechainId\":$LIQUID_ID}" http://enforcer:50051/cusf.mainchain.v1.ValidatorService/GetTwoWayPegData 2>/dev/null ) | jq . || true

echo ""
echo "Tip: For activation mining fallback: USE_GENERATE_FALLBACK=1 ./activate-liquid-id5.sh"
echo "Full e2e: ./tests/e2e-liquid-on-signet.sh (captures txids, errors, state)"
echo "Evidence of prior activation: proposalHeight 118, activationHeight 124 (if listed above)."
