#!/usr/bin/env bash
# activate-liquid-id5.sh — Wrapper for native Liquid/Elements sidechain ID 5 activation.
# Uses the exact same canonical mechanism as plain-bitassets ID 4 (CreateSidechainProposal + mine until active).
# Includes fallback to WalletService/GenerateBlocks for Mac QEMU GBT/mintime fragility during rapid activation mining.
# No federation, no shortcuts — pure CUSF/BIP300/301.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DEV_DIR="/Volumes/T705/code/drivechain-wallet-dev/local-dev"
PROPOSAL_JSON="${PROPOSAL_JSON:-$SCRIPT_DIR/../config/liquid-signet-proposal-id5.json}"
USE_GENERATE_FALLBACK="${USE_GENERATE_FALLBACK:-0}"

echo "=== Activating Liquid/Elements sidechain ID 5 (native drivechain) ==="
echo "Proposal: $PROPOSAL_JSON"
echo "Canonical activator: $LOCAL_DEV_DIR/scripts/activate-sidechain.sh"
echo "GenerateBlocks fallback enabled: $USE_GENERATE_FALLBACK (bypasses python miner GBT issues per LOCAL_DEVELOPMENT_NOTES)"

if [ ! -f "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" ]; then
  echo "ERROR: canonical activate-sidechain.sh not found. Is drivechain-wallet-dev at expected location?" >&2
  exit 1
fi

if [ "$USE_GENERATE_FALLBACK" = "1" ]; then
  echo "[LIQUID-ACTIVATE] Using GenerateBlocks fallback path for activation mining (more stable on local Mac)..."
  # Submit proposal via canonical (or direct), then loop GenerateBlocks + poll
  "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" 5 "$PROPOSAL_JSON" || true
  # If still not active, fallback mining loop
  for i in $(seq 1 12); do
    if command -v buf >/dev/null 2>&1; then
      buf curl --timeout 10s --protocol grpc --http2-prior-knowledge http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/GenerateBlocks >/dev/null 2>&1 || true
    else
      docker compose -f "$LOCAL_DEV_DIR/docker-compose.local-minimal.yml" run --rm --pull=never buf curl --timeout 10s --protocol grpc --http2-prior-knowledge http://enforcer:50051/cusf.mainchain.v1.WalletService/GenerateBlocks >/dev/null 2>&1 || true
    fi
    sleep 2
    if "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" 5 "$PROPOSAL_JSON" 2>&1 | grep -q "already active"; then
      echo "[LIQUID-ACTIVATE] ID 5 active after $i GenerateBlocks fallback."
      exit 0
    fi
  done
  echo "[LIQUID-ACTIVATE] Fallback timed; check GetSidechains manually." >&2
  exit 1
else
  exec "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" 5 "$PROPOSAL_JSON"
fi
