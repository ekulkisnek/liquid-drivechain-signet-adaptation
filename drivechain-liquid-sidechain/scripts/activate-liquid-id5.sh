#!/usr/bin/env bash
# activate-liquid-id5.sh — Wrapper for native Liquid/Elements sidechain ID 5 activation.
# Uses the exact same canonical mechanism as plain-bitassets ID 4 (CreateSidechainProposal + mine until active).
# No federation, no shortcuts — pure CUSF/BIP300/301.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DEV_DIR="/Volumes/T705/code/drivechain-wallet-dev/local-dev"
PROPOSAL_JSON="${PROPOSAL_JSON:-$SCRIPT_DIR/../config/liquid-signet-proposal-id5.json}"

echo "=== Activating Liquid/Elements sidechain ID 5 (native drivechain) ==="
echo "Proposal: $PROPOSAL_JSON"
echo "Canonical activator: $LOCAL_DEV_DIR/scripts/activate-sidechain.sh"

if [ ! -f "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" ]; then
  echo "ERROR: canonical activate-sidechain.sh not found. Is drivechain-wallet-dev at expected location?" >&2
  exit 1
fi

exec "$LOCAL_DEV_DIR/scripts/activate-sidechain.sh" 5 "$PROPOSAL_JSON"
