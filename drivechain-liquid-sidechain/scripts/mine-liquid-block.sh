#!/usr/bin/env bash
printf '%s\n' 'ERROR: quarantined legacy slot-5/regtest launcher. This fork supports only Elements Drivechain (-chain=elements), BIP300 slot 24. See the repository README.md.' >&2
exit 64

# mine-liquid-block.sh — BMM + Elements sidechain block advance (native CUSF).
# Mirrors mine-bitassets-block.sh mechanism. Full version requires adapter + running elementsd.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DEV="$(cd "$SCRIPT_DIR/../../.." && pwd)/drivechain-wallet-dev/local-dev"
LIQUID_ID=5
echo "[LIQUID-MINE] Requesting BMM for ID $LIQUID_ID (placeholder critical_hash — real adapter fills from elementsd getbestblockhash/header)..."
# TODO(real): elements-cli -regtest getblockheader $(elements-cli -regtest getbestblockhash) | compute critical_hash
# Then: grpc CreateBmmCriticalDataTransaction with it, mine, confirm GetBmmHStarCommitment, elements submitblock.
"$LOCAL_DEV/scripts/mine-private-signet-blocks.sh" 1
echo "[LIQUID-MINE] L1 block mined. (Full adapter: confirm h* via enforcer events, advance Elements tip, record side height/txids.)"
