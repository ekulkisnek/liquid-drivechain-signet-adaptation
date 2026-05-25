#!/usr/bin/env bash
# start-liquid-id5-regtest.sh — Launch a clean, isolated regtest elementsd for Liquid sidechain ID 5.
# This is the sidechain participant equivalent to the bitassets process.
set -euo pipefail

DATADIR="${DATADIR:-/tmp/liquid-id5-regtest}"
RPCPORT="${RPCPORT:-18443}"
P2PPORT="${P2PPORT:-18444}"
BIND="${BIND:-127.0.0.1}"

mkdir -p "$DATADIR"

echo "=== Starting isolated regtest elementsd for Liquid ID 5 ==="
echo "Datadir: $DATADIR"
echo "RPC: $BIND:$RPCPORT"
echo "P2P: $BIND:$P2PPORT"

./src/elementsd \
  -regtest \
  -datadir="$DATADIR" \
  -rpcbind="$BIND" \
  -rpcport="$RPCPORT" \
  -rpcallowip=127.0.0.1 \
  -port="$P2PPORT" \
  -bind="$BIND" \
  -listen=1 \
  -server=1 \
  -txindex=1 \
  -printtoconsole=0 \
  -logips=1 \
  -daemon \
  "$@"

echo "Waiting for elementsd RPC ready..."
for i in $(seq 1 30); do
  if ./src/elements-cli -regtest -rpcport="$RPCPORT" -datadir="$DATADIR" getblockchaininfo >/dev/null 2>&1; then
    echo "elementsd ready at height $(./src/elements-cli -regtest -rpcport="$RPCPORT" -datadir="$DATADIR" getblockcount 2>/dev/null || echo 0)"
    exit 0
  fi
  sleep 2
done
echo "Timeout waiting for elementsd RPC"
exit 1
