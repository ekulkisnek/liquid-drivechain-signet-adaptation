#!/usr/bin/env bash
# Exact-SHA Linux x86_64 release recipe for Ubuntu hosts and runners.
set -euo pipefail

REPO=${REPO:-$(git rev-parse --show-toplevel)}
ARTIFACT_DIR=${ARTIFACT_DIR:-"$REPO/release-artifacts"}
LOG_DIR=${LOG_DIR:-"$REPO/release-logs"}
SHA=bf8e9e1e5a6453b3a0573ff57cf9c92b2b3afe2b
SHORT=bf8e9e1e
JOBS=${JOBS:-1}
LOG="$LOG_DIR/linux-build.log"

mkdir -p "$ARTIFACT_DIR" "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

echo "== Linux x86_64 Elements Drivechain release build =="
date -u '+date_utc=%Y-%m-%dT%H:%M:%SZ'
echo "repo=https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation"
echo "target_sha=$SHA"
echo "jobs=$JOBS"
echo "uname=$(uname -a)"
. /etc/os-release
echo "os=$PRETTY_NAME"
echo "arch=$(uname -m)"
echo "gcc=$({ gcc --version | head -n1; } 2>/dev/null)"
echo "g++=$({ g++ --version | head -n1; } 2>/dev/null)"
echo "ld=$({ ld --version | head -n1; } 2>/dev/null)"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cd "$REPO"
echo "source_sha=$(git rev-parse HEAD)"
test "$(git rev-parse HEAD)" = "$SHA"
echo "git_status_begin=$(git status --short | wc -l)"
git diff --quiet

HOST_TRIPLET=$("$REPO/depends/config.guess")
echo "host_triplet=$HOST_TRIPLET"
echo "build_command=make -C depends NO_QT=1 NO_UPNP=1 NO_NATPMP=1 NO_ZMQ=1 NO_QR=1 NO_BDB=1 -j$JOBS"
make -C depends \
  NO_QT=1 \
  NO_UPNP=1 \
  NO_NATPMP=1 \
  NO_ZMQ=1 \
  NO_QR=1 \
  NO_BDB=1 \
  -j"$JOBS"

echo "build_command=./autogen.sh"
./autogen.sh

CONFIGURE_CMD=(
  ./configure
  --prefix=/
  --without-gui
  --disable-bench
  --disable-man
  --disable-ccache
  --with-daemon=yes
  --with-utils=yes
  --with-libs=no
  --enable-wallet
  --with-sqlite=yes
  --without-bdb
)
echo "build_command=CONFIG_SITE=$REPO/depends/$HOST_TRIPLET/share/config.site ${CONFIGURE_CMD[*]}"
CONFIG_SITE="$REPO/depends/$HOST_TRIPLET/share/config.site" "${CONFIGURE_CMD[@]}"

echo "build_command=make -C src -j$JOBS elementsd elements-cli"
make -C src -j"$JOBS" elementsd elements-cli

UNIT_STATUS=not_run
if make -C src -j"$JOBS" test/test_bitcoin; then
  if src/test/test_bitcoin --run_test=elements_startup_validation_tests &&
      src/test/test_bitcoin --run_test=validation_tests; then
    UNIT_STATUS=passed
  else
    UNIT_STATUS=failed
  fi
else
  UNIT_STATUS=build_failed
fi
echo "unit_tests=$UNIT_STATUS"

echo "elementsd_version_begin"
src/elementsd --version
echo "elementsd_version_end"
echo "elements_cli_version_begin"
src/elements-cli --version
echo "elements_cli_version_end"
file src/elementsd src/elements-cli

OUT="$ARTIFACT_DIR/liquid-signet-elements-$SHORT-linux-x86_64"
TARBALL="$ARTIFACT_DIR/liquid-signet-elements-$SHORT-linux-x86_64.tar.gz"
rm -rf "$OUT" "$TARBALL"
mkdir -p "$OUT"

install -m 0755 -s src/elementsd "$OUT/elementsd"
install -m 0755 -s src/elements-cli "$OUT/elements-cli"

cat > "$OUT/liquid-signet" <<'LAUNCHER'
#!/bin/sh
set -eu

case "$0" in
  */*) BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) ;;
  *) BIN_DIR=. ;;
esac

DATADIR=${LIQUID_SIGNET_DATADIR:-"$HOME/.local/share/bitwindow/elements-v1"}
RPCPORT=${LIQUID_SIGNET_RPCPORT:-7045}
P2PPORT=${LIQUID_SIGNET_P2PPORT:-7046}
MAINCHAIN_RPC_HOST=${LIQUID_SIGNET_MAINCHAIN_RPC_HOST:-127.0.0.1}
MAINCHAIN_RPC_PORT=${LIQUID_SIGNET_MAINCHAIN_RPC_PORT:-38332}
MAINCHAIN_RPC_USER=${LIQUID_SIGNET_MAINCHAIN_RPC_USER:-user}
MAINCHAIN_RPC_PASSWORD=${LIQUID_SIGNET_MAINCHAIN_RPC_PASSWORD:-password}
MAINCHAIN_RPC_COOKIEFILE=${LIQUID_SIGNET_MAINCHAIN_RPC_COOKIEFILE:-}

port() {
  case "$1" in
    *:*) printf '%s\n' "${1##*:}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

PASS=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --datadir|-datadir)
      DATADIR=$2
      shift 2
      ;;
    --datadir=*|-datadir=*)
      DATADIR=${1#*=}
      shift
      ;;
    --rpc-addr|-rpc-addr|--rpc-port|-rpc-port)
      RPCPORT=$(port "$2")
      shift 2
      ;;
    --rpc-addr=*|-rpc-addr=*|--rpc-port=*|-rpc-port=*)
      RPCPORT=$(port "${1#*=}")
      shift
      ;;
    --net-addr|-net-addr)
      P2PPORT=$(port "$2")
      shift 2
      ;;
    --net-addr=*|-net-addr=*)
      P2PPORT=$(port "${1#*=}")
      shift
      ;;
    --mainchain-rpc-host|-mainchain-rpc-host)
      MAINCHAIN_RPC_HOST=$2
      shift 2
      ;;
    --mainchain-rpc-host=*|-mainchain-rpc-host=*)
      MAINCHAIN_RPC_HOST=${1#*=}
      shift
      ;;
    --mainchain-rpc-port|-mainchain-rpc-port)
      MAINCHAIN_RPC_PORT=$2
      shift 2
      ;;
    --mainchain-rpc-port=*|-mainchain-rpc-port=*)
      MAINCHAIN_RPC_PORT=${1#*=}
      shift
      ;;
    --mainchain-rpc-cookiefile|-mainchain-rpc-cookiefile)
      MAINCHAIN_RPC_COOKIEFILE=$2
      shift 2
      ;;
    --mainchain-rpc-cookiefile=*|-mainchain-rpc-cookiefile=*)
      MAINCHAIN_RPC_COOKIEFILE=${1#*=}
      shift
      ;;
    --mainchain-grpc-url|--log-level|--log-level-file|--network|--mnemonic-seed-phrase-path)
      shift 2
      ;;
    --mainchain-grpc-url=*|--log-level=*|--log-level-file=*|--network=*|--mnemonic-seed-phrase-path=*|--headless)
      shift
      ;;
    *)
      PASS="${PASS}
$1"
      shift
      ;;
  esac
done

mkdir -p "$DATADIR"

set -- \
  -chain=elements \
  -datadir="$DATADIR" \
  -rpcbind=127.0.0.1 \
  -rpcallowip=127.0.0.1 \
  -rpcport="$RPCPORT" \
  -port="$P2PPORT" \
  -server=1 \
  -txindex=1 \
  -listenonion=0 \
  -mainchainrpchost="$MAINCHAIN_RPC_HOST" \
  -mainchainrpcport="$MAINCHAIN_RPC_PORT"

if [ -n "$MAINCHAIN_RPC_COOKIEFILE" ]; then
  set -- "$@" -mainchainrpccookiefile="$MAINCHAIN_RPC_COOKIEFILE"
else
  set -- "$@" \
    -mainchainrpcuser="$MAINCHAIN_RPC_USER" \
    -mainchainrpcpassword="$MAINCHAIN_RPC_PASSWORD"
fi

if [ -n "$PASS" ]; then
  old_ifs=$IFS
  IFS='
'
  for arg in $PASS; do
    [ -n "$arg" ] && set -- "$@" "$arg"
  done
  IFS=$old_ifs
fi

exec "$BIN_DIR/elementsd" "$@"
LAUNCHER

chmod +x "$OUT"/*
tar -C "$OUT" -czf "$TARBALL" .

echo "artifact=$TARBALL"
sha256sum "$TARBALL"
stat -c '%s' "$TARBALL"
tar -tzf "$TARBALL"

SMOKE_DATADIR=$(mktemp -d)
SMOKE_RPC=37045
SMOKE_P2P=37046
SMOKE_STATUS=not_run
SMOKE_JSON="$LOG_DIR/linux-smoke.json"
rm -f "$SMOKE_JSON"

set +e
"$OUT/liquid-signet" --datadir "$SMOKE_DATADIR" --rpc-addr "127.0.0.1:$SMOKE_RPC" --net-addr "127.0.0.1:$SMOKE_P2P" -daemon -fallbackfee=0.0001
START_STATUS=$?
set -e
if [ "$START_STATUS" -eq 0 ]; then
  for _ in $(seq 1 40); do
    if "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" getblockchaininfo >/dev/null 2>&1; then
      {
        echo '{'
        echo '"getblockchaininfo":'
        "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" getblockchaininfo
        echo ',"getnetworkinfo":'
        "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" getnetworkinfo
        echo ',"getsidechaininfo":'
        "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" getsidechaininfo
        echo ',"genesis":"'
        "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" getblockhash 0
        echo '"}'
      } > "$SMOKE_JSON" 2>"$LOG_DIR/linux-smoke-rpc.stderr"
      SMOKE_STATUS=passed
      break
    fi
    sleep 1
  done
  "$OUT/elements-cli" -chain=elements -datadir="$SMOKE_DATADIR" -rpcport="$SMOKE_RPC" stop || true
  sleep 3
else
  SMOKE_STATUS=start_failed
fi

if pgrep -af "$OUT/elementsd|$SMOKE_DATADIR" >/dev/null 2>&1; then
  echo "remaining_processes=present"
  pgrep -af "$OUT/elementsd|$SMOKE_DATADIR" || true
else
  echo "remaining_processes=none"
fi
echo "smoke_test=$SMOKE_STATUS"
if [ -f "$SMOKE_JSON" ]; then
  cat "$SMOKE_JSON"
fi

echo "git_status_end=$(git status --short | wc -l)"
