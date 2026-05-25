#!/usr/bin/env python3
"""
liquid_id5_side_stub.py — Minimal Python sidechain participant stub for Liquid/Elements ID 5.

This is the critical missing piece for making the native CUSF sidechain slot (ID 5)
actually functional on Luke's private drivechain signet.

Current state (as of latest turn, mainchain height 277):
- ID5 proposal + activation metadata is LIVE (propH=118, actH=124, votes=6).
- Background Elements build (tmux elements-build) actively compiling in make phase.
- Docker stack healthy (mainchain + enforcer + bitassets/ID4).
- All CreateDeposit / CreateBmm / BroadcastWithdrawal for ID5 still fail with
  "broadcast deposit transaction failed" — no sidechain participant for ID5 yet.

Goal of this stub (v0.1 → production):
- Connect to the CUSF enforcer (WalletService + ValidatorService) for sidechain_id=5.
- Drive periodic BMM requests with real critical_hash computed from a running elementsd.
- On Deposit events: credit the value on the Liquid/Elements side (either via pegin
  witness against a dev fedpeg key or a trusted "importdrivechaindeposit" once added).
- On withdrawal intents: build + broadcast bundles.
- Expose a combined RPC surface for the Liquid sidechain.

This must stay 100% native CUSF — no federation, no standing multisig.

Run:
  pip install grpcio grpcio-tools
  python3 liquid_id5_side_stub.py --enforcer 127.0.0.1:50051 --sidechain-id 5

Future:
- Spawn / manage elementsd --regtest (or custom sidechain magic) in a subprocess or docker.
- Compute critical_hash = sha256( elements block header + body or merkle ).
- Use elements-cli or JSON-RPC for pegin claims, generate, submitblock, etc.
- Add real proof export for Floresta later.

Compatible with current private signet and future real BIP300/301 (only host + challenge change).
"""

import argparse
import time
import sys
from datetime import datetime

try:
    import grpc
except ImportError:
    print("ERROR: grpcio not installed. Run: pip install grpcio grpcio-tools", file=sys.stderr)
    sys.exit(1)

# TODO: Generate proper stubs from the protos in drivechain-wallet-dev/plain-bitassets/proto/
# For v0.1 we do dynamic / raw calls via buf or direct until we vendor the .proto here.
# For now this stub focuses on connection + status + skeleton loops.

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enforcer", default="127.0.0.1:50051", help="enforcer gRPC address")
    parser.add_argument("--sidechain-id", type=int, default=5)
    parser.add_argument("--poll-interval", type=int, default=30)
    args = parser.parse_args()

    print(f"=== Liquid ID{args.sidechain_id} Side Stub starting at {datetime.utcnow().isoformat()}Z ===")
    print(f"Target enforcer: {args.enforcer}")
    print("NOTE: This is a skeleton. Full BMM/Deposit handling requires elementsd + real critical_hash + event subscription.")

    # Placeholder: In real impl we would load the generated cusf.mainchain.v1 stubs.
    # channel = grpc.insecure_channel(args.enforcer)
    # validator = cusf.mainchain.v1.ValidatorServiceStub(channel)
    # wallet = cusf.mainchain.v1.WalletServiceStub(channel)

    print("\n[STUB] Would now:")
    print("  1. Call GetSidechains and confirm ID5 has activationHeight and we are past it.")
    print("  2. Start or connect to local elementsd (regtest, isolated P2P).")
    print("  3. Enter loop:")
    print("       - Compute next Elements block template / header hash → critical_hash")
    print("       - WalletService.CreateBmmCriticalDataTransaction(sidechainId=5, criticalHash=..., valueSats=...)")
    print("       - Trigger or wait for L1 block via mine-private-signet-blocks or GenerateBlocks")
    print("       - Confirm via GetBmmHStarCommitment / SubscribeEvents")
    print("       - elementsd submitblock the side block under that main_hash")
    print("       - On Deposit events (GetTwoWayPegData or Subscribe): credit on elements side")
    print("       - Handle BroadcastWithdrawalBundle for pegouts")

    # Example status poll (manual for now until we have generated stubs)
    print(f"\n[STUB] Manual status check recommended:")
    print(f"  ./drivechain-liquid-sidechain/scripts/liquid-side-status.sh")

    print("\n[STUB] To make real progress toward production:")
    print("  - Install: pip install grpcio grpcio-tools")
    print("  - Copy or generate Python stubs from the CUSF protos in the sibling repo.")
    print("  - Implement drive_bmm() and handle_deposit() methods.")
    print("  - Add elementsd management (subprocess or docker) + RPC client.")
    print("  - Wire into e2e-liquid-on-signet.sh so real side txids/heights appear.")
    print("")
    print("  STATUS: Elements build COMPLETE. Real ID5 regtest elementsd is now launching in tmux 'liquid-id5-elements'.")
    print("  Use the launcher: ./drivechain-liquid-sidechain/scripts/start-liquid-id5-regtest.sh")
    print("  Monitor: tmux attach -t liquid-id5-elements  |  tail -f /tmp/liquid-id5.log")

    print("\n=== STUB EXIT (skeleton only; extend me) ===")

if __name__ == "__main__":
    main()
# === REAL INTEGRATION (added this turn) ===
import subprocess
import json

def get_elements_best_block():
    """Get best block from the running ID5 regtest elementsd."""
    try:
        out = subprocess.check_output(
            ["./src/elements-cli", "-regtest", "-rpcport=18443",
             "-datadir=/tmp/liquid-id5-regtest", "getblockchaininfo"],
            stderr=subprocess.DEVNULL, timeout=5
        )
        info = json.loads(out)
        return info["bestblockhash"], info.get("blocks", 0)
    except Exception as e:
        return None, str(e)

def attempt_real_bmm_for_id5():
    """Drive BMM using real critical_hash from the running elementsd."""
    block_hash, height = get_elements_best_block()
    if not block_hash:
        print(f"[REAL] Could not query elementsd: {height}")
        return False

    print(f"[REAL] Elementsd best block height={height}, hash={block_hash[:16]}...")
    # For v0.1 demo, use the block hash as critical_hash (real impl would do header+merkle)
    critical = block_hash

    # Use the exact same working buf curl pattern as the status script
    cmd = [
        "bash", "-c",
        f"""buf curl --timeout 8s --emit-defaults --protocol grpc --http2-prior-knowledge \
        -d '{{"sidechainId":5,"valueSats":{{"value":1000}},"height":{height},"criticalHash":{{"value":"{critical}"}},"prevBytes":{{"value":"0000000000000000000000000000000000000000000000000000000000000000"}}}}' \
        http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>/dev/null || \
        docker compose -f ../drivechain-wallet-dev/local-dev/docker-compose.local-minimal.yml run --rm --pull=never buf curl \
        --timeout 8s --emit-defaults --protocol grpc --http2-prior-knowledge \
        -d '{{"sidechainId":5,"valueSats":{{"value":1000}},"height":{height},"criticalHash":{{"value":"{critical}"}},"prevBytes":{{"value":"0000000000000000000000000000000000000000000000000000000000000000"}}}}' \
        http://enforcer:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>/dev/null"""
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10)
        print("[REAL] BMM response:", out.decode()[:300])
        return True
    except subprocess.CalledProcessError as e:
        print(f"[REAL] BMM FAILED - returncode={e.returncode}")
        if e.output:
            print("Output:", e.output.decode()[:500])
        if e.stderr:
            print("Stderr:", e.stderr.decode()[:500])
        return False
    except Exception as e:
        print(f"[REAL] BMM attempt error: {e}")
        return False

if __name__ == "__main__":
    print("=== Liquid ID5 Stub with REAL elementsd integration (this turn) ===")
    attempt_real_bmm_for_id5()


# === IMPROVED: Simple retry loop for real BMM (added this turn) ===
def run_bmm_loop(max_attempts=5):
    print(f"[LOOP] Starting BMM retry loop (max {max_attempts} attempts) using live elementsd...")
    # Wait for elementsd to be ready (fast readiness check)
    for _ in range(15):
        bh, h = get_elements_best_block()
        if bh:
            print(f"[LOOP] elementsd ready at height {h}")
            break
        time.sleep(2)
    for i in range(max_attempts):
        print(f"[LOOP] Attempt {i+1}/{max_attempts}")
        block_hash, height = get_elements_best_block()
        if block_hash:
            # Use height + 1 for next BMM target
            target_height = height + 1 + i
            critical = block_hash
            print(f"[LOOP] elementsd height={height} -> target BMM height={target_height}")
            
            # Build the exact command with progressing height (robust quoting)
            payload = json.dumps({
                "sidechainId": 5,
                "valueSats": {"value": 1000},
                "height": target_height,
                "criticalHash": {"value": critical},
                "prevBytes": {"value": "0000000000000000000000000000000000000000000000000000000000000000"}
            })
            cmd = [
                "bash", "-c",
                f'echo \'{payload}\' | buf curl --timeout 8s --emit-defaults --protocol grpc --http2-prior-knowledge -d @- http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>&1 || '
                f'echo \'{payload}\' | docker compose -f ../drivechain-wallet-dev/local-dev/docker-compose.local-minimal.yml run --rm --pull=never buf curl --timeout 8s --emit-defaults --protocol grpc --http2-prior-knowledge -d @- http://enforcer:50051/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction 2>&1'
            ]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=12)
                print("[LOOP] Response:", out.decode()[:400])
                if "error" not in out.decode().lower() and "failed" not in out.decode().lower():
                    print("[LOOP] *** POSSIBLE SUCCESS ***")
                    return True
            except subprocess.CalledProcessError as e:
                print(f"[LOOP] FAILED returncode={e.returncode}")
                if e.output:
                    err = e.output.decode()[:600]
                    print("[LOOP] Error details:", err)
                    if "broadcast deposit" in err.lower():
                        print("[LOOP] Root cause still: enforcer rejecting (no active ID5 participant yet)")
            except Exception as e:
                print(f"[LOOP] Error: {e}")
        else:
            print(f"[LOOP] No elementsd block yet: {height}")
        time.sleep(3)  # shorter for faster iteration while elementsd is starting
    print("[LOOP] Loop finished without success.")
    return False

if __name__ == "__main__":
    print("=== Liquid ID5 Stub with REAL elementsd + BMM retry loop (this turn) ===")
    run_bmm_loop(3)
