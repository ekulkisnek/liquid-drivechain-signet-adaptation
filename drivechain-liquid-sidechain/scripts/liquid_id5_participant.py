#!/usr/bin/env python3
if __name__ == "__main__":
    import sys as _quarantine_sys
    _quarantine_sys.stderr.write(
        "ERROR: quarantined legacy slot-5/regtest launcher. This fork supports only "
        "Elements Drivechain (-chain=elements), BIP300 slot 24. See the repository README.md.\n"
    )
    raise SystemExit(64)

"""
Simple visible BMM loop for ID5 - uses the proven working code from grpc_bmm_id5.py.
Replicates the lib/miner.rs tolerate pattern + mine + poll for real inclusion evidence.
Unbuffered output when run with -u.
"""
import os, sys, subprocess, time, json, argparse, traceback

# Proven stub init (from working grpc_bmm_id5.py)
PROTO_ROOT = "/Volumes/T705/code/drivechain-wallet-dev/plain-bitassets/proto/proto"
STUB_DIR = "/tmp/liquid-grpc-stubs-clean"
os.makedirs(STUB_DIR, exist_ok=True)
cmd = [
    sys.executable, "-m", "grpc_tools.protoc",
    f"-I{PROTO_ROOT}",
    f"--python_out={STUB_DIR}",
    f"--grpc_python_out={STUB_DIR}",
    f"{PROTO_ROOT}/cusf/mainchain/v1/wallet.proto",
    f"{PROTO_ROOT}/cusf/mainchain/v1/validator.proto",
    f"{PROTO_ROOT}/cusf/mainchain/v1/common.proto",
    f"{PROTO_ROOT}/cusf/common/v1/common.proto",
    f"{PROTO_ROOT}/cusf/crypto/v1/crypto.proto",
]
subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sys.path.insert(0, STUB_DIR)

import grpc
from google.protobuf import wrappers_pb2
import cusf.mainchain.v1.wallet_pb2 as wallet_pb2
import cusf.mainchain.v1.wallet_pb2_grpc as wallet_grpc
import cusf.mainchain.v1.validator_pb2 as validator_pb2
import cusf.mainchain.v1.validator_pb2_grpc as validator_grpc
import cusf.common.v1.common_pb2 as common_pb2

channel = grpc.insecure_channel("127.0.0.1:50051")
wallet_stub = wallet_grpc.WalletServiceStub(channel)
validator_stub = validator_grpc.ValidatorServiceStub(channel)

def get_elements_best():
    try:
        out = subprocess.check_output([
            "/Volumes/T705/code/liquid-signet-sidechain/src/elements-cli",
            "-datadir=/tmp/liquid-id5-regtest", "-rpcport=18443",
            "-rpccookiefile=/tmp/liquid-id5-regtest/regtest/.cookie",
            "getblockchaininfo"
        ], stderr=subprocess.DEVNULL, timeout=5)
        info = json.loads(out)
        return info["bestblockhash"], info.get("blocks", 0)
    except Exception as e:
        return None, str(e)

def get_dynamic_prev_id5():
    try:
        tip_resp = validator_stub.GetChainTip(validator_pb2.GetChainTipRequest(), timeout=8)
        bh = tip_resp.block_header_info.block_hash
        tip_hex = bh.hex.value if hasattr(bh.hex, 'value') else str(bh.hex)
        tip_h = getattr(tip_resp.block_header_info, 'height', 0)
        bmm_req = validator_pb2.GetBmmHStarCommitmentRequest(
            block_hash=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=tip_hex)),
            sidechain_id=wrappers_pb2.UInt32Value(value=5),
        )
        bmm_resp = validator_stub.GetBmmHStarCommitment(bmm_req, timeout=8)
        committed = None
        if hasattr(bmm_resp, 'result') and bmm_resp.result:
            res = bmm_resp.result
            if hasattr(res, 'commitment') and res.commitment:
                c = res.commitment
                if hasattr(c, 'commitment') and c.commitment:
                    ch = c.commitment
                    if hasattr(ch, 'hex'):
                        val = ch.hex
                        committed = val if isinstance(val, str) else getattr(val, 'value', str(val))
        if committed:
            print(f"[VISIBLE-LOOP] GetBmmHStar prev for ID5: {committed[:16]}... (tip H={tip_h})")
            return committed
        print(f"[VISIBLE-LOOP] No prior for fresh ID5; using tip {tip_hex[:16]}... as prev (H={tip_h})")
        return tip_hex
    except Exception as ex:
        print(f"[VISIBLE-LOOP] GetBmmHStar/GetChainTip failed ({ex}); fallback tip")
        tip_resp = validator_stub.GetChainTip(validator_pb2.GetChainTipRequest(), timeout=5)
        bh = tip_resp.block_header_info.block_hash
        return bh.hex.value if hasattr(bh.hex, 'value') else str(bh.hex)

def trigger_mine():
    print("[VISIBLE-LOOP] Triggering mine (GenerateBlocks + canonical for gbt inclusion)...")
    try:
        subprocess.run(["bash", "-c", "(command -v buf >/dev/null && buf curl --timeout 10s --emit-defaults --protocol grpc --http2-prior-knowledge http://127.0.0.1:50051/cusf.mainchain.v1.WalletService/GenerateBlocks || true)"], timeout=20, check=False)
        subprocess.run(["bash", "-c", "cd /Volumes/T705/code/drivechain-wallet-dev/local-dev && ./scripts/mine-private-signet-blocks.sh 1"], timeout=90, check=False)
        print("[VISIBLE-LOOP] Mine done.")
    except Exception as e:
        print(f"[VISIBLE-LOOP] Mine warning: {e}")

def poll_confirm(our_critical, max_wait=20, interval=2):
    print(f"[VISIBLE-LOOP] Polling GetBmmHStar for our critical {our_critical[:16]}...")
    start = time.time()
    while time.time() - start < max_wait:
        try:
            tip_resp = validator_stub.GetChainTip(validator_pb2.GetChainTipRequest(), timeout=5)
            tip_hex = tip_resp.block_header_info.block_hash.hex.value if hasattr(tip_resp.block_header_info.block_hash.hex, 'value') else str(tip_resp.block_header_info.block_hash.hex)
            bmm_req = validator_pb2.GetBmmHStarCommitmentRequest(
                block_hash=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=tip_hex)),
                sidechain_id=wrappers_pb2.UInt32Value(value=5),
            )
            bmm_resp = validator_stub.GetBmmHStarCommitment(bmm_req, timeout=5)
            committed = None
            if hasattr(bmm_resp, 'result') and bmm_resp.result and hasattr(bmm_resp.result, 'commitment') and bmm_resp.result.commitment:
                c = bmm_resp.result.commitment
                if hasattr(c, 'commitment') and c.commitment:
                    ch = c.commitment
                    if hasattr(ch, 'hex'):
                        val = ch.hex
                        committed = val if isinstance(val, str) else getattr(val, 'value', str(val))
            if committed and our_critical.lower() in str(committed).lower():
                print(f"[VISIBLE-LOOP] *** REAL BMM INCLUSION FOR ID5 *** critical matches at {tip_hex[:16]}")
                return True, tip_hex, committed
        except Exception:
            pass
        time.sleep(interval)
    print("[VISIBLE-LOOP] No match yet (may expire; will retry fresh).")
    return False, None, None

def run(max_cycles=8):
    print("=== Liquid ID5 VISIBLE BMM LOOP (proven code from grpc_bmm_id5.py + lib/miner.rs tolerate) ===")
    bmm_h = 1  # BMM sequence height for the SC -- start at 1 for fresh ID5 (the 'next' expected by the producer for the first BMM after activation)
    for c in range(1, max_cycles+1):
        print(f"\n=== CYCLE {c}/{max_cycles} ===")
        crit, side_h = get_elements_best()
        if not crit:
            print("[VISIBLE-LOOP] No elements critical")
            time.sleep(3)
            continue
        # Use bmm_h (the SC's BMM sequence, starting at 1) for the height param in CreateBmm.
        # The critical is the current elements best hash (the side block committed for this BMM height).
        # This fixes the bug where high target_h (elements H +1) was not the 'next' for fresh ID5.
        target_h = bmm_h
        prev = get_dynamic_prev_id5()
        print(f"[VISIBLE-LOOP] BMM ID5 bmmH={target_h} (SC seq start=1) crit={crit[:16]}... prev={prev[:16]}... (elements H={side_h})")
        req = wallet_pb2.CreateBmmCriticalDataTransactionRequest(
            sidechain_id=wrappers_pb2.UInt32Value(value=5),
            value_sats=wrappers_pb2.UInt64Value(value=1000),
            height=wrappers_pb2.UInt32Value(value=target_h),
            critical_hash=common_pb2.ConsensusHex(hex=wrappers_pb2.StringValue(value=crit)),
            prev_bytes=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=prev)),
        )
        try:
            resp = wallet_stub.CreateBmmCriticalDataTransaction(req, timeout=60)
            print(f"[VISIBLE-LOOP] BMM created: {resp}")
            txid = str(resp)
        except grpc.RpcError as e:
            details = e.details() or ""
            if "broadcast deposit transaction failed" in details.lower():
                txid = None
                if "failed:" in details:
                    txid = details.split("failed:")[-1].strip().split()[0]
                print(f"[VISIBLE-LOOP] TOLERATED (lib/miner.rs pattern): inserted (txid={txid}). Will mine + confirm.")
            else:
                print(f"[VISIBLE-LOOP] BMM hard error: {e.code()} {details[:150]}")
                time.sleep(3)
                continue
        except Exception as ex:
            print(f"[VISIBLE-LOOP] BMM unexpected: {ex}")
            time.sleep(3)
            continue
        bmm_h += 1  # Increment the SC's BMM sequence after every proposal (success or tolerated) -- the 'next' for subsequent BMMs
        trigger_mine()
        confirmed, main_block, committed = poll_confirm(crit)
        if confirmed:
            print(f"\n*** FIRST REAL BMM TXID/INCLUSION FOR ID5 ***")
            print(f"  critical: {crit}")
            print(f"  sideH: {target_h}")
            print(f"  main block: {main_block}")
            print(f"  attempt_tx: {txid}")
            try:
                with open("/Volumes/T705/code/liquid-signet-sidechain/drivechain-liquid-sidechain/tests/liquid-side-state.json", "a") as f:
                    f.write(json.dumps({"real_bmm": True, "critical": crit, "side_h": target_h, "main_block": main_block, "txid": txid, "cycle": c, "ts": time.time()}) + "\n")
            except: pass
            return True
        time.sleep(4)
    print("[VISIBLE-LOOP] Finished without confirmed inclusion. Check logs for P2P/accept details.")
    return False

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--max", type=int, default=8)
    args = p.parse_args()
    sys.exit(0 if run(args.max) else 1)
