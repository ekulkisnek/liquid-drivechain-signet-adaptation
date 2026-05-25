#!/usr/bin/env python3
"""
grpc_bmm_id5.py — Clean Python gRPC caller for Liquid ID5 CreateBmmCriticalDataTransaction
using sibling CUSF protos + installed grpcio. Bypasses buf/docker entirely.
Uses live critical from the ID5 elementsd.
"""
import subprocess
import sys
import os
import grpc
import traceback
from google.protobuf import wrappers_pb2

PROTO_ROOT = "/Volumes/T705/code/drivechain-wallet-dev/plain-bitassets/proto/proto"
STUB_DIR = "/tmp/liquid-grpc-stubs-clean"

def main():
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
    subprocess.run(cmd, check=True)

    sys.path.insert(0, STUB_DIR)
    import cusf.mainchain.v1.wallet_pb2 as wallet_pb2
    import cusf.mainchain.v1.wallet_pb2_grpc as wallet_grpc
    import cusf.mainchain.v1.validator_pb2 as validator_pb2
    import cusf.mainchain.v1.validator_pb2_grpc as validator_grpc
    import cusf.common.v1.common_pb2 as common_pb2

    # Live critical from elementsd ID5 (real side source; still genesis H=0 until BMM drives blocks)
    crit = subprocess.check_output([
        "./src/elements-cli", "-datadir=/tmp/liquid-id5-regtest", "-rpcport=18443",
        "-rpccookiefile=/tmp/liquid-id5-regtest/regtest/.cookie", "getbestblockhash"
    ], text=True).strip()

    print(f"=== gRPC CreateBmm ID5 (post-activation, real Elements critical) : {crit[:16]}... ===")
    print("    Activation evidence: proposal tx 7ba9ad8bd541922006ca230bee5dc593ccac115e3c6ed177cc7f12b69512f414")
    print("    (confirmed ~H42; ID5 active proposalH=42 activationH=48 vote=6 at main H~86; native CUSF only)")

    channel = grpc.insecure_channel("127.0.0.1:50051")
    wallet_stub = wallet_grpc.WalletServiceStub(channel)
    validator_stub = validator_grpc.ValidatorServiceStub(channel)

    # === Root-cause patch for BMM harness (post-activation): dynamic prev_bytes via GetChainTip + GetBmmHStarCommitment ===
    # This is the production CUSF way to obtain the current h* commitment / prev for a sidechain's BMM critical data chain.
    # Replaces manual "expected <foo>" chase from INVALID_ARGUMENT errors (the state machine symptom for fresh ID5 with 0 prior BMMs).
    # See validator.proto: GetBmmHStarCommitmentRequest{block_hash: ReverseHex, sidechain_id: UInt32Value}
    # and CreateBmm...Request prev_bytes: ReverseHex.
    print("Querying GetChainTip + GetBmmHStarCommitment(ID=5) for authoritative prev_bytes (patch applied)...")
    prev = "0000016b7ab6c3f1f569a91653027d63375ff24bd1c77d812bc8bab6ffb53c65"  # fallback: newest enforcer expected from latest post-activation run
    try:
        tip_resp = validator_stub.GetChainTip(validator_pb2.GetChainTipRequest())
        # Handle generated wrapper: ReverseHex.hex can be StringValue with .value (from DEBUG)
        bh = tip_resp.block_header_info.block_hash
        tip_hex = bh.hex.value if hasattr(bh.hex, 'value') else (bh.hex if isinstance(bh.hex, str) else str(bh.hex))
        tip_h = getattr(tip_resp.block_header_info, 'height', '?')
        print(f"  Main tip: {tip_hex[:16]}... (H={tip_h})")
        bmm_req = validator_pb2.GetBmmHStarCommitmentRequest(
            block_hash=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=tip_hex)),
            sidechain_id=wrappers_pb2.UInt32Value(value=5),
        )
        bmm_resp = validator_stub.GetBmmHStarCommitment(bmm_req, timeout=10)
        # Robust extraction for oneof + nested ConsensusHex / possible StringValue wrappers
        committed = None
        if hasattr(bmm_resp, 'result'):
            res = bmm_resp.result
            if hasattr(res, 'commitment') and res.commitment:
                c = res.commitment
                if hasattr(c, 'commitment') and c.commitment:
                    ch = c.commitment
                    if hasattr(ch, 'hex'):
                        val = ch.hex
                        committed = val if isinstance(val, str) else getattr(val, 'value', str(val))
                    else:
                        committed = str(ch)
        if committed:
            prev = committed
            print(f"  Got BMM h* commitment (using as prev_bytes): {prev[:16]}...")
        else:
            print("  No prior BMM commitment for fresh ID5 (post-activation); using current main tip hash as starting prev_bytes (enforcer rule for first BMM after activation)")
            prev = tip_hex  # confirmed by multiple runs: for fresh ID5 (0 prior BMMs), enforcer expects the current GetChainTip block_hash as prev
    except Exception as ex:
        print(f"  GetBmmHStar/GetChainTip exception ({ex}); using latest known expected prev (inspect DEBUG below)")
        print("  DEBUG tip_resp (if defined):", 'tip_resp' in locals() and str(locals().get('tip_resp')) or 'N/A')
        print("  DEBUG bmm_resp (if defined):", 'bmm_resp' in locals() and str(locals().get('bmm_resp')) or 'N/A')
        print("  DEBUG relevant attrs:", [a for a in dir(locals().get('bmm_resp', object())) if not a.startswith('_')][:20] if 'bmm_resp' in locals() else 'N/A')
        traceback.print_exc(limit=3)
        # Fallback keeps the harness runnable for continued diagnostic / chase on the real enforcer state machine.

    req = wallet_pb2.CreateBmmCriticalDataTransactionRequest(
        sidechain_id=wrappers_pb2.UInt32Value(value=5),
        value_sats=wrappers_pb2.UInt64Value(value=1000),
        height=wrappers_pb2.UInt32Value(value=1),
        critical_hash=common_pb2.ConsensusHex(hex=wrappers_pb2.StringValue(value=crit)),
        prev_bytes=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=prev)),
    )
    try:
        resp = wallet_stub.CreateBmmCriticalDataTransaction(req, timeout=10)
        print("SUCCESS:", resp)
    except grpc.RpcError as e:
        print(f"RPC ERROR: {e.code()}")
        print(f"details: {e.details()}")
        if e.trailing_metadata():
            print("metadata:", dict(e.trailing_metadata()))

if __name__ == "__main__":
    main()
