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
    import cusf.common.v1.common_pb2 as common_pb2

    # Live critical from elementsd ID5
    crit = subprocess.check_output([
        "./src/elements-cli", "-datadir=/tmp/liquid-id5-regtest", "-rpcport=18443",
        "-rpccookiefile=/tmp/liquid-id5-regtest/regtest/.cookie", "getbestblockhash"
    ], text=True).strip()

    print(f"=== gRPC CreateBmm ID5 with real critical from elementsd: {crit[:16]}... ===")

    channel = grpc.insecure_channel("127.0.0.1:50051")
    stub = wallet_grpc.WalletServiceStub(channel)

    # Use the prev_bytes that the enforcer itself told us was expected in previous run
    # (re-run with the exact expected value from the latest real INVALID_ARGUMENT error)
    prev = "000002a5424e681cf5261ccfdfaa5ef07ecae20b9d97b17afd4f2c6d1c544f61"  # latest expected from enforcer at current state/height (H~412)

    req = wallet_pb2.CreateBmmCriticalDataTransactionRequest(
        sidechain_id=wrappers_pb2.UInt32Value(value=5),
        value_sats=wrappers_pb2.UInt64Value(value=1000),
        height=wrappers_pb2.UInt32Value(value=1),
        critical_hash=common_pb2.ConsensusHex(hex=wrappers_pb2.StringValue(value=crit)),
        prev_bytes=common_pb2.ReverseHex(hex=wrappers_pb2.StringValue(value=prev)),
    )
    try:
        resp = stub.CreateBmmCriticalDataTransaction(req, timeout=10)
        print("SUCCESS:", resp)
    except grpc.RpcError as e:
        print(f"RPC ERROR: {e.code()}")
        print(f"details: {e.details()}")
        if e.trailing_metadata():
            print("metadata:", dict(e.trailing_metadata()))

if __name__ == "__main__":
    main()
