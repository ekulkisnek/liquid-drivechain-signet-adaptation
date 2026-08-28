#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Bind a real drivechain withdrawal to an activated ECX header checkpoint."""

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading

from feature_fedpeg import FedPegTest, get_new_unconfidential_address
from test_framework.util import assert_equal


STATE_ADDRESS = "ert1p2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqq9w2238"


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def read_compact_size(data, offset):
    first = data[offset]
    offset += 1
    if first < 253:
        return first, offset
    size = {253: 2, 254: 4, 255: 8}[first]
    return int.from_bytes(data[offset:offset + size], "little"), offset + size


def parse_bundle_outputs(wire):
    assert_equal(wire[:6], bytes.fromhex("020000000001"))
    offset = 6
    vin_count, offset = read_compact_size(wire, offset)
    assert_equal(vin_count, 0)
    vout_count, offset = read_compact_size(wire, offset)
    assert_equal(vout_count, 4)
    outputs = []
    for _ in range(vout_count):
        amount = int.from_bytes(wire[offset:offset + 8], "little")
        offset += 8
        script_size, offset = read_compact_size(wire, offset)
        script = wire[offset:offset + script_size]
        offset += script_size
        outputs.append((amount, script))
    assert_equal(wire[offset:offset + 4], b"\x00" * 4)
    assert_equal(offset + 4, len(wire))
    return outputs


class EcxWithdrawalPositiveTest(FedPegTest):
    def set_test_params(self):
        super().set_test_params()

    def setup_network(self, split=False):
        self.mock_state_path = os.path.join(self.options.tmpdir, "mock-enforcer-state.json")
        state_path = self.mock_state_path
        state_lock = threading.Lock()

        class MockConnectHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                assert_equal(self.headers.get("Content-Type"), "application/json")
                assert_equal(self.headers.get("Accept"), "application/json")
                assert_equal(self.headers.get("Connect-Protocol-Version"), "1")
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length <= 0 or content_length > 1024 * 1024:
                    self.send_error(413)
                    return
                payload = json.loads(self.rfile.read(content_length))
                method = self.path.lstrip("/")

                with state_lock:
                    state = {"calls": []}
                    if os.path.exists(state_path):
                        with open(state_path, encoding="utf-8") as state_file:
                            state = json.load(state_file)
                    state["calls"].append(method)

                    if method.endswith("/BroadcastWithdrawalBundle"):
                        wire = base64.b64decode(payload["transaction"], validate=True)
                        assert_equal(wire[4:6], b"\x00\x01")
                        no_witness = wire[:4] + wire[6:]
                        state["m6_consensus_hex"] = sha256d(no_witness).hex()
                        response = {"accepted": True, "mock_scope": "l1-acceptance-only"}
                    elif method.endswith("/GetTwoWayPegData"):
                        if "m6_consensus_hex" not in state:
                            self.send_error(409)
                            return
                        response = {
                            "blocks": [{
                                "blockInfo": {
                                    "events": [{
                                        "withdrawalBundle": {
                                            "m6id": {"hex": state["m6_consensus_hex"]},
                                            "event": {"submitted": {}},
                                        }
                                    }]
                                }
                            }]
                        }
                    else:
                        self.send_error(404)
                        return

                    with open(state_path, "w", encoding="utf-8") as state_file:
                        json.dump(state, state_file, sort_keys=True)

                response_bytes = json.dumps(response, sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_bytes)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_bytes)

            def log_message(self, _format, *_args):
                pass

        self.mock_enforcer = ThreadingHTTPServer(("127.0.0.1", 0), MockConnectHandler)
        self.mock_enforcer_thread = threading.Thread(
            target=self.mock_enforcer.serve_forever,
            name="mock-connect-enforcer",
            daemon=True,
        )
        self.mock_enforcer_thread.start()
        self.mock_enforcer_address = "%s:%d" % self.mock_enforcer.server_address
        super().setup_network(split)

    def shutdown(self):
        try:
            return super().shutdown()
        finally:
            if hasattr(self, "mock_enforcer"):
                self.mock_enforcer.shutdown()
                self.mock_enforcer.server_close()
                self.mock_enforcer_thread.join(timeout=5)

    def sidechain_extra_args(self, node_index):
        return [
            "-anyonecanspendaremine=1",
            "-ecxactivationheight=2147483646",
            "-ecxgenesisstateoutpoint=" + "11" * 32 + ":0",
            "-ecxgenesisstateroot=" + "12" * 32,
            "-ecxchainid=" + "19" * 32,
            "-ecxforcedactiondomain=" + "45" * 32,
            "-ecxdepositinboxdomain=" + "46" * 32,
            "-ecxcollateralvaultscript=5120" + "a1" * 32,
            "-ecxcollateralvaultscripthash=fe71d55db3b84e12e09fec4a925b73bd98465de02a2ecc58bc4c6596f36ac126",
            "-drivechainl1blocksync=0",
            f"-drivechainbmmgrpcaddr={self.mock_enforcer_address}",
        ]

    def sidechain_initial_free_coins(self, node_index):
        return 21000000

    def sidechain_connect_genesis_outputs(self, node_index):
        return True

    def run_test(self):
        self.import_deterministic_coinbase_privkeys()
        parent = self.nodes[0]
        sidechain = self.nodes[2]
        for node in self.nodes:
            node.importprivkey(
                privkey=node.get_deterministic_priv_key().key,
                label="mining",
            )
        state_txid = sidechain.sendtoaddress(
            STATE_ADDRESS, 0.01, "", "", False, False, 1, "UNSET", False)
        state_tx = sidechain.getrawtransaction(state_txid, True)
        state_vout = next(
            output["n"] for output in state_tx["vout"]
            if output["scriptPubKey"]["hex"] ==
            "512050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        )
        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        state_root = sidechain.getecxstateutxoroot(state_txid, state_vout)["root"]
        state_tx_hex = sidechain.gettransaction(state_txid)["hex"]
        sidechain.invalidateblock(sidechain.getbestblockhash())
        assert_equal(sidechain.getblockcount(), 0)
        assert_equal(sidechain.getrawmempool(), [state_txid])
        assert_equal(sidechain.getblockcount(), 0)
        self.stop_node(2)
        os.remove(os.path.join(
            self.nodes[2].datadir,
            self.chain,
            "ecx_consensus.dat",
        ))
        replacement_args = []
        for argument in self.nodes[2].extra_args:
            if argument.startswith((
                "-ecxactivationheight=",
                "-ecxgenesisstateoutpoint=",
                "-ecxgenesisstateroot=",
            )):
                continue
            replacement_args.append(argument)
        replacement_args.extend([
            "-ecxactivationheight=2",
            f"-ecxgenesisstateoutpoint={state_txid}:{state_vout}",
            f"-ecxgenesisstateroot={state_root}",
        ])
        self.start_node(2, extra_args=replacement_args)
        sidechain = self.nodes[2]
        sidechain.importprivkey(
            self.nodes[2].get_deterministic_priv_key().key,
            label="mining",
        )
        assert_equal(sidechain.getrawmempool(), [state_txid])
        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        assert_equal(sidechain.getblockcount(), 1)
        assert_equal(
            sidechain.getblock(sidechain.getbestblockhash())["exchangestateroot"],
            "0" * 64,
        )

        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        checkpoint_height = sidechain.getblockcount()
        checkpoint_hash = sidechain.getbestblockhash()
        checkpoint = sidechain.getblock(checkpoint_hash)
        assert_equal(checkpoint_height, 2)
        assert_equal(checkpoint["exchangestateroot"], state_root)
        assert_equal(checkpoint["withdrawalbundlehash"], "0" * 64)

        destination = get_new_unconfidential_address(parent, "legacy")
        result = sidechain.sendtomainchain(destination, 0.1, False, True)
        pegout = result["drivechain_pegout"]
        assert_equal(pegout["checkpoint_height"], checkpoint_height)
        assert_equal(pegout["sidechain_height"], checkpoint_height)
        assert_equal(pegout["checkpoint_block_hash"], checkpoint_hash)
        assert_equal(pegout["previous_child_hash"], checkpoint["previousblockhash"])
        assert_equal(pegout["exchange_state_root"], checkpoint["exchangestateroot"])
        assert_equal(pegout["sidechain_id"], 24)
        assert_equal(pegout["l1_event_verification"]["event_status"], "submitted")
        assert_equal(
            pegout["broadcast_response"],
            {"accepted": True, "mock_scope": "l1-acceptance-only"},
        )

        wire = bytes.fromhex(pegout["withdrawal_bundle_hex"])
        no_witness = wire[:4] + wire[6:]
        assert_equal(sha256d(no_witness)[::-1].hex(), pegout["m6id"])
        outputs = parse_bundle_outputs(wire)
        withdrawal_outpoint = (
            bytes.fromhex(result["txid"])[::-1]
            + pegout["sidechain_withdrawal_vout"].to_bytes(4, "little")
        )
        commitment_preimage = (
            b"\x02"
            + withdrawal_outpoint
            + b"\x00" * 32
            + checkpoint_height.to_bytes(4, "little")
        )
        withdrawal_commitment = sha256d(commitment_preimage)
        assert_equal(outputs[1], (0, b"\x6a\x20" + withdrawal_commitment))
        anchor_preimage = (
            b"\x01\x18"
            + bytes.fromhex(sidechain.getblockhash(0))[::-1]
            + checkpoint_height.to_bytes(4, "big")
            + bytes.fromhex(checkpoint["previousblockhash"])[::-1]
            + withdrawal_commitment
            + bytes.fromhex(checkpoint["exchangestateroot"])[::-1]
        )
        state_anchor = tagged_hash("ECX/perps-m6-state/v1", anchor_preimage)
        assert_equal(outputs[3], (0, b"\x6a\x25PXST\x01" + state_anchor))

        with open(self.mock_state_path, encoding="utf-8") as mock_state_file:
            mock_state = json.load(mock_state_file)
        assert_equal(
            mock_state["calls"],
            [
                "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
                "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
            ],
        )
        assert_equal(mock_state["m6_consensus_hex"], sha256d(no_witness).hex())

        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        committed = sidechain.getblock(sidechain.getbestblockhash())
        assert_equal(committed["withdrawalbundlehash"], pegout["m6id"])
        assert_equal(committed["exchangestateroot"], state_root)
        assert_equal(sidechain.gettransaction(result["txid"])["confirmations"], 1)


if __name__ == "__main__":
    EcxWithdrawalPositiveTest().main()
