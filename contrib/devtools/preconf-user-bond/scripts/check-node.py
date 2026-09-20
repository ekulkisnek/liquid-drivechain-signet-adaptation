#!/usr/bin/env python3
"""Disposable regtest only; all fixture keys are public. Never use a live datadir."""
import json
from decimal import Decimal
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "test" / "functional"))
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.messages import tx_from_hex
from test_framework.util import assert_equal


class BondTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-con_blocksubsidy=5000000000", "-evbparams=simplicity:-1:::"]]

    def add_options(self, parser):
        parser.add_argument("--fixture", required=True, help="Built regtest Rust example")
        parser.add_argument("--operator", action="store_true", help="Exercise the separate preconfer-funded bond")

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 101)
        protected = wallet.get_utxo()
        a = wallet.create_self_transfer(utxo_to_spend=protected)
        b = wallet.create_self_transfer(utxo_to_spend=protected, fee_rate=Decimal("0.004"))
        context = dict(chain="elementsregtest", operator=self.options.operator, genesis=node.getblockhash(0),
                       asset=node.getsidechaininfo()["pegged_asset"],
                       protected=f"{protected['txid']}:{protected['vout']}",
                       active_until=node.getblockcount() + 20,
                       cli=self.options.bitcoincli,
                       datadir=str(node.datadir_path))

        def fixture(op, **kwargs):
            result = subprocess.run([self.options.fixture], input=json.dumps(dict(context, op=op, **kwargs)),
                                    text=True, capture_output=True, check=True, timeout=120)
            return json.loads(result.stdout)

        assert_equal(fixture("validate", hex=a["hex"])["txid"], a["txid"])
        assert_equal(fixture("validate", hex=b["hex"])["txid"], b["txid"])
        invalid = a["tx"]
        invalid.vout[0].nValue.setToAmount(10000000000000)
        assert "error" in fixture("validate", hex=invalid.serialize().hex())
        script = bytes.fromhex(fixture("script")["script"])
        paths = ("penalty", "unilateral") if self.options.operator else ("penalty", "unilateral", "cooperative")
        bonds = [wallet.send_to(from_node=node, scriptPubKey=script, amount=100000) for _ in paths]
        self.generate(wallet, 1)
        raws = {}
        for op, funding in zip(paths, bonds):
            raws[op] = fixture(op, bond=f"{funding['txid']}:{funding['sent_vout']}",
                               txid_a=a["txid"], txid_b=b["txid"],
                               destination=wallet.get_output_script().hex())["hex"]
        for op in paths[1:]:
            early = node.testmempoolaccept([raws[op]], 0)[0]
            assert not early["allowed"]
            assert_equal(early["reject-reason"], "non-final")
        assert node.testmempoolaccept([raws["penalty"]], 0)[0]["allowed"]
        # Corrupt the control block without changing the transaction's txid.
        malformed = tx_from_hex(raws["penalty"])
        stack = malformed.wit.vtxinwit[0].scriptWitness.stack
        control = bytearray(stack[-1])
        control[-1] ^= 1
        stack[-1] = bytes(control)
        assert not node.testmempoolaccept([malformed.serialize().hex()], 0)[0]["allowed"]
        penalty_id = node.sendrawtransaction(raws["penalty"], 0)
        assert_equal(node.getmempoolentry(penalty_id)["fees"]["base"], Decimal("0.001"))
        mined = self.generate(wallet, 1)
        assert penalty_id in node.getblock(mined[0])["tx"]
        self.generate(wallet, context["active_until"] + 11 - node.getblockcount())
        recovered = []
        for op in paths[1:]:
            assert node.testmempoolaccept([raws[op]], 0)[0]["allowed"]
            recovered.append(node.sendrawtransaction(raws[op], 0))
        mined = self.generate(wallet, 1)
        assert set(recovered).issubset(node.getblock(mined[0])["tx"])
        for funding in bonds:
            assert node.gettxout(funding["txid"], funding["sent_vout"]) is None
        node.sendrawtransaction(a["hex"], 0)
        self.generate(wallet, 1)
        assert "error" in fixture("validate", hex=b["hex"])
        self.restart_node(0)
        assert "error" in fixture("validate", hex=b["hex"])
        self.stop_node(0)
        assert "error" in fixture("validate", hex=a["hex"])


if __name__ == "__main__":
    BondTest(__file__).main()
