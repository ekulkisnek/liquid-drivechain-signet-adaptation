#!/usr/bin/env python3
"""Cross-check the published USDD withdrawal vectors against Elements V7."""

import hashlib
import json
import unittest
from pathlib import Path

from elements_identity_refreeze import Header, IDENTITY_HEADER, calculate_alphanet_v11
from fixtures.legacy_v7_identity import calculate_v7, assert_current_v7


ROOT = Path(__file__).resolve().parents[2]
WITHDRAWAL_VECTOR = ROOT / "doc" / "usdd-withdrawal-accumulator-v1-vectors.json"
CHECKPOINT_VECTOR = ROOT / "doc" / "usdd-bip301-checkpoint-v1-vectors.json"


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


class UsddWithdrawalVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # These published vectors belong to V7, not the current Alpha chain.
        # Preserve their independent derivation using the frozen historical
        # serializer/header instead of rewriting vectors to look like Alpha.
        cls.header = Header(Path(__file__).parent / "fixtures" / "elements-v7-identity.h")
        cls.identity = calculate_v7(cls.header)
        assert_current_v7(cls.header, cls.identity)
        cls.withdrawal = json.loads(WITHDRAWAL_VECTOR.read_text(encoding="utf-8"))
        cls.checkpoint = json.loads(CHECKPOINT_VECTOR.read_text(encoding="utf-8"))

    def test_historical_vectors_cannot_be_mistaken_for_current_alpha(self) -> None:
        alpha = Header(Path(IDENTITY_HEADER))
        self.assertNotEqual(self.identity.genesis_hash, calculate_alphanet_v11(alpha).genesis_hash)
        # The algorithm is shared; the genesis domain is deliberately not.
        for name in ("WITHDRAWAL_BURN_ID_DOMAIN", "WITHDRAWAL_LEAF_DOMAIN"):
            self.assertEqual(self.header.array(name), alpha.array(name))
        for name in ("WITHDRAWAL_PROTOCOL_VERSION", "WITHDRAWAL_TREE_DEPTH", "USDD_UNITS_PER_USDT_MICRO"):
            self.assertEqual(self.header.integer(name), alpha.integer(name))

    def test_withdrawal_vector_is_self_consistent_and_bound_to_v7(self) -> None:
        document = self.withdrawal
        vector = document["vector"]
        genesis = bytes.fromhex(vector["elements_genesis_display"])
        transaction = bytes.fromhex(vector["serialized_elements_transaction"])
        txid_display = hashlib.sha256(hashlib.sha256(transaction).digest()).digest()[::-1]

        self.assertEqual(genesis.hex(), self.identity.genesis_hash)
        self.assertEqual(txid_display.hex(), vector["burn_txid_display"])
        self.assertEqual(
            bytes.fromhex(document["burn_id_domain"]),
            self.header.array("WITHDRAWAL_BURN_ID_DOMAIN"),
        )
        self.assertEqual(
            bytes.fromhex(document["approved_redemption_leaf_domain"]),
            self.header.array("WITHDRAWAL_LEAF_DOMAIN"),
        )
        self.assertEqual(
            document["usdd_base_units_per_usdt_micro"],
            self.header.integer("USDD_UNITS_PER_USDT_MICRO"),
        )
        self.assertEqual(document["tree_depth"], self.header.integer("WITHDRAWAL_TREE_DEPTH"))

        burn_domain = bytes.fromhex(document["burn_id_domain"])
        leaf_domain = bytes.fromhex(document["approved_redemption_leaf_domain"])
        asset = bytes.fromhex(vector["asset_id_display"])
        vault = bytes.fromhex(vector["vault_id"])
        version = self.header.integer("WITHDRAWAL_PROTOCOL_VERSION")
        leaves = []
        for output in vector["outputs"]:
            burn_id = sha256(
                burn_domain
                + genesis
                + txid_display
                + output["burn_vout"].to_bytes(4, "big")
            )
            leaf = sha256(
                bytes([self.header.integer("WITHDRAWAL_LEAF_PREFIX")])
                + leaf_domain
                + version.to_bytes(4, "big")
                + genesis
                + asset
                + vault
                + burn_id
                + output["claim_index"].to_bytes(8, "big")
                + output["amount_usdt_micro"].to_bytes(8, "big")
                + bytes.fromhex(output["ethereum_recipient"])
            )
            self.assertEqual(burn_id.hex(), output["burn_id"])
            self.assertEqual(leaf.hex(), output["leaf"])
            leaves.append(leaf)

        # These are also fixed in validation_tests.cpp, giving the document,
        # Python codec, and consensus implementation one deterministic vector.
        self.assertEqual(
            [output["burn_id"] for output in vector["outputs"]],
            [
                "f7961bb911f26f0187638b835f593466c235c99f8c040559e3ca93e3bfe796ff",
                "8a7a3e77f9f85e4c665465e06ad8ddbac07f4e217750f11e27f2a01fec6a84f8",
            ],
        )
        self.assertEqual(
            [leaf.hex() for leaf in leaves],
            [
                "8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f",
                "411d36323ee653bda6c17167e4321e2437ae288a42e7786bed84832ba7baa7ec",
            ],
        )

        empty_roots = [sha256(b"\x00")]
        for _ in range(document["tree_depth"]):
            empty_roots.append(node_hash(empty_roots[-1], empty_roots[-1]))
        self.assertEqual(empty_roots[-1].hex(), vector["empty_root_depth_64"])

        root = node_hash(leaves[0], leaves[1])
        for level in range(1, document["tree_depth"]):
            root = node_hash(root, empty_roots[level])
        self.assertEqual(root.hex(), vector["root_after_two_appends"])
        self.assertEqual(
            root.hex(),
            "9a9d19c855a9cb649c60024f7de206266056755cc93b4021211870d32a630719",
        )

        proof = vector["proof"]
        siblings = [bytes.fromhex(value) for value in proof["siblings_bottom_up"]]
        self.assertEqual(siblings, [leaves[0], *empty_roots[1:document["tree_depth"]]])
        proof_node = leaves[proof["claim_index"]]
        for level, sibling in enumerate(siblings):
            if (proof["claim_index"] >> level) & 1:
                proof_node = node_hash(sibling, proof_node)
            else:
                proof_node = node_hash(proof_node, sibling)
        self.assertEqual(proof_node, root)

    def test_checkpoint_vector_is_self_consistent_and_bound_to_withdrawal_vector(self) -> None:
        checkpoint = self.checkpoint
        vector = checkpoint["vectors"][0]
        withdrawal = self.withdrawal["vector"]

        self.assertEqual(
            checkpoint["domain_ascii_without_nul"],
            self.header.string("WITHDRAWAL_BIP301_CHECKPOINT_DOMAIN"),
        )
        self.assertEqual(
            checkpoint["version"],
            self.header.integer("WITHDRAWAL_BIP301_CHECKPOINT_VERSION"),
        )
        self.assertEqual(vector["elements_genesis_display"], self.identity.genesis_hash)
        self.assertEqual(vector["elements_genesis_display"], withdrawal["elements_genesis_display"])
        self.assertEqual(vector["sidechain_slot"], self.header.integer("SIDECHAIN_SLOT"))
        self.assertEqual(vector["previous_root"], withdrawal["empty_root_depth_64"])
        self.assertEqual(vector["next_count"], len(withdrawal["outputs"]))
        self.assertEqual(vector["next_root"], withdrawal["root_after_two_appends"])

        preimage = (
            checkpoint["domain_ascii_without_nul"].encode("ascii")
            + checkpoint["version"].to_bytes(4, "big")
            + bytes.fromhex(vector["elements_genesis_display"])
            + bytes([vector["sidechain_slot"]])
            + bytes.fromhex(vector["candidate_block_hash_display"])
            + vector["previous_count"].to_bytes(8, "big")
            + bytes.fromhex(vector["previous_root"])
            + vector["next_count"].to_bytes(8, "big")
            + bytes.fromhex(vector["next_root"])
        )
        critical_hash = sha256(preimage)
        self.assertEqual(preimage.hex(), vector["preimage_hex"])
        self.assertEqual(critical_hash.hex(), vector["critical_hash_display"])
        self.assertEqual(
            critical_hash.hex(),
            "6b9c9c485cce8a07a5d6d78c81b5566f269f5df03fa38cd29d5c3de7cb985161",
        )


if __name__ == "__main__":
    unittest.main()
