#!/usr/bin/env python3

import re
import unittest
from pathlib import Path

from elements_identity_refreeze import (
    Header, IDENTITY_HEADER, ALPHA_CHECKPOINT, assert_current_v7,
    calculate_v11, calculate_alphanet_v11,
)

CURRENT_CONTROLLER_PROGRAM_ID = "4e44d18d512d561128dae53d10bee2b36bd5390d1e4c4b72688464ea544943ec"
CURRENT_ANCHOR_PROGRAM_ID = "518ab5707c07430e28b9eea551b83cc04e1e1fd8662db4e850288ffa483c3d68"
CURRENT_VERIFIER_ID = "6b0292570fa120ae885743a391eba18a1e530455284648cfde30dc28bf3b64a9"
CURRENT_PROFILE_ID = "6fd5a5e55769320cc1c6a497644d0bc7a642eed8442ab1703af304cfac253d25"
HISTORICAL_CONTROLLER_PROGRAM_ID = "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08"
HISTORICAL_BCC6_VERIFIER_ID = "bcc6da9b30af2591d948533493291bd5543da448a3270ba99b1de0ade64e1711"


class ElementsIdentityRefreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header_path = Path(IDENTITY_HEADER)
        cls.header = Header(cls.header_path)
        cls.header_text = cls.header_path.read_text(encoding="utf-8")

    def mutated_string(self, name: str, value: str) -> Header:
        header = Header(self.header_path)
        pattern = rf"(inline constexpr char\s+{re.escape(name)}\[\]\s*\{{).*?(\}};)"
        header.text, count = re.subn(
            pattern,
            rf'\1"{value}"\2',
            header.text,
            count=1,
            flags=re.DOTALL,
        )
        self.assertEqual(count, 1)
        return header

    def mutated_integer(self, name: str, value: int) -> Header:
        header = Header(self.header_path)
        pattern = rf"(inline constexpr [^;{{}}]+\s+{re.escape(name)}\s*\{{)[^{{}};]+(\}};)"
        header.text, count = re.subn(pattern, rf"\g<1>{value}\2", header.text, count=1)
        self.assertEqual(count, 1)
        return header

    def test_independent_serializer_reproduces_current_v11_identity_twice(self) -> None:
        result_a = calculate_alphanet_v11(self.header)
        result_b = calculate_alphanet_v11(Header(self.header_path))
        self.assertEqual(result_a, result_b)
        assert_current_v7(self.header, result_a)
        self.assertEqual(result_a.protocol_manifest_hash, "fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6")
        self.assertEqual(result_a.proposal_hash, "866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400")
        self.assertEqual(result_a.identity_commitment, "589c3dfd784f637680382836bdc38b3af1cf67ecc5390488a56d4b80d58516ab")
        self.assertEqual(result_a.pegged_asset, "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4")
        self.assertEqual(result_a.genesis_merkle_root, "0fc01d7c98bda1c73fef20538e2832f0d870cd2da51bfb42d9f9eddded8c2a44")
        self.assertEqual(result_a.genesis_hash, "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd")
        self.assertEqual(result_a.p2p_message_start, "df91d03e")
        self.assertEqual(result_a.data_dir, "elements-v11")

    def test_v11_uses_parameterized_controller_profile(self) -> None:
        self.assertTrue(self.header.boolean("USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED"))
        self.assertEqual(self.header.array("PARAMETERIZED_CONTROLLER_PROFILE_ID").hex(), CURRENT_PROFILE_ID)
        self.assertEqual(self.header.array("USDD_SP1_INBOUND_MINT_DOMAIN_ID"), bytes(32))
        self.assertEqual(self.header.integer("USDD_SP1_DEPLOYMENT_BINDING_VERSION"), 2)
        self.assertEqual(calculate_alphanet_v11(self.header).mode, "candidate-v11-alphanet-preactivation-parent")

    def test_alpha_checkpoint_is_exact_and_activation_is_runtime_only(self) -> None:
        result = calculate_alphanet_v11(self.header)
        self.assertEqual(self.header.integer("PARENT_CHECKPOINT_HEIGHT"), 995347)
        for name, value in ALPHA_CHECKPOINT.items():
            self.assertEqual(self.header.string(name), value)
        self.assertNotEqual(self.header.string("PARENT_CHECKPOINT_CHAINWORK"), "00" * 32)
        self.assertEqual(self.header.string("PARENT_CHECKPOINT_CTIP_TXID"), "00" * 32)
        self.assertEqual(self.header.integer("PARENT_CHECKPOINT_CTIP_VOUT"), 0xFFFFFFFF)
        self.assertEqual(self.header.integer("PARENT_CHECKPOINT_CTIP_VALUE"), 0)
        self.assertTrue(result.parent_activation_required)
        self.assertFalse(result.future_parent_milestones_committed)

    def test_alpha_rejects_every_mixed_or_noncanonical_checkpoint(self) -> None:
        nonzero = "01" + "00" * 31
        mutations = (
            ("historical proposal description", self.mutated_string("HISTORICAL_PROPOSAL_DESCRIPTION_HEX", "00")),
            ("historical proposal hash", self.mutated_string("HISTORICAL_PROPOSAL_HASH", nonzero)),
            ("historical proposal height", self.mutated_integer("HISTORICAL_PROPOSAL_HEIGHT", 1)),
            ("historical proposal block", self.mutated_string("HISTORICAL_PROPOSAL_BLOCK_HASH", nonzero)),
            ("historical activation height", self.mutated_integer("HISTORICAL_ACTIVATION_HEIGHT", 1)),
            ("historical activation block", self.mutated_string("HISTORICAL_ACTIVATION_BLOCK_HASH", nonzero)),
            ("checkpoint height", self.mutated_integer("PARENT_CHECKPOINT_HEIGHT", 1)),
            ("checkpoint hash", self.mutated_string("PARENT_CHECKPOINT_HASH", nonzero)),
            ("checkpoint chainwork", self.mutated_string("PARENT_CHECKPOINT_CHAINWORK", "00" * 32)),
            ("checkpoint CTIP txid", self.mutated_string("PARENT_CHECKPOINT_CTIP_TXID", nonzero)),
            ("checkpoint CTIP vout", self.mutated_integer("PARENT_CHECKPOINT_CTIP_VOUT", 0)),
            ("checkpoint CTIP value", self.mutated_integer("PARENT_CHECKPOINT_CTIP_VALUE", 1)),
        )
        for label, header in mutations:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    calculate_alphanet_v11(header)

    def test_historical_v11_mode_does_not_silently_select_alpha(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical genesis pre-activation checkpoint is absent"):
            calculate_v11(self.header)

    def test_header_p2p_magic_must_match_the_independent_derivation(self) -> None:
        header = Header(self.header_path)
        header.text = header.text.replace("{{0xdf, 0x91, 0xd0, 0x3e}}", "{{0xde, 0x91, 0xd0, 0x3e}}", 1)
        self.assertNotEqual(header.text, self.header.text)
        with self.assertRaisesRegex(ValueError, "p2p_message_start"):
            assert_current_v7(header, calculate_alphanet_v11(header))

    def test_bootstrap_data_is_independently_bound_not_just_a_declared_hash(self) -> None:
        bootstrap_path = self.header_path.parent / "elements_drivechain_bootstrap.h"
        original = Header(bootstrap_path).text
        for old, new in (
            ("ENABLED{true}", "ENABLED{false}"),
            ("Slot{2,", "Slot{24,"),
            ("Slot{4,", "Slot{2,"),
            ("302000000", "302000001"),
            ("57dd0496", "57dd0497"),
            ("Slot{2,", "UnknownSlot{2,"),
        ):
            with self.subTest(old=old, new=new):
                bootstrap = Header(bootstrap_path)
                self.assertIn(old, original)
                bootstrap.text = original.replace(old, new, 1)
                with self.assertRaises(ValueError):
                    calculate_alphanet_v11(self.header, bootstrap)

    def test_wrong_parent_or_bootstrap_commitment_cannot_be_relabelled_alpha(self) -> None:
        for name in ("PARENT_GENESIS", "PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "refusing Alpha: wrong"):
                    calculate_alphanet_v11(self.mutated_string(name, "01" + "00" * 31))

    def test_repriced_lane_arithmetic_is_identity_bound_without_credit(self) -> None:
        expected = {
            "CONSENSUS_MAX_BLOCK_SERIALIZED_SIZE": 6_000_000,
            "CONSENSUS_MAX_BLOCK_WEIGHT": 6_000_000,
            "USDD_SP1_ANNEXES_PER_BLOCK": 1,
            "USDD_SP1_PROOF_TX_MAX_WEIGHT": 1_500_000,
            "USDD_SP1_ANNEX_MAX_BYTES": 1_310_720,
            "USDD_SP1_MEASURED_RAW_PROOF_BYTES": 1_272_546,
            "USDD_SP1_MEASURED_PUBLIC_VALUES_BYTES": 1_001,
            "USDD_SP1_MEASURED_ANNEX_BYTES": 1_273_602,
            "USDD_SP1_MEASURED_ANNEX_WEIGHT": 1_273_607,
            "USDD_SP1_MAX_ANNEX_WEIGHT": 1_310_725,
            "USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT": 189_275,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.header.integer(name), value)
        self.assertLessEqual(4 * expected["USDD_SP1_PROOF_TX_MAX_WEIGHT"], expected["CONSENSUS_MAX_BLOCK_WEIGHT"])
        self.assertEqual(expected["USDD_SP1_MAX_ANNEX_WEIGHT"] + expected["USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT"], expected["USDD_SP1_PROOF_TX_MAX_WEIGHT"])

    def test_current_proof_identities_and_profile_are_exact(self) -> None:
        self.assertEqual(self.header.array("USDD_SP1_GUEST_PROGRAM_ID").hex(), CURRENT_CONTROLLER_PROGRAM_ID)
        self.assertEqual(self.header.array("USDD_SP1_VERIFIER_SEMANTIC_IDENTITY").hex(), CURRENT_VERIFIER_ID)
        self.assertEqual(self.header.array("PARAMETERIZED_CONTROLLER_PROFILE_ID").hex(), CURRENT_PROFILE_ID)
        self.assertEqual(len(bytes.fromhex(CURRENT_ANCHOR_PROGRAM_ID)), 32)
        self.assertEqual(self.header.array("USDD_SP1_RECURSION_CONSTANTS_COMMITMENT").hex(), "0f4d8d0495d43e3709803b600674e1e948a5cdcb16d1663945ad838de5efadba")

    def test_historical_identities_and_global_cmr_are_absent_from_v11(self) -> None:
        self.assertNotEqual(self.header.array("USDD_SP1_GUEST_PROGRAM_ID").hex(), HISTORICAL_CONTROLLER_PROGRAM_ID)
        self.assertNotEqual(self.header.array("USDD_SP1_VERIFIER_SEMANTIC_IDENTITY").hex(), HISTORICAL_BCC6_VERIFIER_ID)
        self.assertNotIn(HISTORICAL_CONTROLLER_PROGRAM_ID, self.header_text)
        self.assertNotIn(HISTORICAL_BCC6_VERIFIER_ID, self.header_text)
        self.assertNotIn("USDD_SP1_CONTROLLER_CMR", self.header_text)
        with self.assertRaises(ValueError):
            self.header.array("USDD_SP1_CONTROLLER_CMR")


if __name__ == "__main__":
    unittest.main()
