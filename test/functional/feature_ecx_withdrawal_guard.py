#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Reject a drivechain withdrawal without finalized ECX state before mutation."""

from feature_fedpeg import FedPegTest, get_new_unconfidential_address
from test_framework.util import assert_equal, assert_raises_rpc_error


class EcxWithdrawalGuardTest(FedPegTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        self.import_deterministic_coinbase_privkeys()
        parent = self.nodes[0]
        sidechain = self.nodes[2]
        for node in self.nodes:
            node.importprivkey(
                privkey=node.get_deterministic_priv_key().key,
                label="mining",
            )

        self.generate(parent, 101, sync_fun=self.no_op)
        self.generate(sidechain, 101, sync_fun=self.no_op)
        destination = get_new_unconfidential_address(parent, "legacy")

        transactions_before = sidechain.listtransactions("*", 1000, 0, True)
        balance_before = sidechain.getbalances()
        mempool_before = sidechain.getrawmempool()
        assert_raises_rpc_error(
            -4,
            "Cannot withdraw before a finalized ECX state header is active",
            sidechain.sendtomainchain,
            destination,
            1,
        )
        assert_equal(sidechain.listtransactions("*", 1000, 0, True), transactions_before)
        assert_equal(sidechain.getbalances(), balance_before)
        assert_equal(sidechain.getrawmempool(), mempool_before)


if __name__ == "__main__":
    EcxWithdrawalGuardTest().main()
