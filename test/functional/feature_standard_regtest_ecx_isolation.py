#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep ECX/BMM and drivechain extensions inert on Bitcoin regtest."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class StandardRegtestEcxIsolationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.chain = "regtest"
        # Even an explicit Elements-only parent-validation option must remain
        # inert on standard Bitcoin regtest. Port 1 makes an accidental parent
        # RPC attempt fail immediately instead of silently passing the test.
        self.extra_args = [[
            "-validatepegin=1",
            "-mainchainrpcport=1",
            "-mainchainrpctimeout=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getblockhash(0)
        header_hex = node.getblockheader(genesis, False)
        header = node.getblockheader(genesis)

        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        assert_equal(len(header_hex), 160)
        for hidden_field in [
            "withdrawalbundlehash",
            "bmmproofhash",
            "exchangestateroot",
            "forcedinboxroot",
            "depositinboxroot",
            "ecxparentheight",
            "forcedprocessedcursor",
            "depositprocessedcursor",
            "sourcebacklogoldestparentheight",
        ]:
            assert hidden_field not in header

        # These calls deliberately use otherwise-invalid arguments. The exact
        # mode error proves the guard runs before wallet mutation, input
        # interpretation, block scans, or an enforcer/parent-chain request.
        assert_raises_rpc_error(
            -1,
            "sendtomainchain is unavailable outside an Elements parent-chain configuration",
            node.sendtomainchain,
            "not-a-mainchain-address",
            1,
        )
        assert_raises_rpc_error(
            -1,
            "importdrivechaindeposit is unavailable outside an Elements parent-chain configuration",
            node.importdrivechaindeposit,
            "00" * 32,
            "not-an-elements-address",
            1,
        )
        assert_raises_rpc_error(
            -1,
            "getdrivechainpegevents is unavailable outside an Elements parent-chain configuration",
            node.getdrivechainpegevents,
        )
        assert_raises_rpc_error(
            -1,
            "ECX state is unavailable outside an Elements-mode chain",
            node.getecxstateutxoroot,
            "00" * 32,
            0,
        )
        assert_raises_rpc_error(
            -1,
            "ECX consensus context is unavailable outside an Elements-mode chain",
            node.getecxconsensuscontext,
        )

        with open(node.debug_log_path, encoding="utf-8") as debug_log:
            assert "Starting drivechain L1 block sync thread" not in debug_log.read()

        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-con_elementsmode=1"],
            expected_msg="-con_elementsmode is not supported with -chain=regtest",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=["-vbparams=simplicity:0:999999999999"],
            expected_msg="the Simplicity deployment is not supported with -chain=regtest",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=["-vbparams=dynafed:0:999999999999"],
            expected_msg="the dynafed deployment is not supported with -chain=regtest",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == "__main__":
    StandardRegtestEcxIsolationTest(__file__).main()
