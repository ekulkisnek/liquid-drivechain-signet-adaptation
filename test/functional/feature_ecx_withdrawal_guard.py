#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Reject a drivechain withdrawal without finalized ECX state before mutation."""

from pathlib import Path
import shutil
import subprocess

from feature_fedpeg import FedPegTest, get_new_unconfidential_address
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error


class EcxWithdrawalGuardTest(FedPegTest):
    def set_test_params(self):
        super().set_test_params()

    def skip_test_if_missing_module(self):
        super().skip_test_if_missing_module()
        if self.options.usecli:
            raise SkipTest("This test checks structured RPC errors")
        if not all(shutil.which(tool) for tool in ("bash", "openssl", "grpcurl")):
            raise SkipTest("Mutual-TLS preflight requires bash, openssl, and grpcurl")

    def setup_network(self, split=False):
        self.tls_dir = Path(self.options.tmpdir) / "enforcer-tls"
        generator = Path(__file__).resolve().parents[2] / "contrib/drivechain-mtls/generate-certs.sh"
        subprocess.run(["bash", str(generator), str(self.tls_dir)], check=True, capture_output=True)
        # Use the real executable in a private, owned directory, as production requires.
        self.grpcurl = self.tls_dir / "grpcurl"
        shutil.copyfile(shutil.which("grpcurl"), self.grpcurl)
        self.grpcurl.chmod(0o700)
        super().setup_network(split)

    def sidechain_extra_args(self, node_index):
        return [
            "-drivechainbmmgrpcaddr=127.0.0.1:1",
            f"-drivechainbmmgrpcca={self.tls_dir / 'ca.pem'}",
            f"-drivechainbmmgrpccert={self.tls_dir / 'elements-client.pem'}",
            f"-drivechainbmmgrpckey={self.tls_dir / 'elements-client-key.pem'}",
            f"-drivechainbmmgrpcurl={self.grpcurl}",
        ]

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
    EcxWithdrawalGuardTest(__file__).main()
