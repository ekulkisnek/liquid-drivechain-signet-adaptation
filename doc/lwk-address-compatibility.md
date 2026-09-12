# LWK address compatibility

On `-chain=elements`, the node accepts LWK CustomElements witness addresses
using `ert` (Bech32/Bech32m) and `el` (Blech32/Blech32m) as input aliases.
The address payload, including any blinding public key, is decoded unchanged.
Checksum, witness version and witness program validation remain mandatory.

Node-generated addresses still use `elements` and `elementsl`. Existing
addresses, scripts, transaction IDs, balances and chain identity are unchanged.
Aliases do not apply to parent-chain destinations or other node networks.
An alias cannot distinguish this chain from Elements regtest: applications must
verify the configured chain's genesis hash and policy asset independently.

This is address parsing compatibility, not a change to confidential transaction
rules. Accepting a confidential address does not enable confidential outputs on
an explicit-only chain. No blinding key or amount is silently discarded.

An independently operated Esplora/electrs backend also needs compatible address
lookup and Alpha block-header parsing. Updating this node alone does not update
that backend or fix stock LWK's explicit-output accounting. Use the matching SDK
and indexer for full wallet synchronization.

Regression validation: build `test_elements`, then run
`test_elements --run_test=key_io_tests,bech32_tests,blech32_tests`.
