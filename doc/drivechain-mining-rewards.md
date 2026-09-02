# Automatic BMM reward destination

The automatic drivechain miner requires
`-drivechainrewardaddress=<unconfidential Elements address>`. Configure a P2WPKH
(recommended) or P2PKH address owned by the operator's loaded Elements wallet.
The wallet must have private keys enabled and report the destination spendable.
A locked wallet can receive rewards; this setting does not require unlocking it
or exporting any private keys.

The node checks the address before constructing the candidate or paying a BMM
bid. Missing, invalid, wrong-network, confidential, script-hash, future-witness,
or unowned destinations pause automatic bidding. There is no OP_TRUE fallback.
Normal validation and peer connections continue. Nodes built without wallet
support, or with no matching loaded wallet, cannot use this automatic bidder.

The selected reward script enters the coinbase before the candidate block hash
and BIP301 critical hash are computed. The successful candidate therefore pays
its reward to that script; changing the script changes the committed candidate.
This is local block-construction policy, not a new consensus restriction on
other miners' reward destinations. It does not change manual/template RPCs.
Zero-value coinbase outputs retain the existing OP_RETURN behavior.

## Operator setup (only after a verified build is installed)

1. In the intended Elements wallet, obtain a **bech32 receive address** with
   `getnewaddress "bmm-rewards" "bech32"`.
2. Inspect it with `getaddressinfo` in that same wallet. Use its `unconfidential`
   address for this setting, not its confidential address. Confirm ownership and
   that `getwalletinfo` reports `private_keys_enabled: true`. Keep the wallet
   backed up and configured to load after reboot.
3. Add the unconfidential address to `drivechainrewardaddress` in the Elements
   parent-chain configuration or launch arguments. Do not add the option to an
   older binary that does not recognize it.
4. With a reviewed binary and controlled test funding, verify a fee-bearing
   candidate's coinbase script matches that address before enabling production
   bids. Then check the confirmed block and the wallet's coinbase maturity.

The Elements wallet receiving the reward and the mainchain wallet paying the
bid are separate. The operator must control both. A mainchain address must not
be substituted for the Elements reward address.

## Economics and rollout boundaries

The existing [work-priced BIP301 bid policy](bip301-work-fees.md) is unchanged:
candidate policy-asset fees minus the deterministic Simplicity verification
charge and producer reserve. A candidate must fund a positive remaining bid.
Receiving sidechain fees is **not a refund of the mainchain bid** and does not
make an activation or mining round free. This patch neither changes fee rates
nor authorizes a live bid, activation, proof run, or transaction broadcast.

Regression cases in `validation_tests.cpp` exercise address type restrictions,
network mismatch, missing ownership, and clearing an old script on failure.
The full test suite and the live binary/configuration must be verified before
rollout; source changes alone do not fix an already-running older daemon.
