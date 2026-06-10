Elements Project blockchain platform
====================================

[![Release](https://img.shields.io/github/v/release/ElementsProject/elements?label=latest%20release&link=https%3A%2F%2Fgithub.com%2FElementsProject%2Felements%2Freleases%2Flatest)](https://github.com/ElementsProject/elements/releases)

https://elementsproject.org

This is the integration and staging tree for the Elements blockchain platform,
a collection of feature experiments and extensions to the Bitcoin protocol.
This platform enables anyone to build their own businesses or networks
pegged to Bitcoin as a sidechain or run as a standalone blockchain with arbitrary asset tokens.

Modes
-----

Elements supports a few different pre-set chains for syncing. Note though some are intended for QA and debugging only:

* Liquid mode: `elementsd -chain=liquidv1` (syncs with Liquid network)
* Bitcoin mainnet mode: `elementsd -chain=main` (not intended to be run for commerce)
* Bitcoin testnet mode: `elementsd -chain=testnet3`
* Bitcoin regtest mode: `elementsd -chain=regtest`
* Elements custom chains: Any other `-chain=` argument. It has regtest-like default parameters that can be over-ridden by the user by a rich set of start-up options.

Drivechain / BIP 300/301 adaptation
------------------------------------

This tree also contains an adaptation (`liquid-drivechain-signet-adaptation` branch + `drivechain-liquid-sidechain/` directory) that lets you run Liquid/Elements as a **native BIP 300/301 drivechain sidechain** (with Confidential Transactions, assets, Simplicity, etc.) on a patched Bitcoin signet, using only CUSF mechanisms (no federation).

See `drivechain-liquid-sidechain/README.md` (especially the section "Setting Up the Liquid Node on a New Signet + New Sidechain ID (BIP 300/301 + Blind Merged Mining)") for:
- Bootstrapping a fresh L1 signet + enforcer.
- Choosing and activating an unused sidechain slot (0-255).
- Running an isolated `elementsd` for that slot.
- Full Blind Merged Mining (BIP 301 BMM) setup, both manual and automated (participant scripts + adapter).
- Deposits, withdrawals, and end-to-end flows.

The same pattern works for any new signet or new sidechain number.

This branch adapts the Liquid/Elements wallet peg-out path to use a BIP300
drivechain withdrawal bundle instead of the legacy federated/PAK
`sendtomainchain` path. It is intended to run as an Elements sidechain attached
to a Bitcoin signet mainchain that is coordinated by a BIP300/301 enforcer and
a BIP301 blind merge mining (BMM) miner.

### Connect to a new Bitcoin signet

Start the Bitcoin mainchain node first. The mainchain node must be on the same
signet as the enforcer and miner, and the miner must be able to sign blocks for
that signet challenge.

A minimal private signet `bitcoin.conf` looks like:

```ini
signet=1
server=1
txindex=1
rpcuser=<rpc-user>
rpcpassword=<rpc-password>
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
signetchallenge=<hex-script>
```

Use a fresh Bitcoin data directory for each new signet. If this is a private
signet, keep the block-signing key for `signetchallenge` available to the
mainchain miner; otherwise `generatetoaddress`/the signet miner will not be
able to create valid blocks.

Start `elementsd` with peg-in validation pointed at that signet node:

```sh
src/elementsd \
  -chain=<elements-chain-name> \
  -daemon \
  -validatepegin=1 \
  -mainchainrpchost=127.0.0.1 \
  -mainchainrpcport=38332 \
  -mainchainrpcuser=<rpc-user> \
  -mainchainrpcpassword=<rpc-password>
```

Cookie auth can be used instead of `mainchainrpcuser`/`mainchainrpcpassword`:

```sh
src/elementsd \
  -chain=<elements-chain-name> \
  -daemon \
  -validatepegin=1 \
  -mainchainrpchost=127.0.0.1 \
  -mainchainrpcport=38332 \
  -mainchainrpccookiefile=/path/to/bitcoin/signet/.cookie
```

For a production-style deployment, use explicit config files and separate data
directories for the Bitcoin signet node, the enforcer, and every Elements
sidechain node.

### Choose an unused sidechain number

Every BIP300 sidechain on the same signet must use a unique sidechain number.
Before launching a new Liquid sidechain:

1. Check the enforcer/signet state and list the sidechain numbers already
   registered by other sidechains.
2. Pick a sidechain number that is not already registered or reserved on that
   signet.
3. Register/propose that same number with the BIP300/301 enforcer.
4. Start this Elements node with the same number in its drivechain environment.

This branch defaults to sidechain ID `5` for the drivechain peg-out broadcaster.
Override it for a new deployment:

```sh
export ELEMENTS_DRIVECHAIN_SIDECHAIN_ID=<unused-sidechain-number>
```

The sidechain ID used by `ELEMENTS_DRIVECHAIN_SIDECHAIN_ID`, the enforcer
sidechain registration, the BMM miner, wallet tooling, and any mobile clients
must all match. If they do not, peg-outs can be broadcast to the wrong
sidechain slot or fail to be recognized by the mainchain.

### Configure BIP301 blind merge mining

BIP301 BMM is coordinated by the mainchain/enforcer/miner stack, not by
ordinary proof-of-work inside `elementsd`. The required pieces are:

1. A Bitcoin signet node using the intended `signetchallenge`.
2. A BIP300/301 enforcer connected to that Bitcoin node.
3. The selected sidechain number proposed and activated in the enforcer.
4. A miner that can create signet blocks and include BIP301 BMM commitments for
   the selected sidechain number.
5. A funded mainchain wallet for BMM critical-data transactions and withdrawal
   bundle fees.

The high-level BMM loop is:

1. Build or receive the next Elements sidechain block candidate.
2. Ask the BIP300/301 enforcer/miner to commit that candidate's critical data
   for `ELEMENTS_DRIVECHAIN_SIDECHAIN_ID`.
3. Mine/sign a Bitcoin signet block that includes the BIP301 BMM commitment.
4. Let the enforcer and sidechain nodes sync the new mainchain block.
5. Confirm the sidechain tip advances and the enforcer reports the BMM
   inclusion for that sidechain number.

When running a local private signet, mine blocks with the configured signet
miner or with Bitcoin Core RPC if your setup supports direct generation:

```sh
ADDR=$(bitcoin-cli -signet getnewaddress)
bitcoin-cli -signet generatetoaddress 1 "$ADDR"
```

For private signets that require explicit signing, use the miner command/script
that has access to the signing key matching `signetchallenge`.

### Configure drivechain peg-out RPC

The adapted `sendtomainchain` RPC broadcasts a BIP300 withdrawal bundle through
the enforcer gRPC API. Configure the enforcer endpoint before starting
`elementsd`:

```sh
export ELEMENTS_DRIVECHAIN_SIDECHAIN_ID=<unused-sidechain-number>
export ELEMENTS_DRIVECHAIN_PEGOUT_ENFORCER=127.0.0.1:50051
export ELEMENTS_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS=500
```

`ELEMENTS_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS` is subtracted from the withdrawal
amount and encoded as the mainchain fee output in the withdrawal bundle. It
must be non-negative and less than the peg-out amount.

Then start the node from the same environment:

```sh
src/elementsd \
  -chain=<elements-chain-name> \
  -daemon \
  -validatepegin=1 \
  -mainchainrpchost=127.0.0.1 \
  -mainchainrpcport=38332 \
  -mainchainrpccookiefile=/path/to/bitcoin/signet/.cookie
```

Peg out with:

```sh
src/elements-cli -chain=<elements-chain-name> sendtomainchain "<bitcoin-signet-address>" 0.01 false true
```

With `verbose=true`, the result includes a `drivechain_pegout` object with the
sidechain ID, enforcer endpoint, withdrawal bundle hex, broadcaster response,
and sidechain peg-out transaction hex. Save this output when testing a new
signet because it is the easiest way to confirm the wallet used the intended
sidechain number.

### Validation checklist

Before considering a new signet deployment ready:

* `bitcoin-cli -signet getblockchaininfo` reports the expected signet and
  blocks are being signed/mined.
* The enforcer is synced to the same Bitcoin signet tip.
* The selected sidechain number is proposed and activated in the enforcer.
* The BMM miner is producing BIP301 commitments for that sidechain number.
* `elementsd` is connected to the same mainchain RPC and has a fresh data
  directory.
* `getpeginaddress`, mainchain funding, and `claimpegin` work on the new
  signet.
* `sendtomainchain` returns a `drivechain_pegout` object with the expected
  `sidechain_id` and enforcer endpoint.
* After enough BIP300 acknowledgement/confirmation blocks, the mainchain
  enforcer reports the withdrawal bundle as accepted/confirmed.

Confidential Assets
----------------
The latest feature in the Elements blockchain platform is Confidential Assets,
the ability to issue multiple assets on a blockchain where asset identifiers
and amounts are blinded yet auditable through the use of applied cryptography.

 * [Announcement of Confidential Assets](https://blockstream.com/2017/04/03/blockstream-releases-elements-confidential-assets.html)
 * [Confidential Assets Whitepaper](https://blockstream.com/bitcoin17-final41.pdf) to be presented [April 7th at Financial Cryptography 2017](http://fc17.ifca.ai/bitcoin/schedule.html) in Malta
 * [Confidential Assets Tutorial](contrib/assets_tutorial/assets_tutorial.py)
 * [Confidential Assets Demo](https://github.com/ElementsProject/confidential-assets-demo)
 * [Elements Code Tutorial](https://elementsproject.org/elements-code-tutorial/overview) covering blockchain configuration and how to use the main features.

Features of the Elements blockchain platform
----------------

Compared to Bitcoin itself, it adds the following features:
 * [Confidential Assets][asset-issuance]
 * [Confidential Transactions][confidential-transactions]
 * [Federated Two-Way Peg][federated-peg]
 * [Signed Blocks][signed-blocks]
 * [Additional opcodes][opcodes]

Previous elements that have been integrated into Bitcoin:
 * Segregated Witness
 * Relative Lock Time

Elements deferred for additional research and standardization:
 * [Schnorr Signatures][schnorr-signatures]

Additional RPC commands and parameters:
* [RPC Docs](https://elementsproject.org/en/doc/)

The CI (Continuous Integration) systems make sure that every pull request is built for Windows, Linux, and macOS,
and that unit/sanity tests are run automatically.

License
-------
Elements is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see http://opensource.org/licenses/MIT.

[confidential-transactions]: https://elementsproject.org/features/confidential-transactions
[opcodes]: https://elementsproject.org/features/opcodes
[federated-peg]: https://elementsproject.org/features#federatedpeg
[signed-blocks]: https://elementsproject.org/features#signedblocks
[asset-issuance]: https://elementsproject.org/features/issued-assets
[schnorr-signatures]: https://elementsproject.org/features/schnorr-signatures

What is the Elements Project?
-----------------
Elements is an open source, sidechain-capable blockchain platform. It also allows experiments to more rapidly bring technical innovation to the Bitcoin ecosystem.

Learn more on the [Elements Project website](https://elementsproject.org)

https://github.com/ElementsProject/elementsproject.github.io

Secure Reporting
------------------
See [our vulnerability reporting guide](SECURITY.md)
