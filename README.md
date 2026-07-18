Elements Project blockchain platform
====================================

[![Release](https://img.shields.io/github/v/release/ElementsProject/elements?label=latest%20release&link=https%3A%2F%2Fgithub.com%2FElementsProject%2Felements%2Freleases%2Flatest)](https://github.com/ElementsProject/elements/releases)

https://elementsproject.org

This is the integration and staging tree for the Elements blockchain platform,
a collection of feature experiments and extensions to the Bitcoin protocol.
This platform enables anyone to build their own businesses or networks
pegged to Bitcoin as a sidechain or run as a standalone blockchain with arbitrary asset tokens.

Network
-------

This fork's production daemon runs one built-in network: `-chain=elements`,
which is also the default. Inherited Liquid, Bitcoin, regtest, and custom-chain
parameter classes remain only for unit-test/library compatibility; production
startup rejects them. The pre-launch name `-chain=usdd` is not an alias.

Drivechain / BIP 300/301 adaptation
------------------------------------

This fork contains one dedicated built-in Elements Drivechain network:

```sh
src/elementsd -chain=elements -server=1 \
  -mainchainrpchost=127.0.0.1 \
  -mainchainrpcport=38332 \
  -mainchainrpccookiefile=/path/to/bitcoin/signet/.cookie
```

`elements` is the sole production network identity and uses its own versioned
`elements-v1/`
data directory, genesis block,
message magic, ports, address prefixes, and pegged asset. It is permanently
assigned BIP300/301 slot 24. Taproot and Simplicity are active from genesis.
The slot and consensus identities cannot be changed with startup arguments or
environment variables. There is no `-chain=usdd` alias and custom chains do not
inherit any Elements Drivechain identity.

Its P2P magic is the first four bytes (`2ac59d38`) of raw
SHA256d(`ecash-elements-drivechain-p2p-v2`), and its child genesis is
`d758e40eace8dc9c95a9dd44f7be84c241a4f8c5a3bd72812f2346a5801e3e9e`.
The canonical child coinbase parent tag is `ELMTP`. Its unique WIF prefix is
`37`, extended-public prefix is `18717df5`, and extended-secret prefix is
`b263bd77`; each is derived from the documented ASCII domain frozen in
`elements_drivechain_identity.h`.
Pre-launch data directories are incompatible and may be deleted or moved.

Slot 24 is already occupied on the parent Signet by an older generic Elements
proposal. That proposal is historical parent state only, never an alternate
child-chain identity. The Elements network remains fail-closed until the exact
Elements Drivechain proposal below replaces it for slot 24:

```text
proposal description (D):
0008456c656d656e7473456c656d656e7473204472697665636861696e2076313b206e617469766520555344443b207265706c61792076323b2053696d706c6963697479206163746976653b20736c6f74203234a8ec2ac4113afc9f4f964fc27439fd0cab5bb556b050a98e62e0a027ac2f5066f49d0cbac06d5a79012d6dc343d96b5181a1d00d

proposal hash:
b27b2b233f9db48be36046b72cac4876efd24a3055bbb0c25392f52e55042f98
```

Activating it replaces the older slot-24 proposal. Before activation, no
Elements child block or native BIP300 deposit is valid. If slot 24 is later replaced again,
this immutable V1 halts rather than following a different proposal.

The parent must be a fully validating LayerTwo Labs Signet node with `txindex=1`
on the same host. Native-drivechain consensus RPC accepts only IPv4 `127/8` or
IPv6 `::1`: its HTTP Basic authentication is not safe over a LAN, and a remote
endpoint could expose credentials or substitute the parent-chain view.
The Elements node reads raw parent headers, blocks, and transactions from that
node and independently checks their hashes, proof of work, transaction Merkle
roots, frozen Signet challenge, active-chain positions, canonical slot-24 M7
commitment, and the relevant BIP300 treasury transition. The parent node remains
responsible for full Bitcoin and BIP300 consensus, cumulative-work fork choice,
and script validation; do not point consensus RPC at a third-party service.

Parent proposal and CTIP state is derived by authenticating and applying every
parent block from the pinned Signet genesis. Heights 257, 263, and 5580 are
milestone assertions over the replayed state, not assignments or trusted
snapshots. Replay preserves all pending proposals, applies the enforcer's
unused-slot and used-slot threshold pairs, and ignores OP_DRIVECHAIN-looking
outputs until slot 24 is active. Only canonical CTIP increases at or after the
exact Elements proposal activation block can enter the mintable-deposit index.

The authenticated replay tip, every canonical M5 deposit, and every
post-checkpoint M7 edge are stored in `elements-v1/parent-replay/` using a
fixed 4 MiB LevelDB cache. Each parent block advances the records and replay
tip in one synchronous atomic batch, so ordinary restarts resume from the last
durable authenticated tip instead of replaying from genesis. The database is
bound to its schema, child genesis, parent genesis, slot, proposal, manifest,
Signet rules, checkpoint, CTIP, and replay thresholds. It is only a derived
index, never a trust root: malformed records, identity changes, or a parent
reorganization unpublish the replay generation and rebuild the index from
authenticated parent genesis. Consensus history is not expired; the rebuild
is a safe liveness cost rather than a fallback to a trusted checkpoint.

The BIP300/301 enforcer and `grpcurl` are used only to submit proposal and BMM
requests. Their responses never authorize a deposit or sidechain block. A user
can replace those liveness tools without changing consensus or custody.
The automatic miner requires a funded enforcer wallet and submits
`max(-drivechainbmmbid, candidate fees)` satoshis (default minimum: 1,000 sats)
for each BMM request. This bid is operator-funded liveness policy, not a
sidechain fee or consensus proof. The managed `grpcurl` child has a 10-second
deadline and 64 KiB combined-output limit and is terminated during shutdown.

Every non-genesis Elements block commits to a parent block and is accepted only
after the exact active successor contains one canonical M7 for that block hash.
The authenticated parent pair is persisted with the block. Parent reorgs
disconnect affected sidechain blocks without permanently marking them invalid;
RPC unavailability stalls safely.

Native deposits credit the exact address and full amount committed by the
confirmed BIP300 deposit. A relayer cannot redirect the deposit or subtract a
fee. The canonical one-input/one-output import may relay at zero fee; a relayer
can optionally sponsor an ordinary signed input instead.
These M5 imports mint the BTC-denominated `pegged_asset` used as the base fee
asset; they never mint the future USDT-backed USDD issued asset.

Native BIP300 withdrawals are disabled in this version. The node deliberately
rejects CTIP decreases until complete M3/M4/M6 vote validation exists. The
reserved USDD SP1 annex also fails closed because the proof-verifier jet and
the USDD mint/burn controller are not implemented in this repository yet.
Consequently this node work fixes the Elements/Drivechain consensus base; it is
not by itself a deployable Ethereum-USDT-to-USDD bridge.

The historical material under `drivechain-liquid-sidechain/` describes an
older mutable slot-5 prototype. It is not the consensus or deployment guide for
`-chain=elements` and must not be treated as production-ready documentation.

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
