Elements Drivechain Node
========================

This fork implements the native Elements Drivechain network, BIP300 slot 24,
with BIP301 block authorization, Confidential Transactions, assets and
Simplicity. The installed programs accept only `-chain=elements`.
This is not the upstream Liquid network or the historical Liquid-signet demo.

## Network identity

The authoritative frozen constants are in
[`src/elements_drivechain_identity.h`](src/elements_drivechain_identity.h).
The current network uses data subdirectory `elements-v11`, RPC 7065, P2P 7066,
parent RPC 18302, Bitcoin-mainnet ancestry, an empty signet challenge, and
parent checkpoint height 995347. The checkpoint hash is
`000000000000000002838070eb876cd37738a069528efc82d946fbd25e763152`.

Sharing Bitcoin's genesis/address prefixes is not proof that a parent node is
on the required deployment. Confirm the exact checkpoint, protocol manifest,
enforcer compatibility revision and slot activation before funding a wallet.
Changing slot, signet challenge or genesis at runtime cannot create a compatible
network. Never reuse historical/private chain data with this binary.

## Operations and security

- [Authenticated RPC and mTLS setup](doc/drivechain-rpc-security.md).
- [Native deposit, burn, M6 submission and payment verification](doc/drivechain-peg-operations.md).
- [Security contact and private reporting](SECURITY.md).
- [Security-report remediation and outstanding release gates](doc/security-report-remediation.md).
- [SP1 verifier implementation and validation requirements](doc/usdd-sp1-verifier-jet.md).

Native BMM admission uses authenticated parent replay and the frozen parent
identity. The historical signet proof format is not the native chain's
authorization path. `OP_TRUE` signblock syntax does not remove BMM validation.
Automatic block production defaults on; set `drivechainl1blocksync=0` for
read-only setup. Never treat a successful burn or submitted bundle as proof
of a parent payment.

The native build must link the pinned SP1 verifier library; startup rejects a
missing or mismatched verifier identity. Unit tests and a successful build are
not a production-readiness certification. See the remediation document for
remaining cross-platform, operational and independent-review gates.

The `drivechain-liquid-sidechain/` directory and old chain-mode tutorials are
historical reference only. Quarantined entry points fail immediately. They are
not instructions to launch this native network. Historical release recipes
likewise do not build the current verifier-enabled node.

## Building this revision

The upstream integration uses CMake 3.22 or newer and a C++20 compiler, not
Autotools. Configure a fresh out-of-tree build and provide the pinned verifier
archives explicitly. See [build instructions, compatibility checks and known
validation limits](doc/upstream-merge-20260902.md). Upstream `master` is a
development branch; being current with it is not release certification.

## Inherited Elements features

The following upstream references describe the platform this fork derives from,
not alternate supported deployment modes or a guarantee of this fork's CI:

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

Fork CI and release validation are described in the
[remediation and release gates](doc/security-report-remediation.md). Inherited
upstream workflows are not evidence of a validated current cross-platform release.

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with:
`python3 test/functional/test_runner.py --configfile=build/test/config.ini`
(assuming `build` is your build directory). Private functional-test binaries
are separate from the installed, native-only programs. Some inherited tests
need additional dependencies; consult the validation limits linked above.


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
