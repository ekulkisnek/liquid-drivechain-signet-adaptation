# Elements Alpha node

Elements sidechain for **eCash Alphanet, slot 24**. Use `-chain=elements`.
This is not Liquid, Bitcoin mainnet, or the historical signet demo.
Confidential transactions and explicit payments are supported. Rangeproof,
surjection-proof and amount-conservation checks remain mandatory.

Nodes built from the former explicit-only Alpha branch must upgrade before
accepting confidential payments. This consensus change does not alter the
genesis or address prefixes; do not send confidential payments until your
validators have upgraded. The optional explicit-only validation fixtures are
not activated on Alpha. Before replacing an explicit-only deployment, replay
its existing chain in an isolated copy: that branch also selected different
per-asset aggregate limits, so source integration alone is not a historical
chain-compatibility or deployment certification.

## 1. Build

Follow the [build instructions](doc/upstream-merge-20260902.md).
You need CMake 3.22+, a C++20 compiler, and the matching USDD and ECX native
verifier archives. A source checkout alone does not supply those archives.

## 2. Configure

You need a synced, compatible Alpha parent node and enforcer.
Complete the [parent RPC and enforcer mTLS setup](doc/drivechain-rpc-security.md)
first. Keep RPC private; do not expose either node's RPC port to the internet.

Create a private data directory and an `elements.conf` inside it:

```ini
chain=elements
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
mainchainrpchost=127.0.0.1
mainchainrpcport=18302
mainchainrpccookiefile=/absolute/path/to/parent/.cookie

# Start without automatic block production or bidding.
drivechainl1blocksync=0
```

Replace the cookie path and parent port with your authenticated local endpoint.
For a local credential bridge, use `mainchainrpccredentialfile` instead of
`mainchainrpccookiefile`, as described in the security guide. Add the enforcer
TLS settings from that guide; this minimal excerpt does not replace them.

The defaults are P2P **7066**, RPC **7065**, and chain subdirectory
`elements-v11`. The [frozen network identity](src/elements_drivechain_identity.h)
defines the required Alpha parent checkpoint. Do not reuse another chain's data.

## 3. Run

Replace the build and data paths:

```sh
/absolute/path/to/build/bin/elementsd -datadir=/absolute/path/to/data
```

In another terminal:

```sh
/absolute/path/to/build/bin/elements-cli -datadir=/absolute/path/to/data getblockchaininfo
/absolute/path/to/build/bin/elements-cli -datadir=/absolute/path/to/data getpeerinfo
```

To stop cleanly:

```sh
/absolute/path/to/build/bin/elements-cli -datadir=/absolute/path/to/data stop
```

Only expose P2P if you intend to accept public peers. Running directly from home
can reveal your IP to peers; use an isolated relay/VPN setup if privacy is needed.

## More

- [Deposits and withdrawals](doc/drivechain-peg-operations.md)
- [Verifier requirements](doc/usdd-sp1-verifier-jet.md)
- [Security and qualification limits](doc/security-report-remediation.md)
- [Report a vulnerability](SECURITY.md)
- [MIT license](COPYING)

This is experimental Alphanet software, not a real-money production release.
