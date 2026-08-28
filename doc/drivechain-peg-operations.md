# Slot-24 drivechain deposits and withdrawals

This build runs the Elements sidechain in BIP300 slot 24. Deposits are accepted
only after the node independently matches the exact mainchain outpoint against
confirmed, authenticated enforcer data. Withdrawals use a two-phase workflow so
the M6 proposal is built from the block that actually confirmed the sidechain
spend.

## Transport and credentials

Elements never sends parent-chain HTTP Basic credentials to a remote host.
`-mainchainrpchost` must be `localhost` or a numeric loopback address. When the
Bitcoin node is remote, terminate an authenticated TLS tunnel on loopback and
point Elements at that local port.

All enforcer calls use mutual TLS through `grpcurl`. The default endpoint is
`127.0.0.1:55051`; this should be a local mTLS proxy if the enforcer itself only
offers plaintext gRPC. The proxy must authenticate both the enforcer side and
the Elements client. Place credentials under the network data directory by
default:

```text
enforcer-tls/ca.pem
enforcer-tls/elements-client.pem
enforcer-tls/elements-client-key.pem
```

On POSIX systems the credential directory must be owned by the Elements user
and not group/other-writable. The private key must be a regular, non-symlink
file owned by that user with no group or other access:

```sh
chmod 700 /path/to/elements-data/liquid-signet/enforcer-tls
chmod 600 /path/to/elements-data/liquid-signet/enforcer-tls/*.pem
```

Use an explicit configuration such as:

```ini
chain=liquid-signet
validatepegin=1

# Parent Bitcoin RPC. Keep this endpoint on loopback.
mainchainrpchost=127.0.0.1
mainchainrpcport=38332
mainchainrpccookiefile=/path/to/bitcoin/signet/.cookie

# Authenticated enforcer endpoint.
drivechainbmmgrpcaddr=127.0.0.1:55051
drivechainbmmgrpcurl=/absolute/path/to/grpcurl
drivechainbmmgrpcca=/path/to/enforcer-tls/ca.pem
drivechainbmmgrpccert=/path/to/enforcer-tls/elements-client.pem
drivechainbmmgrpckey=/path/to/enforcer-tls/elements-client-key.pem
# Set this only when the certificate name differs from the endpoint address.
# drivechainbmmgrpcauthority=enforcer.internal

drivechainbmmslot=24
drivechainsidechainslot=24
drivechainpegoutmainfee=10000
drivechainsidechainnetwork=liquid-signet
drivechainmainchainnetwork=signet
drivechainmainchainsignetchallenge=00148835832e28c816b7acd8fdb19772ab2199603a56
```

Do not point `drivechainbmmgrpcaddr` at an unauthenticated plaintext port. The
legacy `drivechainpegoutenforcer` option is only an alias; if both endpoint
options are set, they must be identical.

## Deposit

Create or load an Elements wallet and obtain an address that the selected wallet
can spend. After the slot-24 deposit is confirmed in canonical L1/enforcer data,
import the exact outpoint:

```sh
elements-cli -chain=liquid-signet -rpcwallet=<wallet> \
  importdrivechaindeposit \
  "<mainchain-txid>" "<elements-address>" <value-sats> <sidechain-fee-sats> <mainchain-vout>
```

The node verifies the mainchain network and signet challenge, active slot-24
identity, exact txid and vout, destination, value, confirmation, and CTIP state.
It also prevents replay across restarts. Omitting `mainchain-vout` is allowed
only when authenticated slot data contains one unambiguous txid/address/value
match. Supplying it explicitly is preferred for operator auditability.

The returned `txid` is the sidechain transaction. `already_imported` makes
retries idempotent. If the wallet already knows an unconfirmed import, the RPC
rebroadcasts it so mempool eviction or restart cannot strand the credit. A
successful RPC is not a substitute for checking that the transaction confirms
in a strict-BMM-valid sidechain block and remains in the wallet after restart.

## Withdrawal

Only one withdrawal bundle may be active at a time. First create the sidechain
burn transaction:

```sh
WITHDRAWAL_TXID=$(elements-cli -chain=liquid-signet -rpcwallet=<wallet> \
  sendtomainchain "<bitcoin-signet-address>" <amount> false false)
```

Wait until that transaction has at least one active sidechain confirmation.
The confirming block must contain an ECX state root. Then submit its exact,
height-bound M6:

```sh
elements-cli -chain=liquid-signet -rpcwallet=<wallet> \
  submitdrivechainwithdrawal "$WITHDRAWAL_TXID"
```

Before contacting the enforcer, the node writes and fsyncs
`drivechain_withdrawal.dat` in the network data directory. It stores the exact
M6 bytes and verifies that their transaction identity matches the journal.
After a crash or enforcer outage, inspect the durable state with:

```sh
elements-cli -chain=liquid-signet drivechainrecoverwithdrawal
```

If the enforcer reports the bundle as failed or missing and the rejection cause
has been corrected, resubmit the identical M6 bytes with:

```sh
elements-cli -chain=liquid-signet drivechainrecoverwithdrawal true
```

Recovery never rebuilds a new proposal from a later tip. A settled journal is
terminal and cannot be resubmitted. It is retained as a restart-safe tombstone
until the next confirmed withdrawal safely replaces it; this prevents the old
bundle hash in the sidechain tip from becoming active again during the interval
before another sidechain block is produced. Corrupt journal state fails closed
and must be investigated rather than deleted merely to unblock another
withdrawal.

## Readiness checks

Before moving test funds, verify all of the following:

1. Bitcoin, the enforcer, BMM producer, and Elements agree on the intended
   LayerTwoLabs signet and slot 24.
2. Parent RPC is reachable only through loopback and the cookie is readable by
   the Elements process user.
3. The mTLS endpoint rejects clients without the configured certificate.
4. A deposit remains spendable after Elements and enforcer restarts.
5. A withdrawal sidechain transaction confirms before M6 submission.
6. `drivechainrecoverwithdrawal` reports the same M6 ID before and after a
   restart, and eventually reports the authentic L1 success event.
7. Wallet, Elements UTXO state, enforcer CTIP/event state, and the intended L1
   payout address agree on values and transaction identities.
