# Preconfer bond + realtime receipt observation (experimental)

Follow-up to the user-bond template. The original contract and signature domain
are unchanged. **No consensus, node P2P, live deployment or activation changes.**
This adds a different optional Simplicity program and an opt-in companion relay.
An unmodified Elements node does **not** automatically become a receipt relay.

## Collateral and evidence

`operator::Config` commits the genesis, native fee asset, preconfer public key,
protected outpoint, epoch, amount, acceptance cutoff and refund height. The
preconfer funds a separate output from `Bond::funding_output()`. Funding is a
deployment step; this library neither takes wallet keys nor funds outputs.

`contracts/operator_bond.simf` has only two paths:

- Two valid preconfer promises for **different transaction IDs**, bound to the
  same bond/session, pay its entire collateral to miners as an explicit fee.
  Unlike the user-bond contract, an owner's second signature is not required.
- The preconfer can refund its bond with a transaction signature after the
  absolute `REFUND_HEIGHT`. No early release or alternative Taproot key path.

The contract uses existing standard jets and the same fixed NUMS single-leaf
construction as the user bond. It rejects principal-as-collateral, extra inputs,
pegin/issuance, confidential collateral, partial fees and redirected penalties.
The funding fee asset must independently be authenticated as native ECX.

The new BIP340 signing digest is:

```text
SHA256(SHA256("ECX/PreconfOperatorBond/Promise/v1")
  || genesis[32] || bond_txid[32] || bond_vout[4]
  || SHA256(bond_scriptPubKey)[32]
  || protected_txid[32] || protected_vout[4] || epoch[8]
  || active_until[4] || refund_height[4] || spending_txid[32])
```

Integers are big-endian; hashes inside the digest use internal/consensus byte
order. JSON uses lowercase RPC/display hash hex, `txid:vout` outpoints (without
an `[elements]` prefix), 128-character signature hex, and a **decimal string**
for the u64 epoch. Different signatures for the same txid are duplicates, not
misconduct. RBF replacements, quotes and backup exits must not be signed as
additional promises for the same fixed session. The script proves signed
equivocation, not publication or validity of the two principal transactions.

## Relay profile and persistence

The administrator supplies a version-1 JSON profile with `sessions`, each
containing `bond` and the complete `operator::Config`. At most 128 fixed sessions;
unique bonds and protected outpoints, one genesis/fee asset. No remote caller can
allocate sessions, change parameters or make the server compile arbitrary code.
The profile ID printed at startup is SHA256 of the typed profile's canonical
Rust JSON serialization after sorting sessions by outpoint. Pin this ID through
an authenticated channel; do not trust a profile first supplied by a relay.

This is a bounded fixed-session experiment, not a dynamic global bond registry.
All configured peers must use the identical profile. Profile changes require
new state and explicit wallet revalidation, not silent migration of cursors.

The append-only journal takes an exclusive file lock and fsyncs before publishing
an event/ack. Startup checks its profile, sequence, signatures and conflict
evidence. A torn/corrupt journal fails startup; it is not automatically truncated.
Keep it in a private administrator-owned directory on a filesystem supporting
file locks/fsync. Back it up; neither filesystem rollback nor hardware failure
is solved here. A replaced/missing journal gets a different random stream ID,
which existing clients reject. A fresh client cannot detect a dishonest relay
that presents a deliberately incomplete history.

Only the first two distinct txids per bond are retained: enough to establish
the permanent **conflicted** state and construct its penalty evidence. Further
txids receive `already_conflicted`; they do not evict the original pair or
allocate memory. There is no evidence expiry/automatic journal rotation.

## Persistent WebSocket protocol

First message: `{"type":"subscribe","profile":"<pinned ID>","cursor":null}`.
Reconnect with `cursor: {"stream":"<64 hex>","seq":N}` only when the client still
has all previously verified receipts/conflict state. New processes start at
null and replay the full bounded journal. Never restore a bare cursor alone.

Server messages, in order:

1. `begin {profile, stream, from, through}`: snapshot high-water mark.
2. `event {event: {seq, receipt: {bond, txid, signature}, conflict_with}}`.
3. `caught_up {cursor}` at exactly the high-water mark.
4. Further events immediately, and `heartbeat {cursor}` every three seconds.

Snapshot/high-water/subscription are taken under the publish lock, preventing
the snapshot-to-live race. Sequence gaps, unknown stream IDs and cursors ahead
of the journal return an error, not an empty successful response. Slow writes
time out; lagged consumers disconnect and must replay. Heartbeats carry the
last **sent** sequence, never a newer head whose events have not been sent yet.

After subscribing, a publisher/peer can send `publish {receipt}`. The server
verifies the signature against its allowlist and responds with `published
{seq,status}` (`stored`, `duplicate`, or `already_conflicted`). An acknowledgement
is evidence-storage status, **not** node/mempool/settlement acceptance.
Configured peers use the same persistent stream, relay in both directions,
deduplicate loops, and reconnect with replay. Peer errors are logged by index.

Example invocation after supplying an authenticated test profile:

```sh
cargo build --locked --features relay --bin preconf-relay
target/debug/preconf-relay profile.json receipts.jsonl 127.0.0.1:9430 \
  --peer wss://relay.example/preconf \
  --origin chrome-extension://YOUR_EXTENSION_ID
```

The listener only binds loopback. Remote deployment needs a TLS reverse proxy
with authentication/rate/connection limits. Peer URLs require TLS except numeric
loopback. Browser Origins are allowlisted; absent Origin is allowed for native
clients, so **Origin is not authentication**. Limits: 4 KiB messages/frames,
32 inbound connections, 32 publishes/second/connection, eight peers, bounded
history/queues and ten-second I/O deadlines. Internet DoS resistance is not claimed.

## Wallet reference client

`client/monitor.mjs` is browser-compatible, dependency-free transport/state code.
It opens persistent subscriptions to 2–8 configured relays, validates replay
and heartbeats, detects cross-relay conflicts even when neither flags its local
receipt, and retains conflict evidence across reconnects. It never credits a
balance, signs or broadcasts. A required `verifyReceipt` callback must perform
real BIP340 verification against the wallet's authenticated operator profile
(equivalent to Rust `ValidatedProfile::verify`); there is no permissive default.

```js
const monitor = new ReceiptMonitor({
  profile: authenticatedProfileId,
  bonds: authenticatedBondOutpoints,
  relays: independentlyOperatedRelayUrls,
  verifyReceipt: receipt => walletCrypto.verifyOperatorReceipt(receipt),
});
monitor.addEventListener('change', () => updateMonitoringStatus(monitor.health()));
monitor.start();
// Check monitor.observation(bond, txid) again immediately before any decision.
```

`monitoringReady` means all configured subscriptions are synchronized and fresh,
with no verification work pending. It is false on disconnect, stale heartbeat,
queue overflow, malformed messages, invalid signatures or sequence/profile gaps.
Protocol violations require explicit revalidation; ordinary disconnects retry.
Async verification completed after disconnect cannot advance the saved cursor.
Health also checks elapsed time when queried, including after browser suspension.
`observedEverywhere` and `conflicted` describe observations only. Distinct URLs do
not prove independent operators. Browser background execution can stop; use an
independently deployed watcher if ongoing monitoring is required while closed.

## Required integration and risks (not implemented here)

- A signing service must validate the **actual transaction**, its protected
  input, owner authorization, assets, destinations and fee limits before signing
  this domain. `check_authorized_transaction` can supply the trusted-node check.
- Wallets independently verify the deployed Simplicity enforcement, chain and
  fee asset, confirmed canonical bond output/script/amount, unspent principal and
  collateral, epoch, cutoff/challenge window and reorg state. Relays deliberately
  retain valid evidence even if expired or already spent; they are not funding
  or chain-validity oracles. Stop fast acceptance when those checks are unavailable.
- Receiver policy still needs an observation interval, exposure limits and
  settlement/recovery rules. Waiting a few seconds and seeing no conflict does
  **not** rule out withholding, eclipse attacks, partitions or relay collusion.
- Burning a bond does not compensate victims, choose a rightful recipient or
  cap the value of hidden conflicting promises. No economic finality guarantee.
- This bond is fixed to one protected output. It does not implement safe repeated
  off-chain transfers, pooled collateral accounting, dynamic signer committees,
  latest-recipient exits, fee-bumping policy or DEX settlement. The inherited
  absolute refund deadline remains; the proposed two-stage exit is not implemented.
- There is no native Elements P2P/RPC integration, browser crypto/WASM binding,
  production wallet integration, automatic slashing broadcaster, live service
  deployment, consensus change or security-audit claim in this contribution.

See [TESTING.md](TESTING.md) for commands and verified coverage.
