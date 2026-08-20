# Deterministic Drivechain BMM Proof

LayerTwoLabs public-signet sidechain blocks after height 2 commit the L1
successor evidence that proves their BIP301 blind-merge-mining commitment was
mined. Block validation is deterministic and does not call Bitcoin RPC, invoke
`grpcurl`, or query an enforcer.

## Activation

The rule is anchored to the immutable public-signet branch:

- Sidechain height 1:
  `942f31cb89241342064af42a0367405eef490061d2ffe259a6f34d4939dee543`
- Sidechain height 2:
  `ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998`

Height 2 must be the exact checkpoint when it follows the height-1 checkpoint.
Every descendant of height 2 must set `BMM_PROOF_HF_MASK` (`1 << 20`) and
include a proof. The extension is rejected outside this branch. Historical
private-signet blocks retain their original encoding.

Height 2 bootstraps the authenticated parent-chain state at LayerTwoLabs L1
height 6400:

- Hash:
  `0000031bb69e844ed1ebd48cc0ab6cee90de29fb98ff7fb439d49b0b19747665`
- Signet challenge:
  `00148835832e28c816b7acd8fdb19772ab2199603a56`
- Sidechain slot: `24`

## Block Commitment

When the version bit is set, the block header serializes a 32-byte
`hashBmmProof` after `hashWithdrawalBundle` and before `nTime`. The block body
serializes the canonical proof bytes after the transaction vector.
`hashBmmProof` is the double-SHA256 hash of those exact bytes.

The final sidechain block ID includes `hashBmmProof`. BIP301 cannot commit that
final ID without creating a hash cycle, so the BMM critical hash is defined as
the same header hash with `hashBmmProof` set to zero. The L1 M8 commitment must
contain this critical hash for slot 24.

## Proof Schema

Schema version 1 contains:

1. A one-byte schema version.
2. The previously authenticated L1 state.
3. One or more consecutive L1 proof entries.

The authenticated state contains the L1 block hash, height, timestamp, compact
difficulty target, difficulty-period start height and timestamp, and the last
11 timestamps needed for median-time-past validation.

Each proof entry contains:

- The canonical serialized L1 coinbase transaction.
- A canonical Bitcoin partial-Merkle proof authenticating exactly that
  coinbase at transaction index 0.

A proof has at most 128 entries and its canonical serialization is limited to
1,000,000 bytes.

## Consensus Verification

For every entry, the node independently verifies:

- Exact canonical transaction and Merkle-proof serialization.
- Coinbase structure and an exact index-0 Merkle match.
- Contiguous linkage from the persisted L1 state.
- Bitcoin compact-target transitions and proof of work.
- Median-time-past using the prior 11 timestamps.
- The LayerTwoLabs signet solution against the fixed challenge.

The last L1 header must be the immediate successor of the L1 parent hash
committed in the sidechain coinbase. Its coinbase must contain exactly one slot
24 M8 commitment, and that commitment must equal the sidechain critical hash.

The resulting L1 state is stored as a deterministic zero-value synthetic UTXO.
Block disconnect restores the proof's previous state. Reindex therefore
reconstructs the same state from block data, and reorgs cannot replay stale
proofs or skip parent headers.

## Construction

The block producer may use Bitcoin RPC and the enforcer while constructing a
candidate:

1. Build a sidechain block with the proof version bit and a zero proof hash.
2. Submit its critical hash as the slot-24 BMM request.
3. Wait for an authentic L1 successor.
4. Fetch the consecutive L1 coinbases and partial-Merkle proofs.
5. Verify the assembled proof locally.
6. Attach the proof, producing the final sidechain block ID.

External services are construction inputs only. Peers, cold reindex, and
level-4 chain verification use the committed block data and persisted state.
If construction data is unavailable or invalid, block production fails closed;
validation of already committed blocks remains available.
