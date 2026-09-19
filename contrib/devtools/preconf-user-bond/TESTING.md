# Test scope

## Recorded local run

- `cargo test --locked`: **22 passed**.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Pinned-fork C interpreter: **15 checks passed**, including all three valid
  spending paths and 12 negative cases.
- Synthetic fixture CMR:
  `397aa6803ceb30cc12b2853824ba0a9df863731f0ef42045faf47ecf227499ac`.
  This is **not** a deployed contract identity.
- Penalty: 1,011 program bytes, 321 witness bytes, 1,507 serialized transaction
  bytes; accepted under the node-derived **1,456 WU execution budget**.
  Execution budget is not transaction weight or a fee-rate recommendation.

Changing the contract, compiler or immutable parameters changes its identity;
the test fixture pins the CMR to make such changes explicit.

The tests run real BIP340 signatures over deterministic, public test keys.
They compile the `.simf` source, construct Taproot outputs and Elements
transactions, and execute the resulting Simplicity with transaction environments.
They do not mock the covenant decision.

## Rust/interpreter checks

`cargo test --locked` exercises:

- Genuine conflicting owner+matcher authorizations, either evidence order.
- Duplicate transaction IDs with distinct signature randomness (not slashable).
- Each missing/corrupt/wrong-party signature; matcher trying to frame an owner.
- Changed transaction ID after signing.
- Replay across bond txids/vouts, networks, protected txids/vouts, epochs,
  deadlines, owners and matchers.
- Diversion to a spendable output, partial penalty, excess fee amount, wrong
  asset, extra input/output and missing output.
- Wrong/absent/confidential collateral amounts or assets.
- Attempts to consume principal instead of separate collateral or hide issuance.
- Owner-only and cooperative recovery; early recovery even with both signatures;
  timestamp and disabled-locktime bypasses; modified signed payout/fee/sequence.
- Late penalty while collateral is unspent.
- Malformed configuration/witness and structural certificate-subject validation.
- Taproot commitment, NUMS internal key, single leaf and witness serialization.

## Pinned Elements+ C interpreter

`node scripts/check-fork.mjs /path/to/node` builds the pinned node's actual
`src/simplicity` C sources and executes serialized programs/witnesses produced
by this crate. It checks valid penalty/cooperative/unilateral programs plus
corrupted evidence, network/bond replay, diverted/partial/wrong-asset fees,
extra inputs/outputs, early release and disabled locktime.

This includes native decoding, type inference, CMR checking, execution and the
real witness-size-based budget. No generated ECX/SP1 jet or proof-verifier
dependency is required by this contract. The optional verifier feature is not
enabled; no success-returning verifier stub is used.

The C fixture driver deliberately supports only explicit, no-annex test
transactions. Mutated negative fixtures are interpreter tests, not claims that
each malformed transaction would reach script evaluation in a full node.

## Not tested / not claimed

- Full node mempool/block acceptance, actual-height finality, UTXO existence or
  confirmation, complete fee/asset conservation and live validator activation.
- Actual frozen matcher service/profile integration or live signing.
- Statechain ownership transfer, recipient exit, full DEX or wallet flows.
- Economic security, collateral sufficiency, withholding/censorship, reorgs or
  adversarial network scheduling.
- An independent audit or production readiness.

The isolated native interpreter tests establish considerably more than a mocked
unit test, but they do not close the full-node/regtest integration gate listed
in PROTOCOL.md.
