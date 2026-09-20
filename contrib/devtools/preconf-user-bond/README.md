# Elements+ double-authorization collateral template

An **experimental Simplicity covenant**, implementing JK's proposed double-spend
penalty using **separate user collateral**, paid entirely to miners as fees.
The frozen matcher remains a co-signer. This is a reviewable building block,
**not a complete preconfirmation network, statechain, DEX, or production wallet**.

The library never broadcasts, activates a fork, reads wallet keys, or changes
the running dashboard. Authorization validation optionally calls a trusted,
caller-configured `elements-cli testmempoolaccept` (read-only). The functional
test broadcasts only to its disposable regtest node. All examples use public
deterministic test keys; `vectors` uses an invented genesis and asset.
**Do not fund the example addresses.**

The separate [operator-bond and realtime relay follow-up](OPERATOR-RELAY.md)
adds **preconfer-funded** collateral, a persistent WebSocket receipt pool/peer
relay, and a browser monitoring reference client. It does not reinterpret this
original user-bond contract or change the node's consensus/P2P behavior.

## What is implemented

- A readable [SimplicityHL covenant](contracts/user_bond.simf), compiled to actual
  Simplicity, not a host-language boolean pretending to be a covenant.
- A NUMS-internal-key Taproot output with exactly one Simplicity leaf; no known
  private key or alternate script branch can bypass the collateral lock.
- A penalty witness with two distinct transfer authorizations for the same
  protected output. **Both the owner and matcher must sign both statements.**
  The proof is of conflicting authorizations, not two transactions both being
  mined; ordinary UTXO consensus would not allow the latter.
- Network, collateral-outpoint, covenant, protected-outpoint, epoch and deadline
  binding. A signature pair cannot slash an unrelated bond.
- A one-input/one-output penalty transaction: the **entire separate bond** goes
  to an explicit fee output in its original asset. No receiver principal,
  claimant payout, or change. Initial collateral is explicit native ECX only;
  the deployment must independently verify the native fee-asset identity.
- Owner+matcher release and owner-only recovery **after the same absolute
  deadline**. No unrestricted matcher early-release bypass.
- Rust construction/serialization helpers, adversarial tests, and a native
  interpreter harness against the unmodified, pinned Elements+ source.
- Typed SimplicityHL arguments/witnesses, without a JSON/text parsing roundtrip.
- Authorization transaction validity delegated to the node, plus a full-node
  regtest using the repository's existing functional framework and MiniWallet.

## Run locally

Requirements: Rust 1.89+, a C compiler (also used by Rust dependencies), and Node
24 for the fork-interpreter runner. Compiler/dependency versions are pinned in
`Cargo.toml` and `Cargo.lock`.

```sh
cd contrib/devtools/preconf-user-bond
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run --locked --quiet --example vectors
```

The last command prints synthetic signed transaction fixtures as JSON. It does
not write a wallet or send anything.

To test the exact same compiled programs with JK's interpreter:

```sh
node scripts/check-fork.mjs /path/to/liquid-drivechain-signet-adaptation
```

The checkout must contain baseline
`4041a8ba5d9c0870dbe22c188bce28410c10348a` and have the exact same tracked
`src/simplicity` tree, with no local modifications there. This PR's checkout
qualifies: from the tool directory, pass `../../..` as the node path.
The runner builds in this crate's ignored `target/fork-vm`,
not in the node checkout. It compiles the real C interpreter and standard jets,
without external-verifier stubs. Optional ECX/USDD proof-verifier support is not
enabled and is not used by these programs. The harness applies the node's
actual witness-size-based execution budget, not an unlimited test budget.

See [PROTOCOL.md](PROTOCOL.md) for spending rules, trust assumptions, consensus
impact and integration gates. See [TESTING.md](TESTING.md) for verified results
and the precise limits of those tests.

## What JK needs to review

1. The intentionally narrow, fixed-session certificate semantics and format.
   Different replacement transaction IDs count as conflicting authorizations;
   ordinary RBF, backup exits and quotes must not use this signing domain.
2. The real frozen matcher **public key/epoch and signing service**, authenticated
   network profile, and fee asset. These are parameters, not guessed live values.
   Existing matcher receipts are not silently treated as this new format.
3. The acceptance cutoff/challenge duration and integration into the actual
   protected-principal ownership/exit protocol. Ten blocks in fixtures is **only
   test data**, not a safe production recommendation.

**Consensus changes in this prototype: none.** The reviewed source already
executes this standard Simplicity program. Deployment on a live validator set
still needs full-node/regtest qualification and activation-status verification.
Any future custom jets, activation changes or principal-state rules must be
reviewed separately and explicitly documented.

## Sources

- [JK's pinned node](https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation/tree/4041a8ba5d9c0870dbe22c188bce28410c10348a)
- [SimplicityHL compiler](https://github.com/BlockstreamResearch/SimplicityHL)
- [Simplicity execution semantics and implementation](https://github.com/BlockstreamResearch/simplicity)
