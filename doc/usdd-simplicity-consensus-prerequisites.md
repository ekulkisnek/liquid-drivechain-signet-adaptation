# USDD Simplicity consensus prerequisites

## Current safe state

Elements passes the BIP301-authenticated parent median-time-past value from
block validation into `rawElementsBlockEnv` and then into the Simplicity
`txEnv`.  The value is unavailable when the consensus caller has not
authenticated the parent context.

The generated `current_bmm_parent_mtp : ONE |- S TWO^64` environmental jet now
exposes that optional context. It is transaction-catalogue decoder item `51`,
has CMR
`12dc3d4f22466873daaf83b10e1cfa1ea551e23ae7d0fbd6d9da64ce7e89a3e2`,
and costs `108` milli-weight units. Context-free and current mempool execution
return `None`; consensus block execution returns `Some(parent_mtp)` only after
the BIP301 authentication path succeeds. The full-script cache key also binds
the optional value.

The opaque `elementsTransaction` also owns an exact copy of each Taproot annex
that meets all of these conditions:

- it includes the `0x50` Taproot annex tag;
- it exactly matches the tag-stripped annex body used by the released annex
  hash jets; and
- its total size is no greater than 512 KiB.

The public `simplicity_elements_getInputFullAnnex` accessor exposes that
read-only copy for testing and future generated environmental-jet integration.
Missing, inconsistent, and oversized optional copies do not alter existing
annex hashing or transaction validity.

Neither facility verifies an SP1 proof or authorizes asset issuance.  The USDD
annex consensus gate remains fail-closed with `VERIFIER_UNAVAILABLE`.

## Generator provenance for the parent-MTP jet

The vendored Simplicity library contains generated C artifacts, including:

- `src/simplicity/elements/primitiveEnumJet.inc`
- `src/simplicity/elements/primitiveEnumTy.inc`
- `src/simplicity/elements/primitiveInitTy.inc`
- `src/simplicity/elements/primitiveJetNode.inc`
- `src/simplicity/elements/decodeElementsJets.inc`

Those files define consensus-visible jet identities, types, commitment roots,
decoding, and costs. They were not hand-edited. The primitive/model,
catalogue, serialization, C FFI, C implementation, cost entry, and tests were
implemented at BlockstreamResearch/Simplicity revision
`d190505509f4c04b1b9193c6739515f9faa18aac`. The official `GenDecodeJet` and
`GenPrimitive --elements` tools were built with GHC `9.8.4` and Cabal
`3.16.1.0`; their output was then imported mechanically.

The generators changed `decodeElementsJets.inc`, `primitiveEnumJet.inc`, and
`primitiveJetNode.inc`. The generated type files were byte-identical because
`S TWO^64` already existed. The exact upstream patch and generator changes are
tracked as
`contrib/devtools/simplicity-current-bmm-parent-mtp-d190505.patch`; detailed
commands, encodings, and hashes are in
`doc/simplicity-current-bmm-parent-mtp.md`.

Verification completed at the pinned upstream revision:

- 100 QuickCheck cases comparing the Haskell primitive specification with its
  model;
- 100 QuickCheck cases comparing the same specification with the C FFI jet;
- all 479 upstream regression checks, including the new catalogue count and
  fixed CMR; and
- the vendored C suite, including deterministic `None`, `Some(0)`,
  `Some(UINT64_MAX)`, and exact decoder/CMR/cost checks.

## Still missing

- **SP1 verifier jet:** no generated, consensus-pinned raw-compressed-proof
  verifier exists. The annex gate deliberately returns
  `VERIFIER_UNAVAILABLE`; no SP1 proof can authorize minting.
- **Controller:** no compiled singleton program binds one typed public journal
  to that verifier result and enforces the exact issuance and successor state.

V1 does not require a separate full-annex byte jet.  The minimal verifier jet
reads the exact owned annex internally from the authenticated transaction
environment and accepts `(program_id, SHA256(public_values))` as its fixed-size
Simplicity input.  The controller separately hashes its typed public-values
witness and passes that digest to the verifier.  This avoids representing a
variable 512 KiB value in Simplicity or adding an indexed-byte consensus API.
The exact interface and activation requirements are specified in
`doc/usdd-sp1-verifier-jet.md`.

The missing verifier requires coordinated upstream semantics, C FFI,
implementation, type, CMR, decoder, cost, generation, and differential-testing
work. It may not be substituted with a hand-edited generated artifact, host
callback, or parser-only acceptance path.
