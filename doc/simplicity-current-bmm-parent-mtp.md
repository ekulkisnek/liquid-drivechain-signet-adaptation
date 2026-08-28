# `current_bmm_parent_mtp` Simplicity jet

## Consensus contract

`current_bmm_parent_mtp : 1 -> Maybe Word64` exposes the median-time-past of
the Bitcoin parent chain authenticated for the block being validated. `None`
means that no authenticated BIP301 block context was supplied. The value is
not wall-clock time, sidechain MTP, or an unchecked mainchain RPC result.

The Elements consensus path is:

1. `ConnectBlock` obtains a `DrivechainBmmBlockContext` and accepts its parent
   MTP only after the BIP301 context is valid (or receives the equivalent
   already-authenticated candidate/finalized context).
2. The value is copied into `PrecomputedTransactionData::m_bmm_parent_mtp`.
3. `CheckSimplicity` copies it into `rawElementsBlockEnv`; the Simplicity C
   boundary copies it into `txEnv`.
4. The environmental jet returns `Some(mtp)`. Context-free and current mempool
   evaluation use `None`.

The full-script cache key commits to a presence byte followed by the MTP as
eight big-endian bytes. A result evaluated with `None` therefore cannot be
reused for `Some(0)`, and results for different MTP values cannot alias.

The public C execution API can be called by non-consensus embedders with an
arbitrary `rawElementsBlockEnv`; its caller remains responsible for
authentication. The node's consensus caller only supplies the value through
the BIP301 validation path above.

## Fixed generated identity

- Source type: `ONE`
- Target type: `S TWO^64` (`Maybe Word64`)
- Elements transaction-catalogue item: `51`
- `putJetBit` catalogue payload: `11110000111000110011` (20 bits)
- Complete serialized `Jet` node: `111110000111000110011` (21 bits)
- One-node, no-witness program including DAG length: bytes `7c38cc` (the final
  two bits are canonical zero padding)
- CMR: `12dc3d4f22466873daaf83b10e1cfa1ea551e23ae7d0fbd6d9da64ce7e89a3e2`
- Cost: `108` milli-weight units

The cost was generated from the pinned Haskell cost entry. Its raw benchmark
value is a conservative fixed proxy (`60.0`), not an empirical benchmark. It
must be reviewed as a consensus parameter before genesis.

## Generator provenance

The authoritative source patch is
`contrib/devtools/simplicity-current-bmm-parent-mtp-d190505.patch`. It applies
to BlockstreamResearch/Simplicity commit
`d190505509f4c04b1b9193c6739515f9faa18aac`; the patch SHA-256 is
`7ec8a371a63d001cf6952f80b1a4d8ed1eabe06c391559c4b6bc898f378dca26`.
It contains the coordinated Haskell primitive/model, catalogue, serialization,
cost, C FFI, C implementation, tests, and generated artifacts.

Reproduce the generated files from a clean checkout as follows (use an
out-of-tree build directory in production):

```sh
git checkout d190505509f4c04b1b9193c6739515f9faa18aac
git apply /path/to/elements/contrib/devtools/simplicity-current-bmm-parent-mtp-d190505.patch
cabal build GenDecodeJet GenPrimitive testsuite
mkdir generated-bmm-parent-mtp
cd generated-bmm-parent-mtp
"$(cabal list-bin GenDecodeJet --project-dir=..)"
"$(cabal list-bin GenPrimitive --project-dir=..)" --elements
```

The official generators change only these generated C artifacts:

- `decodeElementsJets.inc`
- `primitiveEnumJet.inc`
- `primitiveJetNode.inc`

`primitiveEnumTy.inc` and `primitiveInitTy.inc` regenerate byte-for-byte
unchanged because the existing catalogue already contains `Maybe Word64`.
The vendored generated-file SHA-256 values are:

```text
14bbeaa7f15d5fa56e5c9b6f7cb1dc5a8ab5dc27e9f507b1cd8c4c595c45c51f  decodeElementsJets.inc
f3adf6d52b02a49034e8db4a07ca19e1e61f977bcb92b48225828592c8a975d6  primitiveEnumJet.inc
9fa82768f31faac67270e3751b868bf7626f64969df6bedd9bbf4aa288513b5e  primitiveJetNode.inc
```

## Verification performed

- Haskell primitive specification versus model: 100 QuickCheck cases.
- Haskell primitive specification versus C FFI: 100 QuickCheck cases.
- Upstream regression suite: 479 passing checks, including the catalogue count
  and fixed CMR.
- Vendored C suite: deterministic `None`, `Some(0)`, and
  `Some(UINT64_MAX)` behavior, plus exact encoding/CMR/cost decoding.

This jet does not verify SP1 proofs and must not be treated as proof acceptance.
