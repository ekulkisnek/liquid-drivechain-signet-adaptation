# Reproducible ECX jet catalogue

This directory publishes the 24-interface typed ECX catalogue, its exact
commitments, encodings and fixed costs, and additive C bindings. It replaces the
six catalogue hard-error includes. It is **not** a production activation profile
or authorization to deploy a node, spend funds, broadcast, or start paid proving.

Normal builds still reject the ECX Elements branch-5 encodings. The generated
decoder is opt-in through `ECX_SIMPLICITY_CATALOGUE_FROZEN`; that pre-existing
macro name refers to fixed decoder bindings, not a claim that the live Alpha
activation has been approved. Existing native branch-4 entries are preserved.
The separate production activation-profile guard remains in place.

## Costs and identities

The selected consensus policy costs are:

| Entries | Count | Cost per entry (milliweight) |
| --- | ---: | ---: |
| Required context/identity projections and input-role assertions | 19 | 1,000 |
| SP1 Groth16 verification variants (generic, V3, V4, V5 activation, V6 successor) | 5 | 1,000,000,000 |

These exact numbers are policy choices, not measured timings. Changing a cost
changes the jet commitment and therefore requires re-deriving every downstream
program that uses it. `jet-identities.tsv` and `registry.json` contain the exact
CMR, typed IMR, AMR, source/target type roots, specification roots and encodings
for all 24 entries. The Haskell full encoding includes one outer jet bit that
the C/Rust jet decoder has already consumed.

Historical WSL diagnostic records are preserved byte-for-byte in `evidence/`:

- `sp1-smoke-cost-candidate-20260827.json` records the generic/V3/V4/V5 smoke
  measurements and their derived candidate costs. It does not measure V6 or
  attest to a reviewed production benchmark.
- `current-bmm-wsl-diagnostic-20260828.json` records the current-BMM diagnostic
  and CheckSig baseline. Its derived candidate cost is not the selected policy
  cost and is not a production calibration for the other context jets.

No diagnostic is relabelled as a measurement of these fixed policy values.
`activation_authorized` and `production_benchmark_reviewed` are false.

## Offline checks

From the repository root, with Python 3 and a C11 compiler:

```sh
python3 contrib/devtools/ecx-catalogue/generate.py
PYTHONDONTWRITEBYTECODE=1 python3 contrib/devtools/ecx-catalogue/test_generate.py
sh contrib/devtools/ecx-catalogue/run_c_tests.sh
```

The generator defaults to checking exact bytes; it writes the listed generated
outputs only when explicitly passed `--write`. Its Python implementation
independently recomputes the typed identities with Simplicity's SHA-256
compression/tag/type/jet constructions instead of trusting copied hex strings.

The C runner creates a fresh temporary build, tests both the default-disabled
and opt-in decoders, and runs the existing native C regression suite against
the opt-in decoder. Tests cover all 24 paths, proper-prefix truncations,
unassigned paths, type roots, function bindings, exact policy budgets,
commitments, environment projections and fail-closed behavior. The node's
`ecx_exchange_state_tests` also exercise the actual V6 frame adapter and strict
annex parser with a recording test callback. That callback is not cryptographic
proof verification and is never linked into the node runtime.

## Independent Haskell reproduction

Install `ghc-9.6.7` and Cabal on `PATH` (tested with Cabal 3.14.2.0), plus Git,
Python 3 and the system C/Haskell build prerequisites. Initialize Cabal's
package index if needed. The public `catalogue.project` selects
`with-compiler: ghc-9.6.7`; it has no absolute compiler or local-volume path.
Its companion freeze file pins the dependency solution and index state.

```sh
sh contrib/devtools/ecx-catalogue/reproduce.sh
```

This creates a new directory, checks out upstream Simplicity commit
`e3b670103101108faa238df012676ff5d8b77cf9`, verifies every overlay preimage and the
typed candidate hash, applies the vendored overlay, and builds the actual
Haskell C/Rust generators. It then derives the typed identities, runs the
44 reference-semantics checks, compares the TSV byte-for-byte, and independently
checks all 24 generated C/Rust entries. It never replaces this repository's
native catalogue with the upstream generator's larger catalogue.

The script retains its artifacts for inspection. Set `TMPDIR` to an existing
directory on a volume with adequate space. `ECX_CABAL` can select the Cabal
executable, and `ECX_CABAL_CONFIG` can select a local configuration/cache. Neither
is stored in published consensus inputs. Network access is needed for the
pinned upstream checkout and any uncached dependencies. Compiler toolchain
checks establish catalogue equality, not bit-reproducible node binaries.

## Remaining live gates

Publishing these bindings does not fill the production activation-profile
placeholder, attest to production cost review, or make `proofReady` true. A live
Alpha deployment still needs independently validated node capability and
chain/parent context; the exact production configuration and program identities;
confirmed funding and unbroadcast deployment/activation manifests; and fresh
witness/public values that pass the canonical preflight and execute-only gates.
Private regtest proof artifacts must not be substituted for those inputs.
