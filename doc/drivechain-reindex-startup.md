# Native drivechain reindex startup

## Failure and scope

`ReconcileDrivechainAnchors` shares one two-second parent-validation budget
while holding consensus locks. When reindex starts with an empty active chain,
candidate ancestry can contain every persisted anchor. Repeating authenticated
parent RPC checks for all of them can exhaust that shared budget and make
startup fail with `authenticated parent state unavailable during startup anchor
reconciliation`. Warming the generic parent replay state does not eliminate
those individual anchor checks.

The fix moves bulk authentication of persisted startup anchors outside
`cs_main` and mempool locks. It does not extend the locked validation budget or
change any consensus policy, including peg-in confirmation or withdrawal rules.

## Authentication boundaries

The startup-only snapshot stores positive `ACTIVE` results keyed by the complete
serialized anchor: version, P/Q block hashes, P/Q chainwork, P/Q heights, and
parent median time past. Hash-indexed lookups also compare the exact serialized
bytes. The snapshot is bound to the configured sidechain slot, an exact parent
tip hash, and a nonzero authenticated replay epoch.

Bulk warming has a 120-second aggregate deadline, limits RPC timeouts to the
remaining allowance, and checks interruption. It publishes no partial result
on unavailable, stale, or interrupted authentication. A final fresh tip/epoch
check brackets publication. `ORPHANED` results are never retained as rollback
authority; those mismatches still require fresh checks during reconciliation.

Before each cached reconciliation pass, a fresh RPC tip check and epoch/slot
check must pass. Every local lookup, including repeated ancestry lookups,
checks the epoch and the shared two-second deadline. Even a benign parent-tip
extension requires refreshing the set outside consensus locks. The preliminary
reuse probe has its own two-second budget, also outside those locks. Once the
startup backlog drains, the snapshot is discarded; normal P2P operation does
not start bulk authentication of arbitrary candidate collections.

This snapshot is not the generic parent replay or deposit-context cache.
`ConnectTip` authentication, BMM validation, and each child's exact Q-bound
deposit checks remain unchanged. Missing anchors and unavailable parent state
remain fail-closed, not consensus-invalid evidence.

## Tests

The following cases belong to `validation_tests`:

- `drivechain_anchor_snapshot_exact_identity_and_generation`: all serialized
  fields, exact tip, slot, and replay epoch.
- `drivechain_anchor_snapshot_bulk_positive_only`: 128 exact positive entries,
  duplicate stability, malformed anchors, and rejection of negative results.
- `drivechain_anchor_snapshot_failed_warm_clears_output`: output clearing on
  early budget, slot, and interruption failures.
- `drivechain_anchor_snapshot_does_not_outlive_locked_budget`: expiry and
  nested budgets that cannot reset the shared deadline.

From the repository root, with an already configured native build (including
its required verifier dependencies), use the appropriate build-directory path:

```sh
cmake --build build --target test_elements
build/bin/test_elements --run_test='validation_tests/drivechain_anchor_snapshot_*' --log_level=test_suite
ctest --test-dir build --output-on-failure -R '^validation_tests$'
```

## Qualification and remaining limits

Local macOS ARM64 qualification on 2026-09-03 used a wallet-free cold copy of
the existing Alpha chain, both real verifier archives, disabled peer networking,
and `-reindex-chainstate=1 -checkblocks=0 -checklevel=4`. It authenticated all
62 persisted anchors outside consensus locks, rebuilt from an empty active
chain to the unchanged height-62 tip, and passed `verifychain 4 0` for all
62 blocks / 67 transactions. Genesis, pegged asset, and the existing
100-confirmation peg-in rule were unchanged. A separate fresh cold-copy run
with deliberately incorrect parent credentials rejected startup. The four
new focused tests passed all 574 assertions.

The full unit-suite invocation exited successfully: 820 cases passed all
19,772,094 assertions. One additional case, `script_assets_test`, reported a
warning and skipped its external vectors because `DIR_UNIT_TEST_DATA` was
unset. That optional vector corpus is not included in this qualification.

This is isolated replay evidence, not a live installation or a general release
qualification. The running node, its wallets, and its data were not replaced.
Platform dependencies in this build include newer local Homebrew libraries;
the executable is not a portable macOS release.

The unit tests cover early failure cleanup and pure snapshot boundaries. They
do not inject a parent reorg or transport failure partway through a successful
multi-RPC warm. An invalid-credential startup check supplies separate
fail-closed evidence, not coverage of those mid-warm races.

Deep orphaned-parent reorgs still require fresh locked checks and can exhaust
the existing budget. Very large ancestry sets, repeated parent-tip changes,
or unavailable parent RPC can also prevent completion. These conditions fail
closed; the snapshot is not permission to bypass authentication or deadlines.
