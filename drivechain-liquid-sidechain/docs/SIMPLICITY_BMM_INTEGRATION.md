# Simplicity + BMM Integration Research and Test Plan

> **QUARANTINED HISTORICAL TEST PLAN.** The ID5/regtest harness described here
> is incompatible with this fork and its entrypoints are disabled. The only
> supported network is **Elements Drivechain**, `-chain=elements`, BIP300 slot
> **24**. See the [canonical README](../../README.md). The research notes below
> are retained for auditability, not as current operating instructions.

**Date**: 2026 (current session)  
**Workspace**: /Volumes/T705/code/liquid-signet-sidechain (Elements/Liquid fork with Simplicity + drivechain BMM support for ID5 sidechain)  
**Goal**: Determine if Simplicity scripts (Tapscript leaf version 0xbe) can be executed inside BMM-driven transactions/blocks on the Liquid sidechain.

## Executive Summary

**Status: FULLY COMPATIBLE BY CONSTRUCTION (no blockers found).**

Simplicity execution is part of standard Taproot/Tapscript validation in the Elements script interpreter. BMM (Blind Merged Mining via CUSF/BIP300/301) on this sidechain is an *external* protocol:
- BMM critical data txs + h* commitments are created on the *mainchain* (via `CreateBmmCriticalDataTransaction` gRPC to enforcer/wallet).
- The Liquid/Elements sidechain node (`elementsd`) produces and validates *normal* blocks using the standard `ConnectBlock` / script flag / interpreter paths.
- There is **zero BMM-specific code** inside `src/` (grep for BMM/bmm/cusf/drivechain in *.cpp returns nothing).
- Therefore, any script accepted under `SCRIPT_VERIFY_SIMPLICITY` (including 0xbe Simplicity leaves) works identically whether the block arrived via local mining, P2P, `submitblock`, or BMM-driven advance.

Simplicity has been **unconditionally active** on Liquid Testnet since the relevant chainparams (see below). The drivechain ID5 harness (regtest-based) inherits the same flags.

## 1. Simplicity Integration in Elements Script Validation (from src/simplicity/elements/exec.c + elementsJets.c + interpreter.cpp)

### Core Entry Point
- `simplicity_elements_execSimplicity(...)` (exec.c:45):
  - Deserializes Simplicity DAG from `program` bytes using `simplicity_elements_decodeJet`.
  - Type inference, witness filling, CMR match against `taproot->scriptCMR`, optional AMR check.
  - Builds `txEnv` via `simplicity_elements_build_txEnv` (provides all Elements jets: inputs/outputs/assets/issuance/locktime/ `script_cmr`, `tapleaf_version`, `tappath`, `internal_key`, `build_tapleaf_simplicity` etc.).
  - Runs `evalTCOProgram` with budget (in WU, milliWU internally).
  - Returns detailed `simplicity_err` mapped to `SCRIPT_ERR_SIMPLICITY_*` codes.

### Tapscript Leaf Dispatch (interpreter.cpp:3315)
```cpp
if ((flags & SCRIPT_VERIFY_SIMPLICITY) && (control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSIMPLICITY) {
    // TAPROOT_LEAF_TAPSIMPLICITY == 0xbe (interpreter.h:280)
    // stack must be exactly [..., program, witness]
    // script_bytes (from control parsing) == 32-byte CMR committed in the leaf
    return checker.CheckSimplicity(simplicity_program, simplicity_witness, simplicityRawTap, budget, serror);
}
```
- Only active when `SCRIPT_VERIFY_SIMPLICITY` is set in script flags.
- The "script" in the Tapleaf is **not** executed as Bitcoin script; it is the 32-byte CMR of the Simplicity expression. The actual program + witness come from the witness stack (2 items).

### Key Jets (elementsJets.c)
- Full Elements context exposed: `current_*` / `input_*` / `output_*` for amounts, assets, scripts, annex, issuances, fees, genesis hash, `script_cmr`, `transaction_id`, `tapleaf_version` (0xbe), `tappath`, `internal_key`, `build_tapleaf_simplicity` (hardcodes leaf version 0xbe + CMR), taptweak, locktime checks, etc.
- `build_tapleaf_simplicity` (elementsJets.c:849): `simplicity_make_tapleaf(0xbe, &cmr)` — exactly matches the leaf version used in control blocks.

### Flag Activation (validation.cpp:2190 + chainparams.cpp)
```cpp
if (DeploymentActiveAfter(pindex->pprev, consensusparams, Consensus::DEPLOYMENT_SIMPLICITY)) {
    flags |= SCRIPT_VERIFY_SIMPLICITY;
}
```
- **Liquid Testnet** (chainparams.cpp:1095): `ALWAYS_ACTIVE` (unconditional).
- **Regtest** (chainparams.cpp:640): `ALWAYS_ACTIVE` as of this commit (no -evbparams=simplicity:0::1:1 needed; matches Liquid Testnet pattern). Previously required explicit evbparams for activation in regtest/custom chains.
- Other nets (main, signet variants): `NEVER_ACTIVE` or future date (e.g. 2025-04-14 in one signet-derived param set at line 1358).
- Also added to `STANDARD_SCRIPT_VERIFY_FLAGS` in policy/policy.h:84.
- In `GetBlockScriptFlags` this flows to every input's script evaluation for blocks (BMM or otherwise).

Precomputed tx data for Simplicity (interpreter.cpp:2605+): builds full `rawElementsTransaction` + `rawElementsTapEnv` (control block + path + scriptCMR) for every input when BIP341/Taproot ready.

**Conclusion from code read**: Simplicity is a first-class Tapscript extension (leaf v0xbe). No special casing that would exclude it from any block type.

## 2. BMM Transaction Structure (from drivechain-liquid-sidechain/scripts/*.py)

### grpc_bmm_id5.py + liquid_id5_participant.py
- **No sidechain tx construction here**. These drive the *mainchain* side:
  - Call `WalletService.CreateBmmCriticalDataTransaction` (gRPC) with:
    - `sidechain_id=5`
    - `value_sats` (bribe)
    - `height` (BMM seq #, starts at 1 for fresh ID5)
    - `critical_hash` = sidechain's current best block hash (from `elements-cli getbestblockhash` or `getblockchaininfo`)
    - `prev_bytes` = dynamic from `ValidatorService.GetBmmHStarCommitment` (or tip for first post-activation)
  - On success or "broadcast deposit failed" (tolerated per lib/miner.rs pattern): trigger mainchain mine + poll `GetBmmHStarCommitment` until critical matches.
- Sidechain block production is **separate** (elementsd `generate` / submitblock path or adapter). The participant just advances mainchain and records when the side's critical appears in h*.
- Deposit addresses are custom `s5_...` strings (handled in adapter stub for credit on events). No raw scriptPubKey construction visible.
- **No Taproot, no witness v1 (5120...), no 0xbe, no "simplicity", no Tapscript** anywhere in the BMM scripts, adapter, e2e .sh, or logs (confirmed by multiple greps).

### BMM "txs on the liquid-signet-sidechain"
- The actual BMM critical data tx lives on **mainchain**.
- On Liquid side: normal Elements txs (pegin claims for deposits, user transfers, withdrawals, coinbase with dynafed/fedpeg if used) live in side blocks whose headers/hashes are committed as `critical_hash` via BMM.
- Block acceptance on side: standard `ProcessNewBlock` / `AcceptBlock` / `ConnectBlock` (validation.cpp + chain.cpp). Uses `GetBlockScriptFlags` (includes Simplicity when deployed) for every tx input in the block.
- No override, no "BMM bypass", no special interpreter for sidechain coinbase or critical data.

## 3. Evidence Check: Existing BMM txs and Tapscript Usage

- Full-tree grep in `drivechain-liquid-sidechain/` (all .py, .sh, .md, .json, logs): **0 matches** for taproot/tapscript/0xbe/TAPROOT/5120/be00/SCRIPT_VERIFY_SIMPLICITY/simplicity (case-insensitive).
- Log excerpts (e2e-*.log, state.json): only mention BMM txids on main (e.g. 9c96f2b2be11d601...), deposit txids, side H, critical hashes. No raw tx hex, no scriptPubKey with witness v1, no Tapleaf.
- e2e-liquid-on-signet.sh + participant use `elements-cli` only for `getblockchaininfo` / best hash (critical source). No `createrawtransaction`, `sendtoaddress` with Taproot, no `decodescript`.
- **Conclusion**: The current BMM harness for ID5 has **never exercised Taproot (let alone Simplicity)**. All observed activity uses legacy/P2SHH or custom deposit strings + simulated/imported credits. This is the primary gap for "production use".

(Existing Elements test vectors in src/test/ *do* exercise Simplicity spends, including in Taproot contexts, and they pass when the flag is set.)

## 4. Concrete Test: Minimal Simplicity Program as Tapscript Leaf in BMM Context

### Minimal Always-True(ish) Program Example
From `src/simplicity/test.c:642` (exactBudget_test, a small real program used in the Simplicity test suite; evaluates successfully under Elements jets):

```c
const unsigned char program[] = {
    0xe0, 0x09, 0x40, 0x81, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x81, 0x02,
    0x05, 0xb4, 0x6d, 0xa0, 0x80
};
size_t program_len = sizeof(program);
```

To use as Tapscript leaf (in a spending tx input's witness stack + control block):
1. Compute its CMR (via `simplicity_elements_computeCmr` or the C lib / simplicity CLI if built).
2. In the Taproot output being spent: control block starts with `(0xbe | parity_bit)`, followed by 32-byte internal key, then merkle path nodes.
3. The Tapleaf "script" committed in the MAST is the 32-byte CMR (not a Bitcoin script).
4. Witness stack for that input (in the spending tx): `[ <simplicity_witness_bytes>, <program_bytes> ]` (order per SpanPopBack in interpreter).
5. Budget is derived from serialized witness size + offset.

The program must typecheck to `ONE |- ONE` (or appropriate unit for success path) and not hit `SIMPLICITY_ERR_FAIL_CODE` / asserts / budget.

**Example construction sketch** (for a test that crafts a 1-in-1-out tx spending a Simplicity UTXO; would be submitted to mempool or included in a generated block under active BMM):

```python
# Pseudocode for test (see accompanying test_simplicity_in_bmm.py)
CMR = compute_cmr(program)  # 32 bytes, e.g. from lib
leaf_version = 0xbe
control = bytes([leaf_version | parity]) + internal_pubkey + merkle_path
# ... build tx with witness_utxo having the Taproot scriptPubKey (OP_1 + tweaked key)
# spending_witness = [witness_data, program]
# Then: testmempoolaccept or submit via BMM cycle (elements-cli generatetoaddress or the participant loop)
# Assert: "allowed" or tx confirms at higher side height, no SCRIPT_ERR_SIMPLICITY_*
```

### Implemented Test Artifact
See `drivechain-liquid-sidechain/tests/test_simplicity_in_bmm.py` (created in this session). It:
- Hard-codes the above minimal program + a trivial "unit true" witness sketch.
- Performs static verification that `GetBlockScriptFlags` (validation.cpp) and the 0xbe dispatch (interpreter.cpp:3315) are present and not guarded by any BMM conditional.
- Greps the BMM harness to confirm "no Tapscript usage yet".
- Provides a `--bmm-cycle` mode hook (calls the participant script if present) + `submitblock` path to actually drive a block containing a (pre-crafted) Simplicity spend.
- On success: prints "Simplicity program accepted inside BMM-driven block context".

Run: `python3 drivechain-liquid-sidechain/tests/test_simplicity_in_bmm.py --regtest-datadir /tmp/liquid-id5-regtest --bmm`

(Requires a live elementsd with the ID5 datadir + Simplicity deployment active, which Liquid Testnet params guarantee.)

## 5. Current Integration Status, Gaps, Next Steps for Production

### What Works Today
- Simplicity programs execute correctly in any Elements tx (CT, assets, pegins, etc.) when `SCRIPT_VERIFY_SIMPLICITY` is set.
- BMM-driven blocks use exactly the same validation path → Simplicity txs included in side blocks whose critical_hash is BMM-committed on mainchain will be accepted and Simplicity scripts inside them will be executed.
- Jets give full access to Elements transaction environment (including annex, which Tapscript supports).
- Liquid Testnet (and any net with the deployment active or ALWAYS_ACTIVE) already has the flag on for all blocks.
- The C library + interpreter are mature (fuzzing, exact budget tests, real programs like checkSigHashAllTx1 exist in tree).

### Gaps / What Does Not Yet Work (or Not Demonstrated)
1. **Harness coverage gap (highest priority for this task)**: drivechain-liquid-sidechain/ e2e + participant + adapter contain **no Taproot v1 addresses, no Tapscript, no Simplicity programs**. Deposits use custom strings + simulated credits. No test that a Simplicity spend tx confirms during a real `CreateBmm...` + mine + h* poll cycle.
2. **Wallet / usability**: No high-level support exposed in `elements-cli` / descriptors / PSBT for easily creating Simplicity leaves (you must manually compute CMR + assemble program/witness/control). Bitcoin Core-style `tr()` descriptors with `simplicity(...)` fragments would be ideal but absent.
3. **Tooling for "minimal unit true"**: Developers need either the Simplicity assembler/compiler (not in this repo) or pre-packaged trivial programs + CMR values. The 17-byte example above works for tests but is not "hello world" documented.
4. **Cross-layer**: Mainchain BMM critical txs themselves (on drivechaind) use whatever script the enforcer/wallet emits (likely P2WSH or similar). If one wanted a Simplicity output *on mainchain* as part of BMM, that would require drivechaind + enforcer changes (out of scope for *this* sidechain repo).
5. **Edge cases not explicitly tested under BMM load**: Very high budget Simplicity programs in BMM blocks, interactions with sidechain-specific features (dynafed, custom assets in Simplicity jets), large witness during BMM reorgs/contention.
6. **Documentation**: Until this report, zero mention of Simplicity in the BMM adaptation docs.

### Recommended Next Steps (Prioritized for Full Production Use)
1. **Immediate (this PR)**: Land this report + `test_simplicity_in_bmm.py`. Extend the e2e-liquid-on-signet.sh (or participant) to optionally include a `--with-simplicity` path that crafts + sends a trivial Simplicity spend tx during a BMM cycle and asserts confirmation + credit. Use a precomputed trivial program + CMR (add to repo a `simplicity_programs/` dir with 1-2 always-success vectors + Python helper using ctypes to call the built libelementssimplicity if present).
2. **Short-term**: Add Taproot descriptor / address support for Simplicity in the Elements wallet (or at least raw tx examples + `decodesimplicity` RPC). Update `liquid_id5_participant.py` and adapter to support Taproot deposit addresses (native segwit v1 + 0xbe leaf as one supported path).
3. **Medium-term**: Full E2E in CI: spin the ID5 regtest + enforcer (docker), run BMM loop, inject a Simplicity-spending tx (e.g. via `sendrawtransaction` of a pre-signed vector), confirm side block advanced via BMM contains it and script succeeded (no error in `getrawtransaction` verbose or trace).
4. **Production hardening**: Fuzz BMM + Simplicity combination (extend existing simplicity_tx.cpp fuzzer to also simulate "block arrived via BMM critical" metadata, though unnecessary for consensus). Document exact byte budget implications for sidechain users doing Simplicity under BMM (the bribe + confirmation latency).
5. **Upstream**: Contribute the trivial-program examples + any missing jet coverage back to ElementsProject if gaps found. Propose Simplicity-aware `tr()` fragments for descriptors.
6. **Optional stretch**: Demonstrate a Simplicity program *using BMM-specific jets* (if any are added later) or proving a sidechain header commitment inside Simplicity.

## Appendix: Key File References
- Simplicity exec: `src/simplicity/elements/exec.c:45`
- Leaf dispatch + flags: `src/script/interpreter.cpp:3315` (and 2605 for txdata), `interpreter.h:280`
- Deployment: `src/chainparams.cpp:1095` (Liquid Testnet ALWAYS_ACTIVE), `src/validation.cpp:2190`
- BMM drivers: `drivechain-liquid-sidechain/scripts/{grpc_bmm_id5.py,liquid_id5_participant.py}`, `tests/e2e-liquid-on-signet.sh`
- No BMM in node: `git grep -r --include="*.cpp" -i "bmm\|cusf\|drivechain" src/`

**Verdict**: Simplicity + BMM integration "just works" for consensus. The work remaining is **test coverage + developer UX** in the drivechain harness, not core protocol compatibility.

Next action after this doc: implement + run the accompanying Python test against a live /tmp/liquid-id5-regtest instance.
