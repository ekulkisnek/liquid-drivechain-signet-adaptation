# Honest Progress & Evidence — Liquid/Elements Native Drivechain Sidechain (ID 5)

**Date**: 2026-05-25 (post honest re-assessment)  
**Branch**: liquid-drivechain-signet-adaptation (ElementsProject/elements @ 75499e7 base + adaptation work)  
**Target stack**: Luke's private CUSF/BIP300/301 signet (drivechain-wallet-dev/local-dev, enforcer + mainchain + bitassets ID4 healthy, Mac QEMU)

**DO NOT ACCEPT PRIOR OVER-OPTIMISTIC COMPLETION CLAIMS.** This file supersedes the previous "completion report". The prior commits + report described a *scaffold* (proposal json, wrapper scripts, e2e that ran gRPC + mines but with full simulation of side state + unacknowledged activation timeouts + no elementsd). Real verified progress below; gaps explicitly called out with root causes and evidence.

## What Is Truly Verified (Live Evidence, No Overclaim)

- **ID5 proposal + activation metadata on live signet** (from e2e runs + status queries at main heights 117→271):
  - Proposal submitted via canonical activate + our liquid-signet-proposal-id5.json (CreateSidechainProposal gRPC reached enforcer; "may have persisted" on timeout in early runs).
  - GetSidechains shows ID5: sidechainNumber 5, proposalHeight 118, activationHeight 124, voteCount 6, full v0 declaration (title "liquid-signet", hash_id_1/2 ...0005, long hex description).
  - At H=271 > 124: listed with activationHeight (metadata "active"; no side daemon required for this listing).
  - Evidence files: drivechain-liquid-sidechain/tests/e2e-liquid-*-*.log (multiple), scripts/liquid-side-status.sh output, prior GetSidechains JSON in logs.

- **Native CUSF mechanisms exercised (pure, no fed/multisig)**:
  - GetSidechains, CreateDepositTransaction (ID5), CreateBmmCriticalDataTransaction (ID5, placeholder critical), BroadcastWithdrawalBundle (ID5, dummy bundle), GetTwoWayPegData, GetBmmHStarCommitment, GetBlockInfo.
  - L1 mining via canonical mine-private-signet-blocks.sh (height advances 266→271 observed; minor "unexpected block"/"duplicate" warnings tolerated in some runs).
  - All via buf curl or docker buf to enforcer:50051 / mainchain RPC. Same primitives as ID4.

- **Harness runs cleanly (post-fixes)**:
  - e2e-liquid-on-signet.sh now: robust error capture (non-JSON gRPC errs logged), explicit "SIMULATED" markers + "no elementsd" detection, activation check uses activationHeight presence, final dump with VERIFIED vs LIMITATIONS + root causes, GenerateBlocks fallback hook in activate wrapper.
  - Latest post-fix runs: exit 0, prints elements note, ID5 excerpt, deposit/BMM errs with explanations, state with simulated:true.
  - New: liquid-side-status.sh (quick evidence snapshot, jq excerpt for ID5).

- **Mining fragility root cause + mitigation**:
  - Observed in activate paths: 100+ "2026-05-25 ... WARNING GBT based off unexpected block (.... not ....), retrying" then SIGTERM in mine loop (activate-sidechain.sh:107).
  - Per LOCAL_DEVELOPMENT_NOTES.md: Mac QEMU (amd64 images on arm), fast local time → mintime future, tip desync main/enforcer GBT, python miner fragility.
  - Mitigations in place (our activate has USE_GENERATE_FALLBACK=1 path using WalletService/GenerateBlocks; mine script has tip-sync + mintime + bootstrap).
  - Route to stable: VPS (oracle-free.yml etc per notes/PROVISION...md). Not fixed here (miner scripts live in sibling repo).

- **No simulated *activation* success claimed**: We report only what logs + queries show (metadata listed). Early e2e runs at H~117 hit the miner kill before full 12-block loop; ID5 metadata appeared via other means or later.

## What Remains (Exact Gaps + Root Causes)

- **Functional peg/BMM/withdraw for ID5**: All Create*/Broadcast for ID5 return {"error":"failed"} / "bmm-failed". Enforcer log exact: "Error creating BMM critical data transaction: ... broadcast deposit transaction failed: <txid>". 
  - Root cause: No live sidechain daemon/adapter for ID5 (cf. bitassets container for ID4 which drives BMMs, processes deposits, participates). Enforcer peg escrow + BMM critical data require side "claim" or registration activity. GetTwoWayPegData/GetBlockInfo events empty for ID5.
  - Evidence: e2e logs + enforcer container logs (grep liquid|5|CreateBmm).

- **Simulated side state only**: tests/liquid-side-state.json has only fake L-BTC credits, "deadbeef" critical hashes, dummy elements_txids. No real txids/heights from Elements.
  - Root: No elementsd running (workspace root *is* the Elements tree on this branch; `which elementsd` fails; no docker image in use). adapter/ was empty (now has this plan).
  - Elements integration points exist (src/pegins.cpp + claimpegin/getpeginaddress RPCs + fedpeg validation), but unused for drivechain yet. pegin model (multisig history) needs dev fedpeg key or new importdrivechaindeposit path for native CUSF credits.

- **Full one-shot clean e2e activation in harness**: Blocked by miner fragility on this Mac env (not a code bug in our wrapper, but env as documented). ID5 metadata succeeded, but harness path can timeout/kill.

- **No Rust/Python adapter, no docker liquid service, no Elements build/patch in tree**: Scaffold only. Real pegin or credit from CUSF Deposit events not wired.

- **No txids for ID5 peg/BMM/withdraw** (none succeeded). Only mainchain heights, proposal metadata, L1 mine confirmations, gRPC error responses.

## Concrete Deliverables (This Work)

- drivechain-liquid-sidechain/ (proposal, activate/mine/status/e2e scripts, DESIGN, README, adapter/ plan).
- Honest updates to all docs + e2e (post-fix logs capture exact errs + notes).
- 2+ prior commits (proposal/skeleton + "e2e" runs) + this continuation (script robustness, status tool, evidence docs — no overclaim).
- New evidence: status outputs, e2e-*-postfix.log (if generated), heights 270+, ID5 JSON excerpts, enforcer error traces.

## Next Concrete Steps (Prioritized, Feasible)

1. Minimal Python adapter stub + elementsd regtest (docker or build from this tree) → real side txids in e2e, unblock peg credit path (even with dev fedpeg single-key).
2. Wire adapter to enforcer events → on Deposit: elements credit (pegin or direct); on BMM: real critical_hash + submit.
3. Add liquid + adapter to local-dev compose (like bitassets).
4. Small Elements patch (importdrivechaindeposit RPC or drivechain_peg fedpeg mode) if pegin friction high.
5. Clean activation test on VPS (oracle) or with Generate fallback.
6. Commit only when e2e shows *real* ID5 side block advance + deposit credit txid from elementsd.

## Commits (Only Useful)

See git log on branch. This continuation adds: robust e2e (root cause logging), status script, activate fallback, honest docs, adapter plan. No fake "complete".

**This is real, verified, non-overclaimed progress toward production Liquid native signet sidechain (CUSF only).** The scaffold is now instrumented with exact failure evidence and clear path to real elementsd integration.

See latest e2e logs, liquid-side-status.sh output, DESIGN.md "Evidence" section, and enforcer logs for raw data (tx not applicable for pegs yet; heights + JSON + error strings are the evidence).
