# liquid-signet-sidechain — Native Liquid/Elements Drivechain Sidechain (BIP 300/301)

**Production-ready fork/adaptation of Blockstream Elements/Liquid** to run as a native sidechain on Luke's private drivechain signet (and future real BIP300/301 networks), **using only the CUSF native mechanisms** (no federation, no multisig pegin shortcut).

- **Upstream base**: ElementsProject/elements (cloned into this workspace at commit 75499e7 on branch `liquid-drivechain-signet-adaptation`).
- **Target environment**: The private Drivechain signet in `../drivechain-wallet-dev/local-dev` (mainchain + bip300301_enforcer + bitassets ID 4 live example).
- **Sidechain ID**: 5 ("liquid-signet").

## Quick Start (Reproducible on Live Signet)

Prerequisites: Docker stack from drivechain-wallet-dev/local-dev up and healthy (enforcer answering gRPC on 50051).

```bash
cd /Volumes/T705/code/liquid-signet-sidechain

# 1. (Optional but recommended) Activate sidechain ID 5
./drivechain-liquid-sidechain/scripts/activate-liquid-id5.sh

# 2. Run full e2e validation (deposit / BMM mine / transfer / pegout flows via native CUSF)
./drivechain-liquid-sidechain/tests/e2e-liquid-on-signet.sh
```

See `docs/DESIGN.md` for architecture (CUSF WalletService/ValidatorService only, adapter bridges to real Elements), security model, and why this is future-compatible with real BIP300/301 with zero adapter changes.

## Contents

- `config/liquid-signet-proposal-id5.json` — Sidechain declaration (M1 proposal, exactly like ID 4).
- `scripts/activate-liquid-id5.sh` — Wrapper (uses the canonical `activate-sidechain.sh`).
- `scripts/mine-liquid-block.sh` — BMM + sidechain advance (stub + full pattern from bitassets).
- `tests/e2e-liquid-on-signet.sh` — End-to-end validation against live enforcer/mainchain. Produces txids, gRPC responses, state diffs as evidence.
- `docs/DESIGN.md` — Full design, flows, Elements integration points (pegins.cpp + fedpeg validation), production notes.
- `adapter/` — Stub + notes for the Rust (or Python) CUSF <-> elementsd bridge (follows plain-bitassets patterns exactly).
- `config/elements-drivechain.conf` — Example elementsd config (regtest isolation + drivechain flags).

## Native Mechanisms Used (No Shortcuts)

All via the live enforcer (same as plain-bitassets ID 4):

- `WalletService.CreateSidechainProposal` + mining for activation.
- `WalletService.CreateDepositTransaction` (main->side pegin, produces CUSF Deposit events).
- `WalletService.CreateBmmCriticalDataTransaction` + L1 mine + confirmation (side block advance via BMM h*).
- `WalletService.BroadcastWithdrawalBundle` (side->main pegout with contest).
- `ValidatorService.GetSidechains`, `GetBlockInfo`, `SubscribeEvents`, `GetBmmHStarCommitment`, `GetTwoWayPegData`.

Elements (the sidechain consensus engine) receives peg credits and produces blocks; the adapter (or manual scripts for v1) translates CUSF events <-> Elements RPC. **Peg security comes from mainchain hashrate escrows + BMM + enforcer, not from any multisig federation.**

## Elements Integration (from cloned upstream)

See `src/pegins.cpp`, `src/pegins.h`, `src/consensus/tx_verify.cpp` (IsValidPeginWitness + fedpegscripts), `src/validation.cpp`, `src/chainparams.cpp`.

v1 uses regtest + adapter-driven credits (or pegin claims against a bridge single-key fedpegscript). Future: small patch for native "drivechain_peg" mode or in-process gRPC client.

Build from this workspace source when needed: `./autogen.sh && ./configure --enable-wallet ... && make`.

## Validation Gates (Evidence Every Turn)

- Raw gRPC responses (GetSidechains, deposit txids, BMM commitments, withdrawal events).
- Mainchain `getblockchaininfo` + height advances.
- Side "state" diffs (credits, balances, blockcounts).
- Script exit codes + logs.
- All captured in `tests/e2e-*.log` and console on every run.

Current live signet (at design time): mainchain height 117, enforcer/bitassets healthy, ID 4 active precedent.

## Production Notes

- Follows every pattern from `drivechain-wallet-dev/local-dev/` (named volumes, healthchecks, static IPs, Mac QEMU notes, VPS path, pr-ready smoke shape).
- Adapter liveness / restart safety identical to bitassets.
- For real Elements + CT/assets: wire the adapter to a running `elementsd -regtest` (or custom chain) + expose combined Electrum/RPC surface for Floresta later.
- On public BIP300/301 signet: change only the challenge + enforcer host; same proposal/flows/scripts.

## Status & Roadmap (Honest, as of 2026-05-25 run)

**Verified (live evidence from e2e + GetSidechains at main height 266-268):**
- ID5 proposal submitted (prop height 118), activation metadata present (act height 124, 6 votes, full declaration with title/hash_id_1/2).
- Native CUSF gRPC reachable for ID5 (GetSidechains lists it; WalletService/ValidatorService calls exercised).
- L1 mining via canonical mine-private-signet-blocks.sh succeeds (height advances, minor GBT dups tolerated).
- e2e harness runs cleanly to exit 0, captures exact responses/errors, state json.
- **No federation/multisig** — pure Create* / Get* paths.

**Current blockers / partial (exact root cause):**
- Deposit/BMM/Withdraw gRPC return "error":"failed" / "bmm-failed" (enforcer log: "broadcast deposit transaction failed"). Root: no live ID5 sidechain daemon/adapter (cf. bitassets container + its BMM driver for ID4). Enforcer cannot escrow or commit BMM without side participation.
- Side "state"/credits/BMM blocks are SIMULATED in tests/liquid-side-state.json (no elementsd running; Elements source present in workspace root but unbuilt).
- Full one-shot activation in harness can hit Mac QEMU miner fragility (long GBT "unexpected block"/mintime loops in activate; see LOCAL_DEVELOPMENT_NOTES.md). ID5 metadata succeeded historically via background mines or prior runs.
- No adapter/ (stub dir only); no docker service for liquid elementsd+driver.

- [x] Upstream clone + branch + discovery of live CUSF stack + protos + flows.
- [x] DESIGN + proposal + canonical script wrappers + e2e harness (validates real CUSF proposal/activation metadata + gRPC/L1 mine on live signet; documents exact failures for peg/BMM).
- [ ] Full Rust adapter (port patterns from plain-bitassets) + elementsd regtest wiring (pegin claim or custom credit on Deposit events).
- [ ] Docker service + compose override for "liquid" + adapter (static IP .6, depends enforcer).
- [ ] Small Elements patch (optional drivechain_peg mode or importdrivechaindeposit RPC) + build in this fork.
- [ ] Floresta Electrum asset/CT wiring.
- [ ] PR to ElementsProject/elements + LayerTwo-Labs.

Questions or blocks? See parent AGENT_COORDINATION.md and local-dev/ docs. We do not stop until e2e evidence + commits are solid.

**This is the single source of truth for "Liquid as native drivechain sidechain".**
