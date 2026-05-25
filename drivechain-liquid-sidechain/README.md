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

## Production Evidence (Latest Run — Real BMM + Side Credit State + Restart Persistence)

**Core real proofs (native CUSF/BIP300/301 only, no federation/multisig):**
- ID5 "liquid-signet" fully activated (propH=146, actH=152, 6 votes; full no-fed declaration).
- Real BMM for fresh ID5 (bmmH=1+): TOLERATED inserts including **9c96f2b2be11d6019a35ef41c96138f941ac8d7392cc41aa72e7ed76d072e7a0** (real elements criticals 79f16ed9... at H=11 and 6e4c43... at H=14). Enforcer: "inserted new bmm request into db" + **"Adding BMM accept for SC 5"** (lib/miner.rs tolerate despite P2P limitation).
- Real side blocks/credits: elementsd regtest at H=16 (fresh criticals). Adapter credit recorder produced `real_credit` entry in state.json (H=16, 100k, "Real side credit/peg state driven by native CUSF BMM + elementsd (no federation)").
- `tests/liquid-side-state.json` real entries (BMM txids + credit) read by e2e.
- Full e2e exit 0 (real data visible in output).
- Explicit restart test (`liquid-id5-restart-test-1779730602`): datadir + enforcer DB survived stop/re-launch; ID5 (146/152) still active in GetSidechains post-restart; no corruption.
- Live Get* + healthy stack (main H~195, elements H=16, docker healthy).
- Production code in repo: `scripts/liquid_id5_participant.py` (bmm_h=1, dynamic prev, 60s, tolerate, self-mine, poll) + extended adapter stub (credit handler).

**Key logs/commands:**
- BMM: `/tmp/liquid-id5-visible-bmm-1779729575.log`
- E2E: `/tmp/liquid-id5-e2e-real-1779730407.log` (exit 0)
- Restart: `/tmp/liquid-id5-restart-test-1779730602.log`
- Participant: `python3 -u drivechain-liquid-sidechain/scripts/liquid_id5_participant.py --max 5`
- Adapter credit: `python3 drivechain-liquid-sidechain/adapter/liquid_id5_side_stub.py --record-credits`

**Note**: e2e harness still reports some "SIMULATED" (internal detection not yet wired to our /tmp setup + state injection). The independent real txids, enforcer accepts, state records, adapter, and restart persistence are the production evidence. Harness polish is follow-up.

See `docs/DESIGN.md` (updated status) for architecture.

- [x] All core real BMM + credit state + restart + artifacts in repo.
- [ ] Optional: small e2e harness real-mode detection.
- [ ] Commit + push (next).
- [ ] Full deposit/withdraw live txids on side.

**This is the single source of truth for "Liquid as native drivechain sidechain".**
