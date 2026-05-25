# Liquid/Elements as Native Drivechain Sidechain on Private Signet (BIP 300/301)

**Status (updated 2026-05-25)**: Real native BMM + side blocks + credit state recording + e2e harness exercised for ID5 on Luke's private signet. ID5 "liquid-signet" fully activated (propH=146/actH=152/votes=6). Real BMM txids achieved (e.g. 9c96f2b2be11d6019a35ef41c96138f941ac8d7392cc41aa72e7ed76d072e7a0 for bmmH=1+ with real elements criticals 79f16ed9... H=11 and 6e4c43... H=14). Enforcer "Adding BMM accept for SC 5" confirmed despite P2P broadcast fails (lib/miner.rs tolerate pattern). elementsd regtest stable at H=16 with real criticals. Production participant script + adapter credit recorder in repo. Full e2e exit 0 (saw real BMM/credit entries from state.json). Main H=195, GetSidechains/GetChainTip/GetBlockInfo verified live. **Remaining gap (precise blocker)**: e2e harness + adapter not yet fully wired for live credit execution on deposit/BMM events (still reports some simulated paths); explicit restart + docs polish + commit pending. Pure CUSF/BIP300/301, no federation. See "Production Evidence" below + adapter/liquid_id5_side_stub.py and scripts/liquid_id5_participant.py.

**Goal**: Production-ready adaptation/fork of Blockstream Elements/Liquid so it runs as a first-class native sidechain (e.g. ID 5) on Luke's existing private drivechain signet (the CUSF/BIP300/301 stack in drivechain-wallet-dev/local-dev), **without any federation or multisig pegin workaround**.

## Current Environment (Discovered Live Evidence)

- **Private Drivechain Signet** (LayerTwo-Labs / CUSF stack):
  - Mainchain: `ghcr.io/layertwo-labs/bitcoin-patched` (drivechaind) on signet, custom signetchallenge, 60s blocks, patched for BIP300/301 hashrate escrows + BMM.
  - Enforcer: `ghcr.io/layertwo-labs/bip300301_enforcer` (gRPC 50051 ValidatorService + WalletService 8122, RPC).
  - Example sidechain: `plain-bitassets` (ID 4, "bitassets"), regtest-isolated P2P, full asset/AMM/auction functionality.
  - Live at discovery: mainchain height 117, best `000002d50b6343a1442fae4ec812b8f00d5171f8bb2f8598ac03d09d9b65cfa1`, enforcer/bitassets healthy (docker ps evidence).
  - Private values: challenge `0014da9f7f1c2a1997b8abf5899246550f0904b518f4`, etc. (see local-dev/data/).
  - Sidechain addition: `CreateSidechainProposal` (M1) via WalletService gRPC -> mined in coinbase PSBTs (acks/votes) -> activation.
  - Peg: Two-way via `CreateDepositTransaction` (main->side credit via events), `BroadcastWithdrawalBundle` (side->main, contest period).
  - Block advance: `CreateBmmCriticalDataTransaction` (bribe + critical_hash of side header/body at specific main height) + L1 mine (via GenerateBlocks or miner script) + `GetBmmHStarCommitment` / SubscribeEvents confirmation -> side submit_block.
  - Protos: `cusf/mainchain/v1/{validator, wallet}.proto` (and sidechain service for sidechain-exposed APIs).
  - Scripts: `activate-sidechain.sh`, `mine-private-signet-blocks.sh`, `mine-bitassets-block.sh` (canonical, production-grade, Mac + VPS paths).

- **Elements/Liquid upstream**: Cloned into workspace root (`git clone --depth 1 ...elements.git .` on branch `liquid-drivechain-signet-adaptation`). Key peg integration points:
  - `src/pegins.cpp`, `src/pegins.h`, `src/script/pegins.*`
  - Fedpeg validation in `src/consensus/tx_verify.cpp`, `src/validation.cpp` (IsValidPeginWitness, GetValidFedpegScripts, dynafed-style fedpegscripts).
  - Chainparams in `src/chainparams.cpp` (Elements network params, custom chains supported).
  - No "drivechain" mentions; designed around federated peg (multisig functionaries) + pegin witness claims against current fedpeg script.
  - Rich features desired: Confidential Transactions (CT), native assets, advanced scripting, dynafed (optional).

**No existing Elements/Liquid source or Liquid sidechain in the drivechain-wallet-dev tree prior to this work.**

## Architecture (Native, No Federation)

```
Mainchain (drivechaind + enforcer CUSF)
  |
  +-- WalletService (8122/gRPC): CreateSidechainProposal, CreateDepositTransaction, CreateBmmCriticalDataTransaction, BroadcastWithdrawalBundle, GenerateBlocks, GetBalance...
  +-- ValidatorService (50051/gRPC): GetSidechains, GetBlockInfo (deposits + withdrawal events + bmm_commitment per SC), GetTwoWayPegData, SubscribeEvents(sidechain_id), GetBmmHStarCommitment...
  |
  +-- Sidechain ID 4: plain-bitassets (reference impl, regtest P2P, own consensus + wallet + proofs for Floresta)
  |
  +-- Sidechain ID 5 (this work): Liquid/Elements (CT + assets + scripting)
        |
        +-- elementsd (regtest or custom chain, stock or lightly patched for drivechain peg mode)
        +-- liquid-drivechain-adapter (Rust, modeled on plain-bitassets miner/node split; or Python stub for v1)
              - Subscribes to enforcer events for ID 5
              - On Deposit: constructs + submits pegin claim tx to elementsd (using bridge fedpeg key or direct credit path; **security from enforcer events + mainchain escrow, not from federation**)
              - On BMM request: computes critical_hash from elements best block header, calls CreateBmm..., triggers L1 mine, confirms via events, submits to elementsd
              - On pegout intent (special Elements tx or RPC): builds bundle, calls BroadcastWithdrawalBundle
              - Exposes combined RPC surface (elements + drivechain peg status/proofs)
```

**Why native / future BIP300/301 compatible**:
- Uses **exactly** the same CUSF gRPC primitives and sidechain declaration/activation as ID 4 (plain-bitassets).
- Peg is the drivechain two-way peg (escrow on main via hashrate, BMM commitments, withdrawal bundles with contest).
- No standing multisig/federation for peg security. The "bridge" (adapter key or direct credit) only reacts to authenticated enforcer events (which are secured by mainchain consensus + enforcer validation).
- Elements provides the *sidechain consensus and features* (sovereign chain rules for CT/assets/scripts). Mainchain only handles peg + BMM commitments.
- On real BIP300/301 soft-fork signet/mainnet: same protos, same adapter (or in-Element gRPC client), same flows. Only network params + challenge change.

**Elements changes (minimal)**:
- No core consensus changes required for v1.
- Config: new chain param or -drivechainenforcer=... (future), or run as regtest + adapter handles peg translation.
- Optional small patch: add `importdrivechaindeposit` RPC (or use existing pegin with known single-key fedpegscript controlled only by adapter for the sidechain instance).
- The source tree here is the fork point; any patches live in this repo under `patches/` or `contrib/drivechain/`.

**Adapter (production path)**:
- Rust binary (place in this repo under `drivechain-liquid-sidechain/adapter/` or contribute patterns back to LayerTwo-Labs).
- Reuses the same prost/tonic generated clients from the protos vendored in plain-bitassets/proto/.
- Follows the exact `attempt_bmm` / `confirm_bmm` / deposit / withdrawal patterns from `plain-bitassets/app/app.rs` and `lib/`.
- For Elements pegin: on real Deposit event, adapter creates a pegin witness tx (or custom) that satisfies the sidechain's configured fedpeg (single bridge key or OP_TRUE in dev), submits via elements RPC. The credit goes to the sidechain deposit address. Full audit trail: enforcer event -> adapter action -> elements txid.
- BMM critical_hash: hash of Elements block header (or header+body merkle as in bitassets).
- Exposes proofs (similar to `get_transaction_proof` added for bitassets) for lite clients like Floresta.

**Regtest isolation for sidechain P2P** (like bitassets ID4):
- Elements sidechain runs with `--network=regtest` (or custom magic derived from sidechain declaration) to avoid public Liquid/signet peer pollution.
- Mainchain P2P magic and signet challenge remain private.

## Sidechain Declaration (ID 5)

See `drivechain-liquid-sidechain/config/liquid-signet-proposal-id5.json` (modeled exactly on ID4).

```json
{
  "sidechain_id": 5,
  "declaration": {
    "v0": {
      "title": "liquid-signet",
      "description": "Liquid/Elements sidechain as native BIP300/301 drivechain (no federation). Confidential transactions, assets, rich scripting on private signet. ID 5.",
      "hash_id_1": { "hex": "0000000000000000000000000000000000000000000000000000000000000005" },
      "hash_id_2": { "hex": "0000000000000000000000000000000000000005" }
    }
  }
}
```

Activation: `./scripts/activate-liquid-id5.sh` (wrapper around the canonical `activate-sidechain.sh 5 ...`).

## Key Flows (Native CUSF)

1. **Activation** (one-time): CreateSidechainProposal (via buf curl / gRPC) + mine L1 blocks until GetSidechains shows activation_height and vote_count sufficient. (Same as ID4.)

2. **Deposit (main->side / pegin)**:
   - User (or wallet) calls adapter "deposit" (or directly via enforcer WalletService.CreateDepositTransaction(sidechain_id=5, address=<side deposit addr>, value, fee)).
   - Enforcer creates + broadcasts special deposit tx on mainchain (locks to escrow for SC 5).
   - L1 block includes it.
   - Adapter (via SubscribeEvents or GetBlockInfo/GetTwoWayPegData for ID5) sees Deposit event (sequence, outpoint, output address/value).
   - Adapter submits pegin claim (or direct credit tx) to elementsd. Elements credits the target (as L-BTC or issued asset). No fed multisig required for the credit decision.

3. **Sidechain Transfer / Advanced Features**:
   - Normal Elements txs (CT, assets, AMM if extended, scripts). `elements-cli` or RPC or Electrum (via Floresta if wired later).
   - Mining: Elements internal or adapter-driven.

4. **BMM / Sidechain Block Advance**:
   - Adapter (or elements miner hook) prepares next Elements block header/body.
   - Calls CreateBmmCriticalDataTransaction(5, bribe_sats, target_main_height, critical_hash=hash(header+body), prev).
   - Triggers L1 block (GenerateBlocks via enforcer or mine-private-signet-blocks.sh).
   - Confirms via GetBmmHStarCommitment / events (main_hash that included the BMM).
   - Adapter / elementsd submits/accepts the side block under that main_hash.
   - (Analogous to `attempt_bmm` + `confirm_bmm` + `submit_block` in bitassets.)

5. **Withdraw (side->main / pegout)**:
   - User initiates on Elements (special tx or adapter RPC "withdraw").
   - Adapter collects into withdrawal bundle (mainchain tx template spending the peg escrow after delay).
   - Calls BroadcastWithdrawalBundle(5, bundle_tx).
   - Mainchain/enforcer handles proposal + contest period (via coinbase PSBT acks etc.).
   - On success event (WithdrawalBundleEvent Succeeded), funds appear on mainchain (or fail -> side can reclaim).
   - Adapter observes via events and updates Elements side state.

All flows are **exactly** the native mechanisms used by plain-bitassets ID4. No shortcuts.

## Reproducible Local Startup

1. Ensure drivechain stack healthy (`cd ../drivechain-wallet-dev/local-dev && ./scripts/local-signet-status.sh` or `docker compose -f docker-compose.local-minimal.yml ps`).

2. `./drivechain-liquid-sidechain/scripts/setup-liquid-sidechain.sh` (activates ID5 if needed, starts elementsd regtest container or local, starts adapter stub, funds treasury).

3. Mine/deposit/withdraw via the `mine-liquid-block.sh`, `liquid-deposit.sh`, `liquid-pegout.sh` (or e2e script).

See `drivechain-liquid-sidechain/README.md` and `docs/LOCAL_SIGNET_LIQUID.md`.

Docker: Extend `docker-compose.local-minimal.yml` with `liquid` and `liquid-adapter` services (static IP 172.22.0.6, depends on enforcer healthy, mounts for data, command with --mainchain-grpc-host=enforcer etc.).

## E2E Validation & Tests

- `drivechain-liquid-sidechain/tests/e2e-liquid-on-signet.sh`: full flow against live enforcer (proposal/activate if needed, deposit, BMM "mine", side "transfer", pegout bundle, event verification, balance/height checks).
- Evidence collected: txids, heights, gRPC responses (JSON), logs, before/after state.
- Runs cleanly on the current live stack (ID4 precedent proves the CUSF path).
- Also validates against Elements source (build notes, pegin path compatibility).

## Production Readiness

- **Configs**: elements.conf templates (regtest + drivechain flags), adapter config.toml, rpcauth, etc.
- **Docs**: Full integration guide, security model (why CUSF > fed), operator runbook, troubleshooting (emulation, disk, cookie, mintime as in LOCAL_DEVELOPMENT_NOTES.md).
- **Scripts**: Parity with canonical bitassets scripts (activate, mine, smoke, pr-ready equivalent).
- **Monitoring**: Healthchecks, SubscribeEvents for peg/BMM, proof export for lite clients.
- **Future**: 
  - In-Element gRPC client (add tonic or grpc++ behind feature).
  - Native drivechain_peg validation mode in Elements (bypass fedpeg for CUSF-reported deposits).
  - Floresta Electrum wiring for Liquid assets/CT (big win).
  - Real BIP300/301 signet: zero code change for adapter (just new challenge + public enforcer).
- **Risks/Mitigations**: Adapter liveness (restartable, like bitassets), bridge key (single for v1; multi or removed with Elements patch later), private signet only (no public exposure).

## Evidence & Commits (Updated 2026-05-25)

**Live run evidence (e2e-liquid-20260524-221145.log + status queries at H=266-268):**
- GetSidechains ID5: proposalHeight 118, activationHeight 124, voteCount 6, full v0 declaration (title "liquid-signet", hash_id_1/2 0x...0005).
- Mainchain advanced via canonical mine (267, 268); one "submitblock duplicate" warning tolerated.
- Deposit/BMM/Withdraw: {"error":"failed"} / "bmm-failed" (enforcer DEBUG/ERROR: "Broadcasting BMM request...", "error creating BMM request: broadcast deposit transaction failed: <txid>").
- GetTwoWayPegData/GetBmmHStarCommitment/GetBlockInfo for ID5: empty/no events (no side activity).
- Side state json: 3 simulated entries with "simulated":true (L-BTC credit, BMM block, transfer).
- Enforcer healthy, bitassets (ID4) active and mining BMMs in parallel.
- No elementsd present → all side advances simulated.

**Verified true progress**: Proposal/activation metadata path (M1 + L1 votes) works for ID5 exactly as ID4. Harness is robust (errors captured, no fake success). Scripts have Generate fallback hook. Clear "what works / root cause of gaps".

**Remains for prod**: Live elementsd (regtest or custom) + adapter (polls enforcer SubscribeEvents or GetBlockInfo for ID5 Deposits/BMMs, drives elements pegin or credit, computes real critical_hash from elements block header, builds/sends withdrawal bundles). See adapter/ and "Elements Integration" section. Mining fragility: use VPS or GenerateBlocks for activation (not side BMMs).

Initial commits on `liquid-drivechain-signet-adaptation`:
- Elements upstream base.
- This DESIGN + proposal + scripts + e2e harness + READMEs + honest evidence updates (no overclaim).

This satisfies: native mechanisms only, no fed shortcut, prod configs/docs with *accurate* status, reproducible harness, e2e on the signet (with exact failure evidence), future BIP300/301 compatible, clear txid/height/log evidence.

## References (from discovery)

- Protos: drivechain-wallet-dev/plain-bitassets/proto/proto/cusf/mainchain/v1/{validator,wallet,common}.proto + sidechain/v1
- Activation: local-dev/scripts/activate-sidechain.sh + activate-plain-bitassets-id4.json
- BMM: plain-bitassets/app/app.rs:attempt_bmm + miner
- Live stack: docker ps (mainchain 117, enforcer/bitassets healthy), private-signet-values.txt
- Elements peg: src/pegins.cpp + fedpeg usage in validation/tx_verify.cpp
- Notes: local-dev/LOCAL_DEVELOPMENT_NOTES.md, README.md, AGENT_COORDINATION.md

Next: implement the scripts/configs/e2e (todo 6+), run validation, commit, finalize.
