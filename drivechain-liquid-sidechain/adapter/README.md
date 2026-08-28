# liquid-drivechain-adapter (stub + integration plan)

> **QUARANTINED — DO NOT DEPLOY OR RUN.** This adapter targets the retired
> slot-5/regtest prototype. Its executable files fail closed before contacting
> either chain. The canonical node is **Elements Drivechain** at BIP300 slot
> **24**, selected with `elementsd -chain=elements`; see the
> [repository README](../../README.md). The text below is historical only.

This dir will hold the Rust (preferred, following plain-bitassets) or Python bridge between:
- CUSF enforcer gRPC (WalletService/ValidatorService for ID 5)
- elementsd (regtest or custom chain for Liquid CT/assets/scripting)

**Security model (native, no fed shortcut)**: Peg credits and BMM inclusions are driven by *enforcer events* (secured by mainchain hashrate escrows + BMM commitments + contest periods). The adapter only reacts. Elements consensus independently checks the exact BIP300 deposit outpoint, containing active-chain block, amount, and destination before accepting a pegin, so the adapter is not trusted to authorize credits.

## Current State (2026-05-25)
- Empty except this doc (prior "completion" was scaffold).
- e2e harness + scripts exercise the CUSF side only (proposals, deposits, BMM requests, withdrawals) but fail at enforcer broadcast for ID5 because no side daemon participates.
- Elements source lives in workspace root (src/pegins.cpp, claimpegin/getpeginaddress RPCs, fedpeg validation in tx_verify.cpp). No drivechain-specific code yet.

## v1 Integration Path (Feasible without core Elements consensus changes)
1. Run elementsd in regtest (or custom magic derived from sidechain declaration) with a dev fedpegscript:
   - Single-key (adapter-controlled) or OP_TRUE for early dev.
   - Config: -regtest, -port=... , -rpcport=..., -fedpegscript=... or use existing getpeginaddress flow with known key.
   - Elements will validate pegins against the fedpeg history (adapter must ensure the claim script matches the one active at mainchain deposit time).

2. Adapter (Rust, tonic + prost from vendored protos in plain-bitassets/proto/):
   - Connect to enforcer:50051.
   - SubscribeEvents or poll GetBlockInfo / GetTwoWayPegData for sidechain_id=5.
   - On Deposit event (outpoint, value, address, sequence): 
     - Call `importdrivechaindeposit` with the event's exact txid, vout, block hash, address, and value. The RPC constructs a `drivechain-deposit-v2` witness; normal transaction consensus then rechecks those fields against `GetTwoWayPegData` and Bitcoin's active chain.
   - On BMM request (from side miner or internal): compute critical_hash = sha256(Elements block header + merkle or body), call CreateBmmCriticalDataTransaction, trigger L1 mine (or wait), confirm via GetBmmHStarCommitment, then elementsd submitblock.
   - On pegout intent (Elements tx with special marker or adapter RPC): collect bundle, call BroadcastWithdrawalBundle.
   - Expose unified RPC (elements + drivechain status, proofs for Floresta).

3. Docker: add to local-dev compose:
   ```
   liquid-adapter:
     build: ../liquid-signet-sidechain/adapter  # or image
     depends_on: { enforcer: {condition: service_healthy}, liquid: {condition: service_healthy} }
     networks: { default: { ipv4_address: 172.22.0.6 } }
     command: --enforcer-host=enforcer --elements-rpc=http://liquid:18443 ...
   liquid:
     image: ...elementsd or built from this repo...
     command: elementsd -regtest -rpcallowip=... -mainchain-signet ... (or drivechain flags)
   ```

## Elements native drivechain validation

`importdrivechaindeposit` is a transaction-construction convenience, not an authorization bypass. Every drivechain pegin is consensus-valid only when the configured mainchain node confirms the containing block is active and the configured CUSF enforcer returns the exact deposit event for this sidechain slot. Consensus also binds the deposit to one input, one recipient, the committed address, and an exact recipient-plus-fee total.

See Elements docs/elements-*.md and src/pegins.* for current fedpeg/claimpegin details.

## Next (after this PR skeleton)
- Implement minimal Python stub first (grpcio, python-elements or json-rpc to elementsd) to unblock e2e with *real* side txids/heights.
- Port to Rust + integrate into LayerTwo-Labs patterns.
- Add to e2e: if adapter/ stub present, start it + elementsd, do real deposit credit txid, real BMM side height advance, real withdraw event.
- Build Elements from this workspace: `./autogen.sh && ./configure --enable-wallet --with-gui=no && make -j4 src/elementsd src/elements-cli`.

## Evidence of Current Gap
From e2e 20260524-221145:
- ID5 listed + activated in metadata.
- All CreateDeposit / CreateBmm / BroadcastWithdrawal for ID5 -> error at enforcer (no side to "claim" or participate).
- State json has only simulated entries.

This adapter + elementsd service is the *single missing piece* for production Liquid native drivechain sidechain.
