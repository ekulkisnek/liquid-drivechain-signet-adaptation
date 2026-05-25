# liquid-drivechain-adapter (stub + integration plan)

This dir will hold the Rust (preferred, following plain-bitassets) or Python bridge between:
- CUSF enforcer gRPC (WalletService/ValidatorService for ID 5)
- elementsd (regtest or custom chain for Liquid CT/assets/scripting)

**Security model (native, no fed shortcut)**: Peg credits and BMM inclusions are driven by *enforcer events* (secured by mainchain hashrate escrows + BMM commitments + contest periods). The adapter only *reacts* (constructs pegin claims or direct credits, submits side blocks). A compromised adapter cannot steal peg funds without mainchain consensus.

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
     - Build + sign pegin witness tx (using elements RPC createrawpegin or raw tx + claimpegin if wallet funded?).
     - Or (simpler v1): call a new `importdrivechaindeposit` RPC (small Elements patch) that credits the target without full pegin witness (trusted because event from enforcer).
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

## Elements Patch Sketch (optional, for clean native feel)
```diff
# src/rpc/blockchain.cpp or wallet/rpc
RPCHelpMan importdrivechaindeposit() { ... }  // credits value to address, records source main outpoint/height for audit/proofs. Bypasses fedpeg witness for drivechain SCs.
```
Or extend fedpeg to support "drivechain" mode where adapter key is the sole trusted claimer (still no multisig federation for the peg security root).

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
