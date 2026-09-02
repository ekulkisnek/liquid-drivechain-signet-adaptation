# Native slot-24 deposits and withdrawals

This guide applies to the current `-chain=elements` node, not the historical
Liquid-signet/ECX bridge. Use a fresh `elements-v11` data directory. Do not
point the current binary at a preserved historical chain.

## Identity and transport

The frozen identity in `src/elements_drivechain_identity.h` specifies slot 24,
Bitcoin-mainnet ancestry, an empty signet challenge, and parent checkpoint
995347 (`000000000000000002838070eb876cd37738a069528efc82d946fbd25e763152`).
This is not a runtime-selectable signet. Sharing Bitcoin's genesis and address
prefixes does not prove a connected node follows the intended parent fork.
Verify the checkpoint, enforcer compatibility revision, proposal identity, and
activation on the intended parent deployment before funding anything.

Follow [RPC security](drivechain-rpc-security.md). Parent access requires
authentication on numeric loopback, preferably a private rotating cookie;
an explicit private credential file is supported for same-host bridges.
Enforcer requests require a private, explicit grpcurl executable and mutual TLS. Keep
`drivechainl1blocksync=0` while preparing or auditing the deployment.
No command below is authorization to spend real funds.

## Deposit

Create/load an Elements wallet and obtain an address that it controls. Create
the slot-24 M5 deposit through the parent wallet/enforcer, recording the exact
outpoint and intended destination. The node authenticates parent headers,
raw blocks, treasury transitions, destination and value from parent replay;
a bridge assertion or wallet balance is not deposit evidence.

After the required active parent depth (100 blocks in the frozen identity):

```sh
elements-cli -chain=elements -rpcwallet=<wallet> importdrivechaindeposit \
  "<mainchain-txid>" <mainchain-vout> "<mainchain-block-hash>" \
  "<elements-address>" <value-sats> <fee-sats>
```

The final fee argument defaults to zero. A nonzero Elements transaction fee
requires separately spendable wallet funds; it does not reduce the authenticated
deposit credit. Record the returned sidechain transaction ID. Check
`gettransaction`, `listunspent`, and the active confirming block, including
after restart. A mempool transaction is not confirmed spendable chain state.
Never substitute a different vout, address, amount, or parent block to work
around a rejection.

## Withdrawal

Withdrawals remain supported. They burn the pegged asset on Elements and
propose a deterministic blinded M6 for BIP300 miner voting. A burn is
irreversible; enforcer acceptance of a proposal does not guarantee payment.

Before creating a burn, check parent synchronization, mTLS connectivity,
destination ownership/network, available balance, sidechain fees, and the
explicit parent fee. Parent address prefixes alone cannot distinguish forks.

```sh
elements-cli -chain=elements -rpcwallet=<wallet> sendtomainchain \
  "<parent-address>" <payout-amount> false true <mainchain-fee>
```

Amounts here are coin-denominated, not satoshis. The verbose result identifies
the transaction and `withdrawal_vout`. With the shown `false` setting,
`burn_amount = payout_amount + mainchain_fee`; the Elements transaction fee
is separate. Save the returned IDs and the block hash once confirmed.

Inspect the exact claim without broadcasting:

```sh
elements-cli -chain=elements getdrivechainwithdrawalbundle \
  "<txid>" <withdrawal-vout> "<confirming-elements-blockhash>" 6
```

Once the burn has six active Elements confirmations, submit that exact claim:

```sh
elements-cli -chain=elements submitdrivechainwithdrawal \
  "<txid>" <withdrawal-vout> "<confirming-elements-blockhash>" 6
```

Six is the RPC's default submission depth; keep it explicit for auditability.
The node checks the active burn block, exact output, deterministic M6, and
authenticated parent payment state. Miners/operators can independently call:

```sh
elements-cli -chain=elements verifydrivechainwithdrawalbundle \
  "<blinded-m6-hex>" "<confirming-elements-blockhash>" 6
```

After a timeout or restart, inspect the same claim before retrying the same
submission arguments. Do not create another burn to recover an uncertain
submission. `getdrivechainwithdrawalbundle` reports `m6id`,
`paid_on_parent_chain`, and, when paid, the parent payment block hash/height.
Submission rejects an already-paid claim. The historical
`drivechainrecoverwithdrawal` journal API is not this native RPC path.

## Completion checks

- Parent replay, enforcer, and Elements agree on the frozen network and slot.
- Deposit UTXOs, amounts and ownership remain correct after restart.
- Withdrawal M6 ID/bytes match before and after restart.
- The authentic parent payment spends the expected treasury and pays the exact
  destination/value. Inspect the parent transaction, not just a UI status.
- Reorgs or lost depth invalidate confirmation assumptions. Recheck both active
  chains before reporting finality.
- BIP300 authorization depends on parent miner voting. A proposal may expire
  or fail; neither a submitted flag nor a sidechain burn means funds arrived.
