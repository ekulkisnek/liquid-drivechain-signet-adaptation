# Protocol boundary and security model — prototype v1

## Scope

This is one fixed-session collateral covenant for one owner and one protected
outpoint, plus an exact double-authorization witness and penalty transaction.
It is not an implementation of transferable off-chain ownership. In particular,
recovering **collateral** with this contract is not the same as giving a later
recipient a valid exit for their **principal**.

The user chose separate collateral, user (not matcher) penalties, payment to
miners, unilateral recovery, and retaining the frozen sequencer if needed.
Simplicity was selected over a new Groth16 covenant because the required
hash/signature/introspection operations already exist in the reviewed node.
No new trusted setup, proof circuit, verifier ABI, custom jet or ZK privacy
claim is introduced.

## Immutable contract configuration

`GENESIS`, `FEE_ASSET`, `OWNER`, `MATCHER`, `PROTECTED_TXID`, `PROTECTED_VOUT`,
`EPOCH`, `COLLATERAL`, `ACTIVE_UNTIL`, `REFUND_HEIGHT` and the protocol domain
are committed through the program CMR and Taproot output. The library fixes
the domain and NUMS internal key. The owner and matcher must differ.

The canonical library constructor supplies exactly one Simplicity leaf at
version `0xbe` and the BIP341 NUMS point as internal key. Receivers must reject
alternative trees/internal keys. A contract with a known-secret key-path escape
is not a bond even if it also contains the correct Simplicity script.

The collateral must be explicit, positive, in the deployment's native fee
asset, and separate from the protected output. One bond covers one fixed
protected outpoint/session. Neither automatic rollover nor pooled/reusable
collateral capacity is implemented. A signature cannot migrate to another
collateral outpoint. Do not count the same bond as independent coverage for
multiple promises.

## Transfer authorization format

All hashes below are 32-byte internal/consensus-order bytes, not the reversed
RPC/display form of a transaction ID. Integers are unsigned big-endian.

```text
message = SHA256(
    SHA256("ECX/PreconfUserBond/TransferAuthorization/v1")
    || genesis[32]
    || collateral_txid[32] || collateral_vout[4]
    || SHA256(collateral_scriptPubKey)[32]
    || protected_txid[32] || protected_vout[4]
    || epoch[8] || active_until[4] || refund_height[4]
    || authorized_spending_txid[32]
)
certificate = (authorized_spending_txid, owner_BIP340_signature, matcher_BIP340_signature)
```

Both signatures cover the same message. This is a new explicit certificate
domain, not a reinterpretation of arbitrary existing matcher messages. The
transaction ID commits non-witness transaction data, including outputs. Signing
two different transaction IDs for the same subject/session is slashable;
signing the same ID twice, even with different signature randomness, is not.

The owner, matcher and recipient must obtain and validate the actual proposed
transaction before signing/accepting: it consumes the protected output, has
valid ownership authorization, exact asset/amount destinations, acceptable
fees and no incompatible prior state. The library's
`check_authorization_subject` is **only an application-specific structural
filter**. `check_authorized_transaction` also asks the caller's trusted node to
validate the exact serialized transaction with `testmempoolaccept`, requiring
an affirmative result for the same txid. It reuses the CLI's RPC authentication
and transport; callers must configure the trusted executable, intended network,
datadir and connection timeout. It does not broadcast. Node acceptance is a
point-in-time consensus/policy check, not a reservation, deployment/profile
authentication, recipient approval, or proof that a future spend will succeed.
Callers still enforce destinations, fee limits and protocol state before signing.
The on-chain evidence verifies signed authorizations; it does not
decode/revalidate the two original raw transactions or prove their publication.

Quotes, abandoned drafts, backup transactions, unilateral exits, RBF updates
and valid later-owner transfers MUST NOT be signed in this domain for the same
fixed state. A different owner/state needs its own authenticated authorization
context; this prototype deliberately does not infer such histories.

## Spending paths

| Path | Witness | On-chain conditions |
| --- | --- | --- |
| Penalty | Two different certificates | Both owner signatures and both matcher signatures valid for this bond; exactly one bond input and one explicit fee output; entire collateral to fees in the same asset. |
| Cooperative release | Owner + matcher transaction signatures | Both sign `sig_all_hash`; height lock reaches `REFUND_HEIGHT`. |
| Unilateral recovery | Owner transaction signature | Owner signs `sig_all_hash`; same height lock reaches `REFUND_HEIGHT`; matcher can be offline. |

No pegin or issuance input is accepted. Penalty construction does not consume
the protected principal. Refund signatures bind all outputs and transaction
context. Unilateral recovery makes the cooperative path optional; retaining
that path preserves explicit normal matcher authorization without trusting the
matcher to unlock the bond early. Recovery cannot prove that no unpublished
conflicting signature exists; it instead enforces the finite challenge window.

`check_lock_height` checks the transaction's effective height lock. The full
node, not this contract, checks that the actual chain has reached that lock.
An interpreter test accepting `nLockTime = REFUND_HEIGHT` is **not evidence**
that it would be mined before that height. Timestamp locks and final input
sequences cannot bypass the height condition. This prototype does not use the
upstream `broken_do_not_use_*lock_distance` jets.

## Expiry, withholding and miner limitations

Before `ACTIVE_UNTIL`, a future matcher/receiver service may accept certificates
only after independently validating the chain, confirmed separate collateral,
unspent status, protected principal, exposure limits and the contract profile.
At/after that cutoff it must reject new promises. It must stop early if reorgs,
data availability or remaining settlement/challenge time become unsafe.

The script cannot authenticate when an off-chain signature was created and
does not implement those acceptance rules. The interval between `ACTIVE_UNTIL`
and `REFUND_HEIGHT` is the period for publishing evidence/settling outstanding
activity. The numeric ten-block interval in examples is not a deployment policy.
Honest users/watchers need enough chain access and inclusion opportunity to act.
Monitoring/data availability and withholding attacks remain protocol obligations.

The penalty is possible whenever the collateral is still unspent, even after
the recovery deadline. Once a valid recovery spends it, a later proof cannot
slash a nonexistent UTXO. After the deadline a refund can race a penalty;
miners are not forced to select the higher-fee penalty and may censor it.
Paying collateral to miners is neither compensation for victims nor protection
against a miner controlling the offender. No unconditional security claim rests
on the offender always suffering an economic loss.

## Explicit trust and non-goals

- Matcher co-signatures remain required for these certificates. The matcher can
  halt the fast path. A malicious matcher cannot fabricate the owner's two
  signatures, but this contract does not solve matcher equivocation, collusion,
  censorship or withholding by itself.
- Burning collateral does not choose the rightful recipient among conflicting
  promises. It does not make unconfirmed tokens safe to re-spend by itself.
- No transfer-of-key-share protocol, revocation of old principal owners,
  latest-owner exit, split/merge, atomic two-asset trade, balance database,
  wallet integration or settlement batching is included.
- The fixed owner cannot simply be replaced on later transfers. Repeated
  off-chain transfer of one UTXO needs authenticated ownership-state transitions
  and an exit protocol, not changes to this certificate's interpretation.
- Collateral sizing for volatile assets, hidden liabilities, miner collusion,
  fee-market outages, cross-chain replays and reorg exposure need full protocol
  analysis. Even a large bond does not replace ownership correctness.
- Explicit collateral and public fraud evidence provide no confidentiality.

## Consensus impact and integration checklist

**Current change: zero consensus rules changed.** This is a new optional output
program using existing standard jets and the node's existing Simplicity leaf
version. No hardcoded node matcher value, receipt catalogue or ECX state machine
was modified. The matcher public key is immutable *within each covenant*, but
its equality to the authenticated deployed frozen profile must be verified by
wallets/recipients. This library does not claim to retrieve that profile.

Before accepting even test-network deposits:

1. Authenticate the actual genesis, native asset, frozen matcher key/epoch and
   deployed binary revision. Confirm that validators enforce Simplicity. A
   pre-activation soft-fork leaf may otherwise not enforce the desired rules.
2. Have JK agree to the exact certificate encoding, fixed-session restriction,
   lock duration and prohibition on early collateral release. Integrate the
   domain into his signing service without allowing arbitrary message signing.
3. Run funded, isolated **full-node regtest**: fund with confirmed collateral,
   validate real principal spends, reject premature refund in mempool and blocks,
   mine a penalty, verify fee accounting and UTXO removal, and mine an honest
   refund only after expiry. Repeat for restarts, reorgs and conflicting spends.
4. Connect independently verified wallet/watchtower state and the separate
   protected-principal protocol. Prove latest-recipient recovery with the matcher
   offline before describing received balances as safely re-spendable.
5. Obtain independent review of the scripts, compiler/runtime versions,
   cryptographic domains and economic assumptions.

If future work needs custom jets or new consensus validation, list the exact
validation changes, serialization/activation rules, backward compatibility and
negative block tests in a separate proposal. Do not silently activate them in
this template or deploy this experiment onto the live node.
