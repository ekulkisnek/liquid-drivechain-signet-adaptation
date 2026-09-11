// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <map>

static bool CheckTransactionImpl(const CTransaction&, TxValidationState&, bool, bool);

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    return CheckTransaction(tx, state, false);
}

bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool explicit_asset_totals)
{
    return CheckTransactionImpl(tx, state, explicit_asset_totals, false);
}

bool CheckTransactionWithoutAggregateTotals(const CTransaction& tx, TxValidationState& state)
{
    return CheckTransactionImpl(tx, state, false, true);
}

static bool CheckTransactionImpl(const CTransaction& tx, TxValidationState& state, bool explicit_asset_totals, bool defer_totals)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOutExplicit = 0;
    std::map<CAsset, CAmount> asset_totals;
    for (const auto& txout : tx.vout)
    {
        if (!txout.nValue.IsValid())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-amount-invalid");
        if (!txout.nValue.IsExplicit())
            continue;
        if (txout.nValue.GetAmount() < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue.GetAmount() > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        if (defer_totals) continue;
        // The activated explicit-only rule supplies public asset identities.
        // Never treat an unknown/confidential asset as a distinct public asset.
        if (explicit_asset_totals && !txout.nAsset.IsExplicit())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-asset-not-explicit");
        CAmount& total = explicit_asset_totals ? asset_totals[txout.nAsset.GetAsset()] : nValueOutExplicit;
        if (txout.nValue.GetAmount() > MAX_MONEY - total)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
        total += txout.nValue.GetAmount();
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");

        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            if (tx.vout[i].IsFee()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-fee");
            }
        }
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
