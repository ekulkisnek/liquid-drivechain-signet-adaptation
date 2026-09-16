// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TX_CHECK_H
#define BITCOIN_CONSENSUS_TX_CHECK_H

/**
 * Context-independent transaction checking code that can be called outside the
 * bitcoin server and doesn't depend on chain or mempool state. Transaction
 * verification code that does call server functions or depend on server state
 * belongs in tx_verify.h/cpp instead.
 */

class CTransaction;
class TxValidationState;

// Per-asset totals are opt-in; callers without authenticated activation context
// retain historical aggregate validation.
bool CheckTransaction(const CTransaction& tx, TxValidationState& state);
bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool explicit_asset_totals);
// Only for height-independent block screening. Full totals must be checked
// again with authenticated height in ContextualCheckBlock and ConnectBlock.
bool CheckTransactionWithoutAggregateTotals(const CTransaction& tx, TxValidationState& state);

#endif // BITCOIN_CONSENSUS_TX_CHECK_H
