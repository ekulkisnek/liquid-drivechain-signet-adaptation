// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H
#define BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace wallet {

struct DrivechainWithdrawalBundle {
    /** SegWit-encoded blinded M6 bytes accepted by the enforcer. */
    std::vector<unsigned char> bytes;
    /** Transaction id computed from the canonical no-witness serialization. */
    uint256 m6id;
};

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height);

} // namespace wallet

#endif // BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H
