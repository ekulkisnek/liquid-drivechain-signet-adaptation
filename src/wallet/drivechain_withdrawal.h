// Copyright (c) 2026 The Elements Core developers
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

inline constexpr const char* DRIVECHAIN_WITHDRAWAL_DESTINATION_KEY{
    "drivechain_withdrawal_destination"};
inline constexpr const char* DRIVECHAIN_WITHDRAWAL_AMOUNT_KEY{
    "drivechain_withdrawal_amount"};
inline constexpr const char* DRIVECHAIN_WITHDRAWAL_MAIN_FEE_KEY{
    "drivechain_withdrawal_main_fee"};
inline constexpr const char* DRIVECHAIN_WITHDRAWAL_PAYOUT_SCRIPT_KEY{
    "drivechain_withdrawal_payout_script"};

struct DrivechainWithdrawalBundle {
    std::vector<unsigned char> bytes;
    uint256 m6id;
};

/** Pure native inputless M6 codec; does not authorize a burn or broadcast. */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height);

/** Build the exact ECX-bound BIP300 M6 bytes for a confirmed withdrawal. */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root);

} // namespace wallet

#endif // BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H
