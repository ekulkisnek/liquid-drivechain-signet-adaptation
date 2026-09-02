// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_WITHDRAWAL_H
#define BITCOIN_DRIVECHAIN_WITHDRAWAL_H

#include <consensus/amount.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class CTxOutWitness;

namespace drivechain {

static constexpr size_t NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE{128};
static constexpr size_t NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE{74};
// Version, zero vin, three bounded outputs, and locktime. The longest form
// carries a 128-byte payout script and is exactly 251 bytes.
static constexpr size_t NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE{251};
using NativeWithdrawalCommitment =
    std::array<unsigned char, NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE>;

/** One canonical pegged-asset burn requesting a native BIP300 payout. */
struct NativeWithdrawal
{
    uint256 parent_genesis;
    CScript destination;
    CAmount burn_amount{0};
    CAmount parent_fee{0};
    CAmount payout_amount{0};
};

/**
 * The zero-input legacy serialization whose txid is the BIP300 M6id.
 *
 * This is not a broadcastable Bitcoin transaction. The real M6 replaces its
 * zero-input/fee-commitment form with the current treasury input and output;
 * ComputeDrivechainM6Id blinds the real transaction back to this form.
 */
struct NativeWithdrawalM6
{
    Sidechain::Bitcoin::CMutableTransaction blinded_transaction;
    NativeWithdrawalCommitment burn_commitment{};
    CAmount burn_amount{0};
    CAmount parent_fee{0};
    CAmount payout_amount{0};
    CScript destination;
    std::vector<unsigned char> legacy_serialization;
    uint256 m6id;
};

/** Build the exact OP_RETURN withdrawal script, including an eight-byte BE fee. */
bool BuildNativeWithdrawalScript(const uint256& parent_genesis,
                                 const CScript& destination,
                                 CAmount parent_fee,
                                 CScript& script,
                                 std::string* error = nullptr);

/** Parse only the exact minimally-pushed native withdrawal script. */
bool ParseNativeWithdrawalScript(const CScript& script,
                                 const uint256& expected_parent_genesis,
                                 CScript& destination,
                                 CAmount& parent_fee,
                                 std::string* error = nullptr);

/** Build an explicit pegged-asset burn output. Its output witness must stay empty. */
bool BuildNativeWithdrawalOutput(const CAsset& pegged_asset,
                                 const uint256& parent_genesis,
                                 const CScript& destination,
                                 CAmount burn_amount,
                                 CAmount parent_fee,
                                 CTxOut& output,
                                 std::string* error = nullptr);

/**
 * Parse and validate a burn output. A null witness pointer means the
 * transaction has no serialized witness entry for this output.
 */
bool ParseNativeWithdrawalOutput(const CTxOut& output,
                                 const CTxOutWitness* output_witness,
                                 const CAsset& expected_pegged_asset,
                                 const uint256& expected_parent_genesis,
                                 NativeWithdrawal& withdrawal,
                                 std::string* error = nullptr);

/**
 * Construct the directly parseable, domain-separated M6 burn reference:
 *
 *   "ELWD" || version=1 || elementsGenesisConsensusBytes || slot
 *          || burnTxidConsensusBytes || burnVoutBE
 *
 * Its 74-byte payload produces a 76-byte canonical OP_RETURN script, below
 * Bitcoin Core's 83-byte standard nulldata limit.
 */
NativeWithdrawalCommitment ComputeNativeWithdrawalM6Commitment(
    const uint256& elements_genesis,
    uint8_t sidechain_slot,
    const uint256& burn_txid,
    uint32_t burn_vout);

/** Recover the Elements chain and burn outpoint directly from M6 vout 1. */
bool ParseNativeWithdrawalM6Commitment(
    const CScript& commitment_script,
    uint256& elements_genesis,
    uint8_t& sidechain_slot,
    uint256& burn_txid,
    uint32_t& burn_vout,
    std::string* error = nullptr);

/** Serialize the blinded zero-input template without SegWit marker ambiguity. */
std::vector<unsigned char> SerializeNativeWithdrawalM6Legacy(
    const Sidechain::Bitcoin::CMutableTransaction& transaction);

/** Parse one exact legacy transaction serialization and reject trailing bytes. */
bool DeserializeNativeWithdrawalM6Legacy(
    const std::vector<unsigned char>& bytes,
    Sidechain::Bitcoin::CMutableTransaction& transaction,
    std::string* error = nullptr);

/** Double-SHA256 of the exact legacy serialization. */
uint256 ComputeNativeWithdrawalM6Id(
    const Sidechain::Bitcoin::CMutableTransaction& blinded_transaction);

/** Build the unique blinded M6 template after the burn outpoint is known. */
bool BuildNativeWithdrawalM6(const uint256& elements_genesis,
                             uint8_t sidechain_slot,
                             const uint256& burn_txid,
                             uint32_t burn_vout,
                             const NativeWithdrawal& withdrawal,
                             NativeWithdrawalM6& m6,
                             std::string* error = nullptr);

/** Parse an exact blinded M6 and authenticate its burn-outpoint commitment. */
bool ParseNativeWithdrawalM6(
    const Sidechain::Bitcoin::CMutableTransaction& blinded_transaction,
    const uint256& elements_genesis,
    uint8_t sidechain_slot,
    const uint256& burn_txid,
    uint32_t burn_vout,
    NativeWithdrawalM6& m6,
    std::string* error = nullptr);

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_WITHDRAWAL_H
