// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_PEG_H
#define BITCOIN_DRIVECHAIN_PEG_H

#include <consensus/amount.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>

#include <univalue.h>

class CCoinsViewCache;

namespace drivechain {

static constexpr int PEG_EVENT_SCHEMA_VERSION{1};

struct DepositIdentity
{
    int sidechain_slot{24};
    std::string sidechain_network;
    std::string mainchain_network;
    std::string mainchain_signet_challenge;
    std::string enforcer_network;
    uint256 mainchain_genesis;
    std::string title;
    std::string hash_id_1;
    std::string hash_id_2;
};

struct AuthenticatedDeposit
{
    int sidechain_slot{0};
    int64_t sequence_number{0};
    COutPoint outpoint;
    CAmount value{0};
    std::string address;
    CScript destination_script;
    uint256 confirmation_block;
    int64_t confirmation_height{0};
    COutPoint current_ctip;
    CAmount current_ctip_value{0};
    int64_t current_ctip_sequence{0};
};

struct CtipState
{
    COutPoint outpoint;
    CAmount value{0};
    int64_t sequence_number{0};

    bool operator==(const CtipState& other) const
    {
        return outpoint == other.outpoint &&
            value == other.value &&
            sequence_number == other.sequence_number;
    }
};

/** Extract reorg-safe BIP300 events committed by one Elements block. */
UniValue ExtractSidechainPegEvents(const CBlock& block, int height, const uint256& previous_bundle_hash);

/** Normalize CUSF GetTwoWayPegData into the versioned explorer event contract. */
UniValue NormalizeL1PegEvents(const UniValue& two_way_peg_data, int sidechain_id);

/**
 * Return the canonical lifecycle state for one withdrawal bundle.
 *
 * A bundle can have an earlier `submitted` event followed by a terminal
 * `succeeded` or `failed` event. The input order is not trusted, terminal
 * outcomes take precedence, and conflicting terminal outcomes fail closed.
 * Returns an empty string when the bundle is absent.
 */
std::string GetWithdrawalBundleStatus(
    const UniValue& two_way_peg_data,
    int sidechain_id,
    const uint256& m6id);

/**
 * Authenticate one deposit against canonical L1/enforcer evidence.
 *
 * This function is side-effect free so the exact fail-closed contract can be
 * regression tested without a live enforcer.
 */
bool AuthenticateDepositEvidence(
    const UniValue& mainchain_info,
    const uint256& mainchain_genesis,
    const UniValue& enforcer_chain_info,
    const UniValue& enforcer_tip,
    const UniValue& sidechains,
    const UniValue& two_way_peg_data,
    const UniValue& ctip,
    const std::string& sidechain_network,
    const DepositIdentity& expected,
    const COutPoint& expected_outpoint,
    CAmount expected_value,
    AuthenticatedDeposit& authenticated,
    std::string& error);

/** Verify that the deposit's L1 block is still confirmed on the active chain. */
bool VerifyDepositBlockConfirmation(
    const UniValue& block_header,
    const AuthenticatedDeposit& authenticated,
    std::string& error);

/** Verify that the enforcer's current CTIP is confirmed and unspent on L1. */
bool VerifyCurrentCtipOutput(
    const UniValue& txout,
    const AuthenticatedDeposit& authenticated,
    std::string& error);

/** Bind authenticated deposit evidence to the exact sidechain transaction. */
bool VerifyDepositTransaction(
    const CTransaction& tx,
    size_t input_index,
    const AuthenticatedDeposit& authenticated,
    std::string& error);

/** Verify a v2 witness or one exact historical v1 checkpoint without I/O. */
bool VerifyDeterministicDeposit(
    const CTransaction& tx,
    size_t input_index,
    const CCoinsViewCache& inputs,
    std::string& error);

/** Bind a v2 proof (or exact historical checkpoint) to the L1 parent in the block. */
bool VerifyDepositEvidenceAnchor(
    const CTransaction& tx,
    size_t input_index,
    const uint256& expected_parent,
    std::string& error);

/** Apply and undo deterministic CTIP state in the existing chainstate database. */
bool ConnectDepositState(
    const CTransaction& tx,
    size_t input_index,
    CCoinsViewCache& inputs,
    int height,
    std::string& error);
bool DisconnectDepositState(
    const CTransaction& tx,
    size_t input_index,
    CCoinsViewCache& inputs,
    int height,
    std::string& error);

/** Read the current authenticated slot-24 CTIP state from a coins view. */
bool GetCtipState(const CCoinsViewCache& inputs, CtipState& state, std::string* error = nullptr);

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_PEG_H
