// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_BMM_H
#define BITCOIN_DRIVECHAIN_BMM_H

#include <primitives/block.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlockIndex;
class CCoinsViewCache;

namespace drivechain {

static constexpr uint8_t BMM_PROOF_SCHEMA_VERSION{1};
static constexpr int BMM_SIDECHAIN_SLOT{24};
static constexpr size_t MAX_BMM_PROOF_ENTRIES{128};
static constexpr size_t MAX_BMM_PROOF_BYTES{1'000'000};

struct BmmL1State
{
    uint256 block_hash;
    uint32_t height{0};
    uint32_t block_time{0};
    uint32_t n_bits{0};
    uint32_t period_start_height{0};
    uint32_t period_start_time{0};
    std::vector<uint32_t> recent_times;

    SERIALIZE_METHODS(BmmL1State, obj)
    {
        READWRITE(
            obj.block_hash,
            obj.height,
            obj.block_time,
            obj.n_bits,
            obj.period_start_height,
            obj.period_start_time,
            obj.recent_times);
    }

    bool operator==(const BmmL1State& other) const
    {
        return block_hash == other.block_hash &&
            height == other.height &&
            block_time == other.block_time &&
            n_bits == other.n_bits &&
            period_start_height == other.period_start_height &&
            period_start_time == other.period_start_time &&
            recent_times == other.recent_times;
    }
};

/**
 * Fail-closed clock context derived from an authenticated BMM chainstate.
 * Values are widened to the u64 representation consumed by ECX public values.
 */
struct BmmParentContext
{
    uint256 block_hash;
    uint64_t height{0};
    uint64_t median_time_past{0};
};

struct BmmProofEntry
{
    std::vector<unsigned char> coinbase_tx;
    std::vector<unsigned char> coinbase_proof;

    SERIALIZE_METHODS(BmmProofEntry, obj)
    {
        READWRITE(obj.coinbase_tx, obj.coinbase_proof);
    }
};

struct BmmProof
{
    uint8_t version{BMM_PROOF_SCHEMA_VERSION};
    BmmL1State previous_state;
    std::vector<BmmProofEntry> entries;

    SERIALIZE_METHODS(BmmProof, obj)
    {
        READWRITE(obj.version, obj.previous_state, obj.entries);
    }
};

struct BmmConsensus
{
    uint256 pow_limit;
    int64_t target_timespan{14 * 24 * 60 * 60};
    int64_t target_spacing{10 * 60};
    CScript signet_challenge;
    int sidechain_slot{BMM_SIDECHAIN_SLOT};
    size_t max_entries{MAX_BMM_PROOF_ENTRIES};
    size_t max_proof_bytes{MAX_BMM_PROOF_BYTES};

    int64_t DifficultyAdjustmentInterval() const
    {
        return target_timespan / target_spacing;
    }
};

/** Fixed LayerTwoLabs public-signet consensus values and immutable bootstrap. */
const BmmConsensus& LayerTwoLabsBmmConsensus();
const BmmL1State& LayerTwoLabsInitialBmmState();
const uint256& LayerTwoLabsPublicSidechainBlock1();
const uint256& LayerTwoLabsPublicSidechainBlock2();

/** Header activation and critical-hash rules for the public slot-24 branch. */
bool BmmProofRequiredAfter(const CBlockIndex* previous);
bool CheckBmmHeader(const CBlockHeader& block, const CBlockIndex* previous, std::string& error);

/** Canonical proof encoding and header commitment. */
bool SerializeBmmProof(const BmmProof& proof, std::vector<unsigned char>& bytes, std::string& error);
bool DeserializeBmmProof(const std::vector<unsigned char>& bytes, BmmProof& proof, std::string& error);
uint256 BmmProofCommitment(const std::vector<unsigned char>& bytes);
bool AttachBmmProof(CBlock& block, const BmmProof& proof, std::string& error);

/** Deterministic proof verification, with injectable parameters for focused tests. */
bool VerifyBmmProof(
    const CBlock& block,
    const BmmL1State& expected_previous,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus);
bool VerifyBmmProofEntries(
    const BmmProof& proof,
    const uint256& expected_critical_hash,
    const uint256& expected_parent_hash,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus);

/** Persist and undo the authenticated parent-chain tip in chainstate. */
bool GetBmmState(const CCoinsViewCache& view, BmmL1State& state, std::string* error = nullptr);
bool GetBmmParentContext(
    const BmmL1State& state,
    BmmParentContext& context,
    std::string& error);
bool GetEffectiveBmmState(
    const CCoinsViewCache& view,
    const CBlockIndex* previous,
    BmmL1State& state,
    std::string& error);
bool ConnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    bool allow_incomplete_candidate,
    std::string& error);
bool DisconnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    std::string& error);

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_BMM_H
