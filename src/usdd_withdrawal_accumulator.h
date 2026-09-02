// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_USDD_WITHDRAWAL_ACCUMULATOR_H
#define BITCOIN_USDD_WITHDRAWAL_ACCUMULATOR_H

#include <elements_drivechain_identity.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <string>
#include <vector>

class CBlock;

namespace usdd {

using WithdrawalHash = std::array<unsigned char, 32>;
using EthereumAddress = std::array<unsigned char, 20>;

static constexpr uint8_t WITHDRAWAL_ACCUMULATOR_VERSION{
    ElementsDrivechainIdentity::WITHDRAWAL_ACCUMULATOR_VERSION};
static constexpr uint32_t WITHDRAWAL_PROTOCOL_VERSION{
    ElementsDrivechainIdentity::WITHDRAWAL_PROTOCOL_VERSION};
static constexpr size_t WITHDRAWAL_ACCUMULATOR_DEPTH{
    ElementsDrivechainIdentity::WITHDRAWAL_TREE_DEPTH};
static constexpr uint64_t USDD_UNITS_PER_USDT_MICRO{
    ElementsDrivechainIdentity::USDD_UNITS_PER_USDT_MICRO};
static constexpr uint64_t MAX_WITHDRAWAL_USDT_MICRO{
    ElementsDrivechainIdentity::MAX_WITHDRAWAL_USDT_MICRO};

/** One exact, explicit Elements burn output destined for Ethereum. */
struct EthereumWithdrawalClaim {
    WithdrawalHash elements_genesis{};
    WithdrawalHash asset_id{};
    WithdrawalHash vault_id{};
    WithdrawalHash burn_txid_display{};
    uint32_t burn_vout{0};
    WithdrawalHash burn_id{};
    uint64_t claim_index{0};
    uint64_t amount_usdt_micro{0};
    EthereumAddress recipient{};
    WithdrawalHash leaf{};

    bool operator==(const EthereumWithdrawalClaim& other) const
    {
        return elements_genesis == other.elements_genesis && asset_id == other.asset_id &&
            vault_id == other.vault_id && burn_txid_display == other.burn_txid_display &&
            burn_vout == other.burn_vout && burn_id == other.burn_id &&
            claim_index == other.claim_index && amount_usdt_micro == other.amount_usdt_micro &&
            recipient == other.recipient && leaf == other.leaf;
    }
};

/** Reorg-safe append-only depth-64 sparse-Merkle state at one block. */
struct WithdrawalAccumulatorState {
    uint64_t count{0};
    WithdrawalHash root{};
    std::array<WithdrawalHash, WITHDRAWAL_ACCUMULATOR_DEPTH> frontier{};

    static WithdrawalAccumulatorState Empty();
    bool IsSane() const;
    bool Append(const WithdrawalHash& leaf, std::string* error = nullptr);

    bool operator==(const WithdrawalAccumulatorState& other) const
    {
        return count == other.count && root == other.root && frontier == other.frontier;
    }

    SERIALIZE_METHODS(WithdrawalAccumulatorState, obj)
    {
        uint8_t version{WITHDRAWAL_ACCUMULATOR_VERSION};
        READWRITE(version);
        SER_READ(obj, {
            if (version != WITHDRAWAL_ACCUMULATOR_VERSION) {
                throw std::ios_base::failure("unsupported USDD withdrawal accumulator version");
            }
        });
        READWRITE(obj.count);
        SER_WRITE(obj, s.write(MakeByteSpan(obj.root)));
        SER_READ(obj, s.read(MakeWritableByteSpan(obj.root)));
        for (size_t level = 0; level < WITHDRAWAL_ACCUMULATOR_DEPTH; ++level) {
            const bool occupied = ((obj.count >> level) & 1U) != 0;
            if (occupied) {
                SER_WRITE(obj, s.write(MakeByteSpan(obj.frontier[level])));
                SER_READ(obj, s.read(MakeWritableByteSpan(obj.frontier[level])));
            } else {
                SER_READ(obj, obj.frontier[level].fill(0));
            }
        }
        SER_READ(obj, {
            if (!obj.IsSane()) {
                throw std::ios_base::failure("malformed USDD withdrawal accumulator state");
            }
        });
    }
};

/** Bottom-up 64-sibling membership proof matching USDDVaultV1. */
struct WithdrawalInclusionProof {
    EthereumWithdrawalClaim claim;
    std::array<WithdrawalHash, WITHDRAWAL_ACCUMULATOR_DEPTH> siblings{};
};

WithdrawalHash WithdrawalEmptyRoot(size_t height);
WithdrawalHash WithdrawalNode(const WithdrawalHash& left, const WithdrawalHash& right);
WithdrawalHash ComputeWithdrawalAccumulatorRoot(const WithdrawalAccumulatorState& state);
WithdrawalHash ComputeWithdrawalBurnId(const WithdrawalHash& elements_genesis,
                                       const WithdrawalHash& txid_display,
                                       uint32_t vout);
WithdrawalHash ComputeWithdrawalLeaf(const EthereumWithdrawalClaim& claim);

/**
 * Extract exact minimal `OP_RETURN PUSH65 "USDD" ...` burns in transaction and
 * vout order, assigning contiguous indices beginning at `first_index`.
 * Asset and value must be explicit and value must equal `amountUSDT6 * 100`.
 * Noncanonical lookalikes are ignored.
 */
bool ExtractEthereumWithdrawals(const CBlock& block,
                                const uint256& elements_genesis,
                                uint64_t first_index,
                                std::vector<EthereumWithdrawalClaim>& claims,
                                std::string* error = nullptr);

bool ApplyEthereumWithdrawals(const CBlock& block,
                              const uint256& elements_genesis,
                              const WithdrawalAccumulatorState& previous,
                              WithdrawalAccumulatorState& next,
                              std::vector<EthereumWithdrawalClaim>* claims = nullptr,
                              std::string* error = nullptr);

/**
 * Compute the sole slot-24 BIP301 critical-hash meaning for this network.
 *
 * The preimage is, without a trailing NUL:
 *
 *   domain || version_u32be || elementsGenesis_display || slot_u8 ||
 *   blockHash_display || previousCount_u64be || previousRoot ||
 *   nextCount_u64be || nextRoot
 *
 * and the result is one SHA-256 digest represented as a display-order uint256.
 * The enforcer treats this value as opaque. Elements consensus is responsible
 * for deriving `next` from the fully validated candidate block. A transition
 * must change both count and root or neither; count-only and root-only changes
 * are rejected before hashing.
 */
bool ComputeWithdrawalBip301CriticalHash(
    const uint256& elements_genesis,
    uint8_t sidechain_slot,
    const uint256& block_hash,
    const WithdrawalAccumulatorState& previous,
    const WithdrawalAccumulatorState& next,
    uint256& critical_hash,
    std::string* error = nullptr);

/** Derive `next` from `block`, then compute the exact BIP301 critical hash. */
bool DeriveWithdrawalBip301CriticalHash(
    const CBlock& block,
    const uint256& elements_genesis,
    uint8_t sidechain_slot,
    const WithdrawalAccumulatorState& previous,
    WithdrawalAccumulatorState& next,
    uint256& critical_hash,
    std::string* error = nullptr);

/** Build and verify a proof from the complete contiguous leaf prefix. */
bool BuildWithdrawalInclusionProof(const std::vector<EthereumWithdrawalClaim>& claims,
                                   uint64_t index,
                                   WithdrawalInclusionProof& proof,
                                   WithdrawalHash& root,
                                   std::string* error = nullptr);

} // namespace usdd

#endif // BITCOIN_USDD_WITHDRAWAL_ACCUMULATOR_H
