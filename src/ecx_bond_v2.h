// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef BITCOIN_ECX_BOND_V2_H
#define BITCOIN_ECX_BOND_V2_H

#include <serialize.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>

namespace ecx {

static constexpr uint16_t BOND_V2_CAPITAL_SNAPSHOT_VERSION{4};

/** Serialize fixed public integers without a length prefix. */
struct FixedByteArrayFormatter
{
    template <typename Stream, size_t N>
    void Ser(Stream& stream, const std::array<unsigned char, N>& value)
    {
        stream.write(MakeByteSpan(value));
    }

    template <typename Stream, size_t N>
    void Unser(Stream& stream, std::array<unsigned char, N>& value)
    {
        stream.read(MakeWritableByteSpan(value));
    }
};

/** Canonical unsigned 128-bit integer stored in network byte order. */
struct BigEndianUint128
{
    std::array<unsigned char, 16> bytes{};

    BigEndianUint128() = default;
    BigEndianUint128(uint64_t value) { *this = value; }

    BigEndianUint128& operator=(uint64_t value)
    {
        bytes.fill(0);
        for (size_t i = 0; i < 8; ++i) {
            bytes[15 - i] = static_cast<unsigned char>(value & 0xff);
            value >>= 8;
        }
        return *this;
    }

    bool FitsU64() const
    {
        return std::all_of(bytes.begin(), bytes.begin() + 8,
            [](unsigned char byte) { return byte == 0; });
    }

    bool ToU64(uint64_t& value) const
    {
        if (!FitsU64()) return false;
        value = 0;
        for (size_t i = 8; i < 16; ++i) value = (value << 8) | bytes[i];
        return true;
    }

    bool Increment()
    {
        for (auto cursor = bytes.rbegin(); cursor != bytes.rend(); ++cursor) {
            ++*cursor;
            if (*cursor != 0) return true;
        }
        return false;
    }

    friend bool operator==(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return left.bytes == right.bytes;
    }
    friend bool operator!=(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return !(left == right);
    }
    friend bool operator<(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return left.bytes < right.bytes;
    }
    friend bool operator>(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return right < left;
    }
    friend bool operator<=(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return !(right < left);
    }
    friend bool operator>=(const BigEndianUint128& left, const BigEndianUint128& right)
    {
        return !(left < right);
    }
    friend std::ostream& operator<<(std::ostream& stream, const BigEndianUint128& value)
    {
        static constexpr char HEX[]{"0123456789abcdef"};
        stream << "0x";
        for (const unsigned char byte : value.bytes) {
            stream << HEX[byte >> 4] << HEX[byte & 0x0f];
        }
        return stream;
    }

    SERIALIZE_METHODS(BigEndianUint128, obj)
    {
        READWRITE(Using<FixedByteArrayFormatter>(obj.bytes));
    }
};

/**
 * Public-only projection extracted from an exact, verified PublicValuesV5.
 * Confidential account/order/position/action amounts never enter this record.
 * It is stored under a separate block-index database key, so legacy block-index
 * serialization and every existing header byte remain unchanged.
 */
struct BondV2CapitalSnapshot
{
    uint16_t version{BOND_V2_CAPITAL_SNAPSHOT_VERSION};
    /** 0 = finite PublicValuesV5, 1 = incremental successor public values. */
    uint8_t proof_profile{0};
    uint256 exchange_state_root;
    uint256 configuration_hash;
    uint256 bond_asset_id;
    uint256 bond_deployment_commitment;
    uint256 transition_program_id;
    uint256 transition_cmr;
    /** Exact successor covenant state committed by output zero's P2TR key. */
    uint256 covenant_state_hash;
    uint256 bond_state_root;
    uint256 funding_state_root;
    uint256 bond_inventory_covenant_hash;
    std::array<unsigned char, 16> insurance_reserve{};
    uint64_t issued_share_atoms{0};
    uint64_t outstanding_share_atoms{0};
    uint64_t inventory_share_atoms{0};
    std::array<unsigned char, 16> nav_per_whole_share{};
    std::array<unsigned char, 16> full_bound_deficit{};
    std::array<unsigned char, 16> target_reserve{};
    std::array<unsigned char, 16> coverage_bps{};
    uint8_t capital_mode{0};
    std::array<unsigned char, 16> controlled_usdd_atoms{};
    uint64_t minimum_authenticated_price{0};
    uint64_t maximum_authenticated_price{0};
    uint64_t funding_epoch{0};
    int32_t funding_rate_ppm{0};
    std::array<unsigned char, 16> global_funding_index_numerator{};
    uint256 redemption_queue_root;
    BigEndianUint128 redemption_head;
    BigEndianUint128 redemption_tail;
    uint64_t queued_redemption_share_atoms{0};
    uint256 oracle_certificate_hash;
    uint64_t oracle_valid_through_parent_mtp{0};
    uint8_t oracle_mode{0};
    uint256 encrypted_availability_root;
    /** Inbox state authenticated by the successor covenant. */
    uint256 bond_inbox_head_root;
    BigEndianUint128 bond_inbox_entry_count;
    uint256 bond_inbox_processed_root;
    BigEndianUint128 bond_inbox_processed_cursor;
    uint256 bond_inbox_outcome_root;
    BigEndianUint128 bond_inbox_outcome_count;
    /** Node-derived source head after scanning this block.  This may lead the
     * covenant head by one block and is the exact head the next transition
     * must bind. */
    uint256 node_bond_inbox_head_root;
    BigEndianUint128 node_bond_inbox_entry_count;
    uint256 matcher_execution_receipt_batch_root;
    BigEndianUint128 previous_matcher_execution_sequence;
    BigEndianUint128 matcher_execution_sequence;
    uint64_t last_transition_sidechain_height{0};
    uint8_t operationally_safe{0};
    std::array<unsigned char, 16> legacy_fee_pool{};

    SERIALIZE_METHODS(BondV2CapitalSnapshot, obj)
    {
        READWRITE(
            obj.version,
            obj.proof_profile,
            obj.exchange_state_root,
            obj.configuration_hash,
            obj.bond_asset_id,
            obj.bond_deployment_commitment,
            obj.transition_program_id,
            obj.transition_cmr,
            obj.covenant_state_hash,
            obj.bond_state_root,
            obj.funding_state_root,
            obj.bond_inventory_covenant_hash,
            Using<FixedByteArrayFormatter>(obj.insurance_reserve),
            obj.issued_share_atoms,
            obj.outstanding_share_atoms,
            obj.inventory_share_atoms,
            Using<FixedByteArrayFormatter>(obj.nav_per_whole_share),
            Using<FixedByteArrayFormatter>(obj.full_bound_deficit),
            Using<FixedByteArrayFormatter>(obj.target_reserve),
            Using<FixedByteArrayFormatter>(obj.coverage_bps),
            obj.capital_mode,
            Using<FixedByteArrayFormatter>(obj.controlled_usdd_atoms),
            obj.minimum_authenticated_price,
            obj.maximum_authenticated_price,
            obj.funding_epoch,
            obj.funding_rate_ppm,
            Using<FixedByteArrayFormatter>(obj.global_funding_index_numerator),
            obj.redemption_queue_root,
            obj.redemption_head,
            obj.redemption_tail,
            obj.queued_redemption_share_atoms,
            obj.oracle_certificate_hash,
            obj.oracle_valid_through_parent_mtp,
            obj.oracle_mode,
            obj.encrypted_availability_root,
            obj.bond_inbox_head_root,
            obj.bond_inbox_entry_count,
            obj.bond_inbox_processed_root,
            obj.bond_inbox_processed_cursor,
            obj.bond_inbox_outcome_root,
            obj.bond_inbox_outcome_count,
            obj.node_bond_inbox_head_root,
            obj.node_bond_inbox_entry_count,
            obj.matcher_execution_receipt_batch_root,
            obj.previous_matcher_execution_sequence,
            obj.matcher_execution_sequence,
            obj.last_transition_sidechain_height,
            obj.operationally_safe,
            Using<FixedByteArrayFormatter>(obj.legacy_fee_pool));
    }
};

} // namespace ecx

#endif // BITCOIN_ECX_BOND_V2_H
