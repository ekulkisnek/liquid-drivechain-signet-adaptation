// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <wallet/drivechain_withdrawal.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <limits>
#include <stdexcept>

namespace wallet {
namespace {
static void PushLE32(std::vector<unsigned char>& bytes, uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        bytes.push_back((value >> (8 * i)) & 0xff);
    }
}

static void PushLE64(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        bytes.push_back((value >> (8 * i)) & 0xff);
    }
}

static void PushCompactSize(std::vector<unsigned char>& bytes, uint64_t value)
{
    if (value < 253) {
        bytes.push_back(value);
    } else if (value <= std::numeric_limits<uint16_t>::max()) {
        bytes.push_back(253);
        bytes.push_back(value & 0xff);
        bytes.push_back((value >> 8) & 0xff);
    } else if (value <= std::numeric_limits<uint32_t>::max()) {
        bytes.push_back(254);
        PushLE32(bytes, value);
    } else {
        bytes.push_back(255);
        PushLE64(bytes, value);
    }
}

static void PushBitcoinTxOut(std::vector<unsigned char>& bytes, CAmount amount, const CScript& script_pubkey)
{
    if (amount < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BIP300 withdrawal output amount cannot be negative");
    }
    PushLE64(bytes, amount);
    PushCompactSize(bytes, script_pubkey.size());
    bytes.insert(bytes.end(), script_pubkey.begin(), script_pubkey.end());
}

static std::vector<unsigned char> ToByteVector(const uint256& value)
{
    return std::vector<unsigned char>(value.begin(), value.end());
}

static uint256 DrivechainInputsCommitment(
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height)
{
    std::vector<COutPoint> committed_inputs;
    committed_inputs.push_back(withdrawal_outpoint);
    committed_inputs.emplace_back(Txid{}, sidechain_block_height);
    return (HashWriter{} << committed_inputs).GetHash();
}

static CScript BuildDrivechainInputsCommitmentScript(const uint256& commitment)
{
    return CScript() << OP_RETURN << ToByteVector(commitment);
}

static uint256 Sha256(const std::vector<unsigned char>& bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

static uint256 TaggedHash(
    const std::string& tag,
    const std::vector<unsigned char>& payload)
{
    const std::vector<unsigned char> tag_bytes(tag.begin(), tag.end());
    const uint256 tag_hash = Sha256(tag_bytes);
    uint256 result;
    CSHA256 hasher;
    hasher.Write(tag_hash.begin(), 32);
    hasher.Write(tag_hash.begin(), 32);
    if (!payload.empty()) hasher.Write(payload.data(), payload.size());
    hasher.Finalize(result.begin());
    return result;
}

static void PushBE32(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back((value >> 24) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back(value & 0xff);
}

static uint256 BuildWithdrawalStateAnchor(
    const uint256& child_genesis,
    uint32_t checkpoint_height,
    const uint256& previous_child_hash,
    const uint256& withdrawal_commitment,
    const uint256& exchange_state_root)
{
    if (child_genesis.IsNull() || withdrawal_commitment.IsNull() ||
        exchange_state_root.IsNull()) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Cannot create PXST marker with a null consensus commitment");
    }
    std::vector<unsigned char> payload;
    payload.reserve(134);
    payload.push_back(1);  // PXST interface version
    payload.push_back(24); // LayerTwoLabs BIP300 sidechain slot
    payload.insert(payload.end(), child_genesis.begin(), child_genesis.end());
    PushBE32(payload, checkpoint_height);
    payload.insert(
        payload.end(), previous_child_hash.begin(), previous_child_hash.end());
    payload.insert(
        payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    payload.insert(
        payload.end(), exchange_state_root.begin(), exchange_state_root.end());
    return TaggedHash("ECX/perps-m6-state/v1", payload);
}

static CScript BuildWithdrawalStateMarkerScript(const uint256& anchor)
{
    std::vector<unsigned char> marker{'P', 'X', 'S', 'T', 1};
    marker.insert(marker.end(), anchor.begin(), anchor.end());
    return CScript() << OP_RETURN << marker;
}



DrivechainWithdrawalBundle BuildBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    const CScript* state_marker)
{
    if (!MoneyRange(amount) || amount == 0 || !MoneyRange(mainchain_fee) ||
        mainchain_fee >= amount || payout_script.empty() ||
        payout_script.size() > MAX_SCRIPT_SIZE || withdrawal_outpoint.IsNull()) {
        throw std::invalid_argument("Invalid blinded withdrawal amount, fee, payout, or outpoint");
    }
    std::vector<unsigned char> fee_bytes;
    for (int i = 7; i >= 0; --i) fee_bytes.push_back((static_cast<uint64_t>(mainchain_fee) >> (8 * i)) & 0xff);
    std::vector<unsigned char> no_witness;
    PushLE32(no_witness, 2);
    PushCompactSize(no_witness, 0);
    PushCompactSize(no_witness, state_marker ? 4 : 3);
    PushBitcoinTxOut(no_witness, 0, CScript() << OP_RETURN << fee_bytes);
    PushBitcoinTxOut(no_witness, 0, BuildDrivechainInputsCommitmentScript(
        DrivechainInputsCommitment(withdrawal_outpoint, sidechain_block_height)));
    PushBitcoinTxOut(no_witness, amount - mainchain_fee, payout_script);
    if (state_marker) PushBitcoinTxOut(no_witness, 0, *state_marker);
    PushLE32(no_witness, 0);
    DrivechainWithdrawalBundle result;
    result.m6id = Hash(no_witness);
    result.bytes = no_witness;
    // rust-bitcoin's inputless codec requires the SegWit marker/flag to
    // disambiguate empty vin; the txid remains the no-witness serialization.
    result.bytes.insert(result.bytes.begin() + 4, {0, 1});
    return result;
}
} // namespace

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height)
{
    return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                       sidechain_block_height, nullptr);
}

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    const uint256& child_genesis, const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    const CScript marker = BuildWithdrawalStateMarkerScript(BuildWithdrawalStateAnchor(
        child_genesis, sidechain_block_height, previous_child_hash,
        DrivechainInputsCommitment(withdrawal_outpoint, sidechain_block_height),
        exchange_state_root));
    return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                       sidechain_block_height, &marker);
}
} // namespace wallet
