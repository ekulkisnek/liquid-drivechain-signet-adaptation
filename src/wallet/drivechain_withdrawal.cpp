// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <wallet/drivechain_withdrawal.h>
#include <crypto/common.h>
#include <drivechain_withdrawal.h>
#include <hash.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <streams.h>
#include <util/strencodings.h>
#include <array>
#include <stdexcept>

namespace wallet {
namespace {
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
    std::array<unsigned char, 4> height_bytes{};
    WriteBE32(height_bytes.data(), checkpoint_height);
    payload.insert(payload.end(), height_bytes.begin(), height_bytes.end());
    payload.insert(
        payload.end(), previous_child_hash.begin(), previous_child_hash.end());
    payload.insert(
        payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    payload.insert(
        payload.end(), exchange_state_root.begin(), exchange_state_root.end());
    auto hasher = TaggedHash("ECX/perps-m6-state/v1");
    hasher.write(AsBytes(Span{payload}));
    return hasher.GetSHA256();
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
    std::array<unsigned char, 8> fee_bytes{};
    WriteBE64(fee_bytes.data(), mainchain_fee);
    Sidechain::Bitcoin::CMutableTransaction tx;
    tx.version = 2;
    tx.vout.emplace_back(0, CScript() << OP_RETURN << ToByteVector(Span{fee_bytes}));
    tx.vout.emplace_back(0, BuildDrivechainInputsCommitmentScript(
        DrivechainInputsCommitment(withdrawal_outpoint, sidechain_block_height)));
    tx.vout.emplace_back(amount - mainchain_fee, payout_script);
    if (state_marker) tx.vout.emplace_back(0, *state_marker);
    DrivechainWithdrawalBundle result;
    VectorWriter{result.no_witness_bytes, 0, TX_NO_WITNESS(tx)};
    result.m6id = tx.GetHash();
    result.bytes = result.no_witness_bytes;
    // rust-bitcoin's inputless codec requires the SegWit marker/flag to
    // disambiguate empty vin; the txid remains the no-witness serialization.
    result.bytes.insert(result.bytes.begin() + 4, {0, 1});
    return result;
}
} // namespace

CScript DecodeDrivechainWithdrawalDestination(const std::string& destination)
{
    CScript script;
    if (destination.starts_with("hex:")) {
        const std::string hex = destination.substr(4);
        if (hex.size() > 2 * drivechain::NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE || !IsHex(hex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "hex: destination must be a nonempty, bounded hexadecimal scriptPubKey");
        }
        const auto bytes = ParseHex(hex);
        script = CScript(bytes.begin(), bytes.end());
    } else {
        std::string error;
        const auto address = DecodeParentDestination(destination, error);
        if (!IsValidDestination(address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address: " + error);
        }
        script = GetScriptForDestination(address);
    }
    TxoutType type;
    if (script.empty() || script.size() > drivechain::NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE ||
        !IsStandard(script, std::nullopt, type)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a standard script of 1..128 bytes");
    }
    switch (type) {
    case TxoutType::PUBKEY:
    case TxoutType::PUBKEYHASH:
    case TxoutType::SCRIPTHASH:
    case TxoutType::MULTISIG:
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    case TxoutType::WITNESS_V0_KEYHASH:
    case TxoutType::WITNESS_V1_TAPROOT:
        return script;
    default:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a recognized spendable script");
    }
}

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
