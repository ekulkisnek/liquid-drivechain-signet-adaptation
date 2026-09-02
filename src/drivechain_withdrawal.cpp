// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_withdrawal.h>

#include <hash.h>
#include <primitives/txwitness.h>
#include <span.h>
#include <streams.h>
#include <version.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <utility>

namespace drivechain {
namespace {

constexpr std::array<unsigned char, 4> M6_REFERENCE_MAGIC{{
    'E', 'L', 'W', 'D',
}};
constexpr unsigned char M6_REFERENCE_VERSION{1};
constexpr size_t M6_REFERENCE_GENESIS_OFFSET{5};
constexpr size_t M6_REFERENCE_SLOT_OFFSET{
    M6_REFERENCE_GENESIS_OFFSET + uint256::size()};
constexpr size_t M6_REFERENCE_TXID_OFFSET{M6_REFERENCE_SLOT_OFFSET + 1};
constexpr size_t M6_REFERENCE_VOUT_OFFSET{
    M6_REFERENCE_TXID_OFFSET + uint256::size()};
static_assert(M6_REFERENCE_VOUT_OFFSET + sizeof(uint32_t) ==
              NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE);
static_assert(NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE <= 75);
static_assert(1 + 1 + NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE <= 83);

bool SetError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

std::array<unsigned char, 8> EncodeFee(const CAmount fee)
{
    const uint64_t value = static_cast<uint64_t>(fee);
    std::array<unsigned char, 8> encoded{};
    for (size_t i = 0; i < encoded.size(); ++i) {
        encoded[i] = static_cast<unsigned char>(value >> (56 - 8 * i));
    }
    return encoded;
}

bool DecodeFee(const std::vector<unsigned char>& encoded,
               CAmount& fee,
               std::string* error)
{
    if (encoded.size() != 8) {
        return SetError(error, "native withdrawal parent fee is not eight bytes");
    }
    uint64_t value{0};
    for (const unsigned char byte : encoded) value = (value << 8) | byte;
    if (value > static_cast<uint64_t>(MAX_MONEY)) {
        return SetError(error, "native withdrawal parent fee is outside the money range");
    }
    fee = static_cast<CAmount>(value);
    return true;
}

bool CheckAmounts(const CAmount burn_amount,
                  const CAmount parent_fee,
                  CAmount& payout_amount,
                  std::string* error)
{
    payout_amount = 0;
    if (burn_amount <= 0 || !MoneyRange(burn_amount)) {
        return SetError(error, "native withdrawal burn amount is outside the money range");
    }
    if (parent_fee < 0 || !MoneyRange(parent_fee)) {
        return SetError(error, "native withdrawal parent fee is outside the money range");
    }
    if (burn_amount <= parent_fee) {
        return SetError(error, "native withdrawal burn amount must exceed its parent fee");
    }
    payout_amount = burn_amount - parent_fee;
    if (payout_amount <= 0 || !MoneyRange(payout_amount)) {
        return SetError(error, "native withdrawal payout amount is outside the money range");
    }
    return true;
}

bool ExtractSingleCanonicalPush(const CScript& script,
                                const size_t expected_size,
                                std::vector<unsigned char>& payload)
{
    payload.clear();
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !script.GetOp(cursor, opcode, payload) || opcode > OP_PUSHDATA4 ||
        payload.size() != expected_size || cursor != script.end()) {
        return false;
    }
    return script == (CScript() << OP_RETURN << payload);
}

CScript BuildSinglePushScript(const std::vector<unsigned char>& payload)
{
    return CScript() << OP_RETURN << payload;
}

std::vector<unsigned char> ToVector(const NativeWithdrawalCommitment& commitment)
{
    return {commitment.begin(), commitment.end()};
}

} // namespace

bool BuildNativeWithdrawalScript(const uint256& parent_genesis,
                                 const CScript& destination,
                                 const CAmount parent_fee,
                                 CScript& script,
                                 std::string* error)
{
    script.clear();
    if (error) error->clear();
    if (parent_genesis.IsNull()) {
        return SetError(error, "native withdrawal parent genesis is null");
    }
    if (destination.empty() ||
        destination.size() > NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE) {
        return SetError(error, "native withdrawal destination size is outside 1..128 bytes");
    }
    if (parent_fee < 0 || !MoneyRange(parent_fee)) {
        return SetError(error, "native withdrawal parent fee is outside the money range");
    }

    const auto encoded_fee = EncodeFee(parent_fee);
    script = CScript()
        << OP_RETURN
        << std::vector<unsigned char>(parent_genesis.begin(), parent_genesis.end())
        << std::vector<unsigned char>(destination.begin(), destination.end())
        << std::vector<unsigned char>(encoded_fee.begin(), encoded_fee.end());
    return true;
}

bool ParseNativeWithdrawalScript(const CScript& script,
                                 const uint256& expected_parent_genesis,
                                 CScript& destination,
                                 CAmount& parent_fee,
                                 std::string* error)
{
    destination.clear();
    parent_fee = 0;
    if (error) error->clear();
    if (expected_parent_genesis.IsNull()) {
        return SetError(error, "native withdrawal parent genesis is null");
    }

    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> genesis_bytes;
    std::vector<unsigned char> destination_bytes;
    std::vector<unsigned char> fee_bytes;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !script.GetOp(cursor, opcode, genesis_bytes) || opcode > OP_PUSHDATA4 ||
        !script.GetOp(cursor, opcode, destination_bytes) || opcode > OP_PUSHDATA4 ||
        !script.GetOp(cursor, opcode, fee_bytes) || opcode > OP_PUSHDATA4 ||
        cursor != script.end()) {
        return SetError(error, "native withdrawal script is malformed or has trailing bytes");
    }
    if (genesis_bytes.size() != uint256::size() ||
        uint256{genesis_bytes} != expected_parent_genesis) {
        return SetError(error, "native withdrawal script has the wrong parent genesis");
    }
    if (destination_bytes.empty() ||
        destination_bytes.size() > NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE) {
        return SetError(error, "native withdrawal destination size is outside 1..128 bytes");
    }
    if (!DecodeFee(fee_bytes, parent_fee, error)) return false;

    destination = CScript(destination_bytes.begin(), destination_bytes.end());
    CScript canonical;
    if (!BuildNativeWithdrawalScript(expected_parent_genesis, destination,
                                     parent_fee, canonical, error)) {
        return false;
    }
    if (script != canonical) {
        destination.clear();
        parent_fee = 0;
        return SetError(error, "native withdrawal script uses a noncanonical push encoding");
    }
    return true;
}

bool BuildNativeWithdrawalOutput(const CAsset& pegged_asset,
                                 const uint256& parent_genesis,
                                 const CScript& destination,
                                 const CAmount burn_amount,
                                 const CAmount parent_fee,
                                 CTxOut& output,
                                 std::string* error)
{
    output.SetNull();
    if (error) error->clear();
    if (pegged_asset.IsNull()) {
        return SetError(error, "native withdrawal pegged asset is null");
    }
    CAmount payout_amount{0};
    if (!CheckAmounts(burn_amount, parent_fee, payout_amount, error)) return false;

    CScript script;
    if (!BuildNativeWithdrawalScript(parent_genesis, destination, parent_fee,
                                     script, error)) {
        return false;
    }
    output = CTxOut(pegged_asset, burn_amount, std::move(script));
    return true;
}

bool ParseNativeWithdrawalOutput(const CTxOut& output,
                                 const CTxOutWitness* output_witness,
                                 const CAsset& expected_pegged_asset,
                                 const uint256& expected_parent_genesis,
                                 NativeWithdrawal& withdrawal,
                                 std::string* error)
{
    withdrawal = {};
    if (error) error->clear();
    if (expected_pegged_asset.IsNull()) {
        return SetError(error, "native withdrawal pegged asset is null");
    }
    if (!output.nAsset.IsExplicit() ||
        output.nAsset.GetAsset() != expected_pegged_asset) {
        return SetError(error, "native withdrawal asset is not the explicit pegged asset");
    }
    if (!output.nValue.IsExplicit()) {
        return SetError(error, "native withdrawal value is not explicit");
    }
    if (!output.nNonce.IsNull()) {
        return SetError(error, "native withdrawal nonce is not null");
    }
    if (output_witness && !output_witness->IsNull()) {
        return SetError(error, "native withdrawal output proofs are not empty");
    }

    CScript destination;
    CAmount parent_fee{0};
    if (!ParseNativeWithdrawalScript(output.scriptPubKey,
                                     expected_parent_genesis,
                                     destination, parent_fee, error)) {
        return false;
    }
    const CAmount burn_amount = output.nValue.GetAmount();
    CAmount payout_amount{0};
    if (!CheckAmounts(burn_amount, parent_fee, payout_amount, error)) return false;

    withdrawal.parent_genesis = expected_parent_genesis;
    withdrawal.destination = std::move(destination);
    withdrawal.burn_amount = burn_amount;
    withdrawal.parent_fee = parent_fee;
    withdrawal.payout_amount = payout_amount;
    return true;
}

NativeWithdrawalCommitment ComputeNativeWithdrawalM6Commitment(
    const uint256& elements_genesis,
    const uint8_t sidechain_slot,
    const uint256& burn_txid,
    const uint32_t burn_vout)
{
    NativeWithdrawalCommitment commitment{};
    std::copy(M6_REFERENCE_MAGIC.begin(), M6_REFERENCE_MAGIC.end(),
              commitment.begin());
    commitment[M6_REFERENCE_MAGIC.size()] = M6_REFERENCE_VERSION;
    std::copy(elements_genesis.begin(), elements_genesis.end(),
              commitment.begin() + M6_REFERENCE_GENESIS_OFFSET);
    commitment[M6_REFERENCE_SLOT_OFFSET] = sidechain_slot;
    std::copy(burn_txid.begin(), burn_txid.end(),
              commitment.begin() + M6_REFERENCE_TXID_OFFSET);
    commitment[M6_REFERENCE_VOUT_OFFSET] =
        static_cast<unsigned char>(burn_vout >> 24);
    commitment[M6_REFERENCE_VOUT_OFFSET + 1] =
        static_cast<unsigned char>(burn_vout >> 16);
    commitment[M6_REFERENCE_VOUT_OFFSET + 2] =
        static_cast<unsigned char>(burn_vout >> 8);
    commitment[M6_REFERENCE_VOUT_OFFSET + 3] =
        static_cast<unsigned char>(burn_vout);
    return commitment;
}

bool ParseNativeWithdrawalM6Commitment(
    const CScript& commitment_script,
    uint256& elements_genesis,
    uint8_t& sidechain_slot,
    uint256& burn_txid,
    uint32_t& burn_vout,
    std::string* error)
{
    elements_genesis.SetNull();
    sidechain_slot = 0;
    burn_txid.SetNull();
    burn_vout = std::numeric_limits<uint32_t>::max();
    if (error) error->clear();

    std::vector<unsigned char> payload;
    if (!ExtractSingleCanonicalPush(commitment_script,
                                    NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE,
                                    payload)) {
        return SetError(error, "blinded M6 burn reference is not canonical");
    }
    if (!std::equal(M6_REFERENCE_MAGIC.begin(), M6_REFERENCE_MAGIC.end(),
                    payload.begin())) {
        return SetError(error, "blinded M6 burn reference has the wrong domain");
    }
    if (payload[M6_REFERENCE_MAGIC.size()] != M6_REFERENCE_VERSION) {
        return SetError(error, "blinded M6 burn reference has an unsupported version");
    }

    std::copy(payload.begin() + M6_REFERENCE_GENESIS_OFFSET,
              payload.begin() + M6_REFERENCE_SLOT_OFFSET,
              elements_genesis.begin());
    sidechain_slot = payload[M6_REFERENCE_SLOT_OFFSET];
    std::copy(payload.begin() + M6_REFERENCE_TXID_OFFSET,
              payload.begin() + M6_REFERENCE_VOUT_OFFSET,
              burn_txid.begin());
    burn_vout =
        (static_cast<uint32_t>(payload[M6_REFERENCE_VOUT_OFFSET]) << 24) |
        (static_cast<uint32_t>(payload[M6_REFERENCE_VOUT_OFFSET + 1]) << 16) |
        (static_cast<uint32_t>(payload[M6_REFERENCE_VOUT_OFFSET + 2]) << 8) |
        static_cast<uint32_t>(payload[M6_REFERENCE_VOUT_OFFSET + 3]);
    if (elements_genesis.IsNull()) {
        return SetError(error, "blinded M6 burn reference has a null Elements genesis");
    }
    if (burn_txid.IsNull() ||
        burn_vout == std::numeric_limits<uint32_t>::max()) {
        return SetError(error, "blinded M6 burn reference has an unknown burn outpoint");
    }
    return true;
}

std::vector<unsigned char> SerializeNativeWithdrawalM6Legacy(
    const Sidechain::Bitcoin::CMutableTransaction& transaction)
{
    CDataStream stream(SER_NETWORK,
                       PROTOCOL_VERSION |
                           Sidechain::Bitcoin::SERIALIZE_TRANSACTION_NO_WITNESS);
    stream << transaction;
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

bool DeserializeNativeWithdrawalM6Legacy(
    const std::vector<unsigned char>& bytes,
    Sidechain::Bitcoin::CMutableTransaction& transaction,
    std::string* error)
{
    transaction = {};
    if (error) error->clear();

    // Preflight the complete outer frame before invoking the generic vector
    // deserializer. This format always has one-byte CompactSize counts and
    // script lengths; rejecting any other form prevents attacker-controlled
    // reserve/allocation requests from truncated encodings.
    if (bytes.size() < 124 ||
        bytes.size() > NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE ||
        bytes[4] != 0 || bytes[5] != 3) {
        return SetError(error, "blinded M6 does not have the bounded legacy zero-input/three-output frame");
    }
    size_t cursor{6};
    const auto consume_output = [&](const size_t minimum_script_size,
                                    const size_t maximum_script_size) {
        if (cursor > bytes.size() || bytes.size() - cursor < 9) return false;
        const size_t script_size = bytes[cursor + 8];
        if (script_size < minimum_script_size ||
            script_size > maximum_script_size ||
            bytes.size() - cursor < 9 + script_size) {
            return false;
        }
        cursor += 9 + script_size;
        return true;
    };
    if (!consume_output(10, 10) ||
        !consume_output(76, 76) ||
        !consume_output(1, NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE) ||
        cursor > bytes.size() || bytes.size() - cursor != 4) {
        return SetError(error, "blinded M6 has noncanonical output lengths or trailing bytes");
    }
    try {
        CDataStream stream(bytes, SER_NETWORK,
                           PROTOCOL_VERSION |
                               Sidechain::Bitcoin::SERIALIZE_TRANSACTION_NO_WITNESS);
        stream >> transaction;
        if (!stream.empty()) {
            transaction = {};
            return SetError(error, "blinded M6 legacy serialization has trailing bytes");
        }
    } catch (const std::exception& exception) {
        transaction = {};
        return SetError(error, std::string{"invalid blinded M6 legacy serialization: "} +
                                   exception.what());
    }
    return true;
}

uint256 ComputeNativeWithdrawalM6Id(
    const Sidechain::Bitcoin::CMutableTransaction& blinded_transaction)
{
    return Hash(SerializeNativeWithdrawalM6Legacy(blinded_transaction));
}

bool BuildNativeWithdrawalM6(const uint256& elements_genesis,
                             const uint8_t sidechain_slot,
                             const uint256& burn_txid,
                             const uint32_t burn_vout,
                             const NativeWithdrawal& withdrawal,
                             NativeWithdrawalM6& m6,
                             std::string* error)
{
    m6 = {};
    if (error) error->clear();
    if (elements_genesis.IsNull()) {
        return SetError(error, "blinded M6 Elements genesis is null");
    }
    if (burn_txid.IsNull() ||
        burn_vout == std::numeric_limits<uint32_t>::max()) {
        return SetError(error, "blinded M6 burn outpoint is unknown");
    }
    if (withdrawal.destination.empty() ||
        withdrawal.destination.size() > NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE) {
        return SetError(error, "blinded M6 destination size is outside 1..128 bytes");
    }
    CAmount payout_amount{0};
    if (!CheckAmounts(withdrawal.burn_amount, withdrawal.parent_fee,
                      payout_amount, error)) {
        return false;
    }
    if (withdrawal.payout_amount != 0 &&
        withdrawal.payout_amount != payout_amount) {
        return SetError(error, "blinded M6 withdrawal has an inconsistent payout amount");
    }

    const auto encoded_fee = EncodeFee(withdrawal.parent_fee);
    const std::vector<unsigned char> fee_payload(encoded_fee.begin(),
                                                  encoded_fee.end());
    m6.burn_commitment = ComputeNativeWithdrawalM6Commitment(
        elements_genesis, sidechain_slot, burn_txid, burn_vout);
    m6.blinded_transaction.nVersion =
        Sidechain::Bitcoin::CTransaction::CURRENT_VERSION;
    m6.blinded_transaction.nLockTime = 0;
    m6.blinded_transaction.vin.clear();
    m6.blinded_transaction.vout = {
        Sidechain::Bitcoin::CTxOut(
            0, BuildSinglePushScript(fee_payload)),
        Sidechain::Bitcoin::CTxOut(
            0, BuildSinglePushScript(ToVector(m6.burn_commitment))),
        Sidechain::Bitcoin::CTxOut(payout_amount, withdrawal.destination),
    };
    m6.burn_amount = withdrawal.burn_amount;
    m6.parent_fee = withdrawal.parent_fee;
    m6.payout_amount = payout_amount;
    m6.destination = withdrawal.destination;
    m6.legacy_serialization =
        SerializeNativeWithdrawalM6Legacy(m6.blinded_transaction);
    m6.m6id = Hash(m6.legacy_serialization);
    return true;
}

bool ParseNativeWithdrawalM6(
    const Sidechain::Bitcoin::CMutableTransaction& blinded_transaction,
    const uint256& elements_genesis,
    const uint8_t sidechain_slot,
    const uint256& burn_txid,
    const uint32_t burn_vout,
    NativeWithdrawalM6& m6,
    std::string* error)
{
    m6 = {};
    if (error) error->clear();
    if (elements_genesis.IsNull()) {
        return SetError(error, "blinded M6 Elements genesis is null");
    }
    if (burn_txid.IsNull() ||
        burn_vout == std::numeric_limits<uint32_t>::max()) {
        return SetError(error, "blinded M6 burn outpoint is unknown");
    }
    if (blinded_transaction.nVersion !=
            Sidechain::Bitcoin::CTransaction::CURRENT_VERSION ||
        blinded_transaction.nLockTime != 0 ||
        !blinded_transaction.vin.empty() ||
        blinded_transaction.vout.size() != 3) {
        return SetError(error, "blinded M6 does not have canonical version, inputs, outputs, and locktime");
    }

    const auto& fee_output = blinded_transaction.vout[0];
    const auto& commitment_output = blinded_transaction.vout[1];
    const auto& payout_output = blinded_transaction.vout[2];
    if (fee_output.nValue != 0 || commitment_output.nValue != 0) {
        return SetError(error, "blinded M6 commitment outputs are not zero-valued");
    }

    std::vector<unsigned char> fee_bytes;
    if (!ExtractSingleCanonicalPush(fee_output.scriptPubKey, 8, fee_bytes)) {
        return SetError(error, "blinded M6 fee commitment is not canonical");
    }
    CAmount parent_fee{0};
    if (!DecodeFee(fee_bytes, parent_fee, error)) return false;

    uint256 parsed_elements_genesis;
    uint8_t parsed_sidechain_slot{0};
    uint256 parsed_burn_txid;
    uint32_t parsed_burn_vout{0};
    if (!ParseNativeWithdrawalM6Commitment(
            commitment_output.scriptPubKey, parsed_elements_genesis,
            parsed_sidechain_slot, parsed_burn_txid, parsed_burn_vout,
            error)) {
        return false;
    }
    if (parsed_elements_genesis != elements_genesis ||
        parsed_sidechain_slot != sidechain_slot ||
        parsed_burn_txid != burn_txid || parsed_burn_vout != burn_vout) {
        return SetError(error, "blinded M6 burn reference does not match its Elements outpoint");
    }
    const NativeWithdrawalCommitment expected_commitment =
        ComputeNativeWithdrawalM6Commitment(
            elements_genesis, sidechain_slot, burn_txid, burn_vout);

    if (payout_output.scriptPubKey.empty() ||
        payout_output.scriptPubKey.size() >
            NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE ||
        payout_output.nValue <= 0 || !MoneyRange(payout_output.nValue) ||
        parent_fee > MAX_MONEY - payout_output.nValue) {
        return SetError(error, "blinded M6 payout is outside canonical bounds");
    }
    const CAmount burn_amount = parent_fee + payout_output.nValue;
    CAmount checked_payout{0};
    if (!CheckAmounts(burn_amount, parent_fee, checked_payout, error) ||
        checked_payout != payout_output.nValue) {
        return false;
    }

    m6.blinded_transaction = blinded_transaction;
    m6.burn_commitment = expected_commitment;
    m6.burn_amount = burn_amount;
    m6.parent_fee = parent_fee;
    m6.payout_amount = payout_output.nValue;
    m6.destination = payout_output.scriptPubKey;
    m6.legacy_serialization =
        SerializeNativeWithdrawalM6Legacy(blinded_transaction);
    m6.m6id = Hash(m6.legacy_serialization);
    return true;
}

} // namespace drivechain
