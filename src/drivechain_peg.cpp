// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_peg.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <key_io.h>
#include <pegins.h>
#include <primitives/bitcoin/merkleblock.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <array>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace drivechain {
namespace {

constexpr int DRIVECHAIN_SIDECHAIN_SLOT{24};
const COutPoint CTIP_STATE_OUTPOINT{
    uint256S("2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1"),
    0};
const std::vector<unsigned char> CTIP_STATE_MARKER{
    'd', 'r', 'i', 'v', 'e', 'c', 'h', 'a', 'i', 'n', '-', 'c', 't', 'i', 'p', '-', 'v', '1'};

/**
 * Parse the consensus-defined bootstrap CTIP.
 *
 * A chain that has just been activated on the parent has no CTIP coin yet, so
 * every v2 deposit failed with "no authenticated prior CTIP state" and the
 * chain could never be funded at all. The two immutable LayerTwoLabs Signet
 * checkpoints below are historical and cannot authenticate any other chain.
 *
 * The bootstrap is the CTIP established by this sidechain's own M1/M2
 * activation on the parent chain. It is deliberately explicit configuration
 * rather than a compiled-in constant: it differs per deployment, and it must be
 * agreed by every node on the network before the first deposit, exactly like
 * any other genesis parameter.
 *
 * Format: <txid>:<vout>:<value_sats>:<sequence>
 */
std::optional<CtipState> ParseGenesisCtip(const std::string& spec, std::string& error)
{
    if (spec.empty()) return std::nullopt;

    std::vector<std::string> parts;
    size_t start{0};
    while (true) {
        const size_t sep = spec.find(':', start);
        parts.push_back(spec.substr(start, sep == std::string::npos ? std::string::npos : sep - start));
        if (sep == std::string::npos) break;
        start = sep + 1;
    }
    if (parts.size() != 4) {
        error = "-drivechaingenesisctip must be <txid>:<vout>:<value_sats>:<sequence>";
        return std::nullopt;
    }
    if (parts[0].size() != 64 || !IsHex(parts[0])) {
        error = "-drivechaingenesisctip txid must be 64 hex characters";
        return std::nullopt;
    }

    uint32_t vout{0};
    int64_t value{0};
    int64_t sequence{0};
    if (!ParseUInt32(parts[1], &vout)) {
        error = "-drivechaingenesisctip vout is not a valid index";
        return std::nullopt;
    }
    if (!ParseInt64(parts[2], &value) || value <= 0 || value > MAX_MONEY) {
        error = "-drivechaingenesisctip value must be a positive satoshi amount within MAX_MONEY";
        return std::nullopt;
    }
    if (!ParseInt64(parts[3], &sequence) || sequence < 0) {
        error = "-drivechaingenesisctip sequence must be non-negative";
        return std::nullopt;
    }

    CtipState state;
    state.outpoint = COutPoint(uint256S(parts[0]), vout);
    state.value = static_cast<CAmount>(value);
    state.sequence_number = sequence;
    return state;
}

//! Cached bootstrap CTIP for this process.
const std::optional<CtipState>& GenesisCtip()
{
    static const std::optional<CtipState> cached = [] {
        std::string error;
        const std::string spec = gArgs.GetArg("-drivechaingenesisctip", "");
        auto parsed = ParseGenesisCtip(spec, error);
        if (!spec.empty() && !parsed) {
            // Misconfiguration here would silently leave the chain unfundable,
            // so make it loud rather than falling back to "no bootstrap".
            throw std::runtime_error(error);
        }
        return parsed;
    }();
    return cached;
}

template <typename T>
bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
        stream >> value;
        return stream.empty();
    } catch (...) {
        return false;
    }
}

bool IsSlot24CtipScript(const CScript& script)
{
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_NOP5) return false;
    if (!script.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
        data.size() != 1 || data[0] != DRIVECHAIN_SIDECHAIN_SLOT) {
        return false;
    }
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_1) return false;
    return cursor == script.end();
}

bool ExtractDepositDestination(
    const Sidechain::Bitcoin::CMutableTransaction& deposit_tx,
    std::string& address,
    CScript& destination_script,
    std::string& error)
{
    bool found{false};
    for (const auto& output : deposit_tx.vout) {
        CScript::const_iterator cursor = output.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) || opcode != OP_RETURN) continue;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
            data.empty() || cursor != output.scriptPubKey.end()) {
            continue;
        }
        const std::string candidate(data.begin(), data.end());
        const CTxDestination destination = DecodeDestination(candidate);
        if (!IsValidDestination(destination)) continue;
        if (found) {
            error = "deposit transaction contains multiple valid sidechain destinations";
            return false;
        }
        found = true;
        address = candidate;
        destination_script = GetScriptForDestination(destination);
    }
    if (!found) {
        error = "deposit transaction does not commit a valid sidechain destination";
        return false;
    }
    return true;
}

struct ParsedDeterministicDeposit
{
    AuthenticatedDeposit authenticated;
    CtipState previous_state;
    CtipState next_state;
    uint256 anchor;
};

bool ParseV2Deposit(
    const CTransaction& tx,
    size_t input_index,
    ParsedDeterministicDeposit& parsed,
    std::string& error)
{
    if (input_index >= tx.vin.size() || input_index >= tx.witness.vtxinwit.size()) {
        error = "drivechain deposit input index is out of range";
        return false;
    }

    DrivechainDepositEvidence evidence;
    if (!GetDrivechainDepositEvidence(
            tx.witness.vtxinwit[input_index].m_pegin_witness,
            tx.vin[input_index].prevout,
            evidence,
            error)) {
        return false;
    }

    Sidechain::Bitcoin::CMutableTransaction deposit_tx;
    Sidechain::Bitcoin::CMutableTransaction previous_tx;
    Sidechain::Bitcoin::CMerkleBlock proof;
    if (!DeserializeExactly(evidence.deposit_tx, deposit_tx) ||
        !DeserializeExactly(evidence.previous_ctip_tx, previous_tx) ||
        !DeserializeExactly(evidence.txout_proof, proof)) {
        error = "drivechain deposit evidence contains malformed transaction or merkle proof data";
        return false;
    }
    if (deposit_tx.GetHash() != tx.vin[input_index].prevout.hash ||
        tx.vin[input_index].prevout.n >= deposit_tx.vout.size()) {
        error = "drivechain deposit outpoint is absent from the authenticated L1 transaction";
        return false;
    }

    std::vector<uint256> proof_matches;
    std::vector<unsigned int> proof_indices;
    if (proof.txn.ExtractMatches(proof_matches, proof_indices) != proof.header.hashMerkleRoot ||
        proof_matches.size() != 1 ||
        proof_matches[0] != deposit_tx.GetHash() ||
        evidence.headers.front().GetHash() != proof.header.GetHash()) {
        error = "drivechain deposit merkle proof does not authenticate the exact L1 transaction";
        return false;
    }

    for (size_t i = 0; i < evidence.headers.size(); ++i) {
        const auto& header = evidence.headers[i];
        if (!CheckParentProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) {
            error = "drivechain deposit evidence contains an invalid L1 proof-of-work header";
            return false;
        }
        if (i > 0 && header.hashPrevBlock != evidence.headers[i - 1].GetHash()) {
            error = "drivechain deposit L1 header evidence is not a contiguous chain";
            return false;
        }
    }
    parsed.anchor = evidence.headers.back().GetHash();

    const auto& current_output = deposit_tx.vout[tx.vin[input_index].prevout.n];
    if (!IsSlot24CtipScript(current_output.scriptPubKey) || current_output.nValue <= 0) {
        error = "drivechain deposit outpoint is not the slot-24 CTIP output";
        return false;
    }

    const uint256 previous_txid = previous_tx.GetHash();
    size_t matching_inputs{0};
    uint32_t previous_vout{0};
    for (const auto& input : deposit_tx.vin) {
        if (input.prevout.hash != previous_txid || input.prevout.n >= previous_tx.vout.size()) continue;
        if (!IsSlot24CtipScript(previous_tx.vout[input.prevout.n].scriptPubKey)) continue;
        ++matching_inputs;
        previous_vout = input.prevout.n;
    }
    if (matching_inputs != 1) {
        error = "drivechain deposit transaction does not spend exactly one authenticated prior CTIP";
        return false;
    }

    const CAmount previous_value = previous_tx.vout[previous_vout].nValue;
    CAmount witness_value{0};
    CScript claim_script;
    uint256 witness_txid;
    if (!GetDrivechainDepositPeginData(
            tx.witness.vtxinwit[input_index].m_pegin_witness,
            tx.vin[input_index].prevout,
            witness_value,
            claim_script,
            witness_txid) ||
        previous_value <= 0 ||
        current_output.nValue <= previous_value ||
        current_output.nValue - previous_value != witness_value) {
        error = "drivechain deposit value does not equal the authenticated CTIP increase";
        return false;
    }

    std::string address;
    CScript destination_script;
    if (!ExtractDepositDestination(deposit_tx, address, destination_script, error)) return false;

    parsed.previous_state = {
        COutPoint(previous_txid, previous_vout),
        previous_value,
        evidence.previous_sequence_number};
    parsed.next_state = {
        tx.vin[input_index].prevout,
        current_output.nValue,
        evidence.sequence_number};
    parsed.authenticated.sidechain_slot = DRIVECHAIN_SIDECHAIN_SLOT;
    parsed.authenticated.sequence_number = evidence.sequence_number;
    parsed.authenticated.outpoint = tx.vin[input_index].prevout;
    parsed.authenticated.value = witness_value;
    parsed.authenticated.address = address;
    parsed.authenticated.destination_script = destination_script;
    parsed.authenticated.confirmation_block = proof.header.GetHash();
    parsed.authenticated.current_ctip = parsed.next_state.outpoint;
    parsed.authenticated.current_ctip_value = parsed.next_state.value;
    parsed.authenticated.current_ctip_sequence = parsed.next_state.sequence_number;
    return true;
}

struct LegacyCheckpoint
{
    uint256 sidechain_txid;
    uint256 parent_hash;
    COutPoint outpoint;
    CAmount deposit_value;
    CAmount ctip_value;
    int64_t sequence_number;
    const char* destination;
};

const std::array<LegacyCheckpoint, 2> LEGACY_CHECKPOINTS{{
    {
        uint256S("feed724d3382997ae6500d8185353e116d557a4f299b58e8f722c1aa400ab730"),
        uint256S("000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"),
        COutPoint(uint256S("7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea"), 0),
        2'000,
        14'402'000,
        8,
        "ert1q9263y9nqf2kwjl7hrhsgewefq7859w93z5n8x8",
    },
    {
        uint256S("7d78b50fa26e51ca01d1a916820971e46dd6d11e8da7c06571b95d8c6dd4a382"),
        uint256S("00000268748226d792c32914d26f5608a766a13741f3762c35cb053084ac4d1c"),
        COutPoint(uint256S("010a70b5e1fca8e8433dd2efc7c3b8f0783e98b133bbf03bcbe05cdd29a4edab"), 0),
        100'000,
        14'400'000,
        7,
        "ert1q2d25juv3qvlk90pfsnqed7f9wzzgevp8y2vfmv",
    },
}};

const LegacyCheckpoint* FindLegacyCheckpoint(const CTransaction& tx, size_t input_index)
{
    if (input_index >= tx.vin.size() || input_index >= tx.witness.vtxinwit.size() ||
        !IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness)) {
        return nullptr;
    }
    for (const auto& checkpoint : LEGACY_CHECKPOINTS) {
        if (checkpoint.sidechain_txid == tx.GetHash() &&
            checkpoint.outpoint == tx.vin[input_index].prevout) {
            return &checkpoint;
        }
    }
    return nullptr;
}

bool BuildLegacyAuthenticated(
    const CTransaction& tx,
    size_t input_index,
    const LegacyCheckpoint& checkpoint,
    AuthenticatedDeposit& authenticated,
    std::string& error)
{
    CAmount witness_value{0};
    CScript claim_script;
    uint256 witness_txid;
    if (!GetDrivechainDepositPeginData(
            tx.witness.vtxinwit[input_index].m_pegin_witness,
            tx.vin[input_index].prevout,
            witness_value,
            claim_script,
            witness_txid) ||
        witness_value != checkpoint.deposit_value) {
        error = "historical drivechain checkpoint witness does not match its immutable value";
        return false;
    }
    const CTxDestination destination = DecodeDestination(checkpoint.destination);
    if (!IsValidDestination(destination)) {
        error = "historical drivechain checkpoint destination is invalid for this network";
        return false;
    }
    authenticated.sidechain_slot = DRIVECHAIN_SIDECHAIN_SLOT;
    authenticated.sequence_number = checkpoint.sequence_number;
    authenticated.outpoint = checkpoint.outpoint;
    authenticated.value = checkpoint.deposit_value;
    authenticated.address = checkpoint.destination;
    authenticated.destination_script = GetScriptForDestination(destination);
    authenticated.confirmation_block = checkpoint.parent_hash;
    authenticated.current_ctip = checkpoint.outpoint;
    authenticated.current_ctip_value = checkpoint.ctip_value;
    authenticated.current_ctip_sequence = checkpoint.sequence_number;
    return true;
}

CScript EncodeCtipState(const CtipState& state)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << CTIP_STATE_MARKER << state.outpoint << state.value << state.sequence_number;
    return CScript()
        << std::vector<unsigned char>(
            UCharCast(stream.data()),
            UCharCast(stream.data()) + stream.size())
        << OP_DROP
        << OP_FALSE;
}

bool DecodeCtipState(const Coin& coin, CtipState& state, std::string& error)
{
    if (coin.IsSpent() || !coin.out.nAsset.IsExplicit() ||
        coin.out.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
        !coin.out.nValue.IsExplicit() ||
        coin.out.nValue.GetAmount() != 0) {
        error = "persisted drivechain CTIP state has invalid asset or value encoding";
        return false;
    }
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!coin.out.scriptPubKey.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_DROP ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_FALSE ||
        cursor != coin.out.scriptPubKey.end()) {
        error = "persisted drivechain CTIP state script is malformed";
        return false;
    }
    try {
        CDataStream stream(data, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> marker;
        stream >> marker >> state.outpoint >> state.value >> state.sequence_number;
        if (!stream.empty() || marker != CTIP_STATE_MARKER ||
            state.outpoint.hash.IsNull() || state.value <= 0 ||
            state.sequence_number < 0) {
            error = "persisted drivechain CTIP state payload is invalid";
            return false;
        }
        return true;
    } catch (...) {
        error = "persisted drivechain CTIP state payload cannot be decoded";
        return false;
    }
}

void SetCtipState(CCoinsViewCache& inputs, const CtipState& state, int height)
{
    inputs.SpendCoin(CTIP_STATE_OUTPOINT);
    CTxOut output(
        Params().GetConsensus().pegged_asset,
        0,
        EncodeCtipState(state));
    inputs.AddCoin(
        CTIP_STATE_OUTPOINT,
        Coin(std::move(output), std::max(height, 0), false),
        true);
}

const UniValue& RequireObjectField(const UniValue& value, const std::string& field)
{
    const UniValue& result = value[field];
    if (!result.isObject()) throw std::runtime_error("drivechain peg data field '" + field + "' must be an object");
    return result;
}

const UniValue& RequireArrayField(const UniValue& value, const std::string& field)
{
    const UniValue& result = value[field];
    if (!result.isArray()) throw std::runtime_error("drivechain peg data field '" + field + "' must be an array");
    return result;
}

std::string RequireHexField(const UniValue& value, const std::string& field, size_t bytes = 0)
{
    const UniValue& result = value[field];
    if (!result.isStr() || !IsHex(result.get_str()) || (bytes != 0 && result.get_str().size() != bytes * 2)) {
        throw std::runtime_error("drivechain peg data field '" + field + "' must be valid hex");
    }
    return result.get_str();
}

int64_t RequireInt64Field(const UniValue& value, const std::string& field)
{
    const UniValue& result = value[field];
    if (result.isNum()) return result.get_int64();
    int64_t parsed{0};
    if (result.isStr() && ParseInt64(result.get_str(), &parsed)) return parsed;
    throw std::runtime_error("drivechain peg data field '" + field + "' must be an integer");
}

const UniValue& FindField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    if (!value.isObject()) {
        static const UniValue null_value;
        return null_value;
    }
    const UniValue& lower_value = value[lower_camel];
    return lower_value.isNull() ? value[snake_case] : lower_value;
}

const UniValue& RequireObjectField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& result = FindField(value, lower_camel, snake_case);
    if (!result.isObject()) throw std::runtime_error("drivechain evidence field '" + lower_camel + "' must be an object");
    return result;
}

const UniValue& RequireArrayField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& result = FindField(value, lower_camel, snake_case);
    if (!result.isArray()) throw std::runtime_error("drivechain evidence field '" + lower_camel + "' must be an array");
    return result;
}

int64_t RequireInt64Field(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& result = FindField(value, lower_camel, snake_case);
    if (result.isNum()) return result.get_int64();
    int64_t parsed{0};
    if (result.isStr() && ParseInt64(result.get_str(), &parsed)) return parsed;
    throw std::runtime_error("drivechain evidence field '" + lower_camel + "' must be an integer");
}

std::string RequireStringField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& result = FindField(value, lower_camel, snake_case);
    if (!result.isStr()) throw std::runtime_error("drivechain evidence field '" + lower_camel + "' must be a string");
    return result.get_str();
}

std::string RequireHexObjectField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case, size_t bytes)
{
    const UniValue& object = RequireObjectField(value, lower_camel, snake_case);
    const UniValue& hex = object["hex"];
    if (!hex.isStr() || !IsHex(hex.get_str()) || (bytes != 0 && hex.get_str().size() != bytes * 2)) {
        throw std::runtime_error("drivechain evidence field '" + lower_camel + ".hex' must be valid hex");
    }
    return hex.get_str();
}

std::string DecodeAddress(const std::string& address_hex)
{
    if (!IsHex(address_hex) || (address_hex.size() % 2) != 0) {
        throw std::runtime_error("deposit address is not valid hex");
    }
    const std::vector<unsigned char> bytes = ParseHex(address_hex);
    if (bytes.empty()) throw std::runtime_error("deposit address is empty");
    for (const unsigned char byte : bytes) {
        if (byte < 0x21 || byte > 0x7e) {
            throw std::runtime_error("deposit address contains non-printable bytes");
        }
    }
    return std::string(bytes.begin(), bytes.end());
}

uint32_t CheckedVout(const int64_t vout)
{
    if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("deposit vout is out of range");
    }
    return static_cast<uint32_t>(vout);
}

UniValue SidechainLocation(const CBlock& block, int height)
{
    UniValue location(UniValue::VOBJ);
    location.pushKV("block_hash", block.GetHash().GetHex());
    location.pushKV("height", height);
    return location;
}

UniValue L1Location(const UniValue& block)
{
    const UniValue& header = RequireObjectField(block, "blockHeaderInfo");
    UniValue location(UniValue::VOBJ);
    location.pushKV("block_hash", RequireHexField(RequireObjectField(header, "blockHash"), "hex", 32));
    location.pushKV("height", RequireInt64Field(header, "height"));
    if (!header["timestamp"].isNull()) location.pushKV("timestamp", RequireInt64Field(header, "timestamp"));
    return location;
}

std::string WithdrawalStatus(const UniValue& event)
{
    int states{0};
    std::string status;
    for (const auto& candidate : {"submitted", "succeeded", "failed"}) {
        if (!event[candidate].isNull()) {
            ++states;
            status = candidate;
        }
    }
    if (states != 1) throw std::runtime_error("withdrawal bundle event must contain exactly one lifecycle state");
    if (!event[status].isObject()) throw std::runtime_error("withdrawal bundle lifecycle state must be an object");
    return status;
}

void VerifySidechainIdentity(
    const UniValue& sidechains,
    const DepositIdentity& expected,
    int64_t enforcer_tip_height)
{
    const UniValue& entries = RequireArrayField(sidechains, "sidechains", "sidechains");
    const UniValue* match{nullptr};
    for (const UniValue& entry : entries.getValues()) {
        if (!entry.isObject()) throw std::runtime_error("sidechain entry must be an object");
        const int64_t slot = RequireInt64Field(entry, "sidechainNumber", "sidechain_number");
        if (slot != expected.sidechain_slot) continue;
        if (match != nullptr) throw std::runtime_error("enforcer returned duplicate sidechain slot");
        match = &entry;
    }
    if (match == nullptr) throw std::runtime_error("expected sidechain slot is not active");

    const int64_t activation_height = RequireInt64Field(*match, "activationHeight", "activation_height");
    if (activation_height < 0 || activation_height > enforcer_tip_height) {
        throw std::runtime_error("sidechain activation height is not active at the enforcer tip");
    }

    const UniValue& declaration = RequireObjectField(*match, "declaration", "declaration");
    const UniValue& v0 = RequireObjectField(declaration, "v0", "v0");
    if (RequireStringField(v0, "title", "title") != expected.title ||
        RequireHexObjectField(v0, "hashId1", "hash_id_1", 32) != expected.hash_id_1 ||
        RequireHexObjectField(v0, "hashId2", "hash_id_2", 20) != expected.hash_id_2) {
        throw std::runtime_error("sidechain declaration identity does not match the configured slot");
    }
}

AuthenticatedDeposit FindDeposit(
    const UniValue& two_way_peg_data,
    const DepositIdentity& expected,
    const COutPoint& expected_outpoint,
    CAmount expected_value)
{
    const UniValue& blocks = RequireArrayField(two_way_peg_data, "blocks", "blocks");
    AuthenticatedDeposit result;
    bool found{false};

    for (const UniValue& block : blocks.getValues()) {
        if (!block.isObject()) throw std::runtime_error("GetTwoWayPegData block must be an object");
        const UniValue& header = RequireObjectField(block, "blockHeaderInfo", "block_header_info");
        const uint256 block_hash = uint256S(RequireHexObjectField(header, "blockHash", "block_hash", 32));
        const int64_t block_height = RequireInt64Field(header, "height", "height");
        const UniValue& block_info = RequireObjectField(block, "blockInfo", "block_info");
        const UniValue& events = FindField(block_info, "events", "events");
        if (events.isNull()) continue;
        if (!events.isArray()) throw std::runtime_error("GetTwoWayPegData events must be an array");

        for (const UniValue& raw_event : events.getValues()) {
            if (!raw_event.isObject()) throw std::runtime_error("GetTwoWayPegData event must be an object");
            const UniValue& deposit = FindField(raw_event, "deposit", "deposit");
            if (deposit.isNull()) continue;
            if (!deposit.isObject()) throw std::runtime_error("deposit event must be an object");

            const UniValue& outpoint = RequireObjectField(deposit, "outpoint", "outpoint");
            const uint256 txid = uint256S(RequireHexObjectField(outpoint, "txid", "txid", 32));
            const uint32_t vout = CheckedVout(RequireInt64Field(outpoint, "vout", "vout"));
            if (txid != expected_outpoint.hash || vout != expected_outpoint.n) continue;
            if (found) throw std::runtime_error("duplicate confirmed deposit event for outpoint");

            const UniValue& output = RequireObjectField(deposit, "output", "output");
            const int64_t value = RequireInt64Field(output, "valueSats", "value_sats");
            const int64_t sequence = RequireInt64Field(deposit, "sequenceNumber", "sequence_number");
            if (value <= 0 || value != expected_value) {
                throw std::runtime_error("confirmed deposit value does not match the sidechain claim");
            }
            if (sequence < 0) throw std::runtime_error("deposit sequence number is negative");

            const std::string address_hex = RequireHexObjectField(output, "address", "address", 0);
            const std::string address = DecodeAddress(address_hex);
            const CTxDestination destination = DecodeDestination(address);
            if (!IsValidDestination(destination)) {
                throw std::runtime_error("confirmed deposit address is not valid for this sidechain network");
            }

            result.sidechain_slot = expected.sidechain_slot;
            result.sequence_number = sequence;
            result.outpoint = COutPoint(txid, vout);
            result.value = value;
            result.address = address;
            result.destination_script = GetScriptForDestination(destination);
            result.confirmation_block = block_hash;
            result.confirmation_height = block_height;
            found = true;
        }
    }
    if (!found) throw std::runtime_error("confirmed deposit outpoint is absent from canonical two-way-peg data");
    return result;
}

void VerifyCtip(const UniValue& ctip_response, AuthenticatedDeposit& authenticated)
{
    const UniValue& ctip = RequireObjectField(ctip_response, "ctip", "ctip");
    const uint256 txid = uint256S(RequireHexObjectField(ctip, "txid", "txid", 32));
    const UniValue& vout_field = FindField(ctip, "vout", "vout");
    const uint32_t vout = vout_field.isNull() ? 0 : CheckedVout(RequireInt64Field(ctip, "vout", "vout"));
    const int64_t value = RequireInt64Field(ctip, "value", "value");
    const int64_t sequence = RequireInt64Field(ctip, "sequenceNumber", "sequence_number");
    if (value <= 0 || sequence < 0) throw std::runtime_error("CTIP state contains an invalid value or sequence");
    if (sequence < authenticated.sequence_number) {
        throw std::runtime_error("CTIP sequence predates the confirmed deposit");
    }
    if (sequence == authenticated.sequence_number &&
        COutPoint(txid, vout) != authenticated.outpoint) {
        throw std::runtime_error("CTIP outpoint does not match the deposit at the same sequence");
    }

    authenticated.current_ctip = COutPoint(txid, vout);
    authenticated.current_ctip_value = value;
    authenticated.current_ctip_sequence = sequence;
}

} // namespace

UniValue ExtractSidechainPegEvents(const CBlock& block, int height, const uint256& previous_bundle_hash)
{
    UniValue events(UniValue::VARR);
    const uint256 block_bundle_hash = block.hashWithdrawalBundle;

    if (!block_bundle_hash.IsNull() && block_bundle_hash != previous_bundle_hash) {
        UniValue event(UniValue::VOBJ);
        event.pushKV("event_id", "sidechain:bundle:" + block_bundle_hash.GetHex() + ":" + std::to_string(height));
        event.pushKV("source", "sidechain");
        event.pushKV("kind", "bundle_commitment");
        event.pushKV("status", "sidechain_committed");
        event.pushKV("m6id", block_bundle_hash.GetHex());
        event.pushKV("sidechain", SidechainLocation(block, height));
        events.push_back(event);
    }

    for (const CTransactionRef& tx : block.vtx) {
        const std::string txid = tx->GetHash().GetHex();
        for (size_t vin = 0; vin < tx->vin.size(); ++vin) {
            if (vin >= tx->witness.vtxinwit.size()) continue;

            CAmount value{0};
            CScript claim_script;
            uint256 mainchain_txid;
            if (!GetDrivechainDepositPeginData(tx->witness.vtxinwit[vin].m_pegin_witness, tx->vin[vin].prevout, value, claim_script, mainchain_txid)) continue;

            UniValue event(UniValue::VOBJ);
            event.pushKV("event_id", "sidechain:deposit:" + txid + ":" + std::to_string(vin));
            event.pushKV("source", "sidechain");
            event.pushKV("kind", "deposit");
            event.pushKV("status", "sidechain_confirmed");
            event.pushKV("sidechain_txid", txid);
            event.pushKV("vin", static_cast<uint64_t>(vin));
            event.pushKV("mainchain_txid", mainchain_txid.GetHex());
            event.pushKV("mainchain_vout", static_cast<uint64_t>(tx->vin[vin].prevout.n));
            event.pushKV("value_sats", value);
            event.pushKV("asset", Params().GetConsensus().pegged_asset.GetHex());
            event.pushKV("claim_script", HexStr(claim_script));
            event.pushKV("sidechain", SidechainLocation(block, height));
            events.push_back(event);
        }

        for (size_t vout = 0; vout < tx->vout.size(); ++vout) {
            const CTxOut& output = tx->vout[vout];
            uint256 genesis_hash;
            CScript destination_script;
            if (!output.scriptPubKey.IsPegoutScript(genesis_hash, destination_script) ||
                genesis_hash != Params().ParentGenesisBlockHash() ||
                !output.nAsset.IsExplicit() ||
                output.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
                !output.nValue.IsExplicit()) {
                continue;
            }

            UniValue event(UniValue::VOBJ);
            event.pushKV("event_id", "sidechain:withdrawal:" + txid + ":" + std::to_string(vout));
            event.pushKV("source", "sidechain");
            event.pushKV("kind", "withdrawal");
            event.pushKV("status", "sidechain_confirmed");
            event.pushKV("sidechain_txid", txid);
            event.pushKV("vout", static_cast<uint64_t>(vout));
            event.pushKV("value_sats", output.nValue.GetAmount());
            event.pushKV("asset", output.nAsset.GetAsset().GetHex());
            event.pushKV("mainchain_genesis_hash", genesis_hash.GetHex());
            event.pushKV("mainchain_script", HexStr(destination_script));
            if (!block_bundle_hash.IsNull()) event.pushKV("m6id", block_bundle_hash.GetHex());
            event.pushKV("sidechain", SidechainLocation(block, height));
            events.push_back(event);
        }
    }
    return events;
}

UniValue NormalizeL1PegEvents(const UniValue& two_way_peg_data, int sidechain_id)
{
    if (!two_way_peg_data.isObject()) throw std::runtime_error("GetTwoWayPegData response must be an object");

    UniValue result(UniValue::VARR);
    std::map<std::string, std::string> event_payloads;
    for (const UniValue& block : RequireArrayField(two_way_peg_data, "blocks").getValues()) {
        if (!block.isObject()) throw std::runtime_error("GetTwoWayPegData block must be an object");
        const UniValue location = L1Location(block);
        const int64_t height = location["height"].get_int64();
        const UniValue& block_info = RequireObjectField(block, "blockInfo");
        const UniValue& raw_events = block_info["events"];
        if (raw_events.isNull()) continue;
        if (!raw_events.isArray()) throw std::runtime_error("drivechain peg data field 'events' must be an array");
        for (const UniValue& raw_event : raw_events.getValues()) {
            if (!raw_event.isObject()) throw std::runtime_error("GetTwoWayPegData event must be an object");

            UniValue event(UniValue::VOBJ);
            std::string event_id;
            if (raw_event["deposit"].isObject()) {
                const UniValue& deposit = raw_event["deposit"];
                const UniValue& outpoint = RequireObjectField(deposit, "outpoint");
                const std::string txid = RequireHexField(RequireObjectField(outpoint, "txid"), "hex", 32);
                const int64_t vout = RequireInt64Field(outpoint, "vout");
                const UniValue& output = RequireObjectField(deposit, "output");
                const int64_t sequence = RequireInt64Field(deposit, "sequenceNumber");
                const int64_t value_sats = RequireInt64Field(output, "valueSats");
                if (vout < 0 || value_sats <= 0 || sequence < 0) throw std::runtime_error("deposit contains an invalid negative or zero numeric field");

                event_id = "l1:deposit:" + txid + ":" + std::to_string(vout);
                event.pushKV("event_id", event_id);
                event.pushKV("source", "l1");
                event.pushKV("kind", "deposit");
                event.pushKV("status", "l1_confirmed");
                event.pushKV("sidechain_id", sidechain_id);
                event.pushKV("sequence_number", sequence);
                event.pushKV("mainchain_txid", txid);
                event.pushKV("mainchain_vout", vout);
                event.pushKV("address_hex", RequireHexField(RequireObjectField(output, "address"), "hex"));
                event.pushKV("value_sats", value_sats);
            } else if (raw_event["withdrawalBundle"].isObject()) {
                const UniValue& withdrawal = raw_event["withdrawalBundle"];
                const std::string m6id = RequireHexField(RequireObjectField(withdrawal, "m6id"), "hex", 32);
                const UniValue& lifecycle = RequireObjectField(withdrawal, "event");
                const std::string status = WithdrawalStatus(lifecycle);

                event_id = "l1:withdrawal:" + m6id + ":" + status + ":" + std::to_string(height);
                event.pushKV("event_id", event_id);
                event.pushKV("source", "l1");
                event.pushKV("kind", "withdrawal_bundle");
                event.pushKV("status", status);
                event.pushKV("sidechain_id", sidechain_id);
                event.pushKV("m6id", m6id);

                const UniValue& details = lifecycle[status];
                if (!details["sequenceNumber"].isNull()) event.pushKV("sequence_number", RequireInt64Field(details, "sequenceNumber"));
                if (!details["transaction"].isNull()) {
                    event.pushKV("mainchain_transaction", RequireHexField(RequireObjectField(details, "transaction"), "hex"));
                }
                event.pushKV("acknowledgement", status == "succeeded" ? "accepted" : (status == "failed" ? "rejected" : "pending"));
            } else {
                continue;
            }

            event.pushKV("l1", location);
            const std::string payload = event.write();
            const auto [it, inserted] = event_payloads.emplace(event_id, payload);
            if (inserted) {
                result.push_back(event);
            } else if (it->second != payload) {
                throw std::runtime_error("conflicting drivechain peg events share event_id '" + event_id + "'");
            }
        }
    }
    return result;
}

std::string GetWithdrawalBundleStatus(
    const UniValue& two_way_peg_data,
    const int sidechain_id,
    const uint256& m6id)
{
    if (m6id.IsNull()) {
        throw std::runtime_error("withdrawal bundle id must not be null");
    }

    bool submitted{false};
    std::string terminal;
    const UniValue events = NormalizeL1PegEvents(two_way_peg_data, sidechain_id);
    for (const UniValue& event : events.getValues()) {
        if (!event.isObject() || !event["kind"].isStr() ||
            event["kind"].get_str() != "withdrawal_bundle" ||
            !event["m6id"].isStr()) {
            continue;
        }

        const std::string event_m6id_hex = event["m6id"].get_str();
        if (event_m6id_hex.size() != 64 || !IsHex(event_m6id_hex)) {
            throw std::runtime_error("normalized withdrawal event has an invalid bundle id");
        }
        const uint256 event_m6id = uint256S(event_m6id_hex);
        if (event_m6id != m6id) continue;

        if (!event["status"].isStr()) {
            throw std::runtime_error("normalized withdrawal event has no lifecycle status");
        }
        const std::string status = event["status"].get_str();
        if (status == "submitted") {
            submitted = true;
            continue;
        }
        if (status != "succeeded" && status != "failed") {
            throw std::runtime_error("normalized withdrawal event has an unknown lifecycle status");
        }
        if (!terminal.empty() && terminal != status) {
            throw std::runtime_error(
                "withdrawal bundle has conflicting succeeded and failed events");
        }
        terminal = status;
    }

    if (!terminal.empty()) return terminal;
    return submitted ? "submitted" : "";
}

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
    const CAmount expected_value,
    AuthenticatedDeposit& authenticated,
    std::string& error)
{
    try {
        if (expected.sidechain_slot < 0 || expected.sidechain_slot > 255) {
            throw std::runtime_error("configured sidechain slot is out of range");
        }
        if (sidechain_network != expected.sidechain_network) {
            throw std::runtime_error("sidechain network does not match the configured identity");
        }
        if (mainchain_genesis != expected.mainchain_genesis) {
            throw std::runtime_error("mainchain genesis does not match the configured network");
        }
        if (!mainchain_info.isObject()) throw std::runtime_error("mainchain blockchain info is missing");
        if (RequireStringField(mainchain_info, "chain", "chain") != expected.mainchain_network) {
            throw std::runtime_error("mainchain network does not match the configured network");
        }
        if (RequireStringField(mainchain_info, "signet_challenge", "signet_challenge") != expected.mainchain_signet_challenge) {
            throw std::runtime_error("mainchain signet challenge does not match the configured network");
        }
        const UniValue& ibd = FindField(mainchain_info, "initialblockdownload", "initial_block_download");
        if (!ibd.isBool() || ibd.get_bool()) {
            throw std::runtime_error("mainchain is not fully synchronized");
        }
        const uint256 mainchain_tip = uint256S(RequireStringField(mainchain_info, "bestblockhash", "best_block_hash"));
        const int64_t mainchain_height = RequireInt64Field(mainchain_info, "blocks", "blocks");

        if (!enforcer_chain_info.isObject() ||
            RequireStringField(enforcer_chain_info, "network", "network") != expected.enforcer_network) {
            throw std::runtime_error("enforcer network does not match the configured mainchain");
        }
        const UniValue& tip_header = RequireObjectField(enforcer_tip, "blockHeaderInfo", "block_header_info");
        const uint256 enforcer_tip_hash = uint256S(RequireHexObjectField(tip_header, "blockHash", "block_hash", 32));
        const int64_t enforcer_tip_height = RequireInt64Field(tip_header, "height", "height");
        if (enforcer_tip_hash != mainchain_tip || enforcer_tip_height != mainchain_height) {
            throw std::runtime_error("enforcer tip is not synchronized with the canonical mainchain tip");
        }

        VerifySidechainIdentity(sidechains, expected, enforcer_tip_height);
        AuthenticatedDeposit candidate = FindDeposit(two_way_peg_data, expected, expected_outpoint, expected_value);
        VerifyCtip(ctip, candidate);
        authenticated = std::move(candidate);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool VerifyDepositBlockConfirmation(
    const UniValue& block_header,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    try {
        if (!block_header.isObject()) throw std::runtime_error("mainchain deposit block header is missing");
        const int64_t confirmations = RequireInt64Field(block_header, "confirmations", "confirmations");
        const int64_t height = RequireInt64Field(block_header, "height", "height");
        if (confirmations <= 0) throw std::runtime_error("mainchain deposit block is no longer confirmed");
        if (height != authenticated.confirmation_height) {
            throw std::runtime_error("mainchain deposit block height changed");
        }
        const UniValue& hash = FindField(block_header, "hash", "hash");
        if (!hash.isStr() || !IsHex(hash.get_str()) || hash.get_str().size() != 64) {
            throw std::runtime_error("mainchain deposit block hash is missing or malformed");
        }
        if (uint256S(hash.get_str()) != authenticated.confirmation_block) {
            throw std::runtime_error("mainchain deposit block hash changed");
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool VerifyCurrentCtipOutput(
    const UniValue& txout,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    try {
        if (!txout.isObject()) throw std::runtime_error("current CTIP outpoint is not unspent on the canonical mainchain");
        const int64_t confirmations = RequireInt64Field(txout, "confirmations", "confirmations");
        const UniValue& value = FindField(txout, "value", "value");
        if (confirmations <= 0) throw std::runtime_error("current CTIP outpoint is not confirmed");
        if (value.isNull() || AmountFromValue(value) != authenticated.current_ctip_value) {
            throw std::runtime_error("current CTIP value does not match the enforcer");
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool VerifyDepositTransaction(
    const CTransaction& tx,
    const size_t input_index,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    try {
        if (tx.vin.size() != 1 || input_index != 0 || input_index >= tx.vin.size()) {
            throw std::runtime_error("drivechain deposit transaction must contain exactly one input");
        }
        if (tx.witness.vtxinwit.size() != 1) {
            throw std::runtime_error("drivechain deposit transaction has an invalid input witness count");
        }

        const CTxIn& input = tx.vin[input_index];
        if (!input.m_is_pegin || input.prevout != authenticated.outpoint ||
            !input.scriptSig.empty() || !input.assetIssuance.IsNull()) {
            throw std::runtime_error("drivechain deposit input does not match the authenticated outpoint");
        }

        CAmount witness_value{0};
        CScript claim_script;
        uint256 mainchain_txid;
        if (!GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                input.prevout,
                witness_value,
                claim_script,
                mainchain_txid) ||
            witness_value != authenticated.value ||
            mainchain_txid != authenticated.outpoint.hash ||
            claim_script != (CScript() << OP_TRUE)) {
            throw std::runtime_error("drivechain deposit witness does not match the authenticated deposit");
        }

        if (tx.vout.empty() || tx.vout.size() > 2) {
            throw std::runtime_error("drivechain deposit transaction must contain one credit output and at most one fee output");
        }
        CAmount credited{0};
        CAmount fee{0};
        int credit_outputs{0};
        int fee_outputs{0};
        for (const CTxOut& output : tx.vout) {
            if (!output.nAsset.IsExplicit() ||
                output.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
                !output.nValue.IsExplicit() ||
                !output.nNonce.IsNull()) {
                throw std::runtime_error("drivechain deposit outputs must use explicit native asset values");
            }
            if (output.scriptPubKey.empty()) {
                ++fee_outputs;
                fee += output.nValue.GetAmount();
            } else {
                if (output.scriptPubKey != authenticated.destination_script) {
                    throw std::runtime_error("drivechain deposit destination script does not match enforcer data");
                }
                ++credit_outputs;
                credited += output.nValue.GetAmount();
            }
        }
        if (credit_outputs != 1 || fee_outputs > 1 || credited <= 0 || fee < 0 ||
            credited + fee != authenticated.value) {
            throw std::runtime_error("drivechain deposit output value and fee do not equal the authenticated deposit value");
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool GetCtipState(const CCoinsViewCache& inputs, CtipState& state, std::string* error)
{
    const Coin& coin = inputs.AccessCoin(CTIP_STATE_OUTPOINT);
    if (coin.IsSpent()) return false;
    std::string decode_error;
    if (!DecodeCtipState(coin, state, decode_error)) {
        if (error) *error = decode_error;
        return false;
    }
    return true;
}

bool IsCtipStateInternalOutpoint(const COutPoint& outpoint)
{
    return outpoint == CTIP_STATE_OUTPOINT;
}

bool VerifyDeterministicDeposit(
    const CTransaction& tx,
    const size_t input_index,
    const CCoinsViewCache& inputs,
    std::string& error)
{
    if (const LegacyCheckpoint* checkpoint = FindLegacyCheckpoint(tx, input_index)) {
        CtipState existing;
        std::string state_error;
        if (GetCtipState(inputs, existing, &state_error)) {
            error = "historical drivechain checkpoint cannot overwrite authenticated CTIP state";
            return false;
        }
        if (!state_error.empty()) {
            error = state_error;
            return false;
        }
        AuthenticatedDeposit authenticated;
        return BuildLegacyAuthenticated(tx, input_index, *checkpoint, authenticated, error) &&
            VerifyDepositTransaction(tx, input_index, authenticated, error);
    }
    if (input_index < tx.witness.vtxinwit.size() &&
        IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness)) {
        error = "legacy drivechain deposit witness is not an immutable historical checkpoint";
        return false;
    }

    ParsedDeterministicDeposit parsed;
    if (!ParseV2Deposit(tx, input_index, parsed, error)) return false;

    CtipState current;
    std::string state_error;
    if (!GetCtipState(inputs, current, &state_error)) {
        if (!state_error.empty()) {
            error = state_error;
            return false;
        }
        // No CTIP coin exists yet, so this must be the chain's first deposit.
        // It is accepted only if it extends the consensus-defined bootstrap
        // CTIP established by this sidechain's activation on the parent.
        const std::optional<CtipState>& genesis = GenesisCtip();
        if (!genesis) {
            error = "drivechain deposit has no authenticated prior CTIP state and no "
                    "bootstrap CTIP is configured (-drivechaingenesisctip)";
            return false;
        }
        current = *genesis;
    }
    if (!(current == parsed.previous_state)) {
        error = "drivechain deposit evidence is stale or does not extend the authenticated CTIP state";
        return false;
    }
    return VerifyDepositTransaction(tx, input_index, parsed.authenticated, error);
}

bool VerifyDepositEvidenceAnchor(
    const CTransaction& tx,
    const size_t input_index,
    const uint256& expected_parent,
    std::string& error)
{
    if (const LegacyCheckpoint* checkpoint = FindLegacyCheckpoint(tx, input_index)) {
        if (checkpoint->parent_hash != expected_parent) {
            error = "historical drivechain checkpoint is not in its immutable L1 parent block";
            return false;
        }
        return true;
    }
    if (input_index < tx.witness.vtxinwit.size() &&
        IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness)) {
        error = "legacy drivechain deposit witness is not an immutable historical checkpoint";
        return false;
    }

    ParsedDeterministicDeposit parsed;
    if (!ParseV2Deposit(tx, input_index, parsed, error)) return false;
    if (parsed.anchor != expected_parent) {
        error = strprintf(
            "drivechain deposit evidence anchor %s does not match sidechain block L1 parent %s",
            parsed.anchor.GetHex(),
            expected_parent.GetHex());
        return false;
    }
    return true;
}

bool ConnectDepositState(
    const CTransaction& tx,
    const size_t input_index,
    CCoinsViewCache& inputs,
    const int height,
    std::string& error)
{
    if (const LegacyCheckpoint* checkpoint = FindLegacyCheckpoint(tx, input_index)) {
        AuthenticatedDeposit authenticated;
        if (!BuildLegacyAuthenticated(tx, input_index, *checkpoint, authenticated, error) ||
            !VerifyDepositTransaction(tx, input_index, authenticated, error)) {
            return false;
        }
        SetCtipState(
            inputs,
            {checkpoint->outpoint, checkpoint->ctip_value, checkpoint->sequence_number},
            height);
        return true;
    }

    ParsedDeterministicDeposit parsed;
    if (!ParseV2Deposit(tx, input_index, parsed, error)) return false;
    CtipState current;
    std::string state_error;
    if (!GetCtipState(inputs, current, &state_error)) {
        if (!state_error.empty()) {
            error = state_error;
            return false;
        }
        // First deposit on a fresh chain; bootstrap from the configured CTIP.
        // Kept symmetric with VerifyDeterministicDeposit so a transaction can
        // never validate and then fail to connect.
        const std::optional<CtipState>& genesis = GenesisCtip();
        if (!genesis) {
            error = "cannot connect drivechain deposit over missing CTIP state and no "
                    "bootstrap CTIP is configured (-drivechaingenesisctip)";
            return false;
        }
        current = *genesis;
    }
    if (!(current == parsed.previous_state)) {
        error = "cannot connect drivechain deposit over stale CTIP state";
        return false;
    }
    SetCtipState(inputs, parsed.next_state, height);
    return true;
}

bool DisconnectDepositState(
    const CTransaction& tx,
    const size_t input_index,
    CCoinsViewCache& inputs,
    const int height,
    std::string& error)
{
    CtipState current;
    std::string state_error;
    if (!GetCtipState(inputs, current, &state_error)) {
        error = state_error.empty()
            ? "cannot disconnect drivechain deposit without authenticated CTIP state"
            : state_error;
        return false;
    }

    if (const LegacyCheckpoint* checkpoint = FindLegacyCheckpoint(tx, input_index)) {
        const CtipState expected{
            checkpoint->outpoint,
            checkpoint->ctip_value,
            checkpoint->sequence_number};
        if (!(current == expected)) {
            error = "historical drivechain checkpoint CTIP state is inconsistent during disconnect";
            return false;
        }
        if (!inputs.SpendCoin(CTIP_STATE_OUTPOINT)) {
            error = "historical drivechain checkpoint CTIP state could not be removed";
            return false;
        }
        return true;
    }

    ParsedDeterministicDeposit parsed;
    if (!ParseV2Deposit(tx, input_index, parsed, error)) return false;
    if (!(current == parsed.next_state)) {
        error = "drivechain deposit CTIP state is inconsistent during disconnect";
        return false;
    }
    // Undoing the chain's first deposit must remove the CTIP coin entirely
    // rather than persisting the bootstrap value, so that reconnecting takes
    // the same bootstrap path it took originally. Without this a reorg across
    // the first deposit would leave a CTIP coin that never existed.
    const std::optional<CtipState>& genesis = GenesisCtip();
    if (genesis && parsed.previous_state == *genesis) {
        if (!inputs.SpendCoin(CTIP_STATE_OUTPOINT)) {
            error = "bootstrap drivechain CTIP state could not be removed during disconnect";
            return false;
        }
        return true;
    }
    SetCtipState(inputs, parsed.previous_state, height - 1);
    return true;
}

} // namespace drivechain
