// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <ecx_exchange_state.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/sha256.h>
#include <drivechain_bmm.h>
#include <policy/policy.h>
#include <protocol.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

namespace ecx {
namespace {

const COutPoint EXCHANGE_TRACKER_OUTPOINT{
    uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041"),
    0};
const COutPoint FORCED_INBOX_TRACKER_OUTPOINT{
    uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1"),
    0};
const COutPoint DEPOSIT_INBOX_TRACKER_OUTPOINT{
    uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"),
    0};
const std::vector<unsigned char> EXCHANGE_TRACKER_MARKER{
    'e', 'c', 'x', '-', 's', 't', 'a', 't', 'e', '-', 'v', '1'};
const std::vector<unsigned char> FORCED_INBOX_TRACKER_MARKER{
    'e', 'c', 'x', '-', 'f', 'o', 'r', 'c', 'e', 'd', '-', 'v', '1'};
const std::vector<unsigned char> DEPOSIT_INBOX_TRACKER_MARKER{
    'e', 'c', 'x', '-', 'd', 'e', 'p', 'o', 's', 'i', 't', '-', 'v', '1'};
constexpr std::array<unsigned char, 4> FORCED_MAGIC{{'E', 'C', 'X', 'F'}};
constexpr std::array<unsigned char, 4> DEPOSIT_MAGIC{{'E', 'C', 'X', 'D'}};
constexpr std::array<unsigned char, 16> ECX_USDD_MARKET{{
    'E', 'C', 'X', '-', 'U', 'S', 'D', 'D', '-', 'P', 'E', 'R', 'P', 0, 0, 0}};
constexpr size_t FORCED_CANCEL_BODY_SIZE{201};
constexpr size_t FORCED_LIMIT_BODY_SIZE{208};
constexpr size_t FORCED_WITHDRAW_BODY_SIZE{193};
constexpr size_t DEPOSIT_PAYLOAD_SIZE{73};

uint256 Sha256(const std::vector<unsigned char>& bytes);

ExchangeConsensus LoadExchangeConsensus()
{
    ExchangeConsensus result;
    const bool has_height = gArgs.IsArgSet("-ecxactivationheight");
    const bool has_outpoint = gArgs.IsArgSet("-ecxgenesisstateoutpoint");
    const bool has_root = gArgs.IsArgSet("-ecxgenesisstateroot");
    const bool has_chain_id = gArgs.IsArgSet("-ecxchainid");
    const bool has_forced_domain = gArgs.IsArgSet("-ecxforcedactiondomain");
    const bool has_deposit_domain = gArgs.IsArgSet("-ecxdepositinboxdomain");
    const bool has_vault_script = gArgs.IsArgSet("-ecxcollateralvaultscript");
    const bool has_vault_hash = gArgs.IsArgSet("-ecxcollateralvaultscripthash");
    if (!has_height && !has_outpoint && !has_root && !has_chain_id &&
        !has_forced_domain && !has_deposit_domain && !has_vault_script &&
        !has_vault_hash) return result;
    if (Params().NetworkIDString() != "regtest") {
        throw std::runtime_error(
            "ECX runtime activation parameters are restricted to regtest; "
            "production deployments must freeze them in source");
    }
    if (!has_height || !has_outpoint || !has_root || !has_chain_id ||
        !has_forced_domain || !has_deposit_domain || !has_vault_script ||
        !has_vault_hash) {
        throw std::runtime_error(
            "ECX regtest activation requires -ecxactivationheight, "
            "-ecxgenesisstateoutpoint, -ecxgenesisstateroot, -ecxchainid, "
            "-ecxforcedactiondomain, -ecxdepositinboxdomain, "
            "-ecxcollateralvaultscript, and -ecxcollateralvaultscripthash together");
    }

    const int64_t height = gArgs.GetIntArg("-ecxactivationheight", -1);
    if (height <= 0 || height > std::numeric_limits<int>::max()) {
        throw std::runtime_error("invalid -ecxactivationheight");
    }

    const std::string outpoint = gArgs.GetArg("-ecxgenesisstateoutpoint", "");
    const size_t separator = outpoint.find(':');
    uint32_t vout{0};
    if (separator == std::string::npos ||
        outpoint.find(':', separator + 1) != std::string::npos ||
        separator != 64 ||
        !IsHex(outpoint.substr(0, separator)) ||
        !ParseUInt32(outpoint.substr(separator + 1), &vout)) {
        throw std::runtime_error(
            "invalid -ecxgenesisstateoutpoint; expected txid:vout");
    }
    const uint256 txid = uint256S(outpoint.substr(0, separator));
    if (txid.IsNull()) {
        throw std::runtime_error("ECX genesis state txid must be nonzero");
    }

    const std::string root_hex = gArgs.GetArg("-ecxgenesisstateroot", "");
    if (root_hex.size() != 64 || !IsHex(root_hex)) {
        throw std::runtime_error("invalid -ecxgenesisstateroot");
    }
    const uint256 root = uint256S(root_hex);
    if (root.IsNull()) {
        throw std::runtime_error("ECX genesis state root must be nonzero");
    }

    result.activation_height = static_cast<int>(height);
    result.genesis_state_outpoint = COutPoint{txid, vout};
    result.genesis_state_root = root;

    const auto parse_hash32 = [](const std::string& name) {
        const std::string value = gArgs.GetArg(name, "");
        if (value.size() != 64 || !IsHex(value)) {
            throw std::runtime_error("invalid " + name + "; expected 32 raw hex bytes");
        }
        const std::vector<unsigned char> bytes{ParseHex(value)};
        std::array<unsigned char, 32> result{};
        std::copy(bytes.begin(), bytes.end(), result.begin());
        if (std::all_of(result.begin(), result.end(), [](unsigned char byte) { return byte == 0; })) {
            throw std::runtime_error(name + " must be nonzero");
        }
        return result;
    };
    result.chain_id = parse_hash32("-ecxchainid");
    result.forced_action_domain = parse_hash32("-ecxforcedactiondomain");
    result.deposit_inbox_domain = parse_hash32("-ecxdepositinboxdomain");
    if (result.deposit_inbox_domain == result.forced_action_domain) {
        throw std::runtime_error("ECX forced-action and deposit inbox domains must differ");
    }
    const std::string vault_hex = gArgs.GetArg("-ecxcollateralvaultscript", "");
    if (vault_hex.empty() || !IsHex(vault_hex)) {
        throw std::runtime_error("invalid -ecxcollateralvaultscript");
    }
    const std::vector<unsigned char> vault_bytes{ParseHex(vault_hex)};
    result.collateral_vault_script = CScript(vault_bytes.begin(), vault_bytes.end());
    if (result.collateral_vault_script.empty() ||
        result.collateral_vault_script.IsUnspendable()) {
        throw std::runtime_error("ECX collateral vault script must be nonempty and spendable");
    }
    const std::string vault_hash_hex =
        gArgs.GetArg("-ecxcollateralvaultscripthash", "");
    if (vault_hash_hex.size() != 64 || !IsHex(vault_hash_hex)) {
        throw std::runtime_error("invalid -ecxcollateralvaultscripthash");
    }
    const std::vector<unsigned char> vault_hash_bytes{ParseHex(vault_hash_hex)};
    std::copy(
        vault_hash_bytes.begin(),
        vault_hash_bytes.end(),
        result.collateral_vault_script_hash.begin());
    const std::vector<unsigned char> script_bytes(
        result.collateral_vault_script.begin(),
        result.collateral_vault_script.end());
    if (result.collateral_vault_script_hash.IsNull() ||
        result.collateral_vault_script_hash != Sha256(script_bytes)) {
        throw std::runtime_error(
            "-ecxcollateralvaultscripthash does not match the frozen raw script bytes");
    }
    return result;
}

uint256 Sha256(const std::vector<unsigned char>& bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

uint256 TaggedHash(const std::string& tag, const std::vector<unsigned char>& payload)
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

void PushU32Le(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back(value & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 24) & 0xff);
}

void PushU32Be(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back((value >> 24) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back(value & 0xff);
}

void PushU64Be(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back((value >> shift) & 0xff);
    }
}

uint32_t ReadU32Be(const unsigned char* bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        static_cast<uint32_t>(bytes[3]);
}

uint64_t ReadU64Be(const unsigned char* bytes)
{
    uint64_t result{0};
    for (size_t i = 0; i < 8; ++i) result = (result << 8) | bytes[i];
    return result;
}

template <typename Range>
bool IsZero(const Range& value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return byte == 0;
    });
}

uint256 TxOutHash(const CTxOut& output)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << output;
    return Sha256({
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()});
}

struct ForcedActionPayload
{
    uint8_t kind{0};
    std::vector<unsigned char> body;
};

struct DepositPayload
{
    uint32_t deposit_vout{0};
    std::array<unsigned char, 32> trader{};
};

bool ScriptContainsMagic(
    const CScript& script,
    const std::array<unsigned char, 4>& magic)
{
    return !script.empty() && script[0] == OP_RETURN &&
        std::search(script.begin() + 1, script.end(), magic.begin(), magic.end()) !=
            script.end();
}

bool IsNullOutputWitness(const CTransaction& tx, size_t output_index)
{
    return output_index >= tx.witness.vtxoutwit.size() ||
        tx.witness.vtxoutwit[output_index].IsNull();
}

bool VerifySignedBody(
    const std::string& tag,
    const std::vector<unsigned char>& body,
    size_t unsigned_size,
    size_t trader_offset,
    std::string& error)
{
    const XOnlyPubKey trader{
        Span<const unsigned char>(body.data() + trader_offset, 32)};
    if (!trader.IsFullyValid()) {
        error = "ECX forced action contains an invalid x-only trader key";
        return false;
    }
    const std::vector<unsigned char> unsigned_body(
        body.begin(), body.begin() + unsigned_size);
    const uint256 digest{TaggedHash(tag, unsigned_body)};
    if (!trader.VerifySchnorr(
            digest,
            Span<const unsigned char>(body.data() + unsigned_size, 64))) {
        error = "ECX forced action signature is invalid";
        return false;
    }
    return true;
}

bool ValidateForcedBody(
    uint8_t kind,
    const std::vector<unsigned char>& body,
    const ExchangeConsensus& consensus,
    std::string& error)
{
    const size_t expected_size = kind == 0 ? FORCED_CANCEL_BODY_SIZE :
        kind == 1 ? FORCED_LIMIT_BODY_SIZE :
        kind == 2 ? FORCED_WITHDRAW_BODY_SIZE : 0;
    if (expected_size == 0 || body.size() != expected_size || body[0] != 1) {
        error = "ECX forced action kind, version, or fixed body length is invalid";
        return false;
    }
    if (!std::equal(consensus.chain_id.begin(), consensus.chain_id.end(), body.begin() + 1)) {
        error = "ECX forced action chain id does not match this deployment";
        return false;
    }

    if (kind == 0) {
        if (!std::equal(ECX_USDD_MARKET.begin(), ECX_USDD_MARKET.end(), body.begin() + 33) ||
            ReadU64Be(body.data() + 129) < ReadU64Be(body.data() + 121)) {
            error = "ECX forced cancellation body is non-canonical";
            return false;
        }
        return VerifySignedBody(
            "ECX/cancel-order/v1", body, 137, 49, error);
    }
    if (kind == 1) {
        const uint8_t side = body[81];
        const uint8_t time_in_force = body[82];
        const uint8_t flags = body[83];
        if (!std::equal(ECX_USDD_MARKET.begin(), ECX_USDD_MARKET.end(), body.begin() + 33) ||
            side > 1 || time_in_force != 1 || flags != 1 ||
            ReadU64Be(body.data() + 84) == 0 ||
            ReadU64Be(body.data() + 92) == 0 ||
            ReadU64Be(body.data() + 92) >
                static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
            ReadU32Be(body.data() + 116) > 10'000 ||
            ReadU64Be(body.data() + 136) < ReadU64Be(body.data() + 128)) {
            error = "ECX forced reduce-only IOC body is non-canonical";
            return false;
        }
        return VerifySignedBody(
            "ECX/limit-order/v1", body, 144, 49, error);
    }
    if (ReadU64Be(body.data() + 73) == 0 ||
        ReadU64Be(body.data() + 121) < ReadU64Be(body.data() + 113)) {
        error = "ECX forced withdrawal body is non-canonical";
        return false;
    }
    return VerifySignedBody(
        "ECX/withdrawal-request/v1", body, 129, 33, error);
}

bool ParseForcedOutput(
    const CTransaction& tx,
    size_t output_index,
    const ExchangeConsensus& consensus,
    std::optional<ForcedActionPayload>& result,
    std::string& error)
{
    result.reset();
    const CTxOut& output = tx.vout[output_index];
    if (!ScriptContainsMagic(output.scriptPubKey, FORCED_MAGIC)) return true;

    CScript::const_iterator cursor = output.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> payload;
    if (!output.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !output.scriptPubKey.GetOp(cursor, opcode, payload) ||
        cursor != output.scriptPubKey.end() || opcode != OP_PUSHDATA1 ||
        output.scriptPubKey.size() != payload.size() + 3 ||
        output.scriptPubKey[1] != OP_PUSHDATA1 ||
        output.scriptPubKey[2] != payload.size() ||
        payload.size() < 8 ||
        !std::equal(FORCED_MAGIC.begin(), FORCED_MAGIC.end(), payload.begin())) {
        error = "ECX forced action output is not one exact minimal OP_RETURN push";
        return false;
    }
    const uint16_t body_size =
        (static_cast<uint16_t>(payload[6]) << 8) | payload[7];
    if (payload[4] != 1 || body_size != payload.size() - 8 ||
        !output.nAsset.IsExplicit() ||
        output.nAsset.GetAsset() != ::policyAsset ||
        !output.nValue.IsExplicit() || output.nValue.GetAmount() != 0 ||
        !output.nNonce.IsNull() || !IsNullOutputWitness(tx, output_index)) {
        error = "ECX forced action marker envelope is non-canonical";
        return false;
    }
    ForcedActionPayload parsed;
    parsed.kind = payload[5];
    parsed.body.assign(payload.begin() + 8, payload.end());
    if (!ValidateForcedBody(parsed.kind, parsed.body, consensus, error)) return false;
    result = std::move(parsed);
    return true;
}

bool ParseDepositOutput(
    const CTransaction& tx,
    size_t output_index,
    const ExchangeConsensus& consensus,
    std::optional<DepositPayload>& result,
    std::string& error)
{
    result.reset();
    const CTxOut& marker = tx.vout[output_index];
    if (!ScriptContainsMagic(marker.scriptPubKey, DEPOSIT_MAGIC)) return true;

    CScript::const_iterator cursor = marker.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> payload;
    if (!marker.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !marker.scriptPubKey.GetOp(cursor, opcode, payload) ||
        cursor != marker.scriptPubKey.end() || opcode != DEPOSIT_PAYLOAD_SIZE ||
        marker.scriptPubKey.size() != DEPOSIT_PAYLOAD_SIZE + 2 ||
        payload.size() != DEPOSIT_PAYLOAD_SIZE ||
        !std::equal(DEPOSIT_MAGIC.begin(), DEPOSIT_MAGIC.end(), payload.begin())) {
        error = "ECX deposit marker is not one exact minimal OP_RETURN push";
        return false;
    }
    if (payload[4] != 1 ||
        !std::equal(consensus.chain_id.begin(), consensus.chain_id.end(), payload.begin() + 5) ||
        !marker.nAsset.IsExplicit() ||
        marker.nAsset.GetAsset() != ::policyAsset ||
        !marker.nValue.IsExplicit() || marker.nValue.GetAmount() != 0 ||
        !marker.nNonce.IsNull() || !IsNullOutputWitness(tx, output_index)) {
        error = "ECX deposit marker envelope or chain id is non-canonical";
        return false;
    }

    DepositPayload parsed;
    parsed.deposit_vout = ReadU32Be(payload.data() + 37);
    std::copy(payload.begin() + 41, payload.end(), parsed.trader.begin());
    const XOnlyPubKey trader{Span<const unsigned char>(parsed.trader.data(), 32)};
    if (!trader.IsFullyValid() || parsed.deposit_vout >= tx.vout.size() ||
        parsed.deposit_vout == output_index) {
        error = "ECX deposit marker has an invalid trader or referenced vout";
        return false;
    }
    const CTxOut& deposit = tx.vout[parsed.deposit_vout];
    if (deposit.scriptPubKey != consensus.collateral_vault_script ||
        !deposit.nAsset.IsCommitment() || !deposit.nValue.IsCommitment() ||
        !deposit.nNonce.IsCommitment() ||
        parsed.deposit_vout >= tx.witness.vtxoutwit.size() ||
        tx.witness.vtxoutwit[parsed.deposit_vout].vchRangeproof.empty() ||
        tx.witness.vtxoutwit[parsed.deposit_vout].vchSurjectionproof.empty()) {
        error = "ECX deposit does not match the confidential collateral vault profile";
        return false;
    }
    result = parsed;
    return true;
}

bool ConsensusConfigured(const ExchangeConsensus& consensus, std::string& error)
{
    if (consensus.activation_height == std::numeric_limits<int>::max()) return false;
    if (consensus.activation_height <= 0 ||
        consensus.genesis_state_outpoint.IsNull() ||
        consensus.genesis_state_root.IsNull() ||
        IsZero(consensus.chain_id) ||
        IsZero(consensus.forced_action_domain) ||
        IsZero(consensus.deposit_inbox_domain) ||
        consensus.forced_action_domain == consensus.deposit_inbox_domain ||
        consensus.collateral_vault_script.empty() ||
        consensus.collateral_vault_script_hash.IsNull()) {
        error = "ECX activation parameters are incomplete";
        return false;
    }
    const std::vector<unsigned char> vault_script_bytes(
        consensus.collateral_vault_script.begin(),
        consensus.collateral_vault_script.end());
    if (Sha256(vault_script_bytes) != consensus.collateral_vault_script_hash) {
        error = "ECX collateral vault script hash does not match its frozen bytes";
        return false;
    }
    return true;
}

bool ActiveAt(int height, const ExchangeConsensus& consensus)
{
    return consensus.activation_height != std::numeric_limits<int>::max() &&
        height >= consensus.activation_height;
}

CScript EncodeTracker(const ExchangeStateTracker& tracker)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << EXCHANGE_TRACKER_MARKER << tracker;
    return CScript()
        << std::vector<unsigned char>(
               UCharCast(stream.data()),
               UCharCast(stream.data()) + stream.size())
        << OP_DROP
        << OP_FALSE;
}

CScript EncodeInboxTracker(
    const std::vector<unsigned char>& marker,
    const InboxTracker& tracker)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << marker << tracker;
    return CScript()
        << std::vector<unsigned char>(
               UCharCast(stream.data()),
               UCharCast(stream.data()) + stream.size())
        << OP_DROP
        << OP_FALSE;
}

bool DecodeInboxTracker(
    const Coin& coin,
    const std::vector<unsigned char>& expected_marker,
    InboxTracker& tracker,
    std::string& error)
{
    if (coin.IsSpent() || !coin.out.nAsset.IsExplicit() ||
        coin.out.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
        !coin.out.nValue.IsExplicit() || coin.out.nValue.GetAmount() != 0) {
        error = "persisted ECX inbox tracker has invalid asset or value encoding";
        return false;
    }
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!coin.out.scriptPubKey.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_DROP ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_FALSE ||
        cursor != coin.out.scriptPubKey.end()) {
        error = "persisted ECX inbox tracker script is malformed";
        return false;
    }
    try {
        CDataStream stream(data, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> marker;
        stream >> marker >> tracker;
        if (!stream.empty() || marker != expected_marker || tracker.root.IsNull()) {
            error = "persisted ECX inbox tracker payload is invalid";
            return false;
        }
    } catch (...) {
        error = "persisted ECX inbox tracker cannot be decoded";
        return false;
    }
    return true;
}

bool GetInboxTracker(
    const CCoinsViewCache& view,
    const COutPoint& outpoint,
    const std::vector<unsigned char>& marker,
    InboxTracker& tracker,
    std::string& error)
{
    const Coin& coin = view.AccessCoin(outpoint);
    if (coin.IsSpent()) {
        error = "persisted ECX inbox tracker is missing";
        return false;
    }
    return DecodeInboxTracker(coin, marker, tracker, error);
}

void SetInboxTracker(
    CCoinsViewCache& view,
    const COutPoint& outpoint,
    const std::vector<unsigned char>& marker,
    const InboxTracker& tracker,
    int height)
{
    view.SpendCoin(outpoint);
    CTxOut output(
        Params().GetConsensus().pegged_asset,
        0,
        EncodeInboxTracker(marker, tracker));
    view.AddCoin(
        outpoint,
        Coin(std::move(output), std::max(height, 0), false),
        true);
}

bool DecodeTracker(const Coin& coin, ExchangeStateTracker& tracker, std::string& error)
{
    if (coin.IsSpent() ||
        !coin.out.nAsset.IsExplicit() ||
        coin.out.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
        !coin.out.nValue.IsExplicit() ||
        coin.out.nValue.GetAmount() != 0) {
        error = "persisted ECX tracker has invalid asset or value encoding";
        return false;
    }
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!coin.out.scriptPubKey.GetOp(cursor, opcode, data) ||
        opcode > OP_PUSHDATA4 ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_DROP ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_FALSE ||
        cursor != coin.out.scriptPubKey.end()) {
        error = "persisted ECX tracker script is malformed";
        return false;
    }
    try {
        CDataStream stream(data, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> marker;
        stream >> marker >> tracker;
        if (!stream.empty() || marker != EXCHANGE_TRACKER_MARKER ||
            tracker.outpoint.IsNull() || tracker.root.IsNull()) {
            error = "persisted ECX tracker payload is invalid";
            return false;
        }
    } catch (...) {
        error = "persisted ECX tracker cannot be decoded";
        return false;
    }
    return true;
}

bool GetTracker(
    const CCoinsViewCache& view,
    ExchangeStateTracker& tracker,
    std::string& error)
{
    const Coin& coin = view.AccessCoin(EXCHANGE_TRACKER_OUTPOINT);
    if (coin.IsSpent()) {
        error = "persisted ECX tracker is missing";
        return false;
    }
    return DecodeTracker(coin, tracker, error);
}

void SetTracker(CCoinsViewCache& view, const ExchangeStateTracker& tracker, int height)
{
    view.SpendCoin(EXCHANGE_TRACKER_OUTPOINT);
    CTxOut output(
        Params().GetConsensus().pegged_asset,
        0,
        EncodeTracker(tracker));
    view.AddCoin(
        EXCHANGE_TRACKER_OUTPOINT,
        Coin(std::move(output), std::max(height, 0), false),
        true);
}

bool VerifyTrackedCoin(
    const CCoinsViewCache& view,
    const ExchangeStateTracker& tracker,
    CTxOut& output,
    std::string& error)
{
    const Coin& coin = view.AccessCoin(tracker.outpoint);
    if (coin.IsSpent()) {
        error = "tracked ECX singleton is missing from the UTXO set";
        return false;
    }
    output = coin.out;
    if (!output.nAsset.IsExplicit() || !output.nValue.IsExplicit() ||
        !output.nNonce.IsNull()) {
        error = "ECX state authority must use an explicit asset/value and null nonce";
        return false;
    }
    if (output.scriptPubKey.size() != 34 ||
        output.scriptPubKey[0] != OP_1 || output.scriptPubKey[1] != 0x20) {
        error = "ECX state authority must be a P2TR output";
        return false;
    }
    if (ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            tracker.outpoint,
            output) != tracker.root) {
        error = "tracked ECX singleton does not match its persisted root";
        return false;
    }
    return true;
}

bool DeriveNext(
    const CBlock& block,
    const ExchangeStateTracker& previous,
    const CTxOut& previous_output,
    ExchangeStateTracker& next,
    std::string& error)
{
    std::optional<size_t> transition_index;
    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.vtx[tx_index];
        for (const CTxIn& input : tx.vin) {
            if (input.prevout != previous.outpoint) continue;
            if (transition_index.has_value()) {
                error = "more than one transaction spends the ECX singleton";
                return false;
            }
            transition_index = tx_index;
        }
    }
    if (!transition_index.has_value()) {
        next = previous;
        return true;
    }

    const CTransaction& transition = *block.vtx[*transition_index];
    if (transition.vin.empty() || transition.vin[0].prevout != previous.outpoint) {
        error = "ECX singleton must be transition input zero";
        return false;
    }
    if (transition.vout.empty()) {
        error = "ECX transition has no successor output zero";
        return false;
    }
    const CTxOut& successor = transition.vout[0];
    if (!successor.nAsset.IsExplicit() || !successor.nValue.IsExplicit() ||
        !successor.nNonce.IsNull()) {
        error = "ECX successor authority must use an explicit asset/value and null nonce";
        return false;
    }
    if (successor.nAsset.GetAsset() != previous_output.nAsset.GetAsset()) {
        error = "ECX transition changed the state authority asset";
        return false;
    }
    if (successor.nValue.GetAmount() != previous_output.nValue.GetAmount()) {
        error = "ECX transition changed the state authority value";
        return false;
    }
    if (successor.scriptPubKey.size() != 34 ||
        successor.scriptPubKey[0] != OP_1 || successor.scriptPubKey[1] != 0x20) {
        error = "ECX successor state authority must be a P2TR output";
        return false;
    }

    next.outpoint = COutPoint{transition.GetHash(), 0};
    next.root = ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        next.outpoint,
        successor);
    for (size_t tx_index = *transition_index + 1; tx_index < block.vtx.size(); ++tx_index) {
        for (const CTxIn& input : block.vtx[tx_index]->vin) {
            if (input.prevout == next.outpoint) {
                error = "a block may contain at most one ECX state transition";
                return false;
            }
        }
    }
    return true;
}

bool ResolveAuthenticatedParentHeight(
    const CCoinsViewCache& view,
    std::optional<uint64_t> supplied,
    uint64_t& parent_height,
    std::string& error)
{
    if (supplied.has_value()) {
        if (*supplied == 0) {
            error = "ECX inbox event parent height must be nonzero";
            return false;
        }
        parent_height = *supplied;
        return true;
    }
    drivechain::BmmL1State bmm_state;
    std::string bmm_error;
    if (!drivechain::GetBmmState(view, bmm_state, &bmm_error)) {
        error = bmm_error.empty()
            ? "ECX inbox event requires the authenticated BMM parent height"
            : bmm_error;
        return false;
    }
    parent_height = bmm_state.height;
    return parent_height != 0;
}

uint256 AppendForcedEntry(
    const ForcedActionPayload& action,
    const uint256& source_txid,
    uint32_t source_vout,
    uint64_t sidechain_height,
    uint64_t parent_height,
    const ExchangeConsensus& consensus,
    InboxTracker& tracker)
{
    std::vector<unsigned char> entry;
    entry.reserve(1 + 32 + 8 + 32 + 8 + 8 + 32 + 4 + 1 + action.body.size());
    entry.push_back(1);
    entry.insert(entry.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    PushU64Be(entry, tracker.count);
    entry.insert(entry.end(), tracker.root.begin(), tracker.root.end());
    PushU64Be(entry, sidechain_height);
    PushU64Be(entry, parent_height);
    entry.insert(entry.end(), source_txid.begin(), source_txid.end());
    PushU32Be(entry, source_vout);
    entry.push_back(action.kind);
    entry.insert(entry.end(), action.body.begin(), action.body.end());
    const uint256 entry_hash{TaggedHash("ECX/forced-action-entry/v1", entry)};

    std::vector<unsigned char> step;
    step.reserve(72);
    step.insert(step.end(), tracker.root.begin(), tracker.root.end());
    PushU64Be(step, tracker.count);
    step.insert(step.end(), entry_hash.begin(), entry_hash.end());
    tracker.root = TaggedHash("ECX/forced-inbox-step/v1", step);
    ++tracker.count;
    return entry_hash;
}

uint256 AppendDepositEntry(
    const DepositPayload& deposit,
    const CTransaction& transaction,
    uint32_t marker_vout,
    uint64_t sidechain_height,
    uint64_t parent_height,
    const ExchangeConsensus& consensus,
    InboxTracker& tracker)
{
    const uint256 source_txid{transaction.GetHash()};
    const uint256 output_hash{TxOutHash(transaction.vout[deposit.deposit_vout])};
    std::vector<unsigned char> event;
    event.reserve(1 + 32 + 8 + 32 + 8 + 8 + 32 + 4 + 4 + 32 + 32);
    event.push_back(1);
    event.insert(event.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    PushU64Be(event, tracker.count);
    event.insert(event.end(), tracker.root.begin(), tracker.root.end());
    PushU64Be(event, sidechain_height);
    PushU64Be(event, parent_height);
    event.insert(event.end(), source_txid.begin(), source_txid.end());
    PushU32Be(event, deposit.deposit_vout);
    PushU32Be(event, marker_vout);
    event.insert(event.end(), output_hash.begin(), output_hash.end());
    event.insert(event.end(), deposit.trader.begin(), deposit.trader.end());
    const uint256 event_hash{TaggedHash("ECX/deposit-event/v1", event)};

    std::vector<unsigned char> step;
    step.reserve(72);
    step.insert(step.end(), tracker.root.begin(), tracker.root.end());
    PushU64Be(step, tracker.count);
    step.insert(step.end(), event_hash.begin(), event_hash.end());
    tracker.root = TaggedHash("ECX/deposit-inbox-step/v1", step);
    ++tracker.count;
    return event_hash;
}

bool DeriveInboxNext(
    const CBlock& block,
    const CCoinsViewCache& view,
    int height,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> supplied_parent_height,
    const InboxTracker& previous_forced,
    const InboxTracker& previous_deposits,
    InboxTracker& next_forced,
    InboxTracker& next_deposits,
    uint64_t* forced_appends,
    uint64_t* deposit_appends,
    std::string& error)
{
    next_forced = previous_forced;
    next_deposits = previous_deposits;
    uint64_t resolved_parent_height{0};
    bool have_parent_height{false};
    uint64_t forced_count{0};
    uint64_t deposit_count{0};

    for (const CTransactionRef& transaction_ref : block.vtx) {
        const CTransaction& transaction = *transaction_ref;
        std::optional<std::pair<uint32_t, ForcedActionPayload>> forced;
        std::optional<std::pair<uint32_t, DepositPayload>> deposit;
        for (size_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
            std::optional<ForcedActionPayload> parsed_forced;
            if (!ParseForcedOutput(
                    transaction,
                    output_index,
                    consensus,
                    parsed_forced,
                    error)) {
                return false;
            }
            if (parsed_forced.has_value()) {
                if (forced.has_value()) {
                    error = "an Elements transaction may contain only one ECX forced action";
                    return false;
                }
                forced = std::make_pair(
                    static_cast<uint32_t>(output_index),
                    std::move(*parsed_forced));
            }

            std::optional<DepositPayload> parsed_deposit;
            if (!ParseDepositOutput(
                    transaction,
                    output_index,
                    consensus,
                    parsed_deposit,
                    error)) {
                return false;
            }
            if (parsed_deposit.has_value()) {
                if (deposit.has_value()) {
                    error = "an Elements transaction may contain only one ECX deposit marker";
                    return false;
                }
                deposit = std::make_pair(
                    static_cast<uint32_t>(output_index),
                    *parsed_deposit);
            }
        }

        if ((forced.has_value() || deposit.has_value()) && !have_parent_height) {
            if (!ResolveAuthenticatedParentHeight(
                    view,
                    supplied_parent_height,
                    resolved_parent_height,
                    error)) {
                return false;
            }
            have_parent_height = true;
        }
        if (forced.has_value()) {
            if (next_forced.count == std::numeric_limits<uint64_t>::max()) {
                error = "ECX forced inbox index overflow";
                return false;
            }
            AppendForcedEntry(
                forced->second,
                transaction.GetHash(),
                forced->first,
                static_cast<uint64_t>(height),
                resolved_parent_height,
                consensus,
                next_forced);
            ++forced_count;
        }
        if (deposit.has_value()) {
            if (next_deposits.count == std::numeric_limits<uint64_t>::max()) {
                error = "ECX deposit inbox index overflow";
                return false;
            }
            AppendDepositEntry(
                deposit->second,
                transaction,
                deposit->first,
                static_cast<uint64_t>(height),
                resolved_parent_height,
                consensus,
                next_deposits);
            ++deposit_count;
        }
    }
    if (forced_appends) *forced_appends = forced_count;
    if (deposit_appends) *deposit_appends = deposit_count;
    return true;
}

bool ExpectedForBlock(
    const CBlock& block,
    const CBlockIndex* previous_index,
    const CCoinsViewCache& view,
    int height,
    ExchangeStateTracker& next,
    InboxTracker& next_forced,
    InboxTracker& next_deposits,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    if (height == consensus.activation_height) {
        ExchangeStateTracker genesis{
            consensus.genesis_state_outpoint,
            consensus.genesis_state_root};
        CTxOut genesis_output;
        if (!VerifyTrackedCoin(view, genesis, genesis_output, error)) return false;
        ExchangeStateTracker derived;
        if (!DeriveNext(block, genesis, genesis_output, derived, error)) return false;
        if (derived.outpoint != genesis.outpoint || derived.root != genesis.root) {
            error = "ECX activation block must carry the frozen genesis state";
            return false;
        }
        next = genesis;
        const InboxTracker forced_genesis{
            ComputeForcedInboxGenesis(consensus), 0};
        const InboxTracker deposit_genesis{
            ComputeDepositInboxGenesis(consensus), 0};
        if (forced_genesis.root.IsNull() || deposit_genesis.root.IsNull()) {
            error = "ECX inbox genesis commitment is invalid";
            return false;
        }
        uint64_t forced_appends{0};
        uint64_t deposit_appends{0};
        if (!DeriveInboxNext(
                block,
                view,
                height,
                consensus,
                authenticated_parent_height,
                forced_genesis,
                deposit_genesis,
                next_forced,
                next_deposits,
                &forced_appends,
                &deposit_appends,
                error)) {
            return false;
        }
        if (forced_appends != 0 || deposit_appends != 0) {
            error = "ECX activation block must carry the frozen inbox genesis state";
            return false;
        }
        return true;
    }

    ExchangeStateTracker previous;
    if (!GetTracker(view, previous, error)) return false;
    if (!previous_index ||
        (static_cast<uint32_t>(previous_index->nVersion) &
         CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
        previous_index->hashExchangeStateRoot != previous.root) {
        error = "persisted ECX tracker disagrees with the prior header root";
        return false;
    }
    CTxOut previous_output;
    if (!VerifyTrackedCoin(view, previous, previous_output, error)) return false;
    if (!DeriveNext(block, previous, previous_output, next, error)) return false;

    InboxTracker previous_forced;
    if (!GetInboxTracker(
            view,
            FORCED_INBOX_TRACKER_OUTPOINT,
            FORCED_INBOX_TRACKER_MARKER,
            previous_forced,
            error)) {
        return false;
    }
    InboxTracker previous_deposits;
    if (!GetInboxTracker(
            view,
            DEPOSIT_INBOX_TRACKER_OUTPOINT,
            DEPOSIT_INBOX_TRACKER_MARKER,
            previous_deposits,
            error)) {
        return false;
    }
    if (!previous_index ||
        (static_cast<uint32_t>(previous_index->nVersion) &
         CBlockHeader::FORCED_INBOX_HF_MASK) == 0 ||
        (static_cast<uint32_t>(previous_index->nVersion) &
         CBlockHeader::DEPOSIT_INBOX_HF_MASK) == 0 ||
        previous_index->hashForcedInboxRoot != previous_forced.root ||
        previous_index->hashDepositInboxRoot != previous_deposits.root) {
        error = "persisted ECX inbox trackers disagree with the prior header roots";
        return false;
    }
    return DeriveInboxNext(
        block,
        view,
        height,
        consensus,
        authenticated_parent_height,
        previous_forced,
        previous_deposits,
        next_forced,
        next_deposits,
        nullptr,
        nullptr,
        error);
}

} // namespace

uint256 ComputeForcedInboxGenesis(const ExchangeConsensus& consensus)
{
    std::vector<unsigned char> payload;
    payload.reserve(64);
    payload.insert(
        payload.end(),
        consensus.forced_action_domain.begin(),
        consensus.forced_action_domain.end());
    payload.insert(payload.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    return TaggedHash("ECX/forced-inbox-genesis/v1", payload);
}

uint256 ComputeDepositInboxGenesis(const ExchangeConsensus& consensus)
{
    std::vector<unsigned char> payload;
    payload.reserve(64);
    payload.insert(
        payload.end(),
        consensus.deposit_inbox_domain.begin(),
        consensus.deposit_inbox_domain.end());
    payload.insert(payload.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    return TaggedHash("ECX/deposit-inbox-genesis/v1", payload);
}

const ExchangeConsensus& LayerTwoLabsExchangeConsensus()
{
    // Mainnet/signet remain fail-closed until reviewed constants replace the
    // defaults. Regtest can inject a frozen checkpoint at process start for
    // activation, reorg and reindex functional testing.
    static const ExchangeConsensus consensus{LoadExchangeConsensus()};
    return consensus;
}

bool IsExchangeStateInternalOutpoint(const COutPoint& outpoint)
{
    return outpoint == EXCHANGE_TRACKER_OUTPOINT ||
        outpoint == FORCED_INBOX_TRACKER_OUTPOINT ||
        outpoint == DEPOSIT_INBOX_TRACKER_OUTPOINT;
}

uint256 ComputeStateUtxoRoot(
    const uint256& child_genesis,
    const COutPoint& outpoint,
    const CTxOut& output)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << output;
    const std::vector<unsigned char> output_bytes{
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
    const uint256 output_hash = Sha256(output_bytes);

    std::vector<unsigned char> payload;
    payload.reserve(100);
    payload.insert(payload.end(), child_genesis.begin(), child_genesis.end());
    payload.insert(payload.end(), outpoint.hash.begin(), outpoint.hash.end());
    PushU32Le(payload, outpoint.n);
    payload.insert(payload.end(), output_hash.begin(), output_hash.end());
    return TaggedHash("ECX/header-state/v1", payload);
}

bool CheckExchangeStateHeader(
    const CBlockHeader& block,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    const bool exchange_signalled = block.HasExchangeState();
    const bool forced_signalled = block.HasForcedInbox();
    const bool deposit_signalled = block.HasDepositInbox();
    if (!ActiveAt(height, consensus)) {
        if (exchange_signalled || forced_signalled || deposit_signalled ||
            !block.hashExchangeStateRoot.IsNull() ||
            !block.hashForcedInboxRoot.IsNull() ||
            !block.hashDepositInboxRoot.IsNull() || block.ecxParentHeight != 0) {
            error = "ECX header extensions are forbidden before activation";
            return false;
        }
        return true;
    }
    if (!ConsensusConfigured(consensus, error)) return false;
    if (!exchange_signalled || !forced_signalled || !deposit_signalled ||
        block.hashExchangeStateRoot.IsNull() ||
        block.hashForcedInboxRoot.IsNull() ||
        block.hashDepositInboxRoot.IsNull() || block.ecxParentHeight == 0) {
        error = "all ECX header extensions are required and nonzero after activation";
        return false;
    }
    if (height == consensus.activation_height &&
        (block.hashExchangeStateRoot != consensus.genesis_state_root ||
         block.hashForcedInboxRoot != ComputeForcedInboxGenesis(consensus) ||
         block.hashDepositInboxRoot != ComputeDepositInboxGenesis(consensus))) {
        error = "ECX activation header does not commit the frozen genesis roots";
        return false;
    }
    return true;
}

bool PrepareExchangeStateHeader(
    CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    error.clear();
    if (!ActiveAt(height, consensus)) {
        block.nVersion = static_cast<int32_t>(
            static_cast<uint32_t>(block.nVersion) &
            ~(CBlockHeader::EXCHANGE_STATE_HF_MASK |
              CBlockHeader::FORCED_INBOX_HF_MASK |
              CBlockHeader::DEPOSIT_INBOX_HF_MASK));
        block.hashExchangeStateRoot.SetNull();
        block.hashForcedInboxRoot.SetNull();
        block.hashDepositInboxRoot.SetNull();
        block.ecxParentHeight = 0;
        return true;
    }
    if (!ConsensusConfigured(consensus, error)) return false;
    if (!authenticated_parent_height.has_value()) {
        if (Params().NetworkIDString() != "regtest") {
            error = "ECX block assembly requires an authenticated target parent height";
            return false;
        }
        authenticated_parent_height = previous && previous->ecxParentHeight != 0
            ? static_cast<uint64_t>(previous->ecxParentHeight) + 1
            : 1;
    }
    if (*authenticated_parent_height == 0 ||
        *authenticated_parent_height > std::numeric_limits<uint32_t>::max()) {
        error = "ECX target parent height is outside the committed 32-bit range";
        return false;
    }
    ExchangeStateTracker next;
    InboxTracker next_forced;
    InboxTracker next_deposits;
    if (!ExpectedForBlock(
            block,
            previous,
            view,
            height,
            next,
            next_forced,
            next_deposits,
            error,
            consensus,
            authenticated_parent_height)) {
        return false;
    }
    block.nVersion = static_cast<int32_t>(
        static_cast<uint32_t>(block.nVersion) |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK);
    block.hashExchangeStateRoot = next.root;
    block.hashForcedInboxRoot = next_forced.root;
    block.hashDepositInboxRoot = next_deposits.root;
    block.ecxParentHeight = static_cast<uint32_t>(*authenticated_parent_height);
    return true;
}

bool ConnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height,
    const bool allow_incomplete_candidate)
{
    if (!CheckExchangeStateHeader(block, height, error, consensus)) return false;
    if (!ActiveAt(height, consensus)) return true;
    if (authenticated_parent_height.has_value() &&
        *authenticated_parent_height != block.ecxParentHeight) {
        error = "ECX supplied parent height disagrees with the committed header height";
        return false;
    }
    if (!authenticated_parent_height.has_value()) {
        drivechain::BmmL1State bmm_state;
        std::string bmm_error;
        if (drivechain::GetBmmState(view, bmm_state, &bmm_error)) {
            if (bmm_state.height != block.ecxParentHeight) {
                const bool incomplete = allow_incomplete_candidate &&
                    block.HasBmmProof() && block.hashBmmProof.IsNull() &&
                    block.m_bmm_proof.empty();
                if (!incomplete) {
                    error = "ECX committed parent height disagrees with authenticated BMM state";
                    return false;
                }
            }
        } else if (Params().NetworkIDString() != "regtest") {
            error = bmm_error.empty()
                ? "ECX committed parent height has no authenticated BMM state"
                : bmm_error;
            return false;
        }
        authenticated_parent_height = block.ecxParentHeight;
    }
    ExchangeStateTracker next;
    InboxTracker next_forced;
    InboxTracker next_deposits;
    if (!ExpectedForBlock(
            block,
            previous,
            view,
            height,
            next,
            next_forced,
            next_deposits,
            error,
            consensus,
            authenticated_parent_height)) {
        return false;
    }
    if (block.hashExchangeStateRoot != next.root ||
        block.hashForcedInboxRoot != next_forced.root ||
        block.hashDepositInboxRoot != next_deposits.root) {
        error = "ECX header roots do not match deterministic singleton and inbox derivation";
        return false;
    }
    SetTracker(view, next, height);
    SetInboxTracker(
        view,
        FORCED_INBOX_TRACKER_OUTPOINT,
        FORCED_INBOX_TRACKER_MARKER,
        next_forced,
        height);
    SetInboxTracker(
        view,
        DEPOSIT_INBOX_TRACKER_OUTPOINT,
        DEPOSIT_INBOX_TRACKER_MARKER,
        next_deposits,
        height);
    return true;
}

bool DisconnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    error.clear();
    if (!ActiveAt(height, consensus)) return true;
    if (block.ecxParentHeight == 0 ||
        (authenticated_parent_height.has_value() &&
         *authenticated_parent_height != block.ecxParentHeight)) {
        error = "ECX disconnected block has an inconsistent parent height";
        return false;
    }
    authenticated_parent_height = block.ecxParentHeight;
    ExchangeStateTracker current;
    if (!GetTracker(view, current, error)) return false;
    if (current.root != block.hashExchangeStateRoot) {
        error = "persisted ECX tracker disagrees with disconnected header";
        return false;
    }
    InboxTracker current_forced;
    if (!GetInboxTracker(
            view,
            FORCED_INBOX_TRACKER_OUTPOINT,
            FORCED_INBOX_TRACKER_MARKER,
            current_forced,
            error)) {
        return false;
    }
    InboxTracker current_deposits;
    if (!GetInboxTracker(
            view,
            DEPOSIT_INBOX_TRACKER_OUTPOINT,
            DEPOSIT_INBOX_TRACKER_MARKER,
            current_deposits,
            error)) {
        return false;
    }
    if (current_forced.root != block.hashForcedInboxRoot ||
        current_deposits.root != block.hashDepositInboxRoot) {
        error = "persisted ECX inbox trackers disagree with disconnected header";
        return false;
    }
    if (height == consensus.activation_height) {
        if (!view.SpendCoin(EXCHANGE_TRACKER_OUTPOINT)) {
            error = "ECX activation tracker could not be removed";
            return false;
        }
        if (!view.SpendCoin(FORCED_INBOX_TRACKER_OUTPOINT) ||
            !view.SpendCoin(DEPOSIT_INBOX_TRACKER_OUTPOINT)) {
            error = "ECX activation inbox trackers could not be removed";
            return false;
        }
        return true;
    }
    if (!previous ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
        previous->hashExchangeStateRoot.IsNull()) {
        error = "prior ECX header state is unavailable during disconnect";
        return false;
    }
    if ((static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::FORCED_INBOX_HF_MASK) == 0 ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::DEPOSIT_INBOX_HF_MASK) == 0 ||
        previous->hashForcedInboxRoot.IsNull() ||
        previous->hashDepositInboxRoot.IsNull()) {
        error = "prior ECX inbox header state is unavailable during disconnect";
        return false;
    }

    InboxTracker counting_forced{previous->hashForcedInboxRoot, 0};
    InboxTracker counting_deposits{previous->hashDepositInboxRoot, 0};
    InboxTracker ignored_forced;
    InboxTracker ignored_deposits;
    uint64_t forced_appends{0};
    uint64_t deposit_appends{0};
    if (!DeriveInboxNext(
            block,
            view,
            height,
            consensus,
            authenticated_parent_height,
            counting_forced,
            counting_deposits,
            ignored_forced,
            ignored_deposits,
            &forced_appends,
            &deposit_appends,
            error)) {
        return false;
    }
    if (forced_appends > current_forced.count ||
        deposit_appends > current_deposits.count) {
        error = "ECX inbox count underflow during disconnect";
        return false;
    }
    InboxTracker restored_forced{
        previous->hashForcedInboxRoot,
        current_forced.count - forced_appends};
    InboxTracker restored_deposits{
        previous->hashDepositInboxRoot,
        current_deposits.count - deposit_appends};
    InboxTracker rederived_forced;
    InboxTracker rederived_deposits;
    if (!DeriveInboxNext(
            block,
            view,
            height,
            consensus,
            authenticated_parent_height,
            restored_forced,
            restored_deposits,
            rederived_forced,
            rederived_deposits,
            nullptr,
            nullptr,
            error)) {
        return false;
    }
    if (rederived_forced.root != current_forced.root ||
        rederived_forced.count != current_forced.count ||
        rederived_deposits.root != current_deposits.root ||
        rederived_deposits.count != current_deposits.count) {
        error = "ECX inbox undo does not reproduce the disconnected header state";
        return false;
    }

    COutPoint prior_outpoint = current.outpoint;
    for (const CTransactionRef& tx : block.vtx) {
        if (current.outpoint.n == 0 && tx->GetHash() == current.outpoint.hash) {
            if (tx->vin.empty()) {
                error = "ECX transition cannot recover its prior singleton";
                return false;
            }
            prior_outpoint = tx->vin[0].prevout;
            break;
        }
    }
    const Coin& prior_coin = view.AccessCoin(prior_outpoint);
    if (prior_coin.IsSpent()) {
        error = "prior ECX singleton was not restored by transaction undo";
        return false;
    }
    ExchangeStateTracker restored{
        prior_outpoint,
        ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            prior_outpoint,
            prior_coin.out)};
    if (restored.root != previous->hashExchangeStateRoot) {
        error = "restored ECX singleton disagrees with prior header root";
        return false;
    }
    SetTracker(view, restored, height - 1);
    SetInboxTracker(
        view,
        FORCED_INBOX_TRACKER_OUTPOINT,
        FORCED_INBOX_TRACKER_MARKER,
        restored_forced,
        height - 1);
    SetInboxTracker(
        view,
        DEPOSIT_INBOX_TRACKER_OUTPOINT,
        DEPOSIT_INBOX_TRACKER_MARKER,
        restored_deposits,
        height - 1);
    return true;
}

bool GetPriorActiveExchangeStateRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error)
{
    error.clear();
    root.SetNull();
    if (!previous ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
        previous->hashExchangeStateRoot.IsNull()) {
        error = "prior-active ECX state root is unavailable";
        return false;
    }
    root = previous->hashExchangeStateRoot;
    return true;
}

bool GetPriorActiveForcedInboxRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error)
{
    error.clear();
    root.SetNull();
    if (!previous ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::FORCED_INBOX_HF_MASK) == 0 ||
        previous->hashForcedInboxRoot.IsNull()) {
        error = "prior-active ECX forced inbox root is unavailable";
        return false;
    }
    root = previous->hashForcedInboxRoot;
    return true;
}

bool GetPriorActiveDepositInboxRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error)
{
    error.clear();
    root.SetNull();
    if (!previous ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::DEPOSIT_INBOX_HF_MASK) == 0 ||
        previous->hashDepositInboxRoot.IsNull()) {
        error = "prior-active ECX deposit inbox root is unavailable";
        return false;
    }
    root = previous->hashDepositInboxRoot;
    return true;
}

bool GetExchangeConsensusSnapshot(
    const CCoinsViewCache& view,
    const CBlockIndex* tip,
    ExchangeConsensusSnapshot& snapshot,
    std::string& error)
{
    error.clear();
    snapshot = {};
    if (!tip ||
        (static_cast<uint32_t>(tip->nVersion) &
         CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
        (static_cast<uint32_t>(tip->nVersion) &
         CBlockHeader::FORCED_INBOX_HF_MASK) == 0 ||
        (static_cast<uint32_t>(tip->nVersion) &
         CBlockHeader::DEPOSIT_INBOX_HF_MASK) == 0) {
        error = "active tip has no complete ECX consensus context";
        return false;
    }

    ExchangeStateTracker exchange;
    InboxTracker forced;
    InboxTracker deposits;
    if (!GetTracker(view, exchange, error) ||
        !GetInboxTracker(
            view,
            FORCED_INBOX_TRACKER_OUTPOINT,
            FORCED_INBOX_TRACKER_MARKER,
            forced,
            error) ||
        !GetInboxTracker(
            view,
            DEPOSIT_INBOX_TRACKER_OUTPOINT,
            DEPOSIT_INBOX_TRACKER_MARKER,
            deposits,
            error)) {
        return false;
    }
    if (exchange.root != tip->hashExchangeStateRoot ||
        forced.root != tip->hashForcedInboxRoot ||
        deposits.root != tip->hashDepositInboxRoot) {
        error = "persisted ECX context disagrees with the active tip";
        return false;
    }
    CTxOut exchange_output;
    if (!VerifyTrackedCoin(view, exchange, exchange_output, error)) return false;

    snapshot.exchange_state_root = exchange.root;
    snapshot.forced_inbox_root = forced.root;
    snapshot.forced_entry_count = forced.count;
    snapshot.deposit_inbox_root = deposits.root;
    snapshot.deposit_entry_count = deposits.count;
    return true;
}

} // namespace ecx
