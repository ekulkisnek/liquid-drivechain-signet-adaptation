// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <ecx_exchange_state.h>

#include <chain.h>
#include <chainparams.h>
#include <blind.h>
#include <coins.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <hash.h>
#include <issuance.h>
#include <policy/policy.h>
#include <protocol.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>
extern "C" {
#include <simplicity/elements/env.h>
}

#include <algorithm>
#include <array>
#include <bitset>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <utility>
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
uint256 TaggedHash(const std::string& tag, const std::vector<unsigned char>& payload);
void AppendHash(std::vector<unsigned char>& bytes, const uint256& value);
void PushU32Be(std::vector<unsigned char>& bytes, uint32_t value);
void PushU64Be(std::vector<unsigned char>& bytes, uint64_t value);
uint32_t ReadU32Be(const unsigned char* bytes);
uint64_t ReadU64Be(const unsigned char* bytes);
void ConfigureBondV2FromArgs(ExchangeConsensus& consensus);

#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
#define ECX_PRODUCTION_NETWORK(value) \
    constexpr const char* ECX_PRODUCTION_NETWORK_ID{value};
#define ECX_PRODUCTION_RELEASE_RECORD_SHA256(value) \
    constexpr const char* ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX{value};
#define ECX_PRODUCTION_ARG(name, value)
#include "ecxProductionActivationProfile.inc"
#undef ECX_PRODUCTION_ARG
#undef ECX_PRODUCTION_RELEASE_RECORD_SHA256
#undef ECX_PRODUCTION_NETWORK

const std::vector<std::pair<const char*, const char*>> ECX_PRODUCTION_ACTIVATION_ARGS{
#define ECX_PRODUCTION_NETWORK(value)
#define ECX_PRODUCTION_RELEASE_RECORD_SHA256(value)
#define ECX_PRODUCTION_ARG(name, value) {name, value},
#include "ecxProductionActivationProfile.inc"
#undef ECX_PRODUCTION_ARG
#undef ECX_PRODUCTION_RELEASE_RECORD_SHA256
#undef ECX_PRODUCTION_NETWORK
};

void ApplyFrozenEcxProductionProfile()
{
    if (Params().NetworkIDString() != ECX_PRODUCTION_NETWORK_ID) return;
    if (std::string{ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX}.size() != 64 ||
        !IsHex(ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX)) {
        throw std::runtime_error(
            "source-frozen ECX production release-record hash is noncanonical");
    }
    for (const auto& [name, value] : ECX_PRODUCTION_ACTIVATION_ARGS) {
        if (gArgs.IsArgSet(name) && gArgs.GetArg(name, "") != value) {
            throw std::runtime_error(
                std::string("operator override conflicts with the source-frozen ECX production profile: ") +
                name);
        }
        gArgs.ForceSetArg(name, value);
    }
}
#else
void ApplyFrozenEcxProductionProfile() {}
#endif

bool IsEcxRuntimeTestNetwork()
{
    const std::string& network = Params().NetworkIDString();
    return Params().GetConsensus().elements_mode && network == "elementsregtest";
}

ExchangeConsensus LoadExchangeConsensus()
{
    ApplyFrozenEcxProductionProfile();
    ExchangeConsensus result;
    const bool has_height = gArgs.IsArgSet("-ecxactivationheight");
    const bool has_outpoint = gArgs.IsArgSet("-ecxgenesisstateoutpoint");
    const bool has_root = gArgs.IsArgSet("-ecxgenesisstateroot");
    const bool has_chain_id = gArgs.IsArgSet("-ecxchainid");
    const bool has_forced_domain = gArgs.IsArgSet("-ecxforcedactiondomain");
    const bool has_deposit_domain = gArgs.IsArgSet("-ecxdepositinboxdomain");
    const bool has_vault_script = gArgs.IsArgSet("-ecxcollateralvaultscript");
    const bool has_vault_hash = gArgs.IsArgSet("-ecxcollateralvaultscripthash");
    const bool has_bond_v2 = gArgs.IsArgSet("-ecxbondv2");
    if (!has_height && !has_outpoint && !has_root && !has_chain_id &&
        !has_forced_domain && !has_deposit_domain && !has_vault_script &&
        !has_vault_hash && !has_bond_v2) return result;
    const bool frozen_production_network{
#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
        Params().NetworkIDString() == ECX_PRODUCTION_NETWORK_ID
#else
        false
#endif
    };
    if (!IsEcxRuntimeTestNetwork() && !frozen_production_network) {
        throw std::runtime_error(
            "ECX runtime activation parameters are restricted to elementsregtest; "
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
    if (height <= 0 || height >= std::numeric_limits<int>::max()) {
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
    if (has_bond_v2) ConfigureBondV2FromArgs(result);
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

/* BIP341's reviewed NUMS point H. No ECX covenant may accept an
 * operator-selected Taproot internal key: a known discrete logarithm would
 * provide a key-path bypass around every Simplicity leaf. */
constexpr std::array<unsigned char, 32> ECX_BIP341_NUMS_XONLY{{
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}};

/* SHA256("ECX/bond-inbox-redemption-staging-renderer/v3-no-history").
 * V18 carries this value explicitly so every renderer uses one domain. */
constexpr std::array<unsigned char, 32> ECX_BOND_STAGING_RENDERER_DOMAIN_V18{{
    0xd8, 0xca, 0x78, 0x83, 0x76, 0x9d, 0xd7, 0x38,
    0x30, 0x98, 0x7f, 0x72, 0x7a, 0x34, 0x93, 0x9d,
    0x2d, 0x9b, 0x69, 0xa3, 0xe7, 0x83, 0xe0, 0xa2,
    0xe1, 0xcc, 0xa3, 0x5f, 0xa4, 0x87, 0x2e, 0x6f,
}};

bool IsEcxNumsInternalKey(const unsigned char* bytes)
{
    return std::equal(
        ECX_BIP341_NUMS_XONLY.begin(), ECX_BIP341_NUMS_XONLY.end(), bytes);
}

bool IsEcxStagingRendererDomainV18(const unsigned char* bytes)
{
    return std::equal(
        ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin(),
        ECX_BOND_STAGING_RENDERER_DOMAIN_V18.end(), bytes);
}

bool TapNodeHashLess(const uint256& left, const uint256& right)
{
    /* BIP341 compares the 32 serialized hash bytes lexicographically. Keep
     * that rule explicit here: this branch's opaque uint256 operator< is also
     * a raw memcmp, but an arithmetic-uint256 conversion would be wrong. */
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end());
}

[[maybe_unused]] uint256 ParseRawHash32Arg(const std::string& name)
{
    const std::string value{gArgs.GetArg(name, "")};
    if (value.size() != 64 || !IsHex(value)) {
        throw std::runtime_error("invalid " + name + "; expected 32 raw hex bytes");
    }
    const std::vector<unsigned char> bytes{ParseHex(value)};
    uint256 result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    if (result.IsNull()) throw std::runtime_error(name + " must be nonzero");
    return result;
}

[[maybe_unused]] uint32_t ParseU32Arg(const std::string& name)
{
    const int64_t value{gArgs.GetIntArg(name, -1)};
    if (value < 0 || value > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("invalid " + name);
    }
    return static_cast<uint32_t>(value);
}

struct DecodedFrozenConfigurationV18
{
    uint256 chain_id;
    uint256 ecx_asset_id;
    uint256 usdd_asset_id;
    uint256 policy_asset_id;
    uint256 state_authority_asset_id;
    uint256 availability_scheme_hash;
    uint256 availability_registry_hash;
    uint256 truthcoin_program_id;
    uint256 matcher_genesis_receipt_hash;
    uint256 forced_action_domain;
    uint256 deposit_inbox_domain;
    uint256 collateral_vault_script_sha256;
    uint256 collateral_vault_covenant_cmr;
    uint256 bond_asset_id;
    uint256 deployment_commitment;
    uint256 inventory_script_sha256;
    uint256 queue_script_sha256;
    uint256 staging_template_commitment;
    uint256 staging_renderer_domain;
    uint256 staging_internal_key;
    uint8_t staging_tapleaf_version{0};
    uint256 staging_process_cmr;
    uint256 staging_refund_cmr;
    uint32_t refund_minimum_parent_blocks{0};
    uint256 insurance_script_sha256;
    uint256 insurance_reserve_covenant_cmr;
    uint256 burn_script_sha256;
    uint256 bond_inbox_domain;
    uint256 custody_receipt_codec_hash;
    uint32_t inbox_inclusion_blocks{0};
    uint32_t inbox_max_bundle_bytes{0};
    uint32_t inbox_max_entries_per_block{0};
    uint32_t inbox_max_unique_witness_bytes_per_block{0};
    uint32_t inbox_max_unique_transaction_bytes_per_block{0};
    uint32_t inbox_max_pending_per_transition{0};
    uint32_t inbox_max_consumed_per_transition{0};
    uint32_t redemption_max_queue_entries{0};
    uint32_t matcher_execution_inclusion_parent_blocks{0};
    uint256 ecx_btc_program_id;
    uint256 usdd_usd_program_id;
    uint256 ecx_btc_redemption_covenant;
    uint256 ecx_btc_source_checkpoint;
    uint256 usdd_usd_redemption_covenant;
    uint256 usdd_usd_source_checkpoint;
    uint64_t maximum_conversion_age_seconds{0};
    uint32_t maximum_conversion_proof_bytes{0};
    uint32_t recursive_proof_marker_bytes{0};
    uint64_t fixed_supply_atoms{0};
    uint64_t redemption_delay_parent_blocks{0};
};

class FrozenConfigurationCursor
{
private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_offset{0};

public:
    explicit FrozenConfigurationCursor(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    bool Bytes(unsigned char* output, size_t count)
    {
        if (count > m_bytes.size() - std::min(m_offset, m_bytes.size())) return false;
        std::copy(m_bytes.begin() + m_offset, m_bytes.begin() + m_offset + count, output);
        m_offset += count;
        return true;
    }

    bool U8(uint8_t& output) { return Bytes(&output, 1); }

    bool U32(uint32_t& output)
    {
        unsigned char bytes[4];
        if (!Bytes(bytes, sizeof(bytes))) return false;
        output = ReadU32Be(bytes);
        return true;
    }

    bool U64(uint64_t& output)
    {
        unsigned char bytes[8];
        if (!Bytes(bytes, sizeof(bytes))) return false;
        output = ReadU64Be(bytes);
        return true;
    }

    bool Hash(uint256& output) { return Bytes(output.begin(), 32); }
    bool Finished() const { return m_offset == m_bytes.size(); }
};

bool IsNonzeroBytes(const unsigned char* bytes, size_t count)
{
    return std::any_of(bytes, bytes + count, [](unsigned char value) { return value != 0; });
}

uint256 AvailabilitySchemeHashV1()
{
    std::vector<unsigned char> profile{
        'E', 'C', 'X', 'W', 'I', 'T', '1', 0,
        0, 1, 3, 5};
    PushU64Be(profile, 16 * 1024 * 1024);
    const std::array<std::string, 14> identities{{
        "XChaCha20-Poly1305", "HKDF-SHA256", "X25519",
        "Ristretto255-Feldman", "Ed25519", "ECX/witness-bundle-root/v1",
        "ECX/witness-bundle-header/v1", "ECX/witness-payload-aad/v1",
        "ECX/witness-share-aad/v1", "ECX/witness-payload-key/v1",
        "ECX/witness-share-key/v1", "ECX/witness-custodian-attestation/v1",
        "ECX/witness-custody-receipt/v1", "ECX/witness-share-hash/v1"}};
    for (const std::string& identity : identities) {
        PushU32Be(profile, identity.size());
        profile.insert(profile.end(), identity.begin(), identity.end());
    }
    return TaggedHash("ECX/witness-availability-scheme/v1", profile);
}

uint256 CustodyReceiptCodecHashV1()
{
    const std::string layout{
        "version:u8|bundle_root:32|context:32|witness_len:u64be|"
        "custodian_index:u8(1..5)|ed25519_signature:64"};
    return TaggedHash(
        "ECX/witness-custody-receipt-codec/v1",
        std::vector<unsigned char>(layout.begin(), layout.end()));
}

struct ParsedBondInboxMarker
{
    uint8_t kind{0};
    uint256 signer;
    uint256 action_id;
    uint256 staging_intent_id;
    uint32_t staging_vout{0};
    uint256 refund_script_sha256;
    uint64_t refund_not_before_parent_height{0};
    uint256 payload_commitment;
    uint256 availability_bundle_root;
    uint256 availability_context;
    uint256 availability_receipt_root;
    uint32_t availability_bundle_len{0};
    uint8_t availability_receipt_bitmap{0};
    uint256 source_authorization_commitment;
};

bool ParseCanonicalBondInboxMarker(
    const CScript& script,
    ParsedBondInboxMarker& marker,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool require_wrapper_signature,
    bool successor)
{
    static constexpr size_t MARKER_LEN{503};
    error.clear();
    CScript::const_iterator cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> payload;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !script.GetOp(cursor, opcode, payload) || opcode != OP_PUSHDATA2 ||
        cursor != script.end() || payload.size() != MARKER_LEN ||
        !std::equal(payload.begin(), payload.begin() + 4, "ECXB") ||
        payload[4] != (successor ? 3 : 1) || payload[5] > 3) {
        error = "not an exact minimal-PUSHDATA2 ECX bond-inbox marker";
        return false;
    }
    const auto raw_hash = [&](size_t offset) {
        uint256 value;
        std::copy_n(payload.data() + offset, 32, value.begin());
        return value;
    };
    const uint256 chain_id{raw_hash(6)};
    const uint256 configuration_hash{raw_hash(38)};
    marker.kind = payload[5];
    marker.signer = raw_hash(70);
    marker.action_id = raw_hash(102);
    marker.staging_intent_id = raw_hash(134);
    marker.staging_vout = ReadU32Be(payload.data() + 166);
    marker.refund_script_sha256 = raw_hash(170);
    marker.refund_not_before_parent_height = ReadU64Be(payload.data() + 202);
    marker.payload_commitment = raw_hash(210);
    const uint256 availability_scheme_hash{raw_hash(242)};
    const uint256 availability_registry_hash{raw_hash(274)};
    marker.availability_bundle_root = raw_hash(306);
    marker.availability_context = raw_hash(338);
    marker.availability_receipt_root = raw_hash(370);
    marker.availability_bundle_len = ReadU32Be(payload.data() + 402);
    marker.availability_receipt_bitmap = payload[406];
    marker.source_authorization_commitment = raw_hash(407);

    if (!std::equal(chain_id.begin(), chain_id.end(), consensus.chain_id.begin()) ||
        configuration_hash != consensus.bond_v2.configuration_hash ||
        availability_scheme_hash != consensus.bond_v2.availability_scheme_hash ||
        availability_registry_hash !=
            consensus.bond_v2.availability_custodian_registry_hash ||
        marker.kind > 3 || marker.signer.IsNull() || marker.action_id.IsNull() ||
        marker.payload_commitment.IsNull() || marker.availability_bundle_root.IsNull() ||
        marker.availability_receipt_root.IsNull() ||
        marker.source_authorization_commitment.IsNull() ||
        marker.availability_bundle_len == 0 ||
        marker.availability_bundle_len > consensus.bond_v2.bond_inbox_max_bundle_bytes ||
        (marker.availability_receipt_bitmap & UINT8_C(0xe0)) != 0 ||
        std::bitset<8>(marker.availability_receipt_bitmap).count() < 3) {
        error = "ECX bond-inbox marker identities/availability claim are invalid";
        return false;
    }

    const bool has_staging = marker.staging_vout != UINT32_MAX &&
        !marker.staging_intent_id.IsNull() && !marker.refund_script_sha256.IsNull() &&
        marker.refund_not_before_parent_height != 0;
    const bool no_staging = marker.staging_vout == UINT32_MAX &&
        marker.staging_intent_id.IsNull() && marker.refund_script_sha256.IsNull() &&
        marker.refund_not_before_parent_height == 0;
    if ((marker.kind == 1 && !has_staging) || (marker.kind != 1 && !no_staging)) {
        error = "ECX bond-inbox marker staging sentinels are invalid";
        return false;
    }

    std::vector<unsigned char> context;
    context.reserve(236);
    AppendHash(context, chain_id);
    AppendHash(context, configuration_hash);
    AppendHash(context, marker.action_id);
    AppendHash(context, marker.staging_intent_id);
    PushU32Be(context, marker.staging_vout);
    AppendHash(context, marker.refund_script_sha256);
    PushU64Be(context, marker.refund_not_before_parent_height);
    AppendHash(context, marker.payload_commitment);
    AppendHash(context, marker.source_authorization_commitment);
    const std::string availability_context_domain{successor
        ? "ECX/successor-bond-inbox-availability-context/v2-u128"
        : "ECX/bond-inbox-availability-context/v2"};
    if (TaggedHash(availability_context_domain, context) !=
        marker.availability_context) {
        error = "ECX bond-inbox marker availability context is invalid";
        return false;
    }

    if (marker.kind != 1) {
        std::vector<unsigned char> source_authorization;
        source_authorization.reserve(132);
        AppendHash(source_authorization, chain_id);
        AppendHash(source_authorization, configuration_hash);
        AppendHash(source_authorization, marker.signer);
        AppendHash(source_authorization, marker.action_id);
        /* This binds the marker output index; the caller performs the final
         * check once it knows that index. */
        if (marker.source_authorization_commitment.IsNull()) {
            error = "ECX bond-inbox no-staging authorization is absent";
            return false;
        }
    }

    if (require_wrapper_signature) {
        const uint256 digest{TaggedHash(
            successor
                ? "ECX/successor-bond-inbox-marker-signature/v2-u128"
                : "ECX/bond-inbox-marker-signature/v2",
            std::vector<unsigned char>(payload.begin() + 4, payload.begin() + 439))};
        const XOnlyPubKey signer{Span<const unsigned char>(marker.signer.begin(), 32)};
        if (!signer.IsFullyValid() || !signer.VerifySchnorr(
                digest,
                Span<const unsigned char>(payload.data() + 439, 64))) {
            error = "ECX bond-inbox marker wrapper signature is invalid";
            return false;
        }
    }
    return true;
}

[[maybe_unused]] uint256 OrderedBondInboxCustodyReceiptRoot(
    const ParsedBondInboxMarker& marker,
    const std::vector<std::vector<unsigned char>>& receipts,
    const ExchangeConsensus& consensus,
    bool successor)
{
    std::vector<uint256> leaves;
    leaves.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        const uint8_t one_based_index{receipt[73]};
        std::vector<unsigned char> binding;
        binding.reserve(229);
        AppendHash(binding, consensus.bond_v2.availability_scheme_hash);
        AppendHash(
            binding,
            consensus.bond_v2.availability_custodian_registry_hash);
        AppendHash(binding, marker.availability_context);
        AppendHash(binding, marker.availability_bundle_root);
        PushU32Be(binding, marker.availability_bundle_len);
        AppendHash(binding, marker.payload_commitment);
        AppendHash(binding, marker.source_authorization_commitment);
        binding.push_back(one_based_index - 1);
        const uint256 digest{TaggedHash(
            successor
                ? "ECX/successor-bond-inbox-custody-receipt-binding/v2-u128"
                : "ECX/bond-inbox-custody-receipt-binding/v2",
            binding)};
        std::vector<unsigned char> exact;
        AppendHash(exact, digest);
        PushU32Be(exact, receipt.size());
        exact.insert(exact.end(), receipt.begin(), receipt.end());
        leaves.push_back(TaggedHash(
            successor
                ? "ECX/successor-bond-inbox-exact-custody-receipt/v2-u128"
                : "ECX/bond-inbox-exact-custody-receipt/v2",
            exact));
    }
    const std::string tag{successor
        ? "ECX/successor-bond-inbox-custody-receipts/v2-u128"
        : "ECX/bond-inbox-custody-receipts/v2"};
    if (leaves.empty()) return TaggedHash(tag + "/empty", {});
    std::vector<uint256> nodes;
    nodes.reserve(leaves.size());
    for (size_t index = 0; index < leaves.size(); ++index) {
        std::vector<unsigned char> leaf;
        PushU64Be(leaf, index);
        AppendHash(leaf, leaves[index]);
        nodes.push_back(TaggedHash(tag + "/leaf", leaf));
    }
    size_t width{1};
    while (width < nodes.size()) width <<= 1;
    nodes.resize(width, TaggedHash(tag + "/pad", {}));
    while (nodes.size() > 1) {
        std::vector<uint256> next;
        next.reserve(nodes.size() / 2);
        for (size_t index = 0; index < nodes.size(); index += 2) {
            std::vector<unsigned char> branch;
            AppendHash(branch, nodes[index]);
            AppendHash(branch, nodes[index + 1]);
            next.push_back(TaggedHash(tag + "/node", branch));
        }
        nodes = std::move(next);
    }
    return nodes.front();
}

bool VerifyBondInboxMarkerSourceWitness(
    const CTransaction& transaction,
    const ParsedBondInboxMarker& marker,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool successor)
{
#ifndef ECX_ENABLE_SP1_GROTH16_VERIFIER
    error = "ECX bond-inbox custody verifier is not compiled in";
    return false;
#else
    /* The encrypted bundle cannot be an executed witness-stack element: it
     * may be 64 KiB while script elements are consensus-limited to 520
     * bytes.  Freeze one uniquely placed Taproot key-path annex instead.
     *
     *   input 0 script witness = [64-byte SIGHASH_DEFAULT signature, annex]
     *   annex = 0x50 | "ECXBIN2\0" | version=1 | bundle_len:u32be |
     *           receipt_count:u8 | bundle |
     *           repeated(receipt_len:u16be=138 | exact_receipt)
     *
     * The decoder consumes EOF and every other input is forbidden from
     * carrying an annex. The ordinary script interpreter authenticates the
     * designated key-path spend; wtxid commits the exact annex bytes. */
    if (transaction.vin.empty() || transaction.witness.vtxinwit.empty() ||
        !transaction.vin[0].scriptSig.empty()) {
        error = "ECX bond-inbox source lacks its designated Taproot annex input";
        return false;
    }
    const auto& designated{transaction.witness.vtxinwit[0]};
    if (!designated.vchIssuanceAmountRangeproof.empty() ||
        !designated.vchInflationKeysRangeproof.empty() ||
        !designated.m_pegin_witness.stack.empty() ||
        designated.scriptWitness.stack.size() != 2 ||
        designated.scriptWitness.stack[0].size() != 64) {
        error = "ECX bond-inbox designated input is not an exact key-path annex spend";
        return false;
    }
    for (size_t input_index = 1;
         input_index < transaction.witness.vtxinwit.size(); ++input_index) {
        const auto& stack{transaction.witness.vtxinwit[input_index].scriptWitness.stack};
        if (!stack.empty() && !stack.back().empty() && stack.back()[0] == 0x50) {
            error = "ECX bond-inbox source contains a second Taproot annex";
            return false;
        }
    }
    const std::vector<unsigned char>& annex{designated.scriptWitness.stack[1]};
    static constexpr std::array<unsigned char, 9> PREFIX{{
        0x50, 'E', 'C', 'X', 'B', 'I', 'N', '2', 0}};
    if (annex.size() < PREFIX.size() + 6 ||
        !std::equal(PREFIX.begin(), PREFIX.end(), annex.begin()) ||
        annex[PREFIX.size()] != 1) {
        error = "ECX bond-inbox source annex has a noncanonical prefix/version";
        return false;
    }
    size_t cursor{PREFIX.size() + 1};
    const uint32_t bundle_len{ReadU32Be(annex.data() + cursor)};
    cursor += 4;
    const uint8_t receipt_count{annex[cursor++]};
    if (bundle_len == 0 || bundle_len != marker.availability_bundle_len ||
        bundle_len > consensus.bond_v2.bond_inbox_max_bundle_bytes ||
        receipt_count < 3 || receipt_count > 5 ||
        cursor > annex.size() || bundle_len > annex.size() - cursor) {
        error = "ECX bond-inbox source annex has invalid bundle/receipt lengths";
        return false;
    }
    const unsigned char* const bundle{annex.data() + cursor};
    cursor += bundle_len;
    std::vector<unsigned char> bundle_commitment;
    PushU32Be(bundle_commitment, bundle_len);
    bundle_commitment.insert(bundle_commitment.end(), bundle, bundle + bundle_len);
    if (TaggedHash(
            successor
                ? "ECX/successor-bond-inbox-encrypted-availability-bundle/v2-u128"
                : "ECX/bond-inbox-encrypted-availability-bundle/v2",
            bundle_commitment) != marker.availability_bundle_root) {
        error = "ECX bond-inbox source annex bundle commitment mismatched";
        return false;
    }
    std::vector<unsigned char> registry;
    registry.reserve(325);
    for (size_t position = 0; position < 5; ++position) {
        registry.push_back(position + 1);
        registry.insert(
            registry.end(), consensus.bond_v2.custodian_encryption_keys[position].begin(),
            consensus.bond_v2.custodian_encryption_keys[position].end());
        registry.insert(
            registry.end(), consensus.bond_v2.custodian_attestation_keys[position].begin(),
            consensus.bond_v2.custodian_attestation_keys[position].end());
    }
    std::vector<std::vector<unsigned char>> exact_receipts;
    std::vector<unsigned char> concatenated_receipts;
    uint8_t bitmap{0};
    uint8_t previous_index{0};
    for (size_t index = 0; index < receipt_count; ++index) {
        if (cursor + 2 > annex.size()) {
            error = "ECX bond-inbox source annex truncated a receipt length";
            return false;
        }
        const uint16_t receipt_len{static_cast<uint16_t>(
            (static_cast<uint16_t>(annex[cursor]) << 8) |
            static_cast<uint16_t>(annex[cursor + 1]))};
        cursor += 2;
        if (receipt_len != 138 || cursor + receipt_len > annex.size()) {
            error = "ECX bond-inbox source annex receipt length is noncanonical";
            return false;
        }
        std::vector<unsigned char> receipt{
            annex.begin() + cursor, annex.begin() + cursor + receipt_len};
        cursor += receipt_len;
        if (receipt[0] != 1 || receipt[73] < 1 || receipt[73] > 5 ||
            receipt[73] <= previous_index) {
            error = "ECX bond-inbox source annex receipts are not registry ordered";
            return false;
        }
        previous_index = receipt[73];
        bitmap |= UINT8_C(1) << (receipt[73] - 1);
        concatenated_receipts.insert(
            concatenated_receipts.end(), receipt.begin(), receipt.end());
        exact_receipts.push_back(std::move(receipt));
    }
    if (cursor != annex.size() ||
        receipt_count != std::bitset<8>(marker.availability_receipt_bitmap).count() ||
        bitmap != marker.availability_receipt_bitmap ||
        OrderedBondInboxCustodyReceiptRoot(
            marker, exact_receipts, consensus, successor) !=
            marker.availability_receipt_root ||
        !ecx_witness_availability_verify_custody_receipts_v1(
            bundle, bundle_len, registry.data(), registry.size(),
            concatenated_receipts.data(), receipt_count)) {
        error = "ECX bond-inbox source annex receipt evidence is invalid";
        return false;
    }
    return true;
#endif
}

bool DecodeFrozenConfigurationV18(
    const std::vector<unsigned char>& bytes,
    DecodedFrozenConfigurationV18& decoded,
    std::string& error)
{
    error.clear();
    if (bytes.size() != 1977) {
        error = "canonical FrozenConfigurationV2/V18 must be exactly 1977 bytes";
        return false;
    }
    FrozenConfigurationCursor cursor(bytes);
    uint8_t byte{0};
    uint32_t word{0};
    uint64_t wide{0};
    std::array<unsigned char, 20> sha1{};
    std::array<unsigned char, 16> market{};
    uint256 usdd_light_client, usdd_authority;
    uint256 truth_chain, truth_branch, truth_template, truth_lmsr;
    uint256 scratch_hash;
    uint32_t truth_min_confirmations{0};

    const auto hash = [&](uint256& value) {
        return cursor.Hash(value) && !value.IsNull();
    };
    const auto fail = [&](const char* reason) {
        error = std::string("noncanonical FrozenConfigurationV2/V18: ") + reason;
        return false;
    };

    if (!cursor.U8(byte) || byte != 5 || !cursor.U8(byte) || byte != 3 ||
        !hash(decoded.chain_id) || !cursor.Bytes(market.data(), market.size()) ||
        market != ECX_USDD_MARKET || !hash(decoded.ecx_asset_id) ||
        !hash(decoded.usdd_asset_id) || !hash(decoded.policy_asset_id) ||
        !hash(decoded.state_authority_asset_id)) return fail("outer/base identity");

    if (!cursor.U8(byte) || byte != 1 || !hash(usdd_light_client) ||
        !hash(usdd_authority) || usdd_light_client == usdd_authority ||
        !cursor.U64(wide) || wide == 0 || wide > 13 * 24 * 60 * 60)
        return fail("USDD checkpoint profile");

    uint32_t initial, maintenance, liquidation, maker, taker, funding;
    uint64_t max_oi, max_liquidation;
    if (!cursor.U32(initial) || initial != 1000 ||
        !cursor.U32(maintenance) || maintenance != 600 ||
        !cursor.U32(liquidation) || liquidation != 100 ||
        !cursor.U32(maker) || maker != 0 ||
        !cursor.U32(taker) || taker != 5 ||
        !cursor.U32(funding) || funding != 10000 ||
        !cursor.U64(max_oi) || max_oi != UINT64_C(100000000000000) ||
        !cursor.U64(max_liquidation) || max_liquidation != UINT64_C(1000000000000000) ||
        !cursor.U8(byte) || byte != 0) return fail("risk profile");

    /* FrozenConfigurationV1 permits a generic nonzero availability identity,
     * but the V2 proof relation accepts only the concrete threshold codec.
     * Reject it here during activation decoding instead of admitting a
     * configuration that can never produce an accepted V2 successor. */
    if (!cursor.U8(byte) || byte != 1 || !hash(decoded.availability_scheme_hash) ||
        decoded.availability_scheme_hash != AvailabilitySchemeHashV1() ||
        !hash(decoded.availability_registry_hash) || !cursor.U8(byte) || byte != 3 ||
        !cursor.U8(byte) || byte != 5 || !cursor.U32(word) || word != 16 * 1024 * 1024)
        return fail("availability profile");

    uint8_t sidechain_number{0};
    if (!cursor.U8(byte) || byte != 3 || !cursor.Bytes(sha1.data(), sha1.size()) ||
        !IsNonzeroBytes(sha1.data(), sha1.size()) || !hash(scratch_hash) ||
        !hash(scratch_hash) || !cursor.U8(sidechain_number) || sidechain_number == 0 ||
        !hash(scratch_hash) || !cursor.U64(wide) || wide == 0 ||
        !hash(scratch_hash) || !hash(scratch_hash) || !hash(truth_chain) ||
        !hash(truth_branch) || !hash(truth_template) || !hash(truth_lmsr) ||
        !hash(decoded.truthcoin_program_id) || !hash(scratch_hash) ||
        !cursor.U32(truth_min_confirmations) || truth_min_confirmations == 0 ||
        !cursor.U32(word) || word == 0 || word > 16 * 1024 * 1024)
        return fail("Truthcoin authentication profile");

    uint256 anchor_authority;
    if (!cursor.U8(byte) || byte != 1 || !hash(anchor_authority) ||
        anchor_authority == decoded.policy_asset_id || !cursor.U64(wide) || wide == 0 ||
        !hash(scratch_hash)) return fail("Truthcoin anchor deployment");

    uint256 oracle_chain, oracle_branch, oracle_template, oracle_lmsr;
    uint64_t schedule_origin, epoch_length, maximum_anchor_age,
        maximum_snapshot_age, minimum_lmsr_b, ecx_satoshis, usdd_usd;
    uint32_t min_source_confirmations, minimum_samples, base_weight, max_weight,
        initial_band, max_band, haircut, boundary, max_deviation;
    if (!cursor.U8(byte) || byte != 1 || !hash(oracle_chain) ||
        !hash(oracle_branch) || !hash(oracle_template) || !hash(oracle_lmsr) ||
        oracle_chain != truth_chain || oracle_branch != truth_branch ||
        oracle_template != truth_template || oracle_lmsr != truth_lmsr ||
        !cursor.U64(schedule_origin) || !cursor.U64(epoch_length) || epoch_length == 0 ||
        !cursor.U32(min_source_confirmations) || min_source_confirmations == 0 ||
        min_source_confirmations > truth_min_confirmations ||
        !cursor.U64(maximum_anchor_age) || maximum_anchor_age == 0 ||
        !cursor.U64(maximum_snapshot_age) || maximum_snapshot_age == 0 ||
        !cursor.U64(minimum_lmsr_b) || minimum_lmsr_b == 0 ||
        !cursor.U32(minimum_samples) || minimum_samples == 0 ||
        !cursor.U32(base_weight) || !cursor.U32(max_weight) || base_weight > max_weight ||
        max_weight > 1000000 || !cursor.U32(initial_band) ||
        !cursor.U32(max_band) || initial_band > max_band || max_band >= 10000 ||
        !cursor.U32(haircut) || haircut >= 10000 || !cursor.U32(boundary) ||
        uint64_t{boundary} * 2 >= UINT64_C(1000000000) ||
        !cursor.U32(max_deviation) || max_deviation == 0 || max_deviation > 10000 ||
        !cursor.U64(ecx_satoshis) || ecx_satoshis == 0 ||
        !cursor.U64(usdd_usd) || usdd_usd == 0)
        return fail("hybrid oracle profile");
    (void)schedule_origin;

    std::array<unsigned char, 32> matcher_signer{};
    uint64_t matcher_epoch, matcher_genesis_sequence;
    /* The generic V1 matcher type permits 1..144 blocks.  The transition
     * relation and live source-inbox lane both freeze the V2 profile to six,
     * so the activation decoder mirrors that reachable relation exactly. */
    if (!cursor.U8(byte) || byte != 1 || !cursor.U64(matcher_epoch) ||
        !cursor.Bytes(matcher_signer.data(), matcher_signer.size()) ||
        !XOnlyPubKey(Span<const unsigned char>(matcher_signer.data(), matcher_signer.size())).IsFullyValid() ||
        !cursor.U64(matcher_genesis_sequence) || matcher_genesis_sequence == UINT64_MAX ||
        !hash(decoded.matcher_genesis_receipt_hash) || !cursor.U32(word) ||
        word != FORCED_INCLUSION_BLOCKS)
        return fail("central matcher profile");
    (void)matcher_epoch;

    if (!hash(decoded.forced_action_domain) || !hash(decoded.deposit_inbox_domain) ||
        decoded.forced_action_domain == decoded.deposit_inbox_domain ||
        !hash(decoded.collateral_vault_script_sha256) ||
        !cursor.U32(word) || word == 0 || word > 64)
        return fail("base accumulator profile");

    /* Exact FrozenConfigurationV1::validate identity set.  Pairwise
     * distinctness is consensus critical, not merely a local deployment
     * convenience; aliases can collapse independent asset/domain roles. */
    const std::array<uint256, 12> base_identities{{
        decoded.chain_id,
        decoded.ecx_asset_id,
        decoded.usdd_asset_id,
        decoded.policy_asset_id,
        decoded.state_authority_asset_id,
        usdd_light_client,
        usdd_authority,
        anchor_authority,
        decoded.matcher_genesis_receipt_hash,
        decoded.forced_action_domain,
        decoded.deposit_inbox_domain,
        decoded.collateral_vault_script_sha256,
    }};
    for (size_t i = 0; i < base_identities.size(); ++i) {
        if (base_identities[i].IsNull() ||
            std::find(
                base_identities.begin(),
                base_identities.begin() + i,
                base_identities[i]) != base_identities.begin() + i) {
            return fail("duplicate base identity");
        }
    }

    if (!hash(decoded.collateral_vault_covenant_cmr) ||
        !hash(decoded.bond_asset_id) || !hash(decoded.deployment_commitment) ||
        !hash(decoded.inventory_script_sha256) || !hash(decoded.queue_script_sha256) ||
        !hash(decoded.staging_template_commitment) ||
        !hash(decoded.staging_renderer_domain) ||
        !IsEcxStagingRendererDomainV18(decoded.staging_renderer_domain.begin()) ||
        !hash(decoded.staging_internal_key) ||
        !IsEcxNumsInternalKey(decoded.staging_internal_key.begin()) ||
        !cursor.U8(decoded.staging_tapleaf_version) || decoded.staging_tapleaf_version != 0xbe ||
        !hash(decoded.staging_process_cmr) || !hash(decoded.staging_refund_cmr) ||
        decoded.staging_process_cmr == decoded.staging_refund_cmr ||
        !cursor.U32(decoded.refund_minimum_parent_blocks) ||
        decoded.refund_minimum_parent_blocks != 12 ||
        !hash(decoded.insurance_script_sha256) ||
        !hash(decoded.insurance_reserve_covenant_cmr) ||
        !hash(decoded.burn_script_sha256) ||
        !hash(decoded.bond_inbox_domain) || !hash(decoded.custody_receipt_codec_hash) ||
        decoded.custody_receipt_codec_hash != CustodyReceiptCodecHashV1())
        return fail("bond/covenant identities");

    std::vector<unsigned char> descriptor;
    descriptor.push_back(1); // exact V18 tree-shape version
    AppendHash(descriptor, decoded.staging_renderer_domain);
    descriptor.push_back(decoded.staging_tapleaf_version);
    AppendHash(descriptor, decoded.staging_internal_key);
    AppendHash(descriptor, decoded.staging_process_cmr);
    AppendHash(descriptor, decoded.staging_refund_cmr);
    if (TaggedHash("ECX/bond-inbox-redemption-staging-template/v3-no-history", descriptor) !=
            decoded.staging_template_commitment ||
        !XOnlyPubKey(Span<const unsigned char>(decoded.staging_internal_key.begin(), 32)).IsFullyValid())
        return fail("staging descriptor commitment");

    if (!cursor.U32(decoded.inbox_inclusion_blocks) || decoded.inbox_inclusion_blocks != 6 ||
        !cursor.U32(decoded.inbox_max_bundle_bytes) || decoded.inbox_max_bundle_bytes != 64 * 1024 ||
        !cursor.U32(decoded.inbox_max_entries_per_block) || decoded.inbox_max_entries_per_block != 8 ||
        !cursor.U32(decoded.inbox_max_unique_witness_bytes_per_block) ||
        decoded.inbox_max_unique_witness_bytes_per_block != 576 * 1024 ||
        !cursor.U32(decoded.inbox_max_unique_transaction_bytes_per_block) ||
        decoded.inbox_max_unique_transaction_bytes_per_block != 768 * 1024 ||
        !cursor.U32(decoded.inbox_max_pending_per_transition) ||
        decoded.inbox_max_pending_per_transition != 64 ||
        !cursor.U32(decoded.inbox_max_consumed_per_transition) ||
        decoded.inbox_max_consumed_per_transition != 64 ||
        !cursor.U32(decoded.redemption_max_queue_entries) ||
        decoded.redemption_max_queue_entries != 4096 ||
        !cursor.U32(decoded.matcher_execution_inclusion_parent_blocks) ||
        decoded.matcher_execution_inclusion_parent_blocks != 6)
        return fail("bond inbox/matcher limits");

    if (!hash(decoded.ecx_btc_program_id) || !hash(decoded.usdd_usd_program_id) ||
        !hash(decoded.ecx_btc_redemption_covenant) ||
        !hash(decoded.ecx_btc_source_checkpoint) ||
        !hash(decoded.usdd_usd_redemption_covenant) ||
        !hash(decoded.usdd_usd_source_checkpoint) ||
        decoded.ecx_btc_program_id == decoded.usdd_usd_program_id ||
        decoded.ecx_btc_program_id == decoded.truthcoin_program_id ||
        decoded.usdd_usd_program_id == decoded.truthcoin_program_id ||
        !cursor.U64(decoded.maximum_conversion_age_seconds) ||
        decoded.maximum_conversion_age_seconds == 0 ||
        !cursor.U32(decoded.maximum_conversion_proof_bytes) ||
        decoded.maximum_conversion_proof_bytes == 0 ||
        decoded.maximum_conversion_proof_bytes > 16 * 1024 * 1024 ||
        !cursor.U32(decoded.recursive_proof_marker_bytes) ||
        decoded.recursive_proof_marker_bytes != 32 ||
        !cursor.U64(decoded.fixed_supply_atoms) ||
        decoded.fixed_supply_atoms != UINT64_C(2100000000000000) ||
        !cursor.U64(decoded.redemption_delay_parent_blocks) ||
        decoded.redemption_delay_parent_blocks != 1008 || !cursor.Finished())
        return fail("recursive proof/bond constants or trailing bytes");

    const std::array<uint256, 21> identities{{
        decoded.collateral_vault_covenant_cmr,
        decoded.bond_asset_id, decoded.deployment_commitment,
        decoded.inventory_script_sha256, decoded.queue_script_sha256,
        decoded.staging_template_commitment, decoded.staging_renderer_domain,
        decoded.staging_internal_key,
        decoded.staging_process_cmr, decoded.staging_refund_cmr,
        decoded.insurance_script_sha256,
        decoded.insurance_reserve_covenant_cmr,
        decoded.burn_script_sha256,
        decoded.bond_inbox_domain, decoded.custody_receipt_codec_hash,
        decoded.ecx_btc_program_id, decoded.usdd_usd_program_id,
        decoded.ecx_btc_redemption_covenant, decoded.ecx_btc_source_checkpoint,
        decoded.usdd_usd_redemption_covenant, decoded.usdd_usd_source_checkpoint}};
    for (size_t i = 0; i < identities.size(); ++i) {
        if (std::find(identities.begin(), identities.begin() + i, identities[i]) !=
            identities.begin() + i) return fail("duplicate outer identity");
    }
    if (decoded.bond_inbox_domain == decoded.forced_action_domain ||
        decoded.bond_inbox_domain == decoded.deposit_inbox_domain ||
        decoded.bond_inbox_domain == decoded.availability_scheme_hash ||
        decoded.bond_inbox_domain == decoded.availability_registry_hash ||
        decoded.ecx_btc_program_id == decoded.truthcoin_program_id ||
        decoded.usdd_usd_program_id == decoded.truthcoin_program_id ||
        decoded.staging_process_cmr == decoded.truthcoin_program_id ||
        decoded.staging_refund_cmr == decoded.truthcoin_program_id ||
        decoded.collateral_vault_covenant_cmr == decoded.truthcoin_program_id ||
        decoded.insurance_reserve_covenant_cmr == decoded.truthcoin_program_id) {
        return fail("cross-role identity collision");
    }
    return true;
}

void ConfigureBondV2FromArgs(ExchangeConsensus& consensus)
{
#ifndef ECX_SIMPLICITY_CATALOGUE_FROZEN
    throw std::runtime_error(
        "ECX bond V2 activation is disabled: the reviewed annex-v4/PublicValuesV5 "
        "Simplicity catalogue and its genuine CMR artifact are not compiled in");
#else
    if (!gArgs.GetBoolArg("-ecxbondv2", false)) {
        throw std::runtime_error("-ecxbondv2 must be explicitly set to 1");
    }
    static const std::array<const char*, 34> required{{
        "-ecxbondv2deploymenttx",
        "-ecxbondv2genesistx",
        "-ecxbondv2issuanceinput",
        "-ecxbondv2inventoryoutput",
        "-ecxbondv2burnoutput",
        "-ecxbondv2stateauthoritysourceoutput",
        "-ecxbondv2inventoryassetblinder",
        "-ecxbondv2inventoryvalueblinder",
        "-ecxbondv2transitionprogramid",
        "-ecxbondv2configurationhash",
        "-ecxbondv2configurationbytes",
        "-ecxbondv2publicstatedomain",
        "-ecxbondv2statenodedomain",
        "-ecxbondv2journaldomain",
        "-ecxbondv2transitioncmr",
        "-ecxbondv2incrementalactivationprogramid",
        "-ecxbondv2incrementalactivationconfigurationhash",
        "-ecxbondv2incrementalactivationcmr",
        "-ecxbondv2incrementalsuccessorprogramid",
        "-ecxbondv2incrementalsuccessorconfigurationhash",
        "-ecxbondv2incrementalsuccessortransitioncmr",
        "-ecxbondv2incrementalsuccessorstatenodedomain",
        "-ecxbondv2inventorycmr",
        "-ecxbondv2queuecmr",
        "-ecxbondv2ecxbtcprogramid",
        "-ecxbondv2ecxbtcredemptioncovenant",
        "-ecxbondv2ecxbtcsourcecheckpoint",
        "-ecxbondv2usddusdprogramid",
        "-ecxbondv2usddusdredemptioncovenant",
        "-ecxbondv2usddusdsourcecheckpoint",
        "-ecxbondv2matcherreceipt",
        "-ecxbondv2orderreceiptsroot",
        "-ecxbondv2availabilityroot",
        "-ecxbondv2custodianregistry",
    }};
    for (const char* name : required) {
        if (!gArgs.IsArgSet(name)) {
            throw std::runtime_error(
                std::string("ECX bond V2 activation requires ") + name);
        }
    }
    if (!gArgs.IsArgSet("-ecxbondv2usddasset") ||
        !gArgs.IsArgSet("-ecxbondv2keylessinternalkey") ||
        !gArgs.IsArgSet("-ecxbondv2genesismarkprice")) {
        throw std::runtime_error(
            "ECX bond V2 activation requires USDD, keyless-key, and genesis-mark inputs");
    }

    CMutableTransaction deployment;
    const std::string deployment_hex{gArgs.GetArg("-ecxbondv2deploymenttx", "")};
    if (deployment_hex.empty() ||
        !DecodeHexTx(deployment, deployment_hex, true, true)) {
        throw std::runtime_error("invalid -ecxbondv2deploymenttx");
    }
    consensus.bond_v2.deployment_transaction =
        MakeTransactionRef(std::move(deployment));
    const CTransaction& transaction{*consensus.bond_v2.deployment_transaction};
    auto& frozen{consensus.bond_v2};
    CMutableTransaction genesis_transaction;
    const std::string genesis_hex{gArgs.GetArg("-ecxbondv2genesistx", "")};
    if (genesis_hex.empty() ||
        !DecodeHexTx(genesis_transaction, genesis_hex, true, true)) {
        throw std::runtime_error("invalid -ecxbondv2genesistx");
    }
    frozen.genesis_transaction =
        MakeTransactionRef(std::move(genesis_transaction));
    const CTransaction& genesis{*frozen.genesis_transaction};
    frozen.issuance_input_index = ParseU32Arg("-ecxbondv2issuanceinput");
    frozen.inventory_output_index = ParseU32Arg("-ecxbondv2inventoryoutput");
    frozen.reissuance_token_burn_output_index =
        ParseU32Arg("-ecxbondv2burnoutput");
    frozen.state_authority_source_output_index =
        ParseU32Arg("-ecxbondv2stateauthoritysourceoutput");
    frozen.inventory_asset_blinding_factor =
        ParseRawHash32Arg("-ecxbondv2inventoryassetblinder");
    frozen.inventory_value_blinding_factor =
        ParseRawHash32Arg("-ecxbondv2inventoryvalueblinder");
    if (frozen.inventory_asset_blinding_factor ==
        frozen.inventory_value_blinding_factor) {
        throw std::runtime_error("ECX bond V2 inventory blinders must be distinct");
    }
    frozen.transition_program_id =
        ParseRawHash32Arg("-ecxbondv2transitionprogramid");
    const uint256 authorized_configuration_hash{
        ParseRawHash32Arg("-ecxbondv2configurationhash")};
    const std::string configuration_hex{
        gArgs.GetArg("-ecxbondv2configurationbytes", "")};
    if (configuration_hex.empty() || configuration_hex.size() > 131072 ||
        (configuration_hex.size() & 1) != 0 || !IsHex(configuration_hex)) {
        throw std::runtime_error(
            "invalid -ecxbondv2configurationbytes; expected bounded canonical hex");
    }
    frozen.canonical_configuration_bytes = ParseHex(configuration_hex);
    DecodedFrozenConfigurationV18 decoded_configuration;
    std::string configuration_error;
    if (!DecodeFrozenConfigurationV18(
            frozen.canonical_configuration_bytes,
            decoded_configuration,
            configuration_error)) {
        throw std::runtime_error(configuration_error);
    }
    if (!IsEcxNumsInternalKey(decoded_configuration.staging_internal_key.begin())) {
        throw std::runtime_error(
            "FrozenConfigurationV2 staging internal key is not the exact "
            "BIP341 NUMS H point; key-path bypass is forbidden");
    }
    frozen.configuration_hash = TaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        frozen.canonical_configuration_bytes);
    if (frozen.configuration_hash != authorized_configuration_hash) {
        throw std::runtime_error(
            "-ecxbondv2configurationhash does not match the canonical bytes");
    }
    if (!std::equal(
            decoded_configuration.chain_id.begin(),
            decoded_configuration.chain_id.end(), consensus.chain_id.begin()) ||
        decoded_configuration.ecx_asset_id !=
            Params().GetConsensus().pegged_asset.id ||
        decoded_configuration.usdd_asset_id !=
            ParseRawHash32Arg("-ecxbondv2usddasset") ||
        decoded_configuration.policy_asset_id != ::policyAsset.id ||
        !std::equal(
            decoded_configuration.forced_action_domain.begin(),
            decoded_configuration.forced_action_domain.end(),
            consensus.forced_action_domain.begin()) ||
        !std::equal(
            decoded_configuration.deposit_inbox_domain.begin(),
            decoded_configuration.deposit_inbox_domain.end(),
            consensus.deposit_inbox_domain.begin()) ||
        decoded_configuration.collateral_vault_script_sha256 !=
            consensus.collateral_vault_script_hash) {
        throw std::runtime_error(
            "FrozenConfigurationV2/V18 base identities do not match the active Elements deployment");
    }
    frozen.collateral_vault_covenant_cmr =
        decoded_configuration.collateral_vault_covenant_cmr;
    frozen.public_state_domain_sha256 =
        ParseRawHash32Arg("-ecxbondv2publicstatedomain");
    frozen.state_node_domain_sha256 =
        ParseRawHash32Arg("-ecxbondv2statenodedomain");
    frozen.transition_journal_domain_sha256 =
        ParseRawHash32Arg("-ecxbondv2journaldomain");
    frozen.transition_cmr = ParseRawHash32Arg("-ecxbondv2transitioncmr");
    frozen.incremental_activation_program_id =
        ParseRawHash32Arg("-ecxbondv2incrementalactivationprogramid");
    frozen.incremental_activation_configuration_hash =
        ParseRawHash32Arg("-ecxbondv2incrementalactivationconfigurationhash");
    frozen.incremental_activation_cmr =
        ParseRawHash32Arg("-ecxbondv2incrementalactivationcmr");
    frozen.incremental_successor_program_id =
        ParseRawHash32Arg("-ecxbondv2incrementalsuccessorprogramid");
    frozen.incremental_successor_configuration_hash =
        ParseRawHash32Arg("-ecxbondv2incrementalsuccessorconfigurationhash");
    frozen.incremental_successor_transition_cmr =
        ParseRawHash32Arg("-ecxbondv2incrementalsuccessortransitioncmr");
    frozen.incremental_successor_state_node_domain_sha256 =
        ParseRawHash32Arg("-ecxbondv2incrementalsuccessorstatenodedomain");
    frozen.inventory_cmr = ParseRawHash32Arg("-ecxbondv2inventorycmr");
    frozen.redemption_queue_cmr = ParseRawHash32Arg("-ecxbondv2queuecmr");
    frozen.ecx_btc_conversion_program_id =
        ParseRawHash32Arg("-ecxbondv2ecxbtcprogramid");
    frozen.ecx_btc_redemption_covenant_commitment =
        ParseRawHash32Arg("-ecxbondv2ecxbtcredemptioncovenant");
    frozen.ecx_btc_source_checkpoint_commitment =
        ParseRawHash32Arg("-ecxbondv2ecxbtcsourcecheckpoint");
    frozen.usdd_usd_conversion_program_id =
        ParseRawHash32Arg("-ecxbondv2usddusdprogramid");
    frozen.usdd_usd_redemption_covenant_commitment =
        ParseRawHash32Arg("-ecxbondv2usddusdredemptioncovenant");
    frozen.usdd_usd_source_checkpoint_commitment =
        ParseRawHash32Arg("-ecxbondv2usddusdsourcecheckpoint");
    frozen.matcher_genesis_receipt_hash =
        ParseRawHash32Arg("-ecxbondv2matcherreceipt");
    frozen.order_receipts_genesis_root =
        ParseRawHash32Arg("-ecxbondv2orderreceiptsroot");
    frozen.genesis_availability_root =
        ParseRawHash32Arg("-ecxbondv2availabilityroot");
    frozen.usdd_asset_id = CAsset(ParseRawHash32Arg("-ecxbondv2usddasset"));
    const std::string registry_hex{
        gArgs.GetArg("-ecxbondv2custodianregistry", "")};
    if (registry_hex.size() != 650 || !IsHex(registry_hex)) {
        throw std::runtime_error(
            "invalid -ecxbondv2custodianregistry; expected five exact "
            "index|X25519|Ed25519 records (325 bytes)");
    }
    const std::vector<unsigned char> registry_bytes{ParseHex(registry_hex)};
    for (size_t position = 0; position < 5; ++position) {
        const size_t offset{position * 65};
        if (registry_bytes[offset] != position + 1 ||
            !IsNonzeroBytes(registry_bytes.data() + offset + 1, 32) ||
            !IsNonzeroBytes(registry_bytes.data() + offset + 33, 32)) {
            throw std::runtime_error(
                "ECX bond V2 custodian registry indices/keys are noncanonical");
        }
        std::copy_n(
            registry_bytes.data() + offset + 1, 32,
            frozen.custodian_encryption_keys[position].begin());
        std::copy_n(
            registry_bytes.data() + offset + 33, 32,
            frozen.custodian_attestation_keys[position].begin());
        for (size_t prior = 0; prior < position; ++prior) {
            if (frozen.custodian_encryption_keys[position] ==
                    frozen.custodian_encryption_keys[prior] ||
                frozen.custodian_attestation_keys[position] ==
                    frozen.custodian_attestation_keys[prior]) {
                throw std::runtime_error(
                    "ECX bond V2 custodian registry contains duplicate keys");
            }
        }
    }
    frozen.availability_scheme_hash = decoded_configuration.availability_scheme_hash;
    frozen.availability_custodian_registry_hash =
        decoded_configuration.availability_registry_hash;
    if (TaggedHash("ECX/witness-custodian-registry/v1", registry_bytes) !=
            frozen.availability_custodian_registry_hash) {
        throw std::runtime_error(
            "-ecxbondv2custodianregistry does not match FrozenConfigurationV2/V18");
    }
    frozen.redemption_queue_script_sha256 = decoded_configuration.queue_script_sha256;
    frozen.insurance_reserve_script_sha256 = decoded_configuration.insurance_script_sha256;
    frozen.insurance_reserve_covenant_cmr =
        decoded_configuration.insurance_reserve_covenant_cmr;
    frozen.bond_inbox_redemption_staging_template_commitment =
        decoded_configuration.staging_template_commitment;
    frozen.bond_inbox_redemption_staging_renderer_domain =
        decoded_configuration.staging_renderer_domain;
    frozen.bond_inbox_redemption_staging_internal_key =
        decoded_configuration.staging_internal_key;
    frozen.bond_inbox_redemption_staging_tapleaf_version =
        decoded_configuration.staging_tapleaf_version;
    frozen.bond_inbox_redemption_staging_process_cmr =
        decoded_configuration.staging_process_cmr;
    frozen.bond_inbox_redemption_staging_refund_cmr =
        decoded_configuration.staging_refund_cmr;
    frozen.bond_inbox_refund_minimum_parent_blocks =
        decoded_configuration.refund_minimum_parent_blocks;
    frozen.bond_inbox_domain = decoded_configuration.bond_inbox_domain;
    frozen.bond_inbox_custody_receipt_codec_hash =
        decoded_configuration.custody_receipt_codec_hash;
    frozen.bond_inbox_inclusion_blocks = decoded_configuration.inbox_inclusion_blocks;
    frozen.bond_inbox_max_bundle_bytes = decoded_configuration.inbox_max_bundle_bytes;
    frozen.bond_inbox_max_entries_per_sidechain_block =
        decoded_configuration.inbox_max_entries_per_block;
    frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block =
        decoded_configuration.inbox_max_unique_witness_bytes_per_block;
    frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block =
        decoded_configuration.inbox_max_unique_transaction_bytes_per_block;
    frozen.bond_inbox_max_pending_entries_per_transition =
        decoded_configuration.inbox_max_pending_per_transition;
    frozen.bond_inbox_max_consumed_entries_per_transition =
        decoded_configuration.inbox_max_consumed_per_transition;
    frozen.bond_redemption_max_queue_entries =
        decoded_configuration.redemption_max_queue_entries;
    frozen.matcher_execution_inclusion_parent_blocks =
        decoded_configuration.matcher_execution_inclusion_parent_blocks;
    frozen.maximum_conversion_age_seconds =
        decoded_configuration.maximum_conversion_age_seconds;
    frozen.maximum_conversion_proof_bytes =
        decoded_configuration.maximum_conversion_proof_bytes;
    frozen.recursive_proof_marker_bytes =
        decoded_configuration.recursive_proof_marker_bytes;
    frozen.fixed_supply_atoms = decoded_configuration.fixed_supply_atoms;
    frozen.redemption_delay_parent_blocks =
        decoded_configuration.redemption_delay_parent_blocks;

    if (frozen.transition_program_id == decoded_configuration.truthcoin_program_id ||
        frozen.ecx_btc_conversion_program_id != decoded_configuration.ecx_btc_program_id ||
        frozen.usdd_usd_conversion_program_id != decoded_configuration.usdd_usd_program_id ||
        frozen.ecx_btc_redemption_covenant_commitment !=
            decoded_configuration.ecx_btc_redemption_covenant ||
        frozen.ecx_btc_source_checkpoint_commitment !=
            decoded_configuration.ecx_btc_source_checkpoint ||
        frozen.usdd_usd_redemption_covenant_commitment !=
            decoded_configuration.usdd_usd_redemption_covenant ||
        frozen.usdd_usd_source_checkpoint_commitment !=
            decoded_configuration.usdd_usd_source_checkpoint ||
        frozen.matcher_genesis_receipt_hash !=
            decoded_configuration.matcher_genesis_receipt_hash) {
        throw std::runtime_error(
            "runtime proof/matcher identities differ from FrozenConfigurationV2/V18");
    }
    if (frozen.configuration_hash ==
            frozen.incremental_activation_configuration_hash ||
        frozen.configuration_hash ==
            frozen.incremental_successor_configuration_hash ||
        frozen.incremental_activation_configuration_hash ==
            frozen.incremental_successor_configuration_hash) {
        throw std::runtime_error(
            "finite, activation, and incremental-successor configuration hashes must be distinct");
    }
    const std::array<const uint256*, 5> proof_program_ids{{
        &frozen.transition_program_id,
        &frozen.incremental_activation_program_id,
        &frozen.incremental_successor_program_id,
        &frozen.ecx_btc_conversion_program_id,
        &frozen.usdd_usd_conversion_program_id,
    }};
    for (size_t i = 0; i < proof_program_ids.size(); ++i) {
        if (proof_program_ids[i]->IsNull()) {
            throw std::runtime_error("proof program identity is missing");
        }
        for (size_t j = i + 1; j < proof_program_ids.size(); ++j) {
            if (*proof_program_ids[i] == *proof_program_ids[j]) {
                throw std::runtime_error(
                    "incremental proof program identity collides with another proof role");
            }
        }
    }
    if (frozen.incremental_activation_program_id ==
        frozen.incremental_successor_program_id) {
        throw std::runtime_error(
            "activation and successor proof program identities collide");
    }
    const std::array<const uint256*, 9> covenant_cmrs{{
        &frozen.transition_cmr,
        &frozen.incremental_activation_cmr,
        &frozen.incremental_successor_transition_cmr,
        &frozen.collateral_vault_covenant_cmr,
        &frozen.insurance_reserve_covenant_cmr,
        &frozen.inventory_cmr,
        &frozen.redemption_queue_cmr,
        &frozen.bond_inbox_redemption_staging_process_cmr,
        &frozen.bond_inbox_redemption_staging_refund_cmr,
    }};
    for (size_t i = 0; i < covenant_cmrs.size(); ++i) {
        if (covenant_cmrs[i]->IsNull()) {
            throw std::runtime_error(
                "incremental activation covenant identity is missing or collides");
        }
        for (size_t prior = 0; prior < i; ++prior) {
            if (*covenant_cmrs[i] == *covenant_cmrs[prior]) {
                throw std::runtime_error(
                    "incremental activation covenant identity is missing or collides");
            }
        }
    }
    if (frozen.incremental_successor_state_node_domain_sha256.IsNull() ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.state_node_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.public_state_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.transition_journal_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.bond_inbox_redemption_staging_renderer_domain) {
        throw std::runtime_error(
            "incremental successor state-node identity is missing or collides");
    }
    const uint256 keyless{ParseRawHash32Arg("-ecxbondv2keylessinternalkey")};
    std::copy(keyless.begin(), keyless.end(), frozen.keyless_internal_key.begin());
    if (!IsEcxNumsInternalKey(frozen.keyless_internal_key.data()) ||
        !XOnlyPubKey(Span<const unsigned char>(
            frozen.keyless_internal_key.data(), 32)).IsFullyValid()) {
        throw std::runtime_error(
            "invalid -ecxbondv2keylessinternalkey; every ECX V2 covenant "
            "requires the exact BIP341 NUMS H x-coordinate");
    }
    const auto single_leaf_script_hash = [&](const uint256& cmr) {
        std::vector<unsigned char> leaf_payload{
            TAPROOT_LEAF_TAPSIMPLICITY, 32};
        AppendHash(leaf_payload, cmr);
        const uint256 leaf{TaggedHash("TapLeaf/elements", leaf_payload)};
        const XOnlyPubKey internal{Span<const unsigned char>(
            frozen.keyless_internal_key.data(), 32)};
        const auto tweaked{internal.CreateTapTweak(&leaf)};
        if (!tweaked) {
            throw std::runtime_error(
                "ECX bond V2 single-leaf covenant descriptor is invalid");
        }
        CScript script;
        script << OP_1 << std::vector<unsigned char>(
            tweaked->first.begin(), tweaked->first.end());
        return Sha256(std::vector<unsigned char>(script.begin(), script.end()));
    };
    const uint256 derived_inventory_script_hash{
        single_leaf_script_hash(frozen.inventory_cmr)};
    const uint256 derived_queue_script_hash{
        single_leaf_script_hash(frozen.redemption_queue_cmr)};
    const uint256 derived_collateral_vault_script_hash{
        single_leaf_script_hash(frozen.collateral_vault_covenant_cmr)};
    const uint256 derived_insurance_script_hash{
        single_leaf_script_hash(frozen.insurance_reserve_covenant_cmr)};
    const int64_t mark_price{gArgs.GetIntArg("-ecxbondv2genesismarkprice", 0)};
    if (mark_price <= 0) {
        throw std::runtime_error("invalid -ecxbondv2genesismarkprice");
    }
    frozen.genesis_mark_price = static_cast<uint64_t>(mark_price);

    if (transaction.vin.empty() || transaction.vout.empty() ||
        frozen.issuance_input_index >= transaction.vin.size() ||
        frozen.inventory_output_index >= transaction.vout.size() ||
        frozen.reissuance_token_burn_output_index >= transaction.vout.size() ||
        frozen.state_authority_source_output_index >= transaction.vout.size() ||
        frozen.inventory_output_index ==
            frozen.reissuance_token_burn_output_index ||
        frozen.inventory_output_index ==
            frozen.state_authority_source_output_index ||
        frozen.reissuance_token_burn_output_index ==
            frozen.state_authority_source_output_index ||
        transaction.vin.end() != std::find_if(
            transaction.vin.begin(), transaction.vin.end(),
            [](const CTxIn& input) { return input.m_is_pegin; }) ||
        std::count_if(
            transaction.vin.begin(), transaction.vin.end(),
            [](const CTxIn& input) { return !input.assetIssuance.IsNull(); }) != 1) {
        throw std::runtime_error("ECX bond V2 deployment transaction shape is invalid");
    }
    const CTxIn& issuance{transaction.vin[frozen.issuance_input_index]};
    static constexpr CAmount FIXED_SUPPLY{2'100'000'000'000'000};
    if (issuance.assetIssuance.IsNull() ||
        !issuance.assetIssuance.assetBlindingNonce.IsNull() ||
        !issuance.assetIssuance.nAmount.IsExplicit() ||
        issuance.assetIssuance.nAmount.GetAmount() != FIXED_SUPPLY ||
        !issuance.assetIssuance.nInflationKeys.IsExplicit() ||
        issuance.assetIssuance.nInflationKeys.GetAmount() != 1) {
        throw std::runtime_error("ECX bond V2 issuance is not the exact fixed supply");
    }
    uint256 entropy;
    GenerateAssetEntropy(
        entropy, issuance.prevout, issuance.assetIssuance.assetEntropy);
    CAsset bond_asset;
    CAsset reissuance_token;
    CalculateAsset(bond_asset, entropy);
    CalculateReissuanceToken(reissuance_token, entropy, false);
    if (bond_asset.IsNull() || reissuance_token.IsNull() ||
        bond_asset == reissuance_token) {
        throw std::runtime_error("ECX bond V2 derived asset identities are invalid");
    }
    frozen.bond_asset_id = bond_asset.id;

    const CTxOut& inventory{transaction.vout[frozen.inventory_output_index]};
    const CTxOut& burn{
        transaction.vout[frozen.reissuance_token_burn_output_index]};
    if (!inventory.nAsset.IsCommitment() || !inventory.nValue.IsCommitment() ||
        !inventory.nNonce.IsCommitment() || inventory.scriptPubKey.empty() ||
        inventory.scriptPubKey.IsUnspendable() ||
        !VerifyConfidentialPair(
            inventory.nValue, inventory.nAsset, FIXED_SUPPLY, bond_asset,
            frozen.inventory_value_blinding_factor,
            frozen.inventory_asset_blinding_factor)) {
        throw std::runtime_error("ECX bond V2 inventory opening is invalid");
    }
    if (!burn.nAsset.IsExplicit() || burn.nAsset.GetAsset() != reissuance_token ||
        !burn.nValue.IsExplicit() || burn.nValue.GetAmount() != 1 ||
        !burn.nNonce.IsNull() || !burn.scriptPubKey.IsUnspendable()) {
        throw std::runtime_error("ECX bond V2 reissuance token is not destroyed");
    }
    frozen.inventory_covenant_script_sha256 = Sha256(
        std::vector<unsigned char>(
            inventory.scriptPubKey.begin(), inventory.scriptPubKey.end()));
    frozen.reissuance_token_burn_script_sha256 = Sha256(
        std::vector<unsigned char>(
            burn.scriptPubKey.begin(), burn.scriptPubKey.end()));
    const CTxOut& authority_source{
        transaction.vout[frozen.state_authority_source_output_index]};
    if (!authority_source.nAsset.IsExplicit() ||
        !authority_source.nValue.IsExplicit() ||
        authority_source.nValue.GetAmount() != 1 ||
        !authority_source.nNonce.IsNull() ||
        authority_source.scriptPubKey.empty() ||
        authority_source.scriptPubKey.IsUnspendable()) {
        throw std::runtime_error(
            "ECX bond V2 state-authority source is not one explicit spendable unit");
    }
    frozen.state_authority_asset_id = authority_source.nAsset.GetAsset().id;
    if (frozen.state_authority_asset_id.IsNull() ||
        frozen.state_authority_asset_id !=
            decoded_configuration.state_authority_asset_id ||
        frozen.state_authority_asset_id == frozen.bond_asset_id ||
        frozen.state_authority_asset_id == reissuance_token.id ||
        frozen.state_authority_asset_id == frozen.usdd_asset_id.id) {
        throw std::runtime_error(
            "ECX bond V2 state-authority source asset is not independent");
    }
    for (size_t index = 0; index < transaction.vout.size(); ++index) {
        const CTxOut& output{transaction.vout[index]};
        if (index == frozen.inventory_output_index) continue;
        if (!output.nAsset.IsExplicit() || !output.nValue.IsExplicit() ||
            !output.nNonce.IsNull() ||
            output.nAsset.GetAsset() == bond_asset ||
            (output.nAsset.GetAsset() == reissuance_token &&
             index != frozen.reissuance_token_burn_output_index) ||
            (output.nAsset.GetAsset() == frozen.usdd_asset_id &&
             output.nValue.GetAmount() != 0)) {
            throw std::runtime_error(
                "ECX bond V2 deployment has an unclassified or prefunded output");
        }
    }
    const uint256 deployment_txid{transaction.GetHash()};
    const uint256 genesis_txid{genesis.GetHash()};
    if (deployment_txid == genesis_txid) {
        throw std::runtime_error(
            "ECX bond V2 deployment and genesis must be separate transactions");
    }
    if (consensus.genesis_state_outpoint.hash != genesis_txid ||
        consensus.genesis_state_outpoint.n >= genesis.vout.size() ||
        genesis.vin.empty() ||
        genesis.vin[0].prevout != COutPoint{
            deployment_txid, frozen.state_authority_source_output_index} ||
        std::any_of(
            genesis.vin.begin(), genesis.vin.end(),
            [](const CTxIn& input) {
                return input.m_is_pegin || !input.assetIssuance.IsNull();
            })) {
        throw std::runtime_error(
            "ECX bond V2 genesis is not the preauthorized spend of its deployment authority");
    }
    const CTxOut& state{genesis.vout[consensus.genesis_state_outpoint.n]};
    if (!state.nAsset.IsExplicit() || !state.nValue.IsExplicit() ||
        state.nAsset.GetAsset().id != frozen.state_authority_asset_id ||
        state.nValue.GetAmount() != 1 || !state.nNonce.IsNull() ||
        state.scriptPubKey.size() != 34 || state.scriptPubKey[0] != OP_1 ||
        state.scriptPubKey[1] != 32) {
        throw std::runtime_error("ECX bond V2 state authority output is invalid");
    }
    for (size_t index = 0; index < genesis.vout.size(); ++index) {
        if (index == consensus.genesis_state_outpoint.n) continue;
        const CTxOut& output{genesis.vout[index]};
        if (!output.nAsset.IsExplicit() || !output.nValue.IsExplicit() ||
            !output.nNonce.IsNull() ||
            output.nAsset.GetAsset() == bond_asset ||
            output.nAsset.GetAsset() == reissuance_token ||
            (output.nAsset.GetAsset() == frozen.usdd_asset_id &&
             output.nValue.GetAmount() != 0)) {
            throw std::runtime_error(
                "ECX bond V2 genesis has an unclassified or prefunded output");
        }
    }

    const auto script_hash = [](const CScript& script) {
        return Sha256(std::vector<unsigned char>(script.begin(), script.end()));
    };
    std::vector<unsigned char> commitment;
    commitment.reserve(253);
    commitment.push_back(1);
    commitment.insert(commitment.end(), deployment_txid.begin(), deployment_txid.end());
    commitment.insert(commitment.end(), issuance.prevout.hash.begin(), issuance.prevout.hash.end());
    PushU32Be(commitment, issuance.prevout.n);
    commitment.insert(commitment.end(), bond_asset.begin(), bond_asset.end());
    commitment.insert(commitment.end(), reissuance_token.begin(), reissuance_token.end());
    PushU64Be(commitment, FIXED_SUPPLY);
    PushU32Be(commitment, frozen.inventory_output_index);
    PushU32Be(commitment, frozen.reissuance_token_burn_output_index);
    const uint256 inventory_script_hash{script_hash(inventory.scriptPubKey)};
    const uint256 burn_script_hash{script_hash(burn.scriptPubKey)};
    commitment.insert(commitment.end(), inventory_script_hash.begin(), inventory_script_hash.end());
    commitment.insert(commitment.end(), burn_script_hash.begin(), burn_script_hash.end());
    frozen.bond_deployment_commitment =
        TaggedHash("ECX/frozen-bond-deployment/v2", commitment);

    /* Activation is an exact physical/configuration join.  A valid V18 hash
     * for different Tx1/Tx2 assets or scripts must never activate this
     * singleton. */
    if (decoded_configuration.bond_asset_id != frozen.bond_asset_id ||
        decoded_configuration.deployment_commitment !=
            frozen.bond_deployment_commitment ||
        decoded_configuration.inventory_script_sha256 !=
            frozen.inventory_covenant_script_sha256 ||
        decoded_configuration.inventory_script_sha256 !=
            derived_inventory_script_hash ||
        decoded_configuration.burn_script_sha256 !=
            frozen.reissuance_token_burn_script_sha256 ||
        decoded_configuration.queue_script_sha256 !=
            derived_queue_script_hash ||
        decoded_configuration.staging_template_commitment !=
            frozen.bond_inbox_redemption_staging_template_commitment ||
        decoded_configuration.staging_renderer_domain !=
            frozen.bond_inbox_redemption_staging_renderer_domain ||
        !IsEcxStagingRendererDomainV18(
            frozen.bond_inbox_redemption_staging_renderer_domain.begin()) ||
        decoded_configuration.staging_internal_key !=
            frozen.bond_inbox_redemption_staging_internal_key ||
        !IsEcxNumsInternalKey(
            frozen.bond_inbox_redemption_staging_internal_key.begin()) ||
        decoded_configuration.staging_process_cmr !=
            frozen.bond_inbox_redemption_staging_process_cmr ||
        decoded_configuration.staging_refund_cmr !=
            frozen.bond_inbox_redemption_staging_refund_cmr ||
        decoded_configuration.collateral_vault_covenant_cmr !=
            frozen.collateral_vault_covenant_cmr ||
        frozen.collateral_vault_covenant_cmr == frozen.transition_cmr ||
        frozen.collateral_vault_covenant_cmr ==
            frozen.insurance_reserve_covenant_cmr ||
        decoded_configuration.collateral_vault_script_sha256 !=
            derived_collateral_vault_script_hash ||
        decoded_configuration.collateral_vault_script_sha256 !=
            consensus.collateral_vault_script_hash ||
        decoded_configuration.insurance_reserve_covenant_cmr !=
            frozen.insurance_reserve_covenant_cmr ||
        frozen.insurance_reserve_covenant_cmr == frozen.transition_cmr ||
        decoded_configuration.insurance_script_sha256 !=
            derived_insurance_script_hash) {
        throw std::runtime_error(
            "FrozenConfigurationV2/V18 bond/deployment/covenant identities "
            "do not match physical Tx1/Tx2 activation facts");
    }
    if (frozen.inventory_cmr.IsNull() || frozen.redemption_queue_cmr.IsNull() ||
        frozen.incremental_activation_program_id.IsNull() ||
        frozen.incremental_activation_configuration_hash.IsNull() ||
        frozen.incremental_activation_cmr.IsNull() ||
        frozen.incremental_successor_program_id.IsNull() ||
        frozen.incremental_successor_configuration_hash.IsNull() ||
        frozen.incremental_successor_transition_cmr.IsNull() ||
        frozen.incremental_successor_state_node_domain_sha256.IsNull() ||
        frozen.collateral_vault_covenant_cmr.IsNull() ||
        frozen.insurance_reserve_covenant_cmr.IsNull() ||
        frozen.bond_inbox_redemption_staging_process_cmr.IsNull() ||
        frozen.bond_inbox_redemption_staging_refund_cmr.IsNull()) {
        throw std::runtime_error(
            "ECX bond V2 activation lacks a complete frozen covenant CMR tuple");
    }

    std::vector<unsigned char> derivation;
    CDataStream transaction_bytes(SER_NETWORK, PROTOCOL_VERSION);
    transaction_bytes << transaction;
    derivation.insert(
        derivation.end(), UCharCast(transaction_bytes.data()),
        UCharCast(transaction_bytes.data()) + transaction_bytes.size());
    CDataStream genesis_bytes(SER_NETWORK, PROTOCOL_VERSION);
    genesis_bytes << genesis;
    derivation.insert(
        derivation.end(), UCharCast(genesis_bytes.data()),
        UCharCast(genesis_bytes.data()) + genesis_bytes.size());
    PushU32Be(derivation, frozen.issuance_input_index);
    PushU32Be(derivation, frozen.inventory_output_index);
    PushU32Be(derivation, frozen.reissuance_token_burn_output_index);
    PushU32Be(derivation, frozen.state_authority_source_output_index);
    derivation.insert(
        derivation.end(), frozen.canonical_configuration_bytes.begin(),
        frozen.canonical_configuration_bytes.end());
    for (const uint256* value : {
             &frozen.inventory_asset_blinding_factor,
             &frozen.inventory_value_blinding_factor,
             &frozen.transition_program_id,
             &frozen.configuration_hash,
             &frozen.bond_asset_id,
             &frozen.bond_deployment_commitment,
             &frozen.inventory_covenant_script_sha256,
             &frozen.reissuance_token_burn_script_sha256,
             &frozen.collateral_vault_covenant_cmr,
             &frozen.insurance_reserve_script_sha256,
             &frozen.insurance_reserve_covenant_cmr,
             &frozen.redemption_queue_script_sha256,
             &frozen.bond_inbox_redemption_staging_template_commitment,
             &frozen.bond_inbox_redemption_staging_renderer_domain,
             &frozen.bond_inbox_redemption_staging_internal_key,
             &frozen.bond_inbox_redemption_staging_process_cmr,
             &frozen.bond_inbox_redemption_staging_refund_cmr,
             &frozen.state_authority_asset_id,
             &frozen.public_state_domain_sha256,
             &frozen.state_node_domain_sha256,
             &frozen.transition_journal_domain_sha256,
             &frozen.transition_cmr,
             &frozen.incremental_activation_program_id,
             &frozen.incremental_activation_configuration_hash,
             &frozen.incremental_activation_cmr,
             &frozen.incremental_successor_program_id,
             &frozen.incremental_successor_configuration_hash,
             &frozen.incremental_successor_transition_cmr,
             &frozen.incremental_successor_state_node_domain_sha256,
             &frozen.inventory_cmr,
             &frozen.redemption_queue_cmr,
             &frozen.ecx_btc_conversion_program_id,
             &frozen.ecx_btc_redemption_covenant_commitment,
             &frozen.ecx_btc_source_checkpoint_commitment,
             &frozen.usdd_usd_conversion_program_id,
             &frozen.usdd_usd_redemption_covenant_commitment,
             &frozen.usdd_usd_source_checkpoint_commitment,
             &frozen.matcher_genesis_receipt_hash,
             &frozen.order_receipts_genesis_root,
             &frozen.genesis_availability_root,
             &frozen.usdd_asset_id.id}) {
        derivation.insert(derivation.end(), value->begin(), value->end());
    }
    derivation.insert(
        derivation.end(), frozen.keyless_internal_key.begin(),
        frozen.keyless_internal_key.end());
    PushU64Be(derivation, frozen.genesis_mark_price);
    frozen.identity_derivation_record_sha256 =
        TaggedHash("ECX/bond-v2-activation-identity/v4", derivation);
    frozen.activation_enabled = true;
    static_assert(BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN,
                  "partitioned incremental recovery theorem must be source frozen");
    frozen.identities_frozen = true;
#endif
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

void PushU128Zero(std::vector<unsigned char>& bytes)
{
    bytes.insert(bytes.end(), 16, 0);
}

void AppendHash(std::vector<unsigned char>& bytes, const uint256& value)
{
    bytes.insert(bytes.end(), value.begin(), value.end());
}

uint256 EmptyMerkleRoot()
{
    return TaggedHash("ECX/merkle-empty/v1", {});
}

uint256 EmptyBondV2QueueRoot()
{
    return TaggedHash("ECX/redemption-queue/v2/empty", {});
}

uint256 ComputeBondInboxGenesisRoot(const ExchangeConsensus& consensus)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(96);
    AppendHash(bytes, consensus.bond_v2.bond_inbox_domain);
    bytes.insert(bytes.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    AppendHash(bytes, consensus.bond_v2.configuration_hash);
    return TaggedHash("ECX/bond-inbox-genesis/v2", bytes);
}

uint256 ComputeBondInboxOutcomeGenesisRoot(const ExchangeConsensus& consensus)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(96);
    AppendHash(bytes, consensus.bond_v2.bond_inbox_domain);
    bytes.insert(bytes.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    AppendHash(bytes, consensus.bond_v2.configuration_hash);
    return TaggedHash(
        "ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2", bytes);
}

uint256 EmptyMatcherExecutionReceiptBatchRoot()
{
    return TaggedHash(
        "ECX/central-matcher-execution-receipt-batch/v2/empty", {});
}

uint256 ComputeBondV2GenesisBondStateRoot(
    const ExchangeConsensus& consensus,
    std::vector<unsigned char>* encoded_out = nullptr)
{
    static constexpr uint64_t FIXED_SUPPLY{2'100'000'000'000'000};
    std::vector<unsigned char> encoded;
    encoded.reserve(242);
    encoded.push_back(2);
    AppendHash(encoded, consensus.bond_v2.bond_asset_id);
    AppendHash(encoded, consensus.bond_v2.bond_deployment_commitment);
    AppendHash(encoded, consensus.bond_v2.inventory_covenant_script_sha256);
    PushU128Zero(encoded); // insurance reserve
    PushU64Be(encoded, FIXED_SUPPLY); // issued
    PushU64Be(encoded, 0); // outstanding
    PushU64Be(encoded, FIXED_SUPPLY); // inventory
    PushU128Zero(encoded); // deficit
    PushU128Zero(encoded); // target
    PushU128Zero(encoded); // legacy fee pool
    AppendHash(encoded, EmptyBondV2QueueRoot());
    PushU64Be(encoded, 0); // queue head
    PushU64Be(encoded, 0); // queue tail
    PushU64Be(encoded, 0); // queued shares
    encoded.push_back(0); // Normal
    if (encoded.size() != 242) return {};
    if (encoded_out) *encoded_out = encoded;
    return TaggedHash("ECX/bond-public-state/v2", encoded);
}

uint256 ComputeBondV2GenesisFundingStateRoot(
    const ExchangeConsensus& consensus,
    uint64_t prior_parent_mtp,
    std::vector<unsigned char>* encoded_out = nullptr)
{
    std::vector<unsigned char> encoded;
    encoded.reserve(693);
    encoded.push_back(1);
    PushU64Be(encoded, prior_parent_mtp);
    PushU64Be(encoded, consensus.bond_v2.genesis_mark_price);
    PushU64Be(encoded, std::numeric_limits<uint64_t>::max());
    PushU32Be(encoded, 0); // signed funding rate bits
    PushU128Zero(encoded); // epoch-start open interest
    for (uint8_t bucket = 0; bucket < 8; ++bucket) {
        PushU64Be(encoded, std::numeric_limits<uint64_t>::max());
        encoded.push_back(bucket);
        for (int field = 0; field < 4; ++field) PushU128Zero(encoded);
        PushU64Be(encoded, 0);
    }
    if (encoded.size() != 693) return {};
    if (encoded_out) *encoded_out = encoded;
    return TaggedHash("ECX/funding-state/v2", encoded);
}

uint256 ComputeBondV2GenesisPrivateStateRoot(
    const ExchangeConsensus& consensus,
    uint64_t last_processed_height,
    uint64_t prior_parent_mtp,
    uint256& bond_state_root,
    uint256& funding_state_root)
{
    std::vector<unsigned char> bond_state;
    bond_state_root = ComputeBondV2GenesisBondStateRoot(consensus, &bond_state);
    std::vector<unsigned char> funding_state;
    funding_state_root = ComputeBondV2GenesisFundingStateRoot(
        consensus, prior_parent_mtp, &funding_state);
    if (bond_state_root.IsNull() || funding_state_root.IsNull()) return {};

    const uint256 empty{EmptyMerkleRoot()};
    const uint256 forced{ComputeForcedInboxGenesis(consensus)};
    const uint256 deposits{ComputeDepositInboxGenesis(consensus)};
    std::vector<unsigned char> encoded;
    encoded.reserve(1681);
    encoded.push_back(2); // ExchangeStateV2 container version
    encoded.push_back(8); // V2 transition protocol with bounded DA expiry
    encoded.insert(encoded.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    encoded.insert(encoded.end(), ECX_USDD_MARKET.begin(), ECX_USDD_MARKET.end());
    PushU64Be(encoded, 0); // sequence
    PushU64Be(encoded, last_processed_height);
    PushU64Be(encoded, consensus.bond_v2.genesis_mark_price);
    for (int field = 0; field < 5; ++field) PushU128Zero(encoded);
    PushU64Be(encoded, 0); // matcher sequence
    AppendHash(encoded, consensus.bond_v2.matcher_genesis_receipt_hash);
    AppendHash(encoded, forced);
    PushU64Be(encoded, 0);
    AppendHash(encoded, forced);
    PushU64Be(encoded, 0);
    AppendHash(encoded, deposits);
    PushU64Be(encoded, 0);
    AppendHash(encoded, deposits);
    PushU64Be(encoded, 0);
    for (int root = 0; root < 5; ++root) AppendHash(encoded, empty);
    AppendHash(encoded, consensus.bond_v2.order_receipts_genesis_root);
    encoded.insert(encoded.end(), bond_state.begin(), bond_state.end());
    encoded.insert(encoded.end(), funding_state.begin(), funding_state.end());
    PushU64Be(encoded, 0); // fill-only matcher execution sequence
    PushU64Be(encoded, last_processed_height);
    const uint256 bond_inbox{ComputeBondInboxGenesisRoot(consensus)};
    AppendHash(encoded, bond_inbox);
    PushU64Be(encoded, 0);
    AppendHash(encoded, bond_inbox);
    PushU64Be(encoded, 0);
    AppendHash(encoded, ComputeBondInboxOutcomeGenesisRoot(consensus));
    PushU64Be(encoded, 0);
    AppendHash(encoded, empty); // active order risk
    AppendHash(encoded, empty); // position risk
    if (encoded.size() != 1681) return {};
    return TaggedHash("ECX/exchange-state/v9-expired-unavailable-v2", encoded);
}

uint256 ComputeBondV2GenesisCovenantStateHash(
    const ExchangeConsensus& consensus,
    const uint256& private_state_root,
    const uint256& bond_state_root,
    const uint256& funding_state_root,
    uint64_t last_transition_sidechain_height)
{
    const uint256 forced{ComputeForcedInboxGenesis(consensus)};
    const uint256 deposits{ComputeDepositInboxGenesis(consensus)};
    const uint256 empty{EmptyMerkleRoot()};
    std::vector<unsigned char> preimage;
    preimage.reserve(468);
    AppendHash(preimage, consensus.bond_v2.public_state_domain_sha256);
    PushU32Be(preimage, 4);
    PushU64Be(preimage, 0);
    AppendHash(preimage, private_state_root);
    AppendHash(preimage, consensus.bond_v2.genesis_availability_root);
    AppendHash(preimage, forced);
    AppendHash(preimage, deposits);
    AppendHash(preimage, consensus.bond_v2.configuration_hash);
    AppendHash(preimage, bond_state_root);
    AppendHash(preimage, funding_state_root);
    AppendHash(preimage, empty);
    AppendHash(preimage, empty);
    const uint256 bond_inbox{ComputeBondInboxGenesisRoot(consensus)};
    AppendHash(preimage, bond_inbox);
    PushU64Be(preimage, 0);
    AppendHash(preimage, bond_inbox);
    PushU64Be(preimage, 0);
    AppendHash(preimage, ComputeBondInboxOutcomeGenesisRoot(consensus));
    PushU64Be(preimage, 0);
    PushU64Be(preimage, 0); // matcher execution sequence
    PushU64Be(preimage, last_transition_sidechain_height);
    if (preimage.size() != 468) return {};
    return Sha256(preimage);
}

uint256 ComputeBondV2GenesisStateNode(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash)
{
    std::vector<unsigned char> preimage;
    preimage.reserve(64);
    AppendHash(preimage, consensus.bond_v2.state_node_domain_sha256);
    AppendHash(preimage, covenant_state_hash);
    return Sha256(preimage);
}

uint256 ComputeBondV2GenesisTaprootRoot(
    const ExchangeConsensus& consensus,
    const uint256& state_node)
{
    const auto leaf_hash = [](const uint256& cmr) {
        std::vector<unsigned char> payload;
        payload.reserve(34);
        payload.push_back(TAPROOT_LEAF_TAPSIMPLICITY);
        payload.push_back(32);
        AppendHash(payload, cmr);
        return TaggedHash("TapLeaf/elements", payload);
    };
    const auto branch_hash = [](const uint256& left, const uint256& right) {
        std::vector<unsigned char> payload;
        payload.reserve(64);
        if (TapNodeHashLess(left, right)) {
            AppendHash(payload, left);
            AppendHash(payload, right);
        } else {
            AppendHash(payload, right);
            AppendHash(payload, left);
        }
        return TaggedHash("TapBranch/elements", payload);
    };
    const uint256 transition_leaf{leaf_hash(consensus.bond_v2.transition_cmr)};
    const uint256 activation_leaf{
        leaf_hash(consensus.bond_v2.incremental_activation_cmr)};
    const uint256 activation_or_state{branch_hash(activation_leaf, state_node)};
    return branch_hash(transition_leaf, activation_or_state);
}

bool ComputeBondV2GenesisScript(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash,
    CScript& script)
{
    const uint256 state_node{
        ComputeBondV2GenesisStateNode(consensus, covenant_state_hash)};
    const uint256 root{ComputeBondV2GenesisTaprootRoot(consensus, state_node)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return false;
    script.clear();
    script << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
    return true;
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

uint256 RawHash32(const unsigned char* bytes)
{
    uint256 result;
    std::copy(bytes, bytes + 32, result.begin());
    return result;
}

bool FrozenBondV2IdentityAvailable(
    const ExchangeConsensus::BondV2FrozenConsensus& frozen,
    std::string& error)
{
    if (!frozen.activation_enabled) {
        error = "ECX bond V2 activation is disabled";
        return false;
    }
    if (!frozen.identities_frozen) {
        error = "ECX bond V2 identities are not source-frozen";
        return false;
    }
    const std::array<std::pair<const char*, const uint256*>, 45> identities{{
        {"transition program", &frozen.transition_program_id},
        {"configuration", &frozen.configuration_hash},
        {"collateral vault covenant CMR", &frozen.collateral_vault_covenant_cmr},
        {"bond asset", &frozen.bond_asset_id},
        {"deployment", &frozen.bond_deployment_commitment},
        {"inventory covenant script", &frozen.inventory_covenant_script_sha256},
        {"token burn script", &frozen.reissuance_token_burn_script_sha256},
        {"redemption queue script", &frozen.redemption_queue_script_sha256},
        {"insurance reserve script", &frozen.insurance_reserve_script_sha256},
        {"insurance reserve CMR", &frozen.insurance_reserve_covenant_cmr},
        {"redemption staging descriptor", &frozen.bond_inbox_redemption_staging_template_commitment},
        {"redemption staging renderer domain", &frozen.bond_inbox_redemption_staging_renderer_domain},
        {"redemption staging internal key", &frozen.bond_inbox_redemption_staging_internal_key},
        {"redemption staging process CMR", &frozen.bond_inbox_redemption_staging_process_cmr},
        {"redemption staging refund CMR", &frozen.bond_inbox_redemption_staging_refund_cmr},
        {"bond inbox domain", &frozen.bond_inbox_domain},
        {"custody receipt codec", &frozen.bond_inbox_custody_receipt_codec_hash},
        {"availability scheme", &frozen.availability_scheme_hash},
        {"availability registry", &frozen.availability_custodian_registry_hash},
        {"state authority asset", &frozen.state_authority_asset_id},
        {"public state domain", &frozen.public_state_domain_sha256},
        {"state node domain", &frozen.state_node_domain_sha256},
        {"journal domain", &frozen.transition_journal_domain_sha256},
        {"transition CMR", &frozen.transition_cmr},
        {"incremental activation program", &frozen.incremental_activation_program_id},
        {"incremental activation configuration", &frozen.incremental_activation_configuration_hash},
        {"incremental activation CMR", &frozen.incremental_activation_cmr},
        {"incremental successor program", &frozen.incremental_successor_program_id},
        {"incremental successor configuration", &frozen.incremental_successor_configuration_hash},
        {"incremental successor transition CMR", &frozen.incremental_successor_transition_cmr},
        {"incremental successor state-node domain", &frozen.incremental_successor_state_node_domain_sha256},
        {"inventory CMR", &frozen.inventory_cmr},
        {"redemption queue CMR", &frozen.redemption_queue_cmr},
        {"ECX/BTC conversion program", &frozen.ecx_btc_conversion_program_id},
        {"ECX/BTC redemption covenant", &frozen.ecx_btc_redemption_covenant_commitment},
        {"ECX/BTC source checkpoint", &frozen.ecx_btc_source_checkpoint_commitment},
        {"USDD/USD conversion program", &frozen.usdd_usd_conversion_program_id},
        {"USDD/USD redemption covenant", &frozen.usdd_usd_redemption_covenant_commitment},
        {"USDD/USD source checkpoint", &frozen.usdd_usd_source_checkpoint_commitment},
        {"identity derivation record", &frozen.identity_derivation_record_sha256},
        {"matcher genesis receipt", &frozen.matcher_genesis_receipt_hash},
        {"order receipts genesis", &frozen.order_receipts_genesis_root},
        {"genesis availability", &frozen.genesis_availability_root},
        {"USDD asset", &frozen.usdd_asset_id.id},
        {"inventory asset blinder", &frozen.inventory_asset_blinding_factor},
    }};
    for (const auto& identity : identities) {
        if (identity.second->IsNull()) {
            error = std::string("missing frozen ECX bond V2 ") + identity.first;
            return false;
        }
    }
    if (!frozen.deployment_transaction || !frozen.genesis_transaction ||
        frozen.canonical_configuration_bytes.empty() ||
        frozen.genesis_mark_price == 0 ||
        frozen.inventory_value_blinding_factor.IsNull() ||
        frozen.inventory_asset_blinding_factor ==
            frozen.inventory_value_blinding_factor ||
        IsZero(frozen.keyless_internal_key) ||
        !IsEcxNumsInternalKey(frozen.keyless_internal_key.data()) ||
        !IsEcxStagingRendererDomainV18(
            frozen.bond_inbox_redemption_staging_renderer_domain.begin()) ||
        !IsEcxNumsInternalKey(
            frozen.bond_inbox_redemption_staging_internal_key.begin())) {
        error = "incomplete frozen ECX bond V2 physical activation inputs";
        return false;
    }
    if (frozen.bond_inbox_redemption_staging_tapleaf_version !=
            TAPROOT_LEAF_TAPSIMPLICITY ||
        frozen.bond_inbox_refund_minimum_parent_blocks != 12 ||
        frozen.bond_inbox_inclusion_blocks != 6 ||
        frozen.bond_inbox_max_bundle_bytes != 64 * 1024 ||
        frozen.bond_inbox_max_entries_per_sidechain_block != 8 ||
        frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block !=
            576 * 1024 ||
        frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block !=
            768 * 1024 ||
        frozen.bond_inbox_max_pending_entries_per_transition != 64 ||
        frozen.bond_inbox_max_consumed_entries_per_transition != 64 ||
        frozen.bond_redemption_max_queue_entries != 4096 ||
        frozen.matcher_execution_inclusion_parent_blocks != 6 ||
        frozen.maximum_conversion_age_seconds == 0 ||
        frozen.maximum_conversion_proof_bytes == 0 ||
        frozen.maximum_conversion_proof_bytes > 16 * 1024 * 1024 ||
        frozen.recursive_proof_marker_bytes != 32 ||
        frozen.fixed_supply_atoms != UINT64_C(2100000000000000) ||
        frozen.redemption_delay_parent_blocks != 1008) {
        error = "invalid frozen ECX bond V2 bounds or timing parameters";
        return false;
    }
    for (size_t i = 0; i < frozen.custodian_encryption_keys.size(); ++i) {
        if (IsZero(frozen.custodian_encryption_keys[i]) ||
            IsZero(frozen.custodian_attestation_keys[i])) {
            error = "incomplete frozen ECX bond V2 custodian registry";
            return false;
        }
        for (size_t j = 0; j < i; ++j) {
            if (frozen.custodian_encryption_keys[i] ==
                    frozen.custodian_encryption_keys[j] ||
                frozen.custodian_attestation_keys[i] ==
                    frozen.custodian_attestation_keys[j]) {
                error = "duplicate frozen ECX bond V2 custodian registry key";
                return false;
            }
        }
    }
    if (frozen.configuration_hash ==
            frozen.incremental_activation_configuration_hash ||
        frozen.configuration_hash ==
            frozen.incremental_successor_configuration_hash ||
        frozen.incremental_activation_configuration_hash ==
            frozen.incremental_successor_configuration_hash) {
        error = "finite, activation, and incremental-successor configurations collide";
        return false;
    }
    const std::array<const uint256*, 5> proof_program_ids{{
        &frozen.transition_program_id,
        &frozen.incremental_activation_program_id,
        &frozen.incremental_successor_program_id,
        &frozen.ecx_btc_conversion_program_id,
        &frozen.usdd_usd_conversion_program_id,
    }};
    for (size_t i = 0; i < proof_program_ids.size(); ++i) {
        for (size_t j = i + 1; j < proof_program_ids.size(); ++j) {
            if (*proof_program_ids[i] == *proof_program_ids[j]) {
                error = "incremental proof program identity collides";
                return false;
            }
        }
    }
    const std::array<const uint256*, 9> covenant_cmrs{{
        &frozen.transition_cmr,
        &frozen.incremental_activation_cmr,
        &frozen.incremental_successor_transition_cmr,
        &frozen.collateral_vault_covenant_cmr,
        &frozen.insurance_reserve_covenant_cmr,
        &frozen.inventory_cmr,
        &frozen.redemption_queue_cmr,
        &frozen.bond_inbox_redemption_staging_process_cmr,
        &frozen.bond_inbox_redemption_staging_refund_cmr,
    }};
    for (size_t i = 0; i < covenant_cmrs.size(); ++i) {
        for (size_t prior = 0; prior < i; ++prior) {
            if (*covenant_cmrs[i] == *covenant_cmrs[prior]) {
                error = "frozen ECX bond V2 covenant CMR roles collide";
                return false;
            }
        }
    }
    if (frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.state_node_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.public_state_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.transition_journal_domain_sha256 ||
        frozen.incremental_successor_state_node_domain_sha256 ==
            frozen.bond_inbox_redemption_staging_renderer_domain) {
        error = "incremental successor state-node identity collides";
        return false;
    }
    return true;
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
    if (IsExchangeStateInternalOutpoint(consensus.genesis_state_outpoint) ||
        drivechain::IsBmmStateInternalOutpoint(consensus.genesis_state_outpoint) ||
        drivechain::IsCtipStateInternalOutpoint(consensus.genesis_state_outpoint)) {
        error = "ECX genesis state outpoint collides with a reserved chainstate record";
        return false;
    }
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

bool DecodeCursorPayload(
    const CScript& script,
    bool& is_cursor_marker,
    uint64_t& forced_cursor,
    uint64_t& deposit_cursor,
    std::string& error)
{
    is_cursor_marker = false;
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> payload;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN ||
        !script.GetOp(cursor, opcode, payload) || opcode > OP_PUSHDATA4 ||
        cursor != script.end()) {
        return true;
    }
    static constexpr std::array<unsigned char, 4> magic{{'E','C','X','C'}};
    if (payload.size() < magic.size() ||
        !std::equal(magic.begin(), magic.end(), payload.begin())) {
        return true;
    }
    is_cursor_marker = true;
    if (payload.size() != 21 || payload[4] != 1) {
        error = "ECX processed-cursor marker has an invalid version or length";
        return false;
    }
    const auto read_u64_le = [&payload](size_t offset) {
        uint64_t value{0};
        for (size_t index = 0; index < 8; ++index) {
            value |= static_cast<uint64_t>(payload[offset + index]) << (8 * index);
        }
        return value;
    };
    forced_cursor = read_u64_le(5);
    deposit_cursor = read_u64_le(13);
    return true;
}

bool DeriveProcessedCursors(
    const CBlock& block,
    const ExchangeStateTracker& previous_state,
    const ExchangeStateTracker& next_state,
    uint64_t previous_forced_cursor,
    uint64_t previous_deposit_cursor,
    uint64_t& next_forced_cursor,
    uint64_t& next_deposit_cursor,
    std::string& error)
{
    bool found{false};
    uint256 marker_transaction;
    uint64_t marker_forced{0};
    uint64_t marker_deposit{0};
    for (const CTransactionRef& transaction_ref : block.vtx) {
        for (const CTxOut& output : transaction_ref->vout) {
            bool is_marker{false};
            uint64_t forced{0};
            uint64_t deposit{0};
            if (!DecodeCursorPayload(
                    output.scriptPubKey,
                    is_marker,
                    forced,
                    deposit,
                    error)) {
                return false;
            }
            if (!is_marker) continue;
            if (found) {
                error = "an ECX block may contain only one processed-cursor marker";
                return false;
            }
            found = true;
            marker_transaction = transaction_ref->GetHash();
            marker_forced = forced;
            marker_deposit = deposit;
        }
    }

    const bool transitioned = next_state.outpoint != previous_state.outpoint;
    if (transitioned != found) {
        error = transitioned
            ? "ECX state transition is missing its processed-cursor marker"
            : "ECX processed-cursor marker requires a state transition";
        return false;
    }
    if (!transitioned) {
        next_forced_cursor = previous_forced_cursor;
        next_deposit_cursor = previous_deposit_cursor;
        return true;
    }
    if (marker_transaction != next_state.outpoint.hash ||
        marker_forced < previous_forced_cursor ||
        marker_deposit < previous_deposit_cursor) {
        error = "ECX processed cursors are not monotonic or are outside the state transition";
        return false;
    }
    next_forced_cursor = marker_forced;
    next_deposit_cursor = marker_deposit;
    return true;
}

bool ValidateInboxLiveness(
    const InboxTracker& previous_forced,
    const InboxTracker& previous_deposits,
    const InboxTracker& next_forced,
    const InboxTracker& next_deposits,
    uint64_t previous_forced_cursor,
    uint64_t previous_deposit_cursor,
    uint64_t next_forced_cursor,
    uint64_t next_deposit_cursor,
    uint64_t forced_appends,
    uint64_t deposit_appends,
    uint64_t previous_oldest_parent_height,
    uint64_t current_parent_height,
    uint64_t& next_oldest_parent_height,
    std::string& error)
{
    if (previous_forced_cursor > previous_forced.count ||
        previous_deposit_cursor > previous_deposits.count ||
        next_forced_cursor > next_forced.count ||
        next_deposit_cursor > next_deposits.count) {
        error = "ECX processed cursor exceeds its source entry count";
        return false;
    }
    if (forced_appends > MAX_COMBINED_SAME_PARENT_APPENDS ||
        deposit_appends > MAX_COMBINED_SAME_PARENT_APPENDS - forced_appends) {
        error = "ECX source appends exceed the combined same-parent limit";
        return false;
    }
    const uint64_t previous_forced_pending =
        previous_forced.count - previous_forced_cursor;
    const uint64_t previous_deposit_pending =
        previous_deposits.count - previous_deposit_cursor;
    if (previous_forced_pending > MAX_COMBINED_PENDING_WITNESS_ENTRIES ||
        previous_deposit_pending >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending ||
        forced_appends >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending - previous_deposit_pending ||
        deposit_appends >
            MAX_COMBINED_PENDING_WITNESS_ENTRIES - previous_forced_pending - previous_deposit_pending - forced_appends) {
        error = "ECX source suffix exceeds the maximum transition witness profile";
        return false;
    }
    const uint64_t next_forced_pending = next_forced.count - next_forced_cursor;
    const uint64_t next_deposit_pending = next_deposits.count - next_deposit_cursor;
    if (next_forced_pending > MAX_COMBINED_UNCONSUMED ||
        next_deposit_pending > MAX_COMBINED_UNCONSUMED - next_forced_pending) {
        error = "ECX combined unconsumed source backlog exceeds consensus bounds";
        return false;
    }
    const uint64_t previous_pending =
        previous_forced_pending + previous_deposit_pending;
    const uint64_t next_pending = next_forced_pending + next_deposit_pending;
    if (next_pending == 0) {
        next_oldest_parent_height = 0;
        return true;
    }
    if (current_parent_height == 0) {
        error = "ECX pending source backlog has no authenticated parent height";
        return false;
    }
    if (previous_pending == 0) {
        next_oldest_parent_height = current_parent_height;
    } else {
        if (previous_oldest_parent_height == 0 ||
            previous_oldest_parent_height > current_parent_height) {
            error = "ECX prior backlog age commitment is missing or invalid";
            return false;
        }
        next_oldest_parent_height = previous_oldest_parent_height;
    }
    if (next_oldest_parent_height >
            std::numeric_limits<uint64_t>::max() - FORCED_INCLUSION_BLOCKS ||
        current_parent_height >=
            next_oldest_parent_height + FORCED_INCLUSION_BLOCKS) {
        error = "ECX source backlog exceeded the forced-inclusion deadline";
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
    uint32_t forced_order_work{0};
    std::vector<uint8_t> forced_kinds;

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
            forced_kinds.push_back(forced->second.kind);
            if (!ComputeForcedTrancheOrderWork(
                    forced_kinds, forced_order_work, error)) {
                error = "ECX forced-action source tranche is overweight: " + error;
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
    uint64_t& next_forced_cursor,
    uint64_t& next_deposit_cursor,
    uint64_t& next_oldest_parent_height,
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
        if (!DeriveProcessedCursors(
                block,
                genesis,
                next,
                0,
                0,
                next_forced_cursor,
                next_deposit_cursor,
                error) ||
            !ValidateInboxLiveness(
                forced_genesis,
                deposit_genesis,
                next_forced,
                next_deposits,
                0,
                0,
                next_forced_cursor,
                next_deposit_cursor,
                forced_appends,
                deposit_appends,
                0,
                authenticated_parent_height.value_or(0),
                next_oldest_parent_height,
                error)) {
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
        (static_cast<uint32_t>(previous_index->nVersion) &
         CBlockHeader::INBOX_CURSOR_HF_MASK) == 0 ||
        previous_index->hashForcedInboxRoot != previous_forced.root ||
        previous_index->hashDepositInboxRoot != previous_deposits.root) {
        error = "persisted ECX inbox trackers disagree with the prior header roots";
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
            previous_forced,
            previous_deposits,
            next_forced,
            next_deposits,
            &forced_appends,
            &deposit_appends,
            error) ||
        !DeriveProcessedCursors(
            block,
            previous,
            next,
            previous_index->forcedProcessedCursor,
            previous_index->depositProcessedCursor,
            next_forced_cursor,
            next_deposit_cursor,
            error)) {
        return false;
    }
    return ValidateInboxLiveness(
        previous_forced,
        previous_deposits,
        next_forced,
        next_deposits,
        previous_index->forcedProcessedCursor,
        previous_index->depositProcessedCursor,
        next_forced_cursor,
        next_deposit_cursor,
        forced_appends,
        deposit_appends,
        previous_index->sourceBacklogOldestParentHeight,
        authenticated_parent_height.value_or(0),
        next_oldest_parent_height,
        error);
}

} // namespace

bool ComputeBondV2FiniteStateScript(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash,
    CScript& script)
{
    return ComputeBondV2GenesisScript(consensus, covenant_state_hash, script);
}

bool ComputeBondV2IncrementalSuccessorScript(
    const ExchangeConsensus& consensus,
    const uint256& successor_state_root,
    CScript& script)
{
    const auto& frozen{consensus.bond_v2};
    if (successor_state_root.IsNull() ||
        frozen.incremental_successor_transition_cmr.IsNull() ||
        frozen.incremental_successor_state_node_domain_sha256.IsNull()) {
        return false;
    }
    std::vector<unsigned char> state_preimage;
    state_preimage.reserve(64);
    AppendHash(state_preimage, frozen.incremental_successor_state_node_domain_sha256);
    AppendHash(state_preimage, successor_state_root);
    const uint256 state_node{Sha256(state_preimage)};

    std::vector<unsigned char> leaf_preimage;
    leaf_preimage.reserve(34);
    leaf_preimage.push_back(TAPROOT_LEAF_TAPSIMPLICITY);
    leaf_preimage.push_back(32);
    AppendHash(leaf_preimage, frozen.incremental_successor_transition_cmr);
    const uint256 transition_leaf{TaggedHash("TapLeaf/elements", leaf_preimage)};

    std::vector<unsigned char> branch_preimage;
    branch_preimage.reserve(64);
    if (TapNodeHashLess(transition_leaf, state_node)) {
        AppendHash(branch_preimage, transition_leaf);
        AppendHash(branch_preimage, state_node);
    } else {
        AppendHash(branch_preimage, state_node);
        AppendHash(branch_preimage, transition_leaf);
    }
    const uint256 root{TaggedHash("TapBranch/elements", branch_preimage)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        frozen.keyless_internal_key.data(), frozen.keyless_internal_key.size())};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return false;
    script.clear();
    script << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
    return true;
}

bool ValidateBondV2FrozenConfigurationV18(
    const std::vector<unsigned char>& canonical_bytes,
    uint256& configuration_hash,
    std::string& error)
{
    DecodedFrozenConfigurationV18 decoded;
    if (!DecodeFrozenConfigurationV18(canonical_bytes, decoded, error)) {
        configuration_hash.SetNull();
        return false;
    }
    configuration_hash = TaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        canonical_bytes);
    return true;
}

bool ComputeForcedTrancheOrderWork(
    const std::vector<uint8_t>& kinds,
    uint32_t& order_work,
    std::string& error)
{
    order_work = 0;
    error.clear();
    for (const uint8_t kind : kinds) {
        uint32_t action_work{0};
        switch (kind) {
        case 0:
            action_work = 1;
            break;
        case 1:
            action_work = MAX_FORCED_TRANCHE_ORDER_WORK;
            break;
        case 2:
            break;
        default:
            error = "unknown ECX forced-action kind";
            return false;
        }
        if (action_work > MAX_FORCED_TRANCHE_ORDER_WORK - order_work) {
            error = "parent-height tranche exceeds the 64-operation budget";
            return false;
        }
        order_work += action_work;
    }
    return true;
}

uint256 BondInboxGenesisHead(const ExchangeConsensus& consensus)
{
    return ComputeBondInboxGenesisRoot(consensus);
}

uint256 IncrementalSuccessorBondInboxGenesisHead(
    const ExchangeConsensus& consensus)
{
    std::vector<unsigned char> preimage;
    preimage.reserve(96);
    AppendHash(preimage, consensus.bond_v2.bond_inbox_domain);
    preimage.insert(
        preimage.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    AppendHash(preimage, consensus.bond_v2.configuration_hash);
    return TaggedHash("ECX/successor-bond-inbox-genesis/v2-u128", preimage);
}

bool RenderBondInboxStagingV18(
    const uint256& marker_signer,
    const uint256& stable_intent_id,
    uint32_t staging_vout,
    const uint256& refund_script_sha256,
    uint64_t refund_not_before_parent_height,
    BondInboxStagingRenderV18& rendered,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    rendered = {};
    const auto& frozen{consensus.bond_v2};
    if (frozen.configuration_hash.IsNull() ||
        frozen.bond_inbox_redemption_staging_template_commitment.IsNull() ||
        frozen.bond_inbox_redemption_staging_renderer_domain.IsNull() ||
        !IsEcxStagingRendererDomainV18(
            frozen.bond_inbox_redemption_staging_renderer_domain.begin()) ||
        !IsEcxNumsInternalKey(
            frozen.bond_inbox_redemption_staging_internal_key.begin()) ||
        frozen.bond_inbox_redemption_staging_tapleaf_version !=
            TAPROOT_LEAF_TAPSIMPLICITY ||
        frozen.bond_inbox_redemption_staging_process_cmr.IsNull() ||
        frozen.bond_inbox_redemption_staging_refund_cmr.IsNull() ||
        frozen.bond_inbox_redemption_staging_process_cmr ==
            frozen.bond_inbox_redemption_staging_refund_cmr ||
        marker_signer.IsNull() ||
        !XOnlyPubKey(Span<const unsigned char>(
            marker_signer.begin(), 32)).IsFullyValid() ||
        stable_intent_id.IsNull() || staging_vout == UINT32_MAX ||
        refund_script_sha256.IsNull() ||
        refund_not_before_parent_height == 0 ||
        IsZero(consensus.chain_id)) {
        error = "ECX V18 staging renderer inputs or frozen identity are invalid";
        return false;
    }

    std::vector<unsigned char> hidden_preimage;
    hidden_preimage.reserve(205);
    AppendHash(
        hidden_preimage,
        frozen.bond_inbox_redemption_staging_renderer_domain);
    hidden_preimage.insert(
        hidden_preimage.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    AppendHash(hidden_preimage, frozen.configuration_hash);
    AppendHash(hidden_preimage, marker_signer);
    AppendHash(hidden_preimage, stable_intent_id);
    PushU32Be(hidden_preimage, staging_vout);
    AppendHash(hidden_preimage, refund_script_sha256);
    PushU64Be(hidden_preimage, refund_not_before_parent_height);
    if (hidden_preimage.size() != 204) {
        error = "ECX V18 staging hidden-node preimage has the wrong length";
        return false;
    }
    rendered.hidden_node_hash = TaggedHash(
        "ECX/bond-inbox-redemption-staging-hidden-node/v3-no-history",
        hidden_preimage);

    std::vector<unsigned char> process_leaf_payload{
        frozen.bond_inbox_redemption_staging_tapleaf_version, 32};
    AppendHash(
        process_leaf_payload,
        frozen.bond_inbox_redemption_staging_process_cmr);
    std::vector<unsigned char> refund_leaf_payload{
        frozen.bond_inbox_redemption_staging_tapleaf_version, 32};
    AppendHash(
        refund_leaf_payload,
        frozen.bond_inbox_redemption_staging_refund_cmr);
    rendered.process_leaf_hash =
        TaggedHash("TapLeaf/elements", process_leaf_payload);
    rendered.refund_leaf_hash =
        TaggedHash("TapLeaf/elements", refund_leaf_payload);

    const auto tap_branch = [](const uint256& first, const uint256& second) {
        std::vector<unsigned char> branch;
        branch.reserve(64);
        if (TapNodeHashLess(first, second)) {
            AppendHash(branch, first);
            AppendHash(branch, second);
        } else {
            AppendHash(branch, second);
            AppendHash(branch, first);
        }
        return TaggedHash("TapBranch/elements", branch);
    };
    rendered.lower_branch_hash = tap_branch(
        rendered.refund_leaf_hash, rendered.hidden_node_hash);
    rendered.top_branch_hash = tap_branch(
        rendered.process_leaf_hash, rendered.lower_branch_hash);

    const XOnlyPubKey internal{Span<const unsigned char>(
        frozen.bond_inbox_redemption_staging_internal_key.begin(), 32)};
    const auto tweaked{internal.CreateTapTweak(&rendered.top_branch_hash)};
    if (!tweaked) {
        error = "ECX V18 staging descriptor cannot be rendered";
        rendered = {};
        return false;
    }
    rendered.script_pubkey << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
    if (rendered.script_pubkey.size() != 34 ||
        rendered.script_pubkey[0] != OP_1 || rendered.script_pubkey[1] != 32) {
        error = "ECX V18 staging renderer produced a noncanonical P2TR output";
        rendered = {};
        return false;
    }
    return true;
}

static bool IsCanonicalBondInboxSourceTransactionForProfile(
    const CTransaction& transaction,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool successor)
{
    error.clear();
    const auto& frozen{consensus.bond_v2};
    if (!frozen.activation_enabled || !frozen.identities_frozen ||
        frozen.configuration_hash.IsNull() || frozen.availability_scheme_hash.IsNull() ||
        frozen.availability_custodian_registry_hash.IsNull() ||
        frozen.bond_inbox_max_bundle_bytes != 64 * 1024 ||
        frozen.bond_inbox_max_entries_per_sidechain_block != 8 ||
        frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block !=
            576 * 1024 ||
        frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block !=
            768 * 1024) {
        error = "ECX bond-inbox relay profile is not frozen";
        return false;
    }
    if (transaction.IsCoinBase() || transaction.vin.empty() ||
        transaction.vout.empty() || !transaction.HasWitness() ||
        std::any_of(
            transaction.vin.begin(), transaction.vin.end(),
            [](const CTxIn& input) {
                return input.m_is_pegin || !input.assetIssuance.IsNull();
            })) {
        error = "ECX bond-inbox source transaction has an invalid input/output/witness form";
        return false;
    }

    CDataStream transaction_stream(SER_NETWORK, PROTOCOL_VERSION);
    transaction_stream << transaction;
    if (transaction_stream.size() == 0 ||
        transaction_stream.size() >
            frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block) {
        error = "ECX bond-inbox source transaction exceeds its frozen exact byte cap";
        return false;
    }
    CDataStream witness_stream(SER_NETWORK, PROTOCOL_VERSION);
    witness_stream << transaction.witness;
    if (witness_stream.size() == 0 ||
        witness_stream.size() >
            frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block) {
        error = "ECX bond-inbox source witness exceeds its frozen exact byte cap";
        return false;
    }

    std::vector<uint256> action_ids;
    size_t marker_count{0};
    for (size_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
        const CTxOut& output{transaction.vout[output_index]};
        if (output.scriptPubKey.empty() || output.scriptPubKey[0] != OP_RETURN) continue;
        ParsedBondInboxMarker marker;
        if (!ParseCanonicalBondInboxMarker(
                output.scriptPubKey, marker, error, consensus, true, successor)) return false;
        if (!output.nAsset.IsExplicit() ||
            output.nAsset.GetAsset() != ::policyAsset ||
            !output.nValue.IsExplicit() || output.nValue.GetAmount() != 0 ||
            !output.nNonce.IsNull() || !IsNullOutputWitness(transaction, output_index)) {
            error = "ECX bond-inbox marker output envelope is noncanonical";
            return false;
        }
        ++marker_count;
        if (marker_count > frozen.bond_inbox_max_entries_per_sidechain_block ||
            std::find(action_ids.begin(), action_ids.end(), marker.action_id) !=
                action_ids.end()) {
            error = "ECX bond-inbox source has too many or duplicate markers";
            return false;
        }
        action_ids.push_back(marker.action_id);

        uint256 expected_source_authorization;
        if (marker.kind == 1) {
            if (marker.staging_vout >= transaction.vout.size() ||
                marker.staging_vout == output_index) {
                error = "ECX bond-inbox staging output index is invalid";
                return false;
            }
            const CTxOut& staging{transaction.vout[marker.staging_vout]};
            BondInboxStagingRenderV18 rendered;
            if (!RenderBondInboxStagingV18(
                    marker.signer,
                    marker.staging_intent_id,
                    marker.staging_vout,
                    marker.refund_script_sha256,
                    marker.refund_not_before_parent_height,
                    rendered,
                    error,
                    consensus)) {
                return false;
            }
            if (staging.scriptPubKey != rendered.script_pubkey ||
                staging.scriptPubKey.IsUnspendable() ||
                !staging.nAsset.IsCommitment() ||
                !staging.nValue.IsCommitment() ||
                !staging.nNonce.IsCommitment() ||
                marker.staging_vout >= transaction.witness.vtxoutwit.size() ||
                transaction.witness.vtxoutwit[marker.staging_vout]
                    .vchSurjectionproof.empty() ||
                transaction.witness.vtxoutwit[marker.staging_vout]
                    .vchRangeproof.empty()) {
                error = "ECX bond-inbox staging output is not the exact confidential frozen descriptor form";
                return false;
            }
            CDataStream staging_stream(SER_NETWORK, PROTOCOL_VERSION);
            staging_stream << staging;
            if (staging_stream.size() == 0 ||
                staging_stream.size() > frozen.bond_inbox_max_bundle_bytes) {
                error = "ECX bond-inbox staging output serialization is invalid";
                return false;
            }
            std::vector<unsigned char> authorization;
            PushU32Be(authorization, staging_stream.size());
            authorization.insert(
                authorization.end(), UCharCast(staging_stream.data()),
                UCharCast(staging_stream.data()) + staging_stream.size());
            AppendHash(authorization, marker.staging_intent_id);
            AppendHash(authorization, marker.refund_script_sha256);
            PushU64Be(authorization, marker.refund_not_before_parent_height);
            expected_source_authorization = TaggedHash(
                successor
                    ? "ECX/successor-bond-inbox-staging-source-authorization/v2-u128"
                    : "ECX/bond-inbox-staging-source-authorization/v2",
                authorization);
        } else {
            std::vector<unsigned char> authorization;
            authorization.insert(
                authorization.end(), consensus.chain_id.begin(), consensus.chain_id.end());
            AppendHash(authorization, frozen.configuration_hash);
            AppendHash(authorization, marker.signer);
            AppendHash(authorization, marker.action_id);
            PushU32Be(authorization, output_index);
            expected_source_authorization = TaggedHash(
                successor
                    ? "ECX/successor-bond-inbox-no-staging-source-authorization/v2-u128"
                    : "ECX/bond-inbox-no-staging-source-authorization/v2",
                authorization);
        }
        if (expected_source_authorization != marker.source_authorization_commitment) {
            error = "ECX bond-inbox marker source authorization is invalid";
            return false;
        }
        if (!VerifyBondInboxMarkerSourceWitness(
                transaction, marker, error, consensus, successor)) {
            return false;
        }
    }
    if (marker_count != 1) {
        error = "ECX bond-inbox source transaction must contain exactly one marker";
        return false;
    }
    return true;
}

bool IsCanonicalBondInboxSourceTransaction(
    const CTransaction& transaction,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    return IsCanonicalBondInboxSourceTransactionForProfile(
        transaction, error, consensus, false);
}

bool AppendBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::vector<BondInboxSourceExport>* exported_entries)
{
    error.clear();
    if (sidechain_height == 0 || observed_parent_height == 0 ||
        snapshot.node_bond_inbox_head_root.IsNull() ||
        snapshot.node_bond_inbox_entry_count < snapshot.bond_inbox_entry_count) {
        error = "ECX bond-inbox source tracker has no canonical predecessor";
        return false;
    }
    const std::array<unsigned char, 4> magic{{'E', 'C', 'X', 'B'}};
    uint32_t marker_count{0};
    uint32_t aggregate_witness_bytes{0};
    uint32_t aggregate_transaction_bytes{0};
    std::map<uint256, std::tuple<uint256, uint32_t, uint256, uint32_t>> unique_sources;
    uint256 head{snapshot.node_bond_inbox_head_root};
    uint64_t count{0};
    if (!snapshot.node_bond_inbox_entry_count.ToU64(count)) {
        error = "finite ECX bond-inbox source tracker exceeds its u64 wire";
        return false;
    }
    const uint256 block_hash{block.GetHash()};

    for (size_t transaction_index = 0; transaction_index < block.vtx.size(); ++transaction_index) {
        const CTransaction& transaction{*block.vtx[transaction_index]};
        const bool contains_marker = std::any_of(
            transaction.vout.begin(), transaction.vout.end(),
            [&](const CTxOut& output) {
                return ScriptContainsMagic(output.scriptPubKey, magic);
            });
        if (!contains_marker) continue;
        if (!IsCanonicalBondInboxSourceTransaction(
                transaction, error, consensus)) {
            error = "invalid ECX bond-inbox source transaction: " + error;
            return false;
        }

        CDataStream transaction_stream(SER_NETWORK, PROTOCOL_VERSION);
        transaction_stream << transaction;
        CDataStream witness_stream(SER_NETWORK, PROTOCOL_VERSION);
        witness_stream << transaction.witness;
        if (transaction_stream.size() > UINT32_MAX || witness_stream.size() > UINT32_MAX) {
            error = "ECX bond-inbox source serialization length overflows u32";
            return false;
        }
        const uint32_t transaction_len{static_cast<uint32_t>(transaction_stream.size())};
        const uint32_t witness_len{static_cast<uint32_t>(witness_stream.size())};
        const uint256 txid{transaction.GetHash()};
        const uint256 wtxid{transaction.GetWitnessHash()};
        const uint256 witness_sha256{Sha256({
            UCharCast(witness_stream.data()),
            UCharCast(witness_stream.data()) + witness_stream.size()})};
        const auto source_facts{std::make_tuple(
            txid, transaction_len, witness_sha256, witness_len)};
        const auto [source, inserted]{unique_sources.emplace(wtxid, source_facts)};
        if (!inserted && source->second != source_facts) {
            error = "ECX bond-inbox duplicate wtxid has inconsistent source facts";
            return false;
        }
        if (inserted) {
            if (aggregate_witness_bytes > UINT32_MAX - witness_len ||
                aggregate_transaction_bytes > UINT32_MAX - transaction_len) {
                error = "ECX bond-inbox block source byte accounting overflowed";
                return false;
            }
            aggregate_witness_bytes += witness_len;
            aggregate_transaction_bytes += transaction_len;
            if (aggregate_witness_bytes > consensus.bond_v2
                    .bond_inbox_max_unique_source_witness_bytes_per_sidechain_block ||
                aggregate_transaction_bytes > consensus.bond_v2
                    .bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block) {
                error = "ECX bond-inbox block exceeds deduplicated source byte caps";
                return false;
            }
        }

        for (size_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
            const CScript& script{transaction.vout[output_index].scriptPubKey};
            if (!ScriptContainsMagic(script, magic)) continue;
            ParsedBondInboxMarker marker;
            if (!ParseCanonicalBondInboxMarker(
                    script, marker, error, consensus, true, false)) return false;
            if (observed_parent_height >
                UINT64_MAX - consensus.bond_v2.bond_inbox_inclusion_blocks) {
                error = "ECX bond-inbox process deadline overflows u64";
                return false;
            }
            const uint64_t process_deadline_parent_height{
                observed_parent_height +
                consensus.bond_v2.bond_inbox_inclusion_blocks};
            if (marker.kind == 1 &&
                (observed_parent_height >
                        UINT64_MAX - consensus.bond_v2
                            .bond_inbox_refund_minimum_parent_blocks ||
                 marker.refund_not_before_parent_height <
                    observed_parent_height + consensus.bond_v2
                        .bond_inbox_refund_minimum_parent_blocks)) {
                error =
                    "ECX bond-inbox enqueue refund boundary is earlier than "
                    "the frozen observed-parent delay";
                return false;
            }
            if (marker_count == consensus.bond_v2
                    .bond_inbox_max_entries_per_sidechain_block ||
                count == UINT64_MAX || transaction_index > UINT32_MAX ||
                output_index > UINT32_MAX) {
                error = "ECX bond-inbox block exceeds its marker/index bounds";
                return false;
            }
            ++marker_count;

            CScript::const_iterator script_cursor{script.begin()};
            opcodetype opcode;
            std::vector<unsigned char> marker_payload;
            if (!script.GetOp(script_cursor, opcode) || opcode != OP_RETURN ||
                !script.GetOp(script_cursor, opcode, marker_payload) ||
                opcode != OP_PUSHDATA2 || marker_payload.size() != 503 ||
                script_cursor != script.end()) {
                error = "ECX bond-inbox marker changed after source verification";
                return false;
            }

            std::vector<unsigned char> entry;
            entry.reserve(700);
            entry.push_back(1);
            PushU64Be(entry, count);
            AppendHash(entry, head);
            PushU64Be(entry, sidechain_height);
            PushU64Be(entry, observed_parent_height);
            AppendHash(entry, block_hash);
            AppendHash(entry, txid);
            AppendHash(entry, wtxid);
            PushU32Be(entry, transaction_len);
            AppendHash(entry, witness_sha256);
            PushU32Be(entry, witness_len);
            PushU32Be(entry, transaction_index);
            PushU32Be(entry, output_index);
            entry.insert(entry.end(), marker_payload.begin() + 4, marker_payload.end());
            if (entry.size() != 700) {
                error = "ECX bond-inbox node entry encoding length is not canonical";
                return false;
            }
            if (exported_entries != nullptr) {
                BondInboxSourceExport exported;
                exported.proof_profile = 0;
                exported.entry_index = count;
                exported.entry_index_u128 = count;
                exported.sidechain_height = sidechain_height;
                exported.observed_parent_height = observed_parent_height;
                exported.process_deadline_parent_height =
                    process_deadline_parent_height;
                exported.refund_not_before_parent_height = marker.kind == 1
                    ? marker.refund_not_before_parent_height
                    : 0;
                exported.marker_kind = marker.kind;
                exported.action_id = marker.action_id;
                exported.source_transaction_index =
                    static_cast<uint32_t>(transaction_index);
                exported.marker_vout = static_cast<uint32_t>(output_index);
                exported.source_txid = txid;
                exported.source_wtxid = wtxid;
                exported.canonical_entry = entry;
                exported.source_transaction.assign(
                    UCharCast(transaction_stream.data()),
                    UCharCast(transaction_stream.data()) +
                        transaction_stream.size());
                exported_entries->push_back(std::move(exported));
            }
            const uint256 entry_hash{TaggedHash("ECX/bond-inbox-entry/v2", entry)};
            std::vector<unsigned char> step;
            step.reserve(72);
            AppendHash(step, head);
            PushU64Be(step, count);
            AppendHash(step, entry_hash);
            head = TaggedHash("ECX/bond-inbox-step/v2", step);
            ++count;
        }
    }
    snapshot.node_bond_inbox_head_root = head;
    snapshot.node_bond_inbox_entry_count = count;
    return true;
}

bool AppendIncrementalSuccessorBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::vector<BondInboxSourceExport>* exported_entries)
{
    error.clear();
    if (snapshot.proof_profile != 1 || sidechain_height == 0 ||
        observed_parent_height == 0 ||
        snapshot.node_bond_inbox_head_root.IsNull() ||
        snapshot.node_bond_inbox_entry_count < snapshot.bond_inbox_entry_count) {
        error = "ECX successor bond-inbox source tracker has no canonical predecessor";
        return false;
    }
    const std::array<unsigned char, 4> magic{{'E', 'C', 'X', 'B'}};
    uint32_t marker_count{0};
    uint32_t aggregate_witness_bytes{0};
    uint32_t aggregate_transaction_bytes{0};
    std::map<uint256, std::tuple<uint256, uint32_t, uint256, uint32_t>> unique_sources;
    uint256 head{snapshot.node_bond_inbox_head_root};
    BigEndianUint128 count{snapshot.node_bond_inbox_entry_count};
    const uint256 block_hash{block.GetHash()};

    for (size_t transaction_index = 0; transaction_index < block.vtx.size();
         ++transaction_index) {
        const CTransaction& transaction{*block.vtx[transaction_index]};
        const bool contains_marker = std::any_of(
            transaction.vout.begin(), transaction.vout.end(),
            [&](const CTxOut& output) {
                return ScriptContainsMagic(output.scriptPubKey, magic);
            });
        if (!contains_marker) continue;
        if (!IsCanonicalBondInboxSourceTransactionForProfile(
                transaction, error, consensus, true)) {
            error = "invalid ECX successor bond-inbox source transaction: " + error;
            return false;
        }

        CDataStream transaction_stream(SER_NETWORK, PROTOCOL_VERSION);
        transaction_stream << transaction;
        CDataStream witness_stream(SER_NETWORK, PROTOCOL_VERSION);
        witness_stream << transaction.witness;
        if (transaction_stream.size() > UINT32_MAX ||
            witness_stream.size() > UINT32_MAX) {
            error = "ECX successor bond-inbox source serialization length overflows u32";
            return false;
        }
        const uint32_t transaction_len{static_cast<uint32_t>(transaction_stream.size())};
        const uint32_t witness_len{static_cast<uint32_t>(witness_stream.size())};
        const uint256 txid{transaction.GetHash()};
        const uint256 wtxid{transaction.GetWitnessHash()};
        const uint256 witness_sha256{Sha256({
            UCharCast(witness_stream.data()),
            UCharCast(witness_stream.data()) + witness_stream.size()})};
        const auto source_facts{std::make_tuple(
            txid, transaction_len, witness_sha256, witness_len)};
        const auto [source, inserted]{unique_sources.emplace(wtxid, source_facts)};
        if (!inserted && source->second != source_facts) {
            error = "ECX successor bond-inbox duplicate wtxid has inconsistent source facts";
            return false;
        }
        if (inserted) {
            if (aggregate_witness_bytes > UINT32_MAX - witness_len ||
                aggregate_transaction_bytes > UINT32_MAX - transaction_len) {
                error = "ECX successor bond-inbox block source byte accounting overflowed";
                return false;
            }
            aggregate_witness_bytes += witness_len;
            aggregate_transaction_bytes += transaction_len;
            if (aggregate_witness_bytes > consensus.bond_v2
                    .bond_inbox_max_unique_source_witness_bytes_per_sidechain_block ||
                aggregate_transaction_bytes > consensus.bond_v2
                    .bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block) {
                error = "ECX successor bond-inbox block exceeds source byte caps";
                return false;
            }
        }

        for (size_t output_index = 0; output_index < transaction.vout.size();
             ++output_index) {
            const CScript& script{transaction.vout[output_index].scriptPubKey};
            if (!ScriptContainsMagic(script, magic)) continue;
            ParsedBondInboxMarker marker;
            if (!ParseCanonicalBondInboxMarker(
                    script, marker, error, consensus, true, true)) return false;
            if (observed_parent_height >
                UINT64_MAX - consensus.bond_v2.bond_inbox_inclusion_blocks) {
                error = "ECX successor bond-inbox process deadline overflows u64";
                return false;
            }
            const uint64_t process_deadline_parent_height{
                observed_parent_height + consensus.bond_v2.bond_inbox_inclusion_blocks};
            if (marker.kind == 1 &&
                (observed_parent_height > UINT64_MAX - consensus.bond_v2
                        .bond_inbox_refund_minimum_parent_blocks ||
                 marker.refund_not_before_parent_height < observed_parent_height +
                        consensus.bond_v2.bond_inbox_refund_minimum_parent_blocks)) {
                error = "ECX successor bond-inbox enqueue refund boundary is too early";
                return false;
            }
            if (marker_count == consensus.bond_v2
                    .bond_inbox_max_entries_per_sidechain_block ||
                transaction_index > UINT32_MAX || output_index > UINT32_MAX) {
                error = "ECX successor bond-inbox block exceeds marker/index bounds";
                return false;
            }
            ++marker_count;

            CScript::const_iterator script_cursor{script.begin()};
            opcodetype opcode;
            std::vector<unsigned char> marker_payload;
            if (!script.GetOp(script_cursor, opcode) || opcode != OP_RETURN ||
                !script.GetOp(script_cursor, opcode, marker_payload) ||
                opcode != OP_PUSHDATA2 || marker_payload.size() != 503 ||
                script_cursor != script.end()) {
                error = "ECX successor bond-inbox marker changed after source verification";
                return false;
            }

            std::vector<unsigned char> entry;
            entry.reserve(708);
            entry.push_back(2);
            entry.insert(entry.end(), count.bytes.begin(), count.bytes.end());
            AppendHash(entry, head);
            PushU64Be(entry, sidechain_height);
            PushU64Be(entry, observed_parent_height);
            AppendHash(entry, block_hash);
            AppendHash(entry, txid);
            AppendHash(entry, wtxid);
            PushU32Be(entry, transaction_len);
            AppendHash(entry, witness_sha256);
            PushU32Be(entry, witness_len);
            PushU32Be(entry, transaction_index);
            PushU32Be(entry, output_index);
            entry.insert(entry.end(), marker_payload.begin() + 4, marker_payload.end());
            if (entry.size() != 708) {
                error = "ECX successor bond-inbox node entry encoding length is not canonical";
                return false;
            }
            if (exported_entries != nullptr) {
                BondInboxSourceExport exported;
                exported.proof_profile = 1;
                exported.entry_index_u128 = count;
                count.ToU64(exported.entry_index);
                exported.sidechain_height = sidechain_height;
                exported.observed_parent_height = observed_parent_height;
                exported.process_deadline_parent_height = process_deadline_parent_height;
                exported.refund_not_before_parent_height = marker.kind == 1
                    ? marker.refund_not_before_parent_height
                    : 0;
                exported.marker_kind = marker.kind;
                exported.action_id = marker.action_id;
                exported.source_transaction_index =
                    static_cast<uint32_t>(transaction_index);
                exported.marker_vout = static_cast<uint32_t>(output_index);
                exported.source_txid = txid;
                exported.source_wtxid = wtxid;
                exported.canonical_entry = entry;
                exported.source_transaction.assign(
                    UCharCast(transaction_stream.data()),
                    UCharCast(transaction_stream.data()) + transaction_stream.size());
                exported_entries->push_back(std::move(exported));
            }
            const uint256 entry_hash{TaggedHash(
                "ECX/successor-bond-inbox-entry/v2-u128", entry)};
            std::vector<unsigned char> step;
            step.reserve(80);
            AppendHash(step, head);
            step.insert(step.end(), count.bytes.begin(), count.bytes.end());
            AppendHash(step, entry_hash);
            head = TaggedHash("ECX/successor-bond-inbox-step/v2-u128", step);
            if (!count.Increment()) {
                error = "ECX successor bond-inbox entry count overflows u128";
                return false;
            }
        }
    }
    snapshot.node_bond_inbox_head_root = head;
    snapshot.node_bond_inbox_entry_count = count;
    return true;
}

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

uint256 ComputeRuntimeConsensusFingerprint(
    const ExchangeConsensus& consensus,
    const std::string& network_id,
    const uint256& genesis_hash,
    const uint256& policy_asset,
    const uint256& bmm_consensus_fingerprint,
    const bool private_bmm_enabled,
    const uint32_t private_bmm_activation_height)
{
    std::vector<unsigned char> payload;
    payload.reserve(512 + network_id.size() + consensus.collateral_vault_script.size());
    const auto push_bytes = [&payload](const unsigned char* data, const size_t size) {
        PushU64Be(payload, size);
        payload.insert(payload.end(), data, data + size);
    };
    const auto push_outpoint = [&payload](const COutPoint& outpoint) {
        payload.insert(payload.end(), outpoint.hash.begin(), outpoint.hash.end());
        PushU32Be(payload, outpoint.n);
    };

    PushU32Be(payload, 9);
    PushU32Be(payload, ECX_CONSENSUS_RULESET_REVISION);
    PushU32Be(payload, EXCHANGE_STATE_INTERFACE_VERSION);
    PushU32Be(payload, EXCHANGE_SCRIPT_CACHE_REVISION);
    PushU32Be(payload, CBlockHeader::BMM_PROOF_HF_MASK);
    PushU32Be(payload, CBlockHeader::EXCHANGE_STATE_HF_MASK);
    PushU32Be(payload, CBlockHeader::FORCED_INBOX_HF_MASK);
    PushU32Be(payload, CBlockHeader::DEPOSIT_INBOX_HF_MASK);
    PushU32Be(payload, CBlockHeader::INBOX_CURSOR_HF_MASK);
    PushU32Be(payload, FORCED_INCLUSION_BLOCKS);
    PushU64Be(payload, MAX_COMBINED_UNCONSUMED);
    PushU64Be(payload, MAX_COMBINED_SAME_PARENT_APPENDS);
    PushU64Be(payload, MAX_COMBINED_PENDING_WITNESS_ENTRIES);
    PushU64Be(payload, MAX_FORCED_TRANCHE_ORDER_WORK);
    PushU64Be(payload, 1); // cancel
    PushU64Be(payload, MAX_FORCED_TRANCHE_ORDER_WORK); // reduce-only IOC
    PushU64Be(payload, 0); // withdrawal
    PushU64Be(payload, FORCED_CANCEL_BODY_SIZE);
    PushU64Be(payload, FORCED_LIMIT_BODY_SIZE);
    PushU64Be(payload, FORCED_WITHDRAW_BODY_SIZE);
    PushU64Be(payload, DEPOSIT_PAYLOAD_SIZE);
    push_outpoint(EXCHANGE_TRACKER_OUTPOINT);
    push_outpoint(FORCED_INBOX_TRACKER_OUTPOINT);
    push_outpoint(DEPOSIT_INBOX_TRACKER_OUTPOINT);
    push_bytes(EXCHANGE_TRACKER_MARKER.data(), EXCHANGE_TRACKER_MARKER.size());
    push_bytes(FORCED_INBOX_TRACKER_MARKER.data(), FORCED_INBOX_TRACKER_MARKER.size());
    push_bytes(DEPOSIT_INBOX_TRACKER_MARKER.data(), DEPOSIT_INBOX_TRACKER_MARKER.size());
    push_bytes(FORCED_MAGIC.data(), FORCED_MAGIC.size());
    push_bytes(DEPOSIT_MAGIC.data(), DEPOSIT_MAGIC.size());
    push_bytes(ECX_USDD_MARKET.data(), ECX_USDD_MARKET.size());
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
    payload.push_back(1);
#else
    payload.push_back(0);
#endif
#ifdef ECX_SIMPLICITY_CATALOGUE_FROZEN
    payload.push_back(1);
#else
    payload.push_back(0);
#endif
#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
    payload.push_back(1);
    const std::vector<unsigned char> release_record_hash{
        ParseHex(ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX)};
    payload.insert(
        payload.end(), release_record_hash.begin(), release_record_hash.end());
#else
    payload.push_back(0);
    payload.insert(payload.end(), 32, 0);
#endif
    PushU32Be(payload, static_cast<uint32_t>(network_id.size()));
    payload.insert(payload.end(), network_id.begin(), network_id.end());
    payload.insert(payload.end(), genesis_hash.begin(), genesis_hash.end());
    payload.insert(payload.end(), policy_asset.begin(), policy_asset.end());
    payload.insert(
        payload.end(),
        bmm_consensus_fingerprint.begin(),
        bmm_consensus_fingerprint.end());
    PushU32Be(payload, static_cast<uint32_t>(consensus.activation_height));
    payload.insert(
        payload.end(),
        consensus.genesis_state_outpoint.hash.begin(),
        consensus.genesis_state_outpoint.hash.end());
    PushU32Be(payload, consensus.genesis_state_outpoint.n);
    payload.insert(
        payload.end(),
        consensus.genesis_state_root.begin(),
        consensus.genesis_state_root.end());
    payload.insert(payload.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    payload.insert(
        payload.end(),
        consensus.forced_action_domain.begin(),
        consensus.forced_action_domain.end());
    payload.insert(
        payload.end(),
        consensus.deposit_inbox_domain.begin(),
        consensus.deposit_inbox_domain.end());
    PushU32Be(
        payload,
        static_cast<uint32_t>(consensus.collateral_vault_script.size()));
    payload.insert(
        payload.end(),
        consensus.collateral_vault_script.begin(),
        consensus.collateral_vault_script.end());
    payload.insert(
        payload.end(),
        consensus.collateral_vault_script_hash.begin(),
        consensus.collateral_vault_script_hash.end());
    payload.push_back(consensus.bond_v2.activation_enabled ? 1 : 0);
    payload.push_back(consensus.bond_v2.identities_frozen ? 1 : 0);
    const auto append_transaction = [&payload](const CTransactionRef& transaction) {
        if (!transaction) {
            PushU64Be(payload, 0);
            return;
        }
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << *transaction;
        PushU64Be(payload, stream.size());
        payload.insert(
            payload.end(), UCharCast(stream.data()),
            UCharCast(stream.data()) + stream.size());
    };
    append_transaction(consensus.bond_v2.deployment_transaction);
    append_transaction(consensus.bond_v2.genesis_transaction);
    PushU32Be(payload, consensus.bond_v2.issuance_input_index);
    PushU32Be(payload, consensus.bond_v2.inventory_output_index);
    PushU32Be(payload, consensus.bond_v2.reissuance_token_burn_output_index);
    PushU32Be(payload, consensus.bond_v2.state_authority_source_output_index);
    PushU64Be(payload, consensus.bond_v2.canonical_configuration_bytes.size());
    payload.insert(
        payload.end(),
        consensus.bond_v2.canonical_configuration_bytes.begin(),
        consensus.bond_v2.canonical_configuration_bytes.end());
    for (const uint256* identity : {
             &consensus.bond_v2.inventory_asset_blinding_factor,
             &consensus.bond_v2.inventory_value_blinding_factor,
             &consensus.bond_v2.transition_program_id,
             &consensus.bond_v2.configuration_hash,
             &consensus.bond_v2.bond_asset_id,
             &consensus.bond_v2.bond_deployment_commitment,
             &consensus.bond_v2.collateral_vault_covenant_cmr,
             &consensus.bond_v2.inventory_covenant_script_sha256,
             &consensus.bond_v2.reissuance_token_burn_script_sha256,
             &consensus.bond_v2.redemption_queue_script_sha256,
             &consensus.bond_v2.insurance_reserve_script_sha256,
             &consensus.bond_v2.insurance_reserve_covenant_cmr,
             &consensus.bond_v2.state_authority_asset_id,
             &consensus.bond_v2.public_state_domain_sha256,
             &consensus.bond_v2.state_node_domain_sha256,
              &consensus.bond_v2.transition_journal_domain_sha256,
              &consensus.bond_v2.transition_cmr,
              &consensus.bond_v2.incremental_activation_program_id,
              &consensus.bond_v2.incremental_activation_configuration_hash,
              &consensus.bond_v2.incremental_activation_cmr,
              &consensus.bond_v2.incremental_successor_program_id,
              &consensus.bond_v2.incremental_successor_configuration_hash,
              &consensus.bond_v2.incremental_successor_transition_cmr,
              &consensus.bond_v2.incremental_successor_state_node_domain_sha256,
              &consensus.bond_v2.inventory_cmr,
             &consensus.bond_v2.redemption_queue_cmr,
             &consensus.bond_v2.ecx_btc_conversion_program_id,
             &consensus.bond_v2.ecx_btc_redemption_covenant_commitment,
             &consensus.bond_v2.ecx_btc_source_checkpoint_commitment,
             &consensus.bond_v2.usdd_usd_conversion_program_id,
             &consensus.bond_v2.usdd_usd_redemption_covenant_commitment,
             &consensus.bond_v2.usdd_usd_source_checkpoint_commitment,
             &consensus.bond_v2.matcher_genesis_receipt_hash,
             &consensus.bond_v2.order_receipts_genesis_root,
             &consensus.bond_v2.genesis_availability_root,
             &consensus.bond_v2.usdd_asset_id.id,
             &consensus.bond_v2.identity_derivation_record_sha256}) {
        payload.insert(payload.end(), identity->begin(), identity->end());
    }
    payload.insert(
        payload.end(), consensus.bond_v2.keyless_internal_key.begin(),
        consensus.bond_v2.keyless_internal_key.end());
    PushU64Be(payload, consensus.bond_v2.genesis_mark_price);
    payload.push_back(private_bmm_enabled ? 1 : 0);
    PushU32Be(
        payload,
        private_bmm_enabled ? private_bmm_activation_height : 0);
    return TaggedHash("ECX/runtime-consensus-configuration/v8", payload);
}

bool GetRuntimeConsensusFingerprint(
    uint256& fingerprint,
    bool& runtime_configured,
    int& first_activation_height,
    std::string& error)
{
    error.clear();
    runtime_configured = false;
    first_activation_height = std::numeric_limits<int>::max();
    try {
        const ExchangeConsensus& consensus{LayerTwoLabsExchangeConsensus()};
        if (consensus.activation_height != std::numeric_limits<int>::max() &&
            !ConsensusConfigured(consensus, error)) {
            return false;
        }
        const bool private_checkpoint{
            gArgs.GetBoolArg("-ecxprivatebmmcheckpoint", false)};
        const bool private_activation_set{
            gArgs.IsArgSet("-ecxprivatebmmactivationheight")};
#ifndef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        if (private_checkpoint || private_activation_set) {
            error = "private ECX BMM parameters require a private-E2E build";
            return false;
        }
#endif
        if ((private_checkpoint || private_activation_set) &&
            !IsEcxRuntimeTestNetwork()) {
            error = "private ECX BMM parameters are restricted to elementsregtest";
            return false;
        }
        if (private_checkpoint != private_activation_set) {
            error = private_checkpoint
                ? "-ecxprivatebmmcheckpoint requires an explicit "
                  "-ecxprivatebmmactivationheight"
                : "-ecxprivatebmmactivationheight requires "
                  "-ecxprivatebmmcheckpoint=1";
            return false;
        }
        uint32_t private_activation{0};
        if (private_checkpoint) {
            const int64_t value{
                gArgs.GetIntArg("-ecxprivatebmmactivationheight", -1)};
            if (value <= 0 || value >= std::numeric_limits<int>::max()) {
                error = "invalid -ecxprivatebmmactivationheight";
                return false;
            }
            private_activation = static_cast<uint32_t>(value);
        }
        fingerprint = ComputeRuntimeConsensusFingerprint(
            consensus,
            Params().NetworkIDString(),
            Params().GetConsensus().hashGenesisBlock,
            policyAsset.id,
            drivechain::RuntimeBmmConsensusFingerprint(),
            private_checkpoint,
            private_activation);
        runtime_configured =
            consensus.activation_height != std::numeric_limits<int>::max() ||
            private_checkpoint;
        first_activation_height = std::min(
            consensus.activation_height,
            private_checkpoint
                ? static_cast<int>(private_activation)
                : std::numeric_limits<int>::max());
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool HasPersistedExchangeConsensusState(const CCoinsView& view)
{
    Coin coin;
    return (view.GetCoin(EXCHANGE_TRACKER_OUTPOINT, coin) && !coin.IsSpent()) ||
        (view.GetCoin(FORCED_INBOX_TRACKER_OUTPOINT, coin) && !coin.IsSpent()) ||
        (view.GetCoin(DEPOSIT_INBOX_TRACKER_OUTPOINT, coin) && !coin.IsSpent());
}

const ExchangeConsensus& LayerTwoLabsExchangeConsensus()
{
    // Mainnet/signet remain fail-closed until reviewed constants replace the
    // defaults. Regtest can inject a frozen checkpoint at process start for
    // activation, reorg and reindex functional testing.
    static const ExchangeConsensus consensus{LoadExchangeConsensus()};
    return consensus;
}

bool IsCanonicalForcedActionOutput(
    const CTransaction& transaction,
    const size_t output_index,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    if (output_index >= transaction.vout.size()) {
        error = "ECX forced-action output index is out of range";
        return false;
    }
    std::optional<ForcedActionPayload> action;
    if (!ParseForcedOutput(transaction, output_index, consensus, action, error)) {
        return false;
    }
    if (!action.has_value()) {
        error = "output is not a canonical ECX forced action";
        return false;
    }
    return true;
}

bool CheckSourceTransactionPolicy(
    const CTransaction& transaction,
    const int next_height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    bool forced_seen{false};
    bool deposit_seen{false};
    for (size_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
        std::optional<ForcedActionPayload> forced;
        if (!ParseForcedOutput(
                transaction, output_index, consensus, forced, error)) {
            return false;
        }
        if (forced.has_value()) {
            if (forced_seen) {
                error = "an Elements transaction may contain only one ECX forced action";
                return false;
            }
            forced_seen = true;
        }

        std::optional<DepositPayload> deposit;
        if (!ParseDepositOutput(
                transaction, output_index, consensus, deposit, error)) {
            return false;
        }
        if (deposit.has_value()) {
            if (deposit_seen) {
                error = "an Elements transaction may contain only one ECX deposit marker";
                return false;
            }
            deposit_seen = true;
        }
    }
    if ((forced_seen || deposit_seen) && !ActiveAt(next_height, consensus)) {
        error = "ECX source transaction is premature before exchange activation";
        return false;
    }
    return true;
}

bool CountSourceTransactionMarkers(
    const CTransaction& transaction,
    uint64_t& forced_count,
    uint64_t& deposit_count,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    forced_count = 0;
    deposit_count = 0;
    if (!CheckSourceTransactionPolicy(
            transaction, consensus.activation_height, error, consensus)) {
        return false;
    }
    for (size_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
        std::optional<ForcedActionPayload> forced;
        if (!ParseForcedOutput(transaction, output_index, consensus, forced, error)) {
            return false;
        }
        if (forced.has_value()) ++forced_count;

        std::optional<DepositPayload> deposit;
        if (!ParseDepositOutput(transaction, output_index, consensus, deposit, error)) {
            return false;
        }
        if (deposit.has_value()) ++deposit_count;
    }
    return true;
}

bool ComputeSourceAppendBudget(
    const ExchangeConsensusSnapshot& snapshot,
    uint64_t& budget,
    std::string& error)
{
    budget = 0;
    error.clear();
    if (snapshot.forced_entry_count < snapshot.forced_processed_cursor ||
        snapshot.deposit_entry_count < snapshot.deposit_processed_cursor) {
        error = "ECX source backlog cursors are invalid";
        return false;
    }
    const uint64_t forced_pending =
        snapshot.forced_entry_count - snapshot.forced_processed_cursor;
    const uint64_t deposit_pending =
        snapshot.deposit_entry_count - snapshot.deposit_processed_cursor;
    if (forced_pending > MAX_COMBINED_UNCONSUMED ||
        deposit_pending > MAX_COMBINED_UNCONSUMED - forced_pending) {
        error = "ECX source backlog exceeds consensus bounds";
        return false;
    }
    budget = MAX_COMBINED_UNCONSUMED - forced_pending - deposit_pending;
    return true;
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
    const bool cursor_signalled =
        (static_cast<uint32_t>(block.nVersion) & CBlockHeader::INBOX_CURSOR_HF_MASK) != 0;
    if (!ActiveAt(height, consensus)) {
        if (exchange_signalled || forced_signalled || deposit_signalled || cursor_signalled ||
            !block.hashExchangeStateRoot.IsNull() ||
            !block.hashForcedInboxRoot.IsNull() ||
            !block.hashDepositInboxRoot.IsNull() || block.ecxParentHeight != 0 ||
            block.forcedProcessedCursor != 0 || block.depositProcessedCursor != 0 ||
            block.sourceBacklogOldestParentHeight != 0) {
            error = "ECX header extensions are forbidden before activation";
            return false;
        }
        return true;
    }
    if (!ConsensusConfigured(consensus, error)) return false;
    if (!exchange_signalled || !forced_signalled || !deposit_signalled || !cursor_signalled ||
        block.hashExchangeStateRoot.IsNull() ||
        block.hashForcedInboxRoot.IsNull() ||
        block.hashDepositInboxRoot.IsNull() || block.ecxParentHeight == 0) {
        error = "all ECX header extensions are required and nonzero after activation";
        return false;
    }
    if (height == consensus.activation_height &&
        (block.hashExchangeStateRoot != consensus.genesis_state_root ||
         block.hashForcedInboxRoot != ComputeForcedInboxGenesis(consensus) ||
         block.hashDepositInboxRoot != ComputeDepositInboxGenesis(consensus) ||
         block.forcedProcessedCursor != 0 || block.depositProcessedCursor != 0 ||
         block.sourceBacklogOldestParentHeight != 0)) {
        error = "ECX activation header does not commit the frozen genesis roots";
        return false;
    }
    return true;
}

bool CheckExchangeStateIndexHeader(
    const CBlockIndex& index,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    // Header trimming removes only block-signing/dynafed material. Rebuild the
    // fixed ECX commitment view directly from CBlockIndex so startup auditing
    // remains safe with -trim_headers enabled and never needs to mutate the
    // in-memory index merely to revalidate it.
    CBlockHeader header;
    header.nVersion = index.nVersion;
    header.hashExchangeStateRoot = index.hashExchangeStateRoot;
    header.hashForcedInboxRoot = index.hashForcedInboxRoot;
    header.hashDepositInboxRoot = index.hashDepositInboxRoot;
    header.ecxParentHeight = index.ecxParentHeight;
    header.forcedProcessedCursor = index.forcedProcessedCursor;
    header.depositProcessedCursor = index.depositProcessedCursor;
    header.sourceBacklogOldestParentHeight =
        index.sourceBacklogOldestParentHeight;
    return CheckExchangeStateHeader(header, index.nHeight, error, consensus);
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
              CBlockHeader::DEPOSIT_INBOX_HF_MASK |
              CBlockHeader::INBOX_CURSOR_HF_MASK));
        block.hashExchangeStateRoot.SetNull();
        block.hashForcedInboxRoot.SetNull();
        block.hashDepositInboxRoot.SetNull();
        block.ecxParentHeight = 0;
        block.forcedProcessedCursor = 0;
        block.depositProcessedCursor = 0;
        block.sourceBacklogOldestParentHeight = 0;
        return true;
    }
    if (!ConsensusConfigured(consensus, error)) return false;
    if (!authenticated_parent_height.has_value()) {
        if (!IsEcxRuntimeTestNetwork()) {
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
    uint64_t next_forced_cursor{0};
    uint64_t next_deposit_cursor{0};
    uint64_t next_oldest_parent_height{0};
    if (!ExpectedForBlock(
            block,
            previous,
            view,
            height,
            next,
            next_forced,
            next_deposits,
            next_forced_cursor,
            next_deposit_cursor,
            next_oldest_parent_height,
            error,
            consensus,
            authenticated_parent_height)) {
        return false;
    }
    block.nVersion = static_cast<int32_t>(
        static_cast<uint32_t>(block.nVersion) |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK);
    block.hashExchangeStateRoot = next.root;
    block.hashForcedInboxRoot = next_forced.root;
    block.hashDepositInboxRoot = next_deposits.root;
    block.ecxParentHeight = static_cast<uint32_t>(*authenticated_parent_height);
    block.forcedProcessedCursor = next_forced_cursor;
    block.depositProcessedCursor = next_deposit_cursor;
    block.sourceBacklogOldestParentHeight = next_oldest_parent_height;
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
        } else if (!IsEcxRuntimeTestNetwork()) {
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
    uint64_t next_forced_cursor{0};
    uint64_t next_deposit_cursor{0};
    uint64_t next_oldest_parent_height{0};
    if (!ExpectedForBlock(
            block,
            previous,
            view,
            height,
            next,
            next_forced,
            next_deposits,
            next_forced_cursor,
            next_deposit_cursor,
            next_oldest_parent_height,
            error,
            consensus,
            authenticated_parent_height)) {
        return false;
    }
    if (block.hashExchangeStateRoot != next.root ||
        block.hashForcedInboxRoot != next_forced.root ||
        block.hashDepositInboxRoot != next_deposits.root ||
        block.forcedProcessedCursor != next_forced_cursor ||
        block.depositProcessedCursor != next_deposit_cursor ||
        block.sourceBacklogOldestParentHeight != next_oldest_parent_height) {
        error = "ECX header roots do not match deterministic singleton and inbox derivation";
        return false;
    }
    if (height == consensus.activation_height &&
        (!view.AccessCoin(EXCHANGE_TRACKER_OUTPOINT).IsSpent() ||
         !view.AccessCoin(FORCED_INBOX_TRACKER_OUTPOINT).IsSpent() ||
         !view.AccessCoin(DEPOSIT_INBOX_TRACKER_OUTPOINT).IsSpent())) {
        error = "ECX activation cannot overwrite a reserved chainstate outpoint";
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

bool GetPriorActiveInboxCursors(
    const CBlockIndex* previous,
    uint64_t& forced_cursor,
    uint64_t& deposit_cursor,
    std::string& error)
{
    error.clear();
    forced_cursor = 0;
    deposit_cursor = 0;
    if (!previous ||
        (static_cast<uint32_t>(previous->nVersion) &
         CBlockHeader::INBOX_CURSOR_HF_MASK) == 0) {
        error = "prior active block has no ECX processed-cursor commitment";
        return false;
    }
    forced_cursor = previous->forcedProcessedCursor;
    deposit_cursor = previous->depositProcessedCursor;
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
        deposits.root != tip->hashDepositInboxRoot ||
        (static_cast<uint32_t>(tip->nVersion) &
         CBlockHeader::INBOX_CURSOR_HF_MASK) == 0 ||
        tip->forcedProcessedCursor > forced.count ||
        tip->depositProcessedCursor > deposits.count) {
        error = "persisted ECX context disagrees with the active tip";
        return false;
    }
    CTxOut exchange_output;
    if (!VerifyTrackedCoin(view, exchange, exchange_output, error)) return false;

    snapshot.exchange_state_root = exchange.root;
    snapshot.forced_inbox_root = forced.root;
    snapshot.forced_entry_count = forced.count;
    snapshot.forced_processed_cursor = tip->forcedProcessedCursor;
    snapshot.deposit_inbox_root = deposits.root;
    snapshot.deposit_entry_count = deposits.count;
    snapshot.deposit_processed_cursor = tip->depositProcessedCursor;
    snapshot.source_backlog_oldest_parent_height =
        tip->sourceBacklogOldestParentHeight;
    return true;
}

CScript BuildWithdrawalBundleEnvelopeScript(const WithdrawalBundleEnvelopeV1& envelope)
{
    if (envelope.m6_no_witness.empty() || envelope.m6_no_witness.size() > 100000) {
        throw std::invalid_argument("ECX M6 envelope preimage size is invalid");
    }
    std::vector<unsigned char> payload{'E', 'C', 'X', 'M', 1};
    payload.reserve(45 + envelope.m6_no_witness.size());
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        payload.push_back((envelope.checkpoint_height >> shift) & 0xff);
    }
    payload.insert(
        payload.end(),
        envelope.checkpoint_block_hash.begin(),
        envelope.checkpoint_block_hash.end());
    const uint32_t size = envelope.m6_no_witness.size();
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        payload.push_back((size >> shift) & 0xff);
    }
    payload.insert(
        payload.end(), envelope.m6_no_witness.begin(), envelope.m6_no_witness.end());
    return CScript() << OP_RETURN << payload;
}

bool CheckWithdrawalBundleEnvelope(
    const CBlock& block,
    const CBlockIndex* previous,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    if (height < consensus.activation_height) return true;
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        error = "ECX M6 envelope requires a coinbase transaction";
        return false;
    }

    std::optional<WithdrawalBundleEnvelopeV1> envelope;
    for (const CTxOut& output : block.vtx[0]->vout) {
        CScript::const_iterator cursor = output.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> payload;
        if (!output.scriptPubKey.GetOp(cursor, opcode) || opcode != OP_RETURN ||
            !output.scriptPubKey.GetOp(cursor, opcode, payload) || cursor != output.scriptPubKey.end() ||
            payload.size() < 5 || !std::equal(payload.begin(), payload.begin() + 4, "ECXM")) {
            continue;
        }
        if (envelope.has_value()) {
            error = "duplicate ECX M6 envelope";
            return false;
        }
        if (payload[4] != 1 || payload.size() < 45) {
            error = "malformed ECX M6 envelope";
            return false;
        }
        WithdrawalBundleEnvelopeV1 parsed;
        parsed.checkpoint_height = static_cast<uint32_t>(payload[5]) |
            (static_cast<uint32_t>(payload[6]) << 8) |
            (static_cast<uint32_t>(payload[7]) << 16) |
            (static_cast<uint32_t>(payload[8]) << 24);
        std::copy(payload.begin() + 9, payload.begin() + 41, parsed.checkpoint_block_hash.begin());
        const uint32_t m6_size = static_cast<uint32_t>(payload[41]) |
            (static_cast<uint32_t>(payload[42]) << 8) |
            (static_cast<uint32_t>(payload[43]) << 16) |
            (static_cast<uint32_t>(payload[44]) << 24);
        if (m6_size == 0 || m6_size > 100000 || payload.size() != 45 + m6_size) {
            error = "invalid ECX M6 envelope length";
            return false;
        }
        parsed.m6_no_witness.assign(payload.begin() + 45, payload.end());
        if (output.scriptPubKey != BuildWithdrawalBundleEnvelopeScript(parsed)) {
            error = "noncanonical ECX M6 envelope script";
            return false;
        }
        envelope = std::move(parsed);
    }

    const uint256 previous_bundle = previous == nullptr ? uint256::ZERO : previous->hashWithdrawalBundle;
    const bool bundle_changed = block.hashWithdrawalBundle != previous_bundle;
    const bool previous_ecx_active = previous != nullptr &&
        previous->nHeight >= consensus.activation_height &&
        (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0;
    const bool bundle_needs_envelope = !block.hashWithdrawalBundle.IsNull() &&
        (bundle_changed || !previous_ecx_active);
    if (!bundle_needs_envelope && !bundle_changed) {
        if (envelope.has_value()) {
            error = "ECX M6 envelope may appear only when hashWithdrawalBundle changes";
            return false;
        }
        return true;
    }
    if (block.hashWithdrawalBundle.IsNull()) {
        if (envelope.has_value()) {
            error = "ECX M6 envelope exists while clearing the withdrawal bundle commitment";
            return false;
        }
        return true;
    }
    if (!envelope.has_value()) {
        error = "withdrawal bundle commitment lacks its ECX M6 envelope";
        return false;
    }
    if (Hash(envelope->m6_no_witness) != block.hashWithdrawalBundle) {
        error = "ECX M6 envelope does not hash to hashWithdrawalBundle";
        return false;
    }
    if (previous == nullptr || envelope->checkpoint_height >= static_cast<uint32_t>(height)) {
        error = "ECX M6 checkpoint is not a prior block";
        return false;
    }
    const CBlockIndex* checkpoint = previous->GetAncestor(envelope->checkpoint_height);
    if (checkpoint == nullptr || checkpoint->GetBlockHash() != envelope->checkpoint_block_hash ||
        checkpoint->pprev == nullptr ||
        (static_cast<uint32_t>(checkpoint->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
        checkpoint->hashExchangeStateRoot.IsNull()) {
        error = "ECX M6 checkpoint is not the committed active-chain state";
        return false;
    }

    const std::vector<unsigned char>& raw = envelope->m6_no_witness;
    size_t offset{0};
    const auto read_le32 = [&raw, &offset](uint32_t& value) {
        if (offset + 4 > raw.size()) return false;
        value = static_cast<uint32_t>(raw[offset]) |
            (static_cast<uint32_t>(raw[offset + 1]) << 8) |
            (static_cast<uint32_t>(raw[offset + 2]) << 16) |
            (static_cast<uint32_t>(raw[offset + 3]) << 24);
        offset += 4;
        return true;
    };
    const auto read_le64 = [&raw, &offset](uint64_t& value) {
        if (offset + 8 > raw.size()) return false;
        value = 0;
        for (unsigned int shift = 0; shift < 64; shift += 8) value |= uint64_t{raw[offset++]} << shift;
        return true;
    };
    const auto read_compact = [&raw, &offset](uint64_t& value) {
        if (offset >= raw.size()) return false;
        const unsigned char prefix = raw[offset++];
        if (prefix < 253) { value = prefix; return true; }
        const size_t width = prefix == 253 ? 2 : prefix == 254 ? 4 : 8;
        if (offset + width > raw.size()) return false;
        value = 0;
        for (size_t i = 0; i < width; ++i) value |= uint64_t{raw[offset++]} << (8 * i);
        return (width == 2 && value >= 253) || (width == 4 && value > 0xffff) ||
            (width == 8 && value > 0xffffffffULL);
    };
    uint32_t version{0};
    uint64_t input_count{0};
    uint64_t output_count{0};
    if (!read_le32(version) || version != 2 || !read_compact(input_count) || input_count != 0 ||
        !read_compact(output_count) || output_count != 4) {
        error = "ECX M6 preimage has a noncanonical transaction prefix";
        return false;
    }
    std::array<std::vector<unsigned char>, 4> scripts;
    for (size_t i = 0; i < scripts.size(); ++i) {
        uint64_t amount{0};
        uint64_t script_size{0};
        if (!read_le64(amount) || !read_compact(script_size) || script_size > 10000 ||
            offset + script_size > raw.size()) {
            error = "ECX M6 preimage has an invalid output";
            return false;
        }
        scripts[i].assign(raw.begin() + offset, raw.begin() + offset + script_size);
        offset += script_size;
        if ((i == 0 || i == 1 || i == 3) && amount != 0) {
            error = "ECX M6 commitment outputs must remain zero-valued";
            return false;
        }
    }
    uint32_t locktime{0};
    if (!read_le32(locktime) || locktime != 0 || offset != raw.size()) {
        error = "ECX M6 preimage has trailing or noncanonical locktime bytes";
        return false;
    }
    if (scripts[1].size() != 34 || scripts[1][0] != OP_RETURN || scripts[1][1] != 32 ||
        scripts[3].size() != 39 || scripts[3][0] != OP_RETURN || scripts[3][1] != 37 ||
        !std::equal(scripts[3].begin() + 2, scripts[3].begin() + 6, "PXST") || scripts[3][6] != 1) {
        error = "ECX M6 preimage lacks its canonical commitment or PXST output";
        return false;
    }
    uint256 withdrawal_commitment;
    std::copy(scripts[1].begin() + 2, scripts[1].end(), withdrawal_commitment.begin());
    std::vector<unsigned char> anchor_payload;
    anchor_payload.reserve(134);
    anchor_payload.push_back(1);
    anchor_payload.push_back(24);
    const uint256 child_genesis = Params().GetConsensus().hashGenesisBlock;
    anchor_payload.insert(anchor_payload.end(), child_genesis.begin(), child_genesis.end());
    anchor_payload.push_back((envelope->checkpoint_height >> 24) & 0xff);
    anchor_payload.push_back((envelope->checkpoint_height >> 16) & 0xff);
    anchor_payload.push_back((envelope->checkpoint_height >> 8) & 0xff);
    anchor_payload.push_back(envelope->checkpoint_height & 0xff);
    const uint256 previous_hash = checkpoint->pprev->GetBlockHash();
    anchor_payload.insert(anchor_payload.end(), previous_hash.begin(), previous_hash.end());
    anchor_payload.insert(anchor_payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    anchor_payload.insert(anchor_payload.end(), checkpoint->hashExchangeStateRoot.begin(), checkpoint->hashExchangeStateRoot.end());
    const uint256 expected_anchor = TaggedHash("ECX/perps-m6-state/v1", anchor_payload);
    if (!std::equal(scripts[3].begin() + 7, scripts[3].end(), expected_anchor.begin())) {
        error = "ECX M6 PXST does not bind the selected active-chain checkpoint";
        return false;
    }
    return true;
}

bool DecodeBondV2CapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    if (!FrozenBondV2IdentityAvailable(consensus.bond_v2, error)) return false;
    if (active_exchange_state_root.IsNull()) {
        error = "ECX bond V2 capital projection has no active exchange root";
        return false;
    }
    std::array<unsigned char, 32> program_id{};
    std::array<unsigned char, 32> public_values_sha256{};
    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> values{};
    if (!simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
            stripped_annex.data(),
            stripped_annex.size(),
            program_id.data(),
            public_values_sha256.data(),
            values.data())) {
        error = "ECX bond V2 transition lacks one canonical version-4/PublicValuesV5 annex";
        return false;
    }
    if (!std::equal(
            program_id.begin(), program_id.end(),
            consensus.bond_v2.transition_program_id.begin()) ||
        RawHash32(values.data()) !=
            consensus.bond_v2.transition_journal_domain_sha256 ||
        RawHash32(values.data() + 36) != consensus.bond_v2.configuration_hash ||
        RawHash32(values.data() + 276) != consensus.bond_v2.bond_asset_id ||
        RawHash32(values.data() + 308) !=
            consensus.bond_v2.bond_deployment_commitment) {
        error = "ECX bond V2 annex does not match the source-frozen deployment identities";
        return false;
    }

    snapshot = {};
    snapshot.proof_profile = 0;
    snapshot.exchange_state_root = active_exchange_state_root;
    snapshot.configuration_hash = RawHash32(values.data() + 36);
    snapshot.bond_asset_id = RawHash32(values.data() + 276);
    snapshot.bond_deployment_commitment = RawHash32(values.data() + 308);
    snapshot.transition_program_id = consensus.bond_v2.transition_program_id;
    snapshot.transition_cmr = consensus.bond_v2.transition_cmr;
    snapshot.covenant_state_hash = RawHash32(values.data() + 100);
    snapshot.bond_state_root = RawHash32(values.data() + 340);
    snapshot.funding_state_root = RawHash32(values.data() + 404);
    snapshot.bond_inventory_covenant_hash =
        consensus.bond_v2.inventory_covenant_script_sha256;
    std::copy(values.begin() + 468, values.begin() + 484,
        snapshot.insurance_reserve.begin());
    snapshot.outstanding_share_atoms = ReadU64Be(values.data() + 484);
    snapshot.issued_share_atoms = UINT64_C(2100000000000000);
    snapshot.inventory_share_atoms =
        snapshot.issued_share_atoms - snapshot.outstanding_share_atoms;
    std::copy(values.begin() + 492, values.begin() + 508,
        snapshot.nav_per_whole_share.begin());
    std::copy(values.begin() + 508, values.begin() + 524,
        snapshot.full_bound_deficit.begin());
    std::copy(values.begin() + 524, values.begin() + 540,
        snapshot.target_reserve.begin());
    std::copy(values.begin() + 540, values.begin() + 556,
        snapshot.coverage_bps.begin());
    snapshot.capital_mode = values[556];
    snapshot.minimum_authenticated_price = ReadU64Be(values.data() + 557);
    snapshot.maximum_authenticated_price = ReadU64Be(values.data() + 565);
    snapshot.funding_epoch = ReadU64Be(values.data() + 573);
    snapshot.funding_rate_ppm = static_cast<int32_t>(ReadU32Be(values.data() + 581));
    snapshot.redemption_queue_root = RawHash32(values.data() + 372);
    snapshot.redemption_head = ReadU64Be(values.data() + 585);
    snapshot.redemption_tail = ReadU64Be(values.data() + 593);
    snapshot.queued_redemption_share_atoms = ReadU64Be(values.data() + 601);
    snapshot.oracle_certificate_hash = RawHash32(values.data() + 609);
    snapshot.oracle_valid_through_parent_mtp = ReadU64Be(values.data() + 641);
    snapshot.oracle_mode = values[649];
    snapshot.encrypted_availability_root = RawHash32(values.data() + 650);
    snapshot.bond_inbox_head_root = RawHash32(values.data() + 682);
    snapshot.bond_inbox_entry_count = ReadU64Be(values.data() + 714);
    snapshot.bond_inbox_processed_root = RawHash32(values.data() + 722);
    snapshot.bond_inbox_processed_cursor = ReadU64Be(values.data() + 754);
    snapshot.bond_inbox_outcome_root = RawHash32(values.data() + 762);
    snapshot.bond_inbox_outcome_count = ReadU64Be(values.data() + 794);
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
    snapshot.node_bond_inbox_entry_count = snapshot.bond_inbox_entry_count;
    snapshot.matcher_execution_receipt_batch_root = RawHash32(values.data() + 802);
    snapshot.previous_matcher_execution_sequence = ReadU64Be(values.data() + 834);
    snapshot.matcher_execution_sequence = ReadU64Be(values.data() + 842);
    // V2 has no treasury/operations allocation. The legacy fee pool is a
    // consensus invariant and is therefore projected as exact zero only.
    snapshot.legacy_fee_pool.fill(0);
    return true;
}

bool DecodeBondV2IncrementalSuccessorCapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    if (!FrozenBondV2IdentityAvailable(consensus.bond_v2, error)) return false;
    if (active_exchange_state_root.IsNull()) {
        error = "ECX incremental successor projection has no active exchange root";
        return false;
    }
    std::array<unsigned char, 32> program_id{};
    std::array<unsigned char, 32> public_values_sha256{};
    std::array<unsigned char, ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN> values{};
    if (!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
            stripped_annex.data(), stripped_annex.size(), program_id.data(),
            public_values_sha256.data(), values.data())) {
        error = "ECX incremental successor lacks one canonical version-6/PublicValuesV23 annex";
        return false;
    }
    const auto& frozen{consensus.bond_v2};
    if (!std::equal(program_id.begin(), program_id.end(),
            frozen.incremental_successor_program_id.begin()) ||
        RawHash32(values.data() + 4) !=
            frozen.incremental_successor_configuration_hash ||
        RawHash32(values.data() + 388) != frozen.configuration_hash ||
        !std::equal(values.begin() + 420, values.begin() + 452,
            consensus.chain_id.begin()) ||
        RawHash32(values.data() + 452) != frozen.bond_asset_id ||
        RawHash32(values.data() + 484) != frozen.bond_deployment_commitment ||
        RawHash32(values.data() + 516) != frozen.inventory_covenant_script_sha256) {
        error = "ECX incremental successor annex does not match frozen program/configuration/deployment identities";
        return false;
    }

    snapshot = {};
    snapshot.proof_profile = 1;
    snapshot.exchange_state_root = active_exchange_state_root;
    snapshot.configuration_hash = RawHash32(values.data() + 4);
    snapshot.bond_asset_id = RawHash32(values.data() + 452);
    snapshot.bond_deployment_commitment = RawHash32(values.data() + 484);
    snapshot.transition_program_id = frozen.incremental_successor_program_id;
    snapshot.transition_cmr = frozen.incremental_successor_transition_cmr;
    snapshot.covenant_state_hash = RawHash32(values.data() + 68);
    snapshot.bond_inventory_covenant_hash = RawHash32(values.data() + 516);
    snapshot.bond_state_root = RawHash32(values.data() + 548);
    snapshot.funding_state_root = RawHash32(values.data() + 580);
    snapshot.redemption_queue_root = RawHash32(values.data() + 612);
    snapshot.oracle_certificate_hash = RawHash32(values.data() + 644);
    snapshot.matcher_execution_receipt_batch_root = RawHash32(values.data() + 676);
    snapshot.encrypted_availability_root = RawHash32(values.data() + 228);
    snapshot.bond_inbox_head_root = RawHash32(values.data() + 708);
    snapshot.bond_inbox_processed_root = RawHash32(values.data() + 740);
    snapshot.bond_inbox_outcome_root = RawHash32(values.data() + 772);
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;

    static constexpr size_t SCALAR_OFFSET{4 + 40 * 32};
    snapshot.minimum_authenticated_price = ReadU64Be(values.data() + SCALAR_OFFSET + 24);
    snapshot.maximum_authenticated_price = ReadU64Be(values.data() + SCALAR_OFFSET + 40);
    snapshot.issued_share_atoms = ReadU64Be(values.data() + SCALAR_OFFSET + 48);
    snapshot.outstanding_share_atoms = ReadU64Be(values.data() + SCALAR_OFFSET + 56);
    snapshot.inventory_share_atoms = ReadU64Be(values.data() + SCALAR_OFFSET + 64);
    snapshot.queued_redemption_share_atoms = ReadU64Be(values.data() + SCALAR_OFFSET + 72);
    snapshot.funding_epoch = ReadU64Be(values.data() + SCALAR_OFFSET + 80);
    snapshot.oracle_valid_through_parent_mtp = ReadU64Be(values.data() + SCALAR_OFFSET + 88);
    std::copy(values.begin() + SCALAR_OFFSET + 96,
        values.begin() + SCALAR_OFFSET + 112,
        snapshot.global_funding_index_numerator.begin());
    static constexpr size_t WIDE_OFFSET{SCALAR_OFFSET + 112};
    std::copy(values.begin() + WIDE_OFFSET + 32,
        values.begin() + WIDE_OFFSET + 48, snapshot.full_bound_deficit.begin());
    std::copy(values.begin() + WIDE_OFFSET + 48,
        values.begin() + WIDE_OFFSET + 64, snapshot.target_reserve.begin());
    std::copy(values.begin() + WIDE_OFFSET + 64,
        values.begin() + WIDE_OFFSET + 80, snapshot.insurance_reserve.begin());
    std::copy(values.begin() + WIDE_OFFSET + 80,
        values.begin() + WIDE_OFFSET + 96, snapshot.controlled_usdd_atoms.begin());
    std::copy(values.begin() + WIDE_OFFSET + 96,
        values.begin() + WIDE_OFFSET + 112, snapshot.matcher_execution_sequence.bytes.begin());
    std::copy(values.begin() + WIDE_OFFSET + 112,
        values.begin() + WIDE_OFFSET + 128, snapshot.nav_per_whole_share.begin());
    std::copy(values.begin() + WIDE_OFFSET + 128,
        values.begin() + WIDE_OFFSET + 144, snapshot.coverage_bps.begin());
    std::copy(values.begin() + WIDE_OFFSET + 144,
        values.begin() + WIDE_OFFSET + 160, snapshot.redemption_head.bytes.begin());
    std::copy(values.begin() + WIDE_OFFSET + 160,
        values.begin() + WIDE_OFFSET + 176, snapshot.redemption_tail.bytes.begin());
    std::copy(values.begin() + WIDE_OFFSET + 176,
        values.begin() + WIDE_OFFSET + 192, snapshot.bond_inbox_entry_count.bytes.begin());
    std::copy(values.begin() + WIDE_OFFSET + 192,
        values.begin() + WIDE_OFFSET + 208, snapshot.bond_inbox_processed_cursor.bytes.begin());
    std::copy(values.begin() + WIDE_OFFSET + 208,
        values.begin() + WIDE_OFFSET + 224, snapshot.bond_inbox_outcome_count.bytes.begin());
    snapshot.node_bond_inbox_entry_count = snapshot.bond_inbox_entry_count;
    snapshot.funding_rate_ppm =
        static_cast<int32_t>(ReadU32Be(values.data() + WIDE_OFFSET + 224));
    snapshot.capital_mode = values[WIDE_OFFSET + 228];
    snapshot.oracle_mode = values[WIDE_OFFSET + 229];
    snapshot.operationally_safe = values[WIDE_OFFSET + 230];
    snapshot.legacy_fee_pool.fill(0);
    return true;
}

bool VerifyBondV2DeploymentAndGenesis(
    const CCoinsViewCache& view,
    const uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    if (!FrozenBondV2IdentityAvailable(consensus.bond_v2, error)) return false;
    if (prior_parent_mtp == 0) {
        error = "ECX bond V2 genesis has no authenticated parent MTP";
        return false;
    }
    const auto& frozen{consensus.bond_v2};
    const CTransaction& deployment{*frozen.deployment_transaction};
    const CTransaction& genesis{*frozen.genesis_transaction};
    const uint256 deployment_txid{deployment.GetHash()};
    const uint256 genesis_txid{genesis.GetHash()};
    static constexpr CAmount FIXED_SUPPLY{2'100'000'000'000'000};

    if (deployment_txid == genesis_txid ||
        consensus.genesis_state_outpoint.hash != genesis_txid ||
        frozen.issuance_input_index >= deployment.vin.size() ||
        frozen.inventory_output_index >= deployment.vout.size() ||
        frozen.reissuance_token_burn_output_index >= deployment.vout.size() ||
        frozen.state_authority_source_output_index >= deployment.vout.size() ||
        consensus.genesis_state_outpoint.n >= genesis.vout.size() ||
        genesis.vin.empty() ||
        genesis.vin[0].prevout != COutPoint{
            deployment_txid, frozen.state_authority_source_output_index}) {
        error = "ECX bond V2 physical deployment/genesis linkage changed";
        return false;
    }

    const CTxIn& issuance{deployment.vin[frozen.issuance_input_index]};
    if (issuance.assetIssuance.IsNull() ||
        !issuance.assetIssuance.assetBlindingNonce.IsNull() ||
        !issuance.assetIssuance.nAmount.IsExplicit() ||
        issuance.assetIssuance.nAmount.GetAmount() != FIXED_SUPPLY ||
        !issuance.assetIssuance.nInflationKeys.IsExplicit() ||
        issuance.assetIssuance.nInflationKeys.GetAmount() != 1 ||
        std::count_if(
            deployment.vin.begin(), deployment.vin.end(),
            [](const CTxIn& input) { return !input.assetIssuance.IsNull(); }) != 1 ||
        std::any_of(
            deployment.vin.begin(), deployment.vin.end(),
            [](const CTxIn& input) { return input.m_is_pegin; }) ||
        std::any_of(
            genesis.vin.begin(), genesis.vin.end(),
            [](const CTxIn& input) {
                return input.m_is_pegin || !input.assetIssuance.IsNull();
            })) {
        error = "ECX bond V2 deployment/genesis issuance shape changed";
        return false;
    }
    uint256 entropy;
    GenerateAssetEntropy(entropy, issuance.prevout, issuance.assetIssuance.assetEntropy);
    CAsset bond_asset;
    CAsset token_asset;
    CalculateAsset(bond_asset, entropy);
    CalculateReissuanceToken(token_asset, entropy, false);
    if (bond_asset.id != frozen.bond_asset_id || bond_asset == token_asset) {
        error = "ECX bond V2 physical issuance derives a substituted asset";
        return false;
    }

    const CTxOut& inventory{deployment.vout[frozen.inventory_output_index]};
    const CTxOut& burn{
        deployment.vout[frozen.reissuance_token_burn_output_index]};
    const CTxOut& authority_source{
        deployment.vout[frozen.state_authority_source_output_index]};
    if (!VerifyConfidentialPair(
            inventory.nValue, inventory.nAsset, FIXED_SUPPLY, bond_asset,
            frozen.inventory_value_blinding_factor,
            frozen.inventory_asset_blinding_factor) ||
        Sha256(std::vector<unsigned char>(
            inventory.scriptPubKey.begin(), inventory.scriptPubKey.end())) !=
            frozen.inventory_covenant_script_sha256 ||
        !burn.nAsset.IsExplicit() || burn.nAsset.GetAsset() != token_asset ||
        !burn.nValue.IsExplicit() || burn.nValue.GetAmount() != 1 ||
        !burn.nNonce.IsNull() || !burn.scriptPubKey.IsUnspendable() ||
        Sha256(std::vector<unsigned char>(
            burn.scriptPubKey.begin(), burn.scriptPubKey.end())) !=
            frozen.reissuance_token_burn_script_sha256 ||
        !authority_source.nAsset.IsExplicit() ||
        authority_source.nAsset.GetAsset().id != frozen.state_authority_asset_id ||
        !authority_source.nValue.IsExplicit() ||
        authority_source.nValue.GetAmount() != 1 ||
        !authority_source.nNonce.IsNull() ||
        authority_source.scriptPubKey.empty() ||
        authority_source.scriptPubKey.IsUnspendable()) {
        error = "ECX bond V2 deployment outputs differ from the authorized facts";
        return false;
    }

    std::vector<unsigned char> commitment;
    commitment.reserve(253);
    commitment.push_back(1);
    AppendHash(commitment, deployment_txid);
    AppendHash(commitment, issuance.prevout.hash);
    PushU32Be(commitment, issuance.prevout.n);
    AppendHash(commitment, bond_asset.id);
    AppendHash(commitment, token_asset.id);
    PushU64Be(commitment, FIXED_SUPPLY);
    PushU32Be(commitment, frozen.inventory_output_index);
    PushU32Be(commitment, frozen.reissuance_token_burn_output_index);
    AppendHash(commitment, frozen.inventory_covenant_script_sha256);
    AppendHash(commitment, frozen.reissuance_token_burn_script_sha256);
    if (TaggedHash("ECX/frozen-bond-deployment/v2", commitment) !=
        frozen.bond_deployment_commitment) {
        error = "ECX bond V2 deployment commitment was substituted";
        return false;
    }

    const Coin& deployment_inventory{
        view.AccessCoin(COutPoint{deployment_txid, frozen.inventory_output_index})};
    const Coin& state_coin{view.AccessCoin(consensus.genesis_state_outpoint)};
    if (deployment_inventory.IsSpent() || state_coin.IsSpent() ||
        deployment_inventory.out != inventory ||
        state_coin.out != genesis.vout[consensus.genesis_state_outpoint.n] ||
        deployment_inventory.nHeight == 0 || state_coin.nHeight == 0 ||
        deployment_inventory.nHeight == UINT32_C(0x7fffffff) ||
        state_coin.nHeight == UINT32_C(0x7fffffff) ||
        state_coin.nHeight < deployment_inventory.nHeight ||
        deployment_inventory.nHeight >=
            static_cast<uint32_t>(consensus.activation_height) ||
        state_coin.nHeight >= static_cast<uint32_t>(consensus.activation_height)) {
        error =
            "ECX bond V2 activation requires confirmed ordered deployment and genesis UTXOs";
        return false;
    }

    uint256 bond_state_root;
    uint256 funding_state_root;
    const uint256 private_state_root{ComputeBondV2GenesisPrivateStateRoot(
        consensus,
        state_coin.nHeight,
        prior_parent_mtp,
        bond_state_root,
        funding_state_root)};
    if (private_state_root.IsNull()) {
        error = "ECX bond V2 canonical genesis encoding failed";
        return false;
    }
    const uint256 covenant_state_hash{ComputeBondV2GenesisCovenantStateHash(
        consensus, private_state_root, bond_state_root, funding_state_root,
        state_coin.nHeight)};
    CScript expected_script;
    if (!ComputeBondV2GenesisScript(
            consensus, covenant_state_hash, expected_script) ||
        state_coin.out.scriptPubKey != expected_script ||
        !state_coin.out.nAsset.IsExplicit() ||
        state_coin.out.nAsset.GetAsset().id != frozen.state_authority_asset_id ||
        !state_coin.out.nValue.IsExplicit() ||
        state_coin.out.nValue.GetAmount() != 1 ||
        !state_coin.out.nNonce.IsNull() ||
        ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            consensus.genesis_state_outpoint,
            state_coin.out) != consensus.genesis_state_root) {
        error = "ECX bond V2 genesis singleton is not the exact derived empty state";
        return false;
    }

    snapshot = {};
    snapshot.proof_profile = 0;
    snapshot.exchange_state_root = consensus.genesis_state_root;
    snapshot.configuration_hash = frozen.configuration_hash;
    snapshot.bond_asset_id = frozen.bond_asset_id;
    snapshot.bond_deployment_commitment = frozen.bond_deployment_commitment;
    snapshot.transition_program_id = frozen.transition_program_id;
    snapshot.transition_cmr = frozen.transition_cmr;
    snapshot.covenant_state_hash = covenant_state_hash;
    snapshot.bond_state_root = bond_state_root;
    snapshot.funding_state_root = funding_state_root;
    snapshot.bond_inventory_covenant_hash = frozen.inventory_covenant_script_sha256;
    snapshot.issued_share_atoms = static_cast<uint64_t>(FIXED_SUPPLY);
    snapshot.inventory_share_atoms = static_cast<uint64_t>(FIXED_SUPPLY);
    snapshot.coverage_bps[14] = 0x30;
    snapshot.coverage_bps[15] = 0xd4; // 12,500 bps when deficit is zero
    snapshot.capital_mode = 0;
    snapshot.minimum_authenticated_price = frozen.genesis_mark_price;
    snapshot.maximum_authenticated_price = frozen.genesis_mark_price;
    snapshot.funding_epoch = prior_parent_mtp / 28'800;
    snapshot.redemption_queue_root = EmptyBondV2QueueRoot();
    snapshot.oracle_valid_through_parent_mtp = prior_parent_mtp;
    snapshot.encrypted_availability_root = frozen.genesis_availability_root;
    snapshot.bond_inbox_head_root = ComputeBondInboxGenesisRoot(consensus);
    snapshot.bond_inbox_processed_root = snapshot.bond_inbox_head_root;
    snapshot.bond_inbox_outcome_root = ComputeBondInboxOutcomeGenesisRoot(consensus);
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
    snapshot.matcher_execution_receipt_batch_root =
        EmptyMatcherExecutionReceiptBatchRoot();
    snapshot.last_transition_sidechain_height = state_coin.nHeight;
    return true;
}

bool DeriveBondV2CapitalProjectionAfterScripts(
    const CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    const int height,
    const uint256& prior_parent_block_hash,
    const uint64_t prior_parent_height,
    const uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    if (!FrozenBondV2IdentityAvailable(consensus.bond_v2, error)) return false;
    if (height < consensus.activation_height) {
        error = "ECX bond V2 capital projection requested before activation";
        return false;
    }
    if (height == consensus.activation_height) {
        // Activation must rederive the asset, supply/token burn, inventory
        // opening, singleton script/outpoint and complete empty ExchangeStateV2.
        // No operator-provided summary or marker is an admissible substitute.
        if (block.hashExchangeStateRoot != consensus.genesis_state_root) {
            error = "ECX bond V2 activation header does not commit exact genesis";
            return false;
        }
        if (!VerifyBondV2DeploymentAndGenesis(
                view, prior_parent_mtp, snapshot, error, consensus)) return false;
        return AppendBondInboxSourcesForBlock(
            block, height, prior_parent_height, snapshot, error, consensus);
    }
    if (!previous || !previous->ecxBondV2Capital.has_value()) {
        error = "ECX bond V2 predecessor lacks a verified block-index capital projection";
        return false;
    }
    if (block.hashExchangeStateRoot == previous->hashExchangeStateRoot) {
        snapshot = *previous->ecxBondV2Capital;
        const bool finite_identity{
            snapshot.proof_profile == 0 &&
            snapshot.configuration_hash == consensus.bond_v2.configuration_hash &&
            snapshot.transition_program_id == consensus.bond_v2.transition_program_id &&
            snapshot.transition_cmr == consensus.bond_v2.transition_cmr};
        const bool successor_identity{
            snapshot.proof_profile == 1 &&
            snapshot.configuration_hash ==
                consensus.bond_v2.incremental_successor_configuration_hash &&
            snapshot.transition_program_id ==
                consensus.bond_v2.incremental_successor_program_id &&
            snapshot.transition_cmr ==
                consensus.bond_v2.incremental_successor_transition_cmr};
        if (snapshot.exchange_state_root != block.hashExchangeStateRoot ||
            (!finite_identity && !successor_identity) ||
            snapshot.bond_asset_id != consensus.bond_v2.bond_asset_id ||
            snapshot.bond_deployment_commitment !=
                consensus.bond_v2.bond_deployment_commitment) {
            error = "ECX bond V2 carry-forward projection is not root/frozen-identity bound";
            return false;
        }
        if (successor_identity) {
            return AppendIncrementalSuccessorBondInboxSourcesForBlock(
                block, height, prior_parent_height, snapshot, error, consensus);
        }
        return AppendBondInboxSourcesForBlock(
            block, height, prior_parent_height, snapshot, error, consensus);
    }
    if (prior_parent_block_hash.IsNull() || prior_parent_height == 0 ||
        prior_parent_mtp == 0) {
        error = "ECX bond V2 transition has no authenticated prior BMM context";
        return false;
    }

    const CTransaction* transition{nullptr};
    for (const CTransactionRef& transaction_ref : block.vtx) {
        const CTransaction& candidate{*transaction_ref};
        if (candidate.vin.empty() || candidate.vout.empty()) continue;
        const COutPoint successor{candidate.GetHash(), 0};
        if (ComputeStateUtxoRoot(
                Params().GetConsensus().hashGenesisBlock,
                successor,
                candidate.vout[0]) != block.hashExchangeStateRoot) continue;
        if (transition) {
            error = "ECX bond V2 block contains more than one successor-root transaction";
            return false;
        }
        transition = &candidate;
    }
    if (!transition || transition->witness.vtxinwit.empty()) {
        error = "ECX bond V2 state change lacks its transition input/witness";
        return false;
    }
    const auto& stack{transition->witness.vtxinwit[0].scriptWitness.stack};
    if (stack.size() < 2 || stack.back().empty() || stack.back()[0] != 0x50) {
        error = "ECX bond V2 transition input zero lacks a Taproot annex";
        return false;
    }
    const std::vector<unsigned char> stripped_annex(
        stack.back().begin() + 1, stack.back().end());
    const BondV2CapitalSnapshot& prior_capital{*previous->ecxBondV2Capital};
    if (stripped_annex.size() > 7 && stripped_annex[7] == 5) {
        std::array<unsigned char, 32> program_id{};
        std::array<unsigned char, 32> public_values_sha256{};
        std::array<unsigned char, ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN> values{};
        if (prior_capital.proof_profile != 0 ||
            !simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
                stripped_annex.data(), stripped_annex.size(), program_id.data(),
                public_values_sha256.data(), values.data())) {
            error = "ECX incremental activation is not a canonical finite-state one-shot annex";
            return false;
        }
        if (!std::equal(program_id.begin(), program_id.end(),
                consensus.bond_v2.incremental_activation_program_id.begin()) ||
            RawHash32(values.data() + 4) !=
                consensus.bond_v2.incremental_activation_configuration_hash ||
            RawHash32(values.data() + 36) != consensus.bond_v2.configuration_hash ||
            RawHash32(values.data() + 68) != prior_capital.covenant_state_hash ||
            RawHash32(values.data() + 100) !=
                consensus.bond_v2.incremental_successor_configuration_hash ||
            RawHash32(values.data() + 164) != transition->GetHash() ||
            RawHash32(values.data() + 196) != prior_parent_block_hash ||
            !std::equal(values.begin() + 228, values.begin() + 260,
                consensus.chain_id.begin()) ||
            ReadU64Be(values.data() + 324) != static_cast<uint64_t>(height) ||
            ReadU64Be(values.data() + 332) != prior_parent_mtp) {
            error = "ECX incremental activation does not bind the frozen predecessor/transaction/BMM context";
            return false;
        }
        const uint256 successor_state_root{RawHash32(values.data() + 132)};
        CScript expected_successor_script;
        if (!ComputeBondV2IncrementalSuccessorScript(
                consensus, successor_state_root, expected_successor_script) ||
            transition->vout[0].scriptPubKey != expected_successor_script) {
            error = "ECX incremental activation output does not commit the proven successor state";
            return false;
        }
        snapshot = {};
        snapshot.proof_profile = 1;
        snapshot.exchange_state_root = block.hashExchangeStateRoot;
        snapshot.configuration_hash =
            consensus.bond_v2.incremental_successor_configuration_hash;
        snapshot.bond_asset_id = consensus.bond_v2.bond_asset_id;
        snapshot.bond_deployment_commitment =
            consensus.bond_v2.bond_deployment_commitment;
        snapshot.transition_program_id =
            consensus.bond_v2.incremental_successor_program_id;
        snapshot.transition_cmr =
            consensus.bond_v2.incremental_successor_transition_cmr;
        snapshot.covenant_state_hash = successor_state_root;
        snapshot.bond_state_root = RawHash32(values.data() + 260);
        snapshot.funding_state_root = RawHash32(values.data() + 292);
        snapshot.bond_inventory_covenant_hash =
            consensus.bond_v2.inventory_covenant_script_sha256;
        snapshot.issued_share_atoms = UINT64_C(2100000000000000);
        snapshot.inventory_share_atoms = snapshot.issued_share_atoms;
        snapshot.coverage_bps[14] = 0x30;
        snapshot.coverage_bps[15] = 0xd4;
        snapshot.minimum_authenticated_price = ReadU64Be(values.data() + 348);
        snapshot.maximum_authenticated_price = ReadU64Be(values.data() + 356);
        snapshot.funding_epoch = prior_parent_mtp / UINT64_C(28800);
        std::vector<unsigned char> queue_empty(4, 0);
        snapshot.redemption_queue_root = TaggedHash(
            "ECX/successor-redemption-queue/v2-u128", queue_empty);
        snapshot.bond_inbox_head_root =
            IncrementalSuccessorBondInboxGenesisHead(consensus);
        snapshot.bond_inbox_processed_root = snapshot.bond_inbox_head_root;
        snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
        std::vector<unsigned char> inbox_genesis;
        AppendHash(inbox_genesis, consensus.bond_v2.bond_inbox_domain);
        inbox_genesis.insert(
            inbox_genesis.end(), consensus.chain_id.begin(), consensus.chain_id.end());
        AppendHash(inbox_genesis, consensus.bond_v2.configuration_hash);
        snapshot.bond_inbox_outcome_root = TaggedHash(
            "ECX/successor-bond-inbox-outcomes-genesis/v2-u128", inbox_genesis);
        snapshot.last_transition_sidechain_height = static_cast<uint64_t>(height);
        snapshot.operationally_safe = 1;
        return AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, height, prior_parent_height, snapshot, error, consensus);
    }

    if (stripped_annex.size() > 7 && stripped_annex[7] == 6) {
        if (prior_capital.proof_profile != 1 ||
            !DecodeBondV2IncrementalSuccessorCapitalProjection(
                stripped_annex, block.hashExchangeStateRoot, snapshot, error, consensus)) {
            if (error.empty()) error = "ECX incremental successor cannot follow a finite predecessor";
            return false;
        }
        std::array<unsigned char, 32> program_id{};
        std::array<unsigned char, 32> public_values_sha256{};
        std::array<unsigned char, ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN> values{};
        if (!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
                stripped_annex.data(), stripped_annex.size(), program_id.data(),
                public_values_sha256.data(), values.data())) {
            error = "ECX incremental successor annex changed between decode and context binding";
            return false;
        }
        CScript expected_successor_script;
        if (!ComputeBondV2IncrementalSuccessorScript(
                consensus, snapshot.covenant_state_hash, expected_successor_script) ||
            transition->vout[0].scriptPubKey != expected_successor_script ||
            RawHash32(values.data() + 36) != prior_capital.covenant_state_hash ||
            RawHash32(values.data() + 100) != transition->GetHash() ||
            RawHash32(values.data() + 132) != previous->hashExchangeStateRoot ||
            RawHash32(values.data() + 164) != prior_parent_block_hash ||
            ReadU64Be(values.data() + 1284) != prior_parent_height ||
            ReadU64Be(values.data() + 1292) != prior_parent_mtp ||
            ReadU64Be(values.data() + 1300) != static_cast<uint64_t>(height) ||
            snapshot.bond_inbox_head_root != prior_capital.node_bond_inbox_head_root ||
            snapshot.bond_inbox_entry_count != prior_capital.node_bond_inbox_entry_count ||
            snapshot.bond_inbox_processed_cursor < prior_capital.bond_inbox_processed_cursor ||
            snapshot.matcher_execution_sequence < prior_capital.matcher_execution_sequence) {
            error = "ECX incremental successor does not bind the transition/header/BMM/cursor context";
            return false;
        }
        snapshot.previous_matcher_execution_sequence =
            prior_capital.matcher_execution_sequence;
        snapshot.last_transition_sidechain_height = static_cast<uint64_t>(height);
        return AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, height, prior_parent_height, snapshot, error, consensus);
    }

    if (prior_capital.proof_profile != 0 ||
        !DecodeBondV2CapitalProjection(
            stripped_annex, block.hashExchangeStateRoot, snapshot, error, consensus)) {
        if (error.empty()) error = "finite V18 annex cannot follow an incremental successor";
        return false;
    }
    std::array<unsigned char, 32> program_id{};
    std::array<unsigned char, 32> public_values_sha256{};
    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> values{};
    if (!simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
            stripped_annex.data(), stripped_annex.size(), program_id.data(),
            public_values_sha256.data(), values.data())) {
        error = "ECX finite V18 annex changed between decode and context binding";
        return false;
    }
    CScript expected_successor_script;
    if (!ComputeBondV2FiniteStateScript(
            consensus, snapshot.covenant_state_hash, expected_successor_script) ||
        transition->vout[0].scriptPubKey != expected_successor_script ||
        RawHash32(values.data() + 68) != prior_capital.covenant_state_hash ||
        RawHash32(values.data() + 132) != transition->GetHash() ||
        RawHash32(values.data() + 164) != previous->hashExchangeStateRoot ||
        RawHash32(values.data() + 196) != prior_parent_block_hash ||
        ReadU64Be(values.data() + 228) != prior_parent_height ||
        ReadU64Be(values.data() + 236) != prior_parent_mtp ||
        snapshot.bond_inbox_head_root != prior_capital.node_bond_inbox_head_root ||
        snapshot.bond_inbox_entry_count != prior_capital.node_bond_inbox_entry_count ||
        snapshot.bond_inbox_processed_cursor < prior_capital.bond_inbox_processed_cursor ||
        snapshot.matcher_execution_sequence < prior_capital.matcher_execution_sequence ||
        snapshot.previous_matcher_execution_sequence !=
            prior_capital.matcher_execution_sequence) {
        error = "ECX finite V18 public values do not bind the transition/header/BMM context";
        return false;
    }
    snapshot.last_transition_sidechain_height = static_cast<uint64_t>(height);
    return AppendBondInboxSourcesForBlock(
        block, height, prior_parent_height, snapshot, error, consensus);
}

} // namespace ecx
