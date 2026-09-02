// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include <ecx_exchange_state.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <hash.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
extern "C" {
#include <simplicity/elements/env.h>
}
#include <streams.h>
#include <test/ecx_simplicity_test_shim.h>
#include <test/util/setup_common.h>
#include <test/data/ecx_v17_configuration.hex.h>
#include <test/data/ecx_v18_configuration.hex.h>
#include <test/data/ecx_successor_bond_inbox_source_v23.hex.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <limits>
#include <set>

namespace {

struct ElementsTestingSetup : BasicTestingSetup {
    ElementsTestingSetup()
        : BasicTestingSetup("elementsregtest")
    {
    }
};

class MemoryCoinsView final : public CCoinsView
{
public:
    std::map<COutPoint, Coin> coins;

    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override
    {
        const auto it = coins.find(outpoint);
        if (it == coins.end() || it->second.IsSpent()) return false;
        coin = it->second;
        return true;
    }

    bool BatchWrite(CCoinsMap& entries, const uint256&) override
    {
        for (auto it = entries.begin(); it != entries.end();) {
            if (it->second.flags & CCoinsCacheEntry::DIRTY) {
                if (it->second.coin.IsSpent()) {
                    coins.erase(it->first.second);
                } else {
                    coins[it->first.second] = it->second.coin;
                }
            }
            it = entries.erase(it);
        }
        return true;
    }
};

CScript TaprootScript(unsigned char value)
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, value);
}

CTxOut AuthorityOutput(unsigned char script_byte, CAmount amount = 1)
{
    return CTxOut(
        Params().GetConsensus().pegged_asset,
        amount,
        TaprootScript(script_byte));
}

ecx::ExchangeConsensus ConfiguredConsensus(
    int height,
    const COutPoint& genesis,
    const uint256& genesis_root)
{
    ecx::ExchangeConsensus consensus;
    consensus.activation_height = height;
    consensus.genesis_state_outpoint = genesis;
    consensus.genesis_state_root = genesis_root;
    consensus.chain_id.fill(0x11);
    consensus.forced_action_domain.fill(0x22);
    consensus.deposit_inbox_domain.fill(0x33);
    consensus.collateral_vault_script = TaprootScript(0x44);
    CSHA256 hasher;
    hasher.Write(
        consensus.collateral_vault_script.data(),
        consensus.collateral_vault_script.size());
    hasher.Finalize(consensus.collateral_vault_script_hash.begin());
    return consensus;
}

void PopulateTestBondV2FrozenIdentities(ecx::ExchangeConsensus& consensus)
{
    auto& frozen{consensus.bond_v2};
    frozen.activation_enabled = true;
    frozen.identities_frozen = true;
    frozen.deployment_transaction = MakeTransactionRef(CMutableTransaction{});
    frozen.genesis_transaction = MakeTransactionRef(CMutableTransaction{});
    frozen.canonical_configuration_bytes = {1};
    const auto fill = [](uint256& value, unsigned char byte) {
        std::fill(value.begin(), value.end(), byte);
    };
    fill(frozen.public_state_domain_sha256, 19);
    fill(frozen.state_node_domain_sha256, 20);
    fill(frozen.incremental_activation_program_id, 70);
    fill(frozen.incremental_activation_configuration_hash, 71);
    fill(frozen.incremental_activation_cmr, 72);
    fill(frozen.incremental_successor_program_id, 73);
    fill(frozen.incremental_successor_configuration_hash, 74);
    fill(frozen.incremental_successor_transition_cmr, 75);
    fill(frozen.incremental_successor_state_node_domain_sha256, 76);
    fill(frozen.inventory_cmr, 21);
    fill(frozen.redemption_queue_cmr, 22);
    fill(frozen.ecx_btc_conversion_program_id, 23);
    fill(frozen.ecx_btc_redemption_covenant_commitment, 24);
    fill(frozen.ecx_btc_source_checkpoint_commitment, 25);
    fill(frozen.usdd_usd_conversion_program_id, 26);
    fill(frozen.usdd_usd_redemption_covenant_commitment, 27);
    fill(frozen.usdd_usd_source_checkpoint_commitment, 28);
    fill(frozen.matcher_genesis_receipt_hash, 29);
    fill(frozen.order_receipts_genesis_root, 30);
    fill(frozen.genesis_availability_root, 31);
    fill(frozen.inventory_covenant_script_sha256, 32);
    fill(frozen.reissuance_token_burn_script_sha256, 33);
    fill(frozen.state_authority_asset_id, 34);
    fill(frozen.inventory_asset_blinding_factor, 35);
    fill(frozen.inventory_value_blinding_factor, 36);
    fill(frozen.redemption_queue_script_sha256, 37);
    fill(frozen.insurance_reserve_script_sha256, 38);
    fill(frozen.insurance_reserve_covenant_cmr, 39);
    fill(frozen.bond_inbox_redemption_staging_template_commitment, 40);
    const std::vector<unsigned char> renderer_domain{ParseHex(
        "d8ca7883769dd73830987f727a34939d2d9b69a3e783e0a2e1cca35fa4872e6f")};
    std::copy(
        renderer_domain.begin(), renderer_domain.end(),
        frozen.bond_inbox_redemption_staging_renderer_domain.begin());
    const std::vector<unsigned char> nums_internal_key{ParseHex(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")};
    std::copy(
        nums_internal_key.begin(), nums_internal_key.end(),
        frozen.bond_inbox_redemption_staging_internal_key.begin());
    fill(frozen.bond_inbox_redemption_staging_process_cmr, 42);
    fill(frozen.bond_inbox_redemption_staging_refund_cmr, 43);
    fill(frozen.bond_inbox_domain, 44);
    fill(frozen.bond_inbox_custody_receipt_codec_hash, 45);
    fill(frozen.availability_scheme_hash, 46);
    fill(frozen.availability_custodian_registry_hash, 47);
    fill(frozen.collateral_vault_covenant_cmr, 48);
    frozen.bond_inbox_redemption_staging_tapleaf_version = 0xbe;
    frozen.bond_inbox_refund_minimum_parent_blocks = 12;
    frozen.bond_inbox_inclusion_blocks = 6;
    frozen.bond_inbox_max_bundle_bytes = 64 * 1024;
    frozen.bond_inbox_max_entries_per_sidechain_block = 8;
    frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block =
        576 * 1024;
    frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block =
        768 * 1024;
    frozen.bond_inbox_max_pending_entries_per_transition = 64;
    frozen.bond_inbox_max_consumed_entries_per_transition = 64;
    frozen.bond_redemption_max_queue_entries = 4096;
    frozen.matcher_execution_inclusion_parent_blocks = 6;
    frozen.maximum_conversion_age_seconds = 3600;
    frozen.maximum_conversion_proof_bytes = 16 * 1024 * 1024;
    frozen.recursive_proof_marker_bytes = 32;
    frozen.fixed_supply_atoms = UINT64_C(2100000000000000);
    frozen.redemption_delay_parent_blocks = 1008;
    for (size_t i = 0; i < frozen.custodian_encryption_keys.size(); ++i) {
        frozen.custodian_encryption_keys[i].fill(50 + i);
        frozen.custodian_attestation_keys[i].fill(60 + i);
    }
    frozen.usdd_asset_id = CAsset(uint256S("37"));
    std::copy(
        nums_internal_key.begin(), nums_internal_key.end(),
        frozen.keyless_internal_key.begin());
    frozen.genesis_mark_price = 1;
}

CBlockIndex IndexFor(const CBlock& block, int height, CBlockIndex* previous = nullptr)
{
    CBlockIndex index{block};
    index.nHeight = height;
    index.pprev = previous;
    return index;
}

uint256 TestSha256(const std::vector<unsigned char>& bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

uint256 TestTaggedHash(const std::string& tag, const std::vector<unsigned char>& bytes)
{
    const uint256 tag_hash{TestSha256(
        std::vector<unsigned char>(tag.begin(), tag.end()))};
    uint256 result;
    CSHA256 hasher;
    hasher.Write(tag_hash.begin(), 32).Write(tag_hash.begin(), 32);
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

CScript TestBondV2SuccessorScript(
    const ecx::ExchangeConsensus& consensus,
    const uint256& covenant_state_hash)
{
    std::vector<unsigned char> state_node_preimage;
    state_node_preimage.insert(
        state_node_preimage.end(),
        consensus.bond_v2.state_node_domain_sha256.begin(),
        consensus.bond_v2.state_node_domain_sha256.end());
    state_node_preimage.insert(
        state_node_preimage.end(), covenant_state_hash.begin(), covenant_state_hash.end());
    const uint256 state_node{TestSha256(state_node_preimage)};

    const auto leaf_hash = [](const uint256& cmr) {
        std::vector<unsigned char> payload{TAPROOT_LEAF_TAPSIMPLICITY, 32};
        payload.insert(payload.end(), cmr.begin(), cmr.end());
        return TestTaggedHash("TapLeaf/elements", payload);
    };
    const auto branch_hash = [](const uint256& left, const uint256& right) {
        std::vector<unsigned char> payload;
        if (std::lexicographical_compare(
                left.begin(), left.end(), right.begin(), right.end())) {
            payload.insert(payload.end(), left.begin(), left.end());
            payload.insert(payload.end(), right.begin(), right.end());
        } else {
            payload.insert(payload.end(), right.begin(), right.end());
            payload.insert(payload.end(), left.begin(), left.end());
        }
        return TestTaggedHash("TapBranch/elements", payload);
    };
    const uint256 transition_leaf{leaf_hash(consensus.bond_v2.transition_cmr)};
    const uint256 activation_leaf{
        leaf_hash(consensus.bond_v2.incremental_activation_cmr)};
    const uint256 activation_or_state{branch_hash(activation_leaf, state_node)};
    const uint256 root{branch_hash(transition_leaf, activation_or_state)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return {};
    return CScript() << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
}

CScript TestBondV2IncrementalSuccessorScript(
    const ecx::ExchangeConsensus& consensus,
    const uint256& successor_state_root)
{
    std::vector<unsigned char> state_node_preimage;
    state_node_preimage.insert(
        state_node_preimage.end(),
        consensus.bond_v2.incremental_successor_state_node_domain_sha256.begin(),
        consensus.bond_v2.incremental_successor_state_node_domain_sha256.end());
    state_node_preimage.insert(
        state_node_preimage.end(), successor_state_root.begin(), successor_state_root.end());
    const uint256 state_node{TestSha256(state_node_preimage)};

    std::vector<unsigned char> leaf_preimage{TAPROOT_LEAF_TAPSIMPLICITY, 32};
    leaf_preimage.insert(
        leaf_preimage.end(),
        consensus.bond_v2.incremental_successor_transition_cmr.begin(),
        consensus.bond_v2.incremental_successor_transition_cmr.end());
    const uint256 transition_leaf{TestTaggedHash("TapLeaf/elements", leaf_preimage)};
    std::vector<unsigned char> branch_preimage;
    if (std::lexicographical_compare(
            transition_leaf.begin(), transition_leaf.end(),
            state_node.begin(), state_node.end())) {
        branch_preimage.insert(
            branch_preimage.end(), transition_leaf.begin(), transition_leaf.end());
        branch_preimage.insert(branch_preimage.end(), state_node.begin(), state_node.end());
    } else {
        branch_preimage.insert(branch_preimage.end(), state_node.begin(), state_node.end());
        branch_preimage.insert(
            branch_preimage.end(), transition_leaf.begin(), transition_leaf.end());
    }
    const uint256 root{TestTaggedHash("TapBranch/elements", branch_preimage)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return {};
    return CScript() << OP_1 << std::vector<unsigned char>(
        tweaked->first.begin(), tweaked->first.end());
}

void TestPushU32Be(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back((value >> 24) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back(value & 0xff);
}

void TestPushU64Be(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back((value >> shift) & 0xff);
    }
}

void TestPushU128Be(
    std::vector<unsigned char>& bytes,
    uint64_t high,
    uint64_t low)
{
    TestPushU64Be(bytes, high);
    TestPushU64Be(bytes, low);
}

void TestAppendFill(
    std::vector<unsigned char>& bytes,
    unsigned char value,
    size_t count = 32)
{
    bytes.insert(bytes.end(), count, value);
}

struct AnnexVerifierRecorder
{
    unsigned int calls{0};
    bool reject{false};
};

bool TestSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    auto& recorder{*static_cast<AnnexVerifierRecorder*>(context)};
    ++recorder.calls;
    if (proof_len != ECX_SP1_GROTH16_PROOF_LEN) return false;
    for (size_t i = 0; i < proof_len; ++i) {
        if (proof[i] != 0xa5) return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (program_id_words[i] != i + 1) return false;
    }
    const std::vector<unsigned char> expected_hash{
        ParseHex("8d6dfa4aa7f674825e7d237028b78c242fbc127b59a8b152599e59c8e11522df")};
    return !recorder.reject && std::equal(
        expected_hash.begin(), expected_hash.end(), public_values_sha256);
}

bool TestIncrementalActivationSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    auto& recorder{*static_cast<AnnexVerifierRecorder*>(context)};
    ++recorder.calls;
    if (proof_len != ECX_SP1_GROTH16_PROOF_LEN) return false;
    for (size_t i = 0; i < proof_len; ++i) {
        if (proof[i] != 0xa5) return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (program_id_words[i] != i + 1) return false;
    }
    const std::vector<unsigned char> expected_hash{ParseHex(
        "5cc1295a4757282f49662e61cc2b20eec325418c17807da9c35548cb9b4951c2")};
    return !recorder.reject && std::equal(
        expected_hash.begin(), expected_hash.end(), public_values_sha256);
}

bool TestIncrementalSuccessorSp1Verifier(
    void* context,
    const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
    size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32])
{
    auto& recorder{*static_cast<AnnexVerifierRecorder*>(context)};
    ++recorder.calls;
    if (proof_len != ECX_SP1_GROTH16_PROOF_LEN) return false;
    for (size_t i = 0; i < proof_len; ++i) {
        if (proof[i] != 0xa5) return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (program_id_words[i] != i + 1) return false;
    }
    const std::vector<unsigned char> expected_hash{ParseHex(
        "97af54a6584a6453f697b1099ecf42eb68ebc3b7228e0a908a345f1328a9b706")};
    return !recorder.reject && std::equal(
        expected_hash.begin(), expected_hash.end(), public_values_sha256);
}

std::vector<unsigned char> BondV2PublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(850);
    TestAppendFill(values, 1);
    TestPushU32Be(values, 5);
    for (unsigned char value = 2; value <= 7; ++value) TestAppendFill(values, value);
    TestPushU64Be(values, 8);
    TestPushU64Be(values, 9);
    for (unsigned char value = 10; value <= 16; ++value) TestAppendFill(values, value);
    TestPushU128Be(values, 0, 1000);
    TestPushU64Be(values, 100);
    TestPushU128Be(values, 0, 1000000000);
    TestPushU128Be(values, 0, 800);
    TestPushU128Be(values, 0, 1000);
    TestPushU128Be(values, 0, 12500);
    values.push_back(0);
    TestPushU64Be(values, 23);
    TestPushU64Be(values, 24);
    TestPushU64Be(values, 25);
    TestPushU32Be(values, static_cast<uint32_t>(-26));
    TestPushU64Be(values, 27);
    TestPushU64Be(values, 28);
    TestPushU64Be(values, 29);
    TestAppendFill(values, 17);       // oracle certificate
    TestPushU64Be(values, 30);       // valid-through parent MTP
    values.push_back(0);             // oracle Normal
    TestAppendFill(values, 18);      // next encrypted availability
    TestAppendFill(values, 19);      // inbox head
    TestPushU64Be(values, 4);        // inbox entry count
    TestAppendFill(values, 20);      // processed root
    TestPushU64Be(values, 3);        // processed cursor
    TestAppendFill(values, 21);      // outcome root
    TestPushU64Be(values, 3);        // outcome count
    TestAppendFill(values, 22);      // execution receipt batch root
    TestPushU64Be(values, 5);        // previous execution sequence
    TestPushU64Be(values, 6);        // next execution sequence
    BOOST_REQUIRE_EQUAL(values.size(), 850U);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "8d6dfa4aa7f674825e7d237028b78c242fbc127b59a8b152599e59c8e11522df");
    return values;
}

std::vector<unsigned char> TestSp1AnnexPayload(bool v2)
{
    const std::vector<unsigned char> values{BondV2PublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0};
    annex.push_back(v2 ? 4 : 2);
    annex.push_back(2);
    annex.push_back(1);
    annex.push_back(0);
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    if (v2) annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), v2 ? 1285U : 435U);
    return annex;
}

std::vector<unsigned char> IncrementalActivationPublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN);
    TestPushU32Be(values, 1);
    for (unsigned char value = 1; value <= 10; ++value) {
        TestAppendFill(values, value);
    }
    TestPushU64Be(values, 11);
    TestPushU64Be(values, 12);
    TestPushU64Be(values, 100);
    TestPushU64Be(values, 90);
    TestPushU64Be(values, 110);
    BOOST_REQUIRE_EQUAL(
        values.size(), ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "5cc1295a4757282f49662e61cc2b20eec325418c17807da9c35548cb9b4951c2");
    return values;
}

std::vector<unsigned char> TestIncrementalActivationAnnexPayload()
{
    const std::vector<unsigned char> values{
        IncrementalActivationPublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0, 5, 2, 1, 0};
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), 799U);
    return annex;
}

std::vector<unsigned char> IncrementalSuccessorPublicValuesVector()
{
    std::vector<unsigned char> values;
    values.reserve(ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
    TestPushU32Be(values, 23);
    for (unsigned char value = 1; value <= 40; ++value) {
        TestAppendFill(values, value);
    }
    for (uint64_t value : {
             UINT64_C(30), UINT64_C(31), UINT64_C(32), UINT64_C(100),
             UINT64_C(90), UINT64_C(110), UINT64_C(2100000000000000),
             UINT64_C(100), UINT64_C(2099999999999900), UINT64_C(28),
             UINT64_C(0), UINT64_C(31)}) {
        TestPushU64Be(values, value);
    }
    TestPushU128Be(values, UINT64_MAX, UINT64_MAX - 32); // signed i128 -33
    for (uint64_t value : {
             8, 7, 8, 10, 9, 1000, 34, 9000000, 11250, 26, 27, 40, 39, 38}) {
        TestPushU128Be(values, 0, value);
    }
    TestPushU32Be(values, UINT32_MAX - 99); // signed i32 -100
    values.push_back(1); // reduce-only
    values.push_back(0); // normal oracle
    values.push_back(1); // operationally safe
    BOOST_REQUIRE_EQUAL(
        values.size(), ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
    BOOST_REQUIRE_EQUAL(
        HexStr(TestSha256(values)),
        "97af54a6584a6453f697b1099ecf42eb68ebc3b7228e0a908a345f1328a9b706");
    return values;
}

std::vector<unsigned char> TestIncrementalSuccessorAnnexPayload()
{
    const std::vector<unsigned char> values{
        IncrementalSuccessorPublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    std::vector<unsigned char> annex{'E', 'C', 'X', 'S', 'P', '1', 0, 6, 2, 1, 0};
    for (uint32_t word = 1; word <= 8; ++word) TestPushU32Be(annex, word);
    annex.insert(annex.end(), values_hash.begin(), values_hash.end());
    TestPushU32Be(annex, ECX_SP1_GROTH16_PROOF_LEN);
    annex.insert(annex.end(), ECX_SP1_GROTH16_PROOF_LEN, 0xa5);
    annex.insert(annex.end(), values.begin(), values.end());
    BOOST_REQUIRE_EQUAL(annex.size(), 2062U);
    return annex;
}

void RecommitIncrementalSuccessorPublicValues(std::vector<unsigned char>& annex)
{
    BOOST_REQUIRE_EQUAL(annex.size(), 2062U);
    const std::vector<unsigned char> values(annex.begin() + 435, annex.end());
    const uint256 hash{TestSha256(values)};
    std::copy(hash.begin(), hash.end(), annex.begin() + 43);
}

void RecommitV2PublicValues(std::vector<unsigned char>& annex)
{
    BOOST_REQUIRE_EQUAL(annex.size(), 1285U);
    const std::vector<unsigned char> values(annex.begin() + 435, annex.end());
    const uint256 hash{TestSha256(values)};
    std::copy(hash.begin(), hash.end(), annex.begin() + 43);
}

bool StrictlyParsesV2(const std::vector<unsigned char>& annex)
{
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 32> digest{};
    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> values{};
    return simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
        annex.data(), annex.size(), program.data(), digest.data(), values.data());
}

void TestPushU64Le(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int shift = 0; shift <= 56; shift += 8) {
        bytes.push_back((value >> shift) & 0xff);
    }
}

void TestPushU32Le(std::vector<unsigned char>& bytes, uint32_t value)
{
    for (int shift = 0; shift <= 24; shift += 8) bytes.push_back((value >> shift) & 0xff);
}

void TestPushBitcoinOutput(
    std::vector<unsigned char>& bytes,
    uint64_t amount,
    const CScript& script)
{
    TestPushU64Le(bytes, amount);
    BOOST_REQUIRE(script.size() < 253);
    bytes.push_back(script.size());
    bytes.insert(bytes.end(), script.begin(), script.end());
}

std::vector<unsigned char> TestM6(
    uint32_t checkpoint_height,
    const uint256& previous_hash,
    const uint256& state_root,
    unsigned char anchor_mutation = 0)
{
    const uint256 withdrawal_commitment{uint256S("77")};
    std::vector<unsigned char> anchor_payload{1, 24};
    const uint256 child_genesis{Params().GetConsensus().hashGenesisBlock};
    anchor_payload.insert(anchor_payload.end(), child_genesis.begin(), child_genesis.end());
    TestPushU32Be(anchor_payload, checkpoint_height);
    anchor_payload.insert(anchor_payload.end(), previous_hash.begin(), previous_hash.end());
    anchor_payload.insert(anchor_payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    anchor_payload.insert(anchor_payload.end(), state_root.begin(), state_root.end());
    uint256 anchor{TestTaggedHash("ECX/perps-m6-state/v1", anchor_payload)};
    anchor.begin()[0] ^= anchor_mutation;
    const CScript fee = CScript() << OP_RETURN << std::vector<unsigned char>(8, 0);
    const CScript inputs = CScript() << OP_RETURN <<
        std::vector<unsigned char>(withdrawal_commitment.begin(), withdrawal_commitment.end());
    const CScript payout = CScript() << OP_TRUE;
    std::vector<unsigned char> pxst{'P', 'X', 'S', 'T', 1};
    pxst.insert(pxst.end(), anchor.begin(), anchor.end());
    const CScript state = CScript() << OP_RETURN << pxst;
    std::vector<unsigned char> bytes;
    TestPushU32Le(bytes, 2);
    bytes.push_back(0);
    bytes.push_back(4);
    TestPushBitcoinOutput(bytes, 0, fee);
    TestPushBitcoinOutput(bytes, 0, inputs);
    TestPushBitcoinOutput(bytes, 1000, payout);
    TestPushBitcoinOutput(bytes, 0, state);
    TestPushU32Le(bytes, 0);
    return bytes;
}

CTransactionRef TestCoinbase(const std::optional<CScript>& commitment = std::nullopt)
{
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout.SetNull();
    transaction.vin[0].scriptSig = CScript() << 1 << OP_0;
    if (commitment.has_value()) {
        transaction.vout.emplace_back(::policyAsset, 0, *commitment);
    }
    transaction.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN);
    return MakeTransactionRef(std::move(transaction));
}

CTxOut CursorMarker(uint64_t forced_cursor, uint64_t deposit_cursor)
{
    std::vector<unsigned char> payload{'E', 'C', 'X', 'C', 1};
    TestPushU64Le(payload, forced_cursor);
    TestPushU64Le(payload, deposit_cursor);
    return CTxOut(::policyAsset, 0, CScript() << OP_RETURN << payload);
}

uint256 RawHash(const std::string& hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 32);
    uint256 result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

CKey TestTraderKey()
{
    const std::array<unsigned char, 32> secret{{
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32}};
    CKey key;
    key.Set(secret.begin(), secret.end(), true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

std::vector<unsigned char> SignedCancelBody(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key)
{
    static constexpr std::array<unsigned char, 16> market{{
        'E', 'C', 'X', '-', 'U', 'S', 'D', 'D', '-', 'P', 'E', 'R', 'P', 0, 0, 0}};
    const XOnlyPubKey trader{key.GetPubKey()};
    std::vector<unsigned char> body;
    body.reserve(201);
    body.push_back(1);
    body.insert(body.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    body.insert(body.end(), market.begin(), market.end());
    body.insert(body.end(), trader.begin(), trader.end());
    body.insert(body.end(), 32, 0x55);
    TestPushU64Be(body, 7);
    TestPushU64Be(body, 100);
    TestPushU64Be(body, 200);
    BOOST_REQUIRE_EQUAL(body.size(), 137);
    std::array<unsigned char, 64> signature{};
    BOOST_REQUIRE(key.SignSchnorr(
        TestTaggedHash("ECX/cancel-order/v1", body),
        Span<unsigned char>(signature),
        nullptr,
        uint256{}));
    body.insert(body.end(), signature.begin(), signature.end());
    BOOST_REQUIRE_EQUAL(body.size(), 201);
    return body;
}

CMutableTransaction ForcedCancelTransaction(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key,
    bool corrupt_signature = false)
{
    std::vector<unsigned char> body{SignedCancelBody(consensus, key)};
    if (corrupt_signature) body[137] ^= 1;
    std::vector<unsigned char> payload{'E', 'C', 'X', 'F', 1, 0};
    payload.push_back((body.size() >> 8) & 0xff);
    payload.push_back(body.size() & 0xff);
    payload.insert(payload.end(), body.begin(), body.end());
    CMutableTransaction tx;
    tx.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN << payload);
    return tx;
}

CMutableTransaction ConfidentialDepositTransaction(
    const ecx::ExchangeConsensus& consensus,
    const CKey& key,
    bool include_proofs = true)
{
    const XOnlyPubKey trader{key.GetPubKey()};
    CTxOut deposit;
    deposit.nAsset.vchCommitment.assign(33, 0x41);
    deposit.nAsset.vchCommitment[0] = 10;
    deposit.nValue.vchCommitment.assign(33, 0x42);
    deposit.nValue.vchCommitment[0] = 8;
    deposit.nNonce.vchCommitment.assign(33, 0x43);
    deposit.nNonce.vchCommitment[0] = 2;
    deposit.scriptPubKey = consensus.collateral_vault_script;

    std::vector<unsigned char> marker{'E', 'C', 'X', 'D', 1};
    marker.insert(marker.end(), consensus.chain_id.begin(), consensus.chain_id.end());
    TestPushU32Be(marker, 0);
    marker.insert(marker.end(), trader.begin(), trader.end());
    BOOST_REQUIRE_EQUAL(marker.size(), 73);

    CMutableTransaction tx;
    tx.vout.push_back(std::move(deposit));
    tx.vout.emplace_back(::policyAsset, 0, CScript() << OP_RETURN << marker);
    tx.witness.vtxoutwit.resize(2);
    if (include_proofs) {
        tx.witness.vtxoutwit[0].vchRangeproof = {0x51};
        tx.witness.vtxoutwit[0].vchSurjectionproof = {0x52};
    }
    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ecx_exchange_state_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(tapbranch_ordering_uses_serialized_hash_bytes_not_arithmetic_value)
{
    uint256 serialized_first;
    serialized_first.begin()[31] = 1;
    uint256 serialized_second;
    serialized_second.begin()[0] = 1;

    // TapBranch/elements sorts the 32 serialized bytes.  These values are
    // intentionally ordered the other way when interpreted as little-endian
    // integers, so a future UintToArith256 conversion cannot silently pass.
    BOOST_CHECK(serialized_first < serialized_second);
    BOOST_CHECK(UintToArith256(serialized_second) <
                UintToArith256(serialized_first));
}

BOOST_AUTO_TEST_CASE(finite_state_tree_preauthorizes_incremental_activation_leaf)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    std::fill(
        consensus.bond_v2.transition_cmr.begin(),
        consensus.bond_v2.transition_cmr.end(), 0x11);
    const uint256 covenant_state_hash{uint256S("1234")};
    CScript production;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(
        consensus, covenant_state_hash, production));
    BOOST_CHECK_EQUAL(
        HexStr(production),
        HexStr(TestBondV2SuccessorScript(consensus, covenant_state_hash)));

    ecx::ExchangeConsensus changed{consensus};
    changed.bond_v2.incremental_activation_cmr.begin()[0] ^= 1;
    CScript changed_script;
    BOOST_REQUIRE(ecx::ComputeBondV2FiniteStateScript(
        changed, covenant_state_hash, changed_script));
    BOOST_CHECK_NE(HexStr(production), HexStr(changed_script));
}

BOOST_AUTO_TEST_CASE(frozen_configuration_v18_exact_rust_vector_and_mutations)
{
    static constexpr size_t COLLATERAL_COVENANT_CMR_OFFSET{1232};
    static constexpr size_t ECX_ASSET_OFFSET{50};
    static constexpr size_t USDD_ASSET_OFFSET{82};
    static constexpr size_t STATE_AUTHORITY_ASSET_OFFSET{146};
    static constexpr size_t TRUTHCOIN_ANCHOR_AUTHORITY_OFFSET{722};
    static constexpr size_t AVAILABILITY_SCHEME_OFFSET{293};
    static constexpr size_t MATCHER_FORCED_INCLUSION_BLOCKS_OFFSET{1128};
    static constexpr size_t STAGING_TEMPLATE_OFFSET{1392};
    static constexpr size_t STAGING_RENDERER_DOMAIN_OFFSET{1424};
    static constexpr size_t STAGING_INTERNAL_KEY_OFFSET{1456};
    static constexpr size_t INSURANCE_COVENANT_CMR_OFFSET{1589};
    static constexpr size_t INBOX_INCLUSION_BLOCKS_OFFSET{1717};
    const std::vector<unsigned char> bytes{ParseHex(ECX_V18_CONFIGURATION_HEX)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 1977U);
    BOOST_REQUIRE_EQUAL(bytes[0], 5U);
    BOOST_REQUIRE_EQUAL(bytes[1], 3U);

    uint256 configuration_hash;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ValidateBondV2FrozenConfigurationV18(
            bytes, configuration_hash, error),
        error);
    BOOST_CHECK_EQUAL(
        HexStr(configuration_hash),
        "ec2c8cdb6a538079fb7a1b6688476c03476e7ecf2bd0114ab49a1a6a246ade1e");
    BOOST_CHECK_EQUAL(
        configuration_hash,
        TestTaggedHash(
            "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
            bytes));

    const auto rejects = [&](std::vector<unsigned char> candidate) {
        uint256 rejected_hash;
        std::string rejection;
        BOOST_CHECK(!ecx::ValidateBondV2FrozenConfigurationV18(
            candidate, rejected_hash, rejection));
        BOOST_CHECK(rejected_hash.IsNull());
        BOOST_CHECK(!rejection.empty());
    };
    std::vector<unsigned char> wrong_outer_version{bytes};
    wrong_outer_version[0] = 4;
    rejects(std::move(wrong_outer_version));
    std::vector<unsigned char> wrong_base_version{bytes};
    wrong_base_version[1] = 4;
    rejects(std::move(wrong_base_version));
    std::vector<unsigned char> ecx_equals_usdd{bytes};
    std::copy(
        ecx_equals_usdd.begin() + ECX_ASSET_OFFSET,
        ecx_equals_usdd.begin() + ECX_ASSET_OFFSET + 32,
        ecx_equals_usdd.begin() + USDD_ASSET_OFFSET);
    rejects(std::move(ecx_equals_usdd));
    std::vector<unsigned char> anchor_equals_state_authority{bytes};
    std::copy(
        anchor_equals_state_authority.begin() + STATE_AUTHORITY_ASSET_OFFSET,
        anchor_equals_state_authority.begin() + STATE_AUTHORITY_ASSET_OFFSET + 32,
        anchor_equals_state_authority.begin() + TRUTHCOIN_ANCHOR_AUTHORITY_OFFSET);
    rejects(std::move(anchor_equals_state_authority));
    std::vector<unsigned char> wrong_availability_scheme{bytes};
    wrong_availability_scheme[AVAILABILITY_SCHEME_OFFSET] ^= 1;
    rejects(std::move(wrong_availability_scheme));
    std::vector<unsigned char> wrong_matcher_forced_window{bytes};
    wrong_matcher_forced_window[MATCHER_FORCED_INCLUSION_BLOCKS_OFFSET + 3] ^= 1;
    rejects(std::move(wrong_matcher_forced_window));
    std::vector<unsigned char> zero_collateral_cmr{bytes};
    std::fill(
        zero_collateral_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET,
        zero_collateral_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET + 32,
        0);
    rejects(std::move(zero_collateral_cmr));
    std::vector<unsigned char> zero_reserve_cmr{bytes};
    std::fill(
        zero_reserve_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET,
        zero_reserve_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET + 32,
        0);
    rejects(std::move(zero_reserve_cmr));
    std::vector<unsigned char> duplicate_cmr{bytes};
    std::copy(
        duplicate_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET,
        duplicate_cmr.begin() + COLLATERAL_COVENANT_CMR_OFFSET + 32,
        duplicate_cmr.begin() + INSURANCE_COVENANT_CMR_OFFSET);
    rejects(std::move(duplicate_cmr));
    std::vector<unsigned char> wrong_template{bytes};
    wrong_template[STAGING_TEMPLATE_OFFSET] ^= 1;
    rejects(std::move(wrong_template));
    std::vector<unsigned char> wrong_renderer_domain{bytes};
    wrong_renderer_domain[STAGING_RENDERER_DOMAIN_OFFSET + 31] ^= 1;
    rejects(std::move(wrong_renderer_domain));
    std::vector<unsigned char> wrong_internal_key{bytes};
    wrong_internal_key[STAGING_INTERNAL_KEY_OFFSET] ^= 1;
    rejects(std::move(wrong_internal_key));
    std::vector<unsigned char> wrong_inclusion_limit{bytes};
    wrong_inclusion_limit[INBOX_INCLUSION_BLOCKS_OFFSET + 3] ^= 1;
    rejects(std::move(wrong_inclusion_limit));
    std::vector<unsigned char> trailing{bytes};
    trailing.push_back(0);
    rejects(std::move(trailing));
    std::vector<unsigned char> truncated{bytes};
    truncated.pop_back();
    rejects(std::move(truncated));

    // V17 is retained only as a historical fixture and is never accepted by
    // the live V18 decoder, even if its former tagged digest is known.
    rejects(ParseHex(ECX_V17_CONFIGURATION_HEX));
}

BOOST_AUTO_TEST_CASE(v18_no_history_staging_renderer_matches_rust_vector)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    consensus.chain_id.fill(1);
    consensus.bond_v2.configuration_hash = RawHash(
        "e931a255224cf33a6a5fa701ceb164e95a17e5c0bb5ac8ab4e4c5ba0728b7363");
    consensus.bond_v2.bond_inbox_redemption_staging_template_commitment =
        RawHash("35eacbcd9ff74d6e37e505f1458b7cbd631a126d437c7a09d50e66eec56f9e56");
    consensus.bond_v2.bond_inbox_redemption_staging_renderer_domain =
        RawHash("d8ca7883769dd73830987f727a34939d2d9b69a3e783e0a2e1cca35fa4872e6f");
    consensus.bond_v2.bond_inbox_redemption_staging_process_cmr =
        RawHash("1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e");
    consensus.bond_v2.bond_inbox_redemption_staging_refund_cmr =
        RawHash("2020202020202020202020202020202020202020202020202020202020202020");
    const uint256 signer{RawHash(
        "e7e9acacbdb43fc9fb71a8db1536c0f866caa78def49f666fa121a6f7954bb01")};
    const uint256 intent{RawHash(
        "3737373737373737373737373737373737373737373737373737373737373737")};
    const uint256 refund_script{RawHash(
        "3838383838383838383838383838383838383838383838383838383838383838")};
    ecx::BondInboxStagingRenderV18 rendered;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::RenderBondInboxStagingV18(
            signer, intent, 0, refund_script, 1012, rendered, error, consensus),
        error);
    BOOST_CHECK_EQUAL(HexStr(rendered.process_leaf_hash),
        "3fe278e4460370d1ebd1f082504e72ee7d390b2cd0281a58466092a9d0593130");
    BOOST_CHECK_EQUAL(HexStr(rendered.refund_leaf_hash),
        "8a8a8991b79c63483ba9b7bca2ab3738a34ea819d560d520f744d4e83883c778");
    BOOST_CHECK_EQUAL(HexStr(rendered.hidden_node_hash),
        "b9ac34936211f599aa2f0a108936605f9621085b88b80f60ac826e0e7b27e874");
    BOOST_CHECK_EQUAL(HexStr(rendered.lower_branch_hash),
        "e032812b4ac93f75dcf8f2ca08d8d042971802174c055cb6359327f0b8b4389f");
    BOOST_CHECK_EQUAL(HexStr(rendered.top_branch_hash),
        "affa0246f1d6235d5feac1537d8fcd12fa695bea29812c6c39d52c981f32c5d5");
    BOOST_CHECK_EQUAL(HexStr(rendered.script_pubkey),
        "512024fb6e85f3cb2f7a399ce3c62897330d353ddf49aa4e5f2c53ec55e6ef93ba80");
    BOOST_CHECK_EQUAL(HexStr(TestSha256(std::vector<unsigned char>(
        rendered.script_pubkey.begin(), rendered.script_pubkey.end()))),
        "4385ee863343948312e1ac68dbf9e3b9aaa64825ee5bc0723d24cd4f1de1ba0e");

    ecx::ExchangeConsensus wrong_domain{consensus};
    wrong_domain.bond_v2.bond_inbox_redemption_staging_renderer_domain.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, wrong_domain));
    ecx::ExchangeConsensus key_path_bypass{consensus};
    key_path_bypass.bond_v2.bond_inbox_redemption_staging_internal_key.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, key_path_bypass));
    ecx::ExchangeConsensus swapped{consensus};
    std::swap(
        swapped.bond_v2.bond_inbox_redemption_staging_process_cmr,
        swapped.bond_v2.bond_inbox_redemption_staging_refund_cmr);
    BOOST_REQUIRE(ecx::RenderBondInboxStagingV18(
        signer, intent, 0, refund_script, 1012, rendered, error, swapped));
    BOOST_CHECK_NE(HexStr(rendered.script_pubkey),
        "512024fb6e85f3cb2f7a399ce3c62897330d353ddf49aa4e5f2c53ec55e6ef93ba80");
}

BOOST_AUTO_TEST_CASE(sp1_v5_annex_binds_exact_public_values_and_preserves_v1)
{
    const std::vector<unsigned char> values{BondV2PublicValuesVector()};
    const uint256 values_hash{TestSha256(values)};
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    AnnexVerifierRecorder recorder;
    const std::vector<unsigned char> v2{TestSp1AnnexPayload(true)};
    BOOST_CHECK_EQUAL(
        HexStr(TestSha256(v2)),
        "f5c241fd10f4b0593dc43ad39232e98038a43a39007ae527087fefd14942b57d");
    std::vector<unsigned char> wire_v2{0x50};
    wire_v2.insert(wire_v2.end(), v2.begin(), v2.end());
    BOOST_CHECK_EQUAL(
        HexStr(TestSha256(wire_v2)),
        "71d92946400fd6bd70c3f358eb65ba6b067a0e18cf644154a6ddbc5cc47c302b");
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        v2.data(), v2.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> bad_values{v2};
    bad_values[435] ^= 1;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        bad_values.data(), bad_values.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> bad_mode{v2};
    bad_mode[435 + 556] = 3;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        bad_mode.data(), bad_mode.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> trailing{v2};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        trailing.data(), trailing.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::vector<unsigned char> duplicate{v2};
    duplicate.insert(duplicate.end(), values.begin(), values.end());
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        duplicate.data(), duplicate.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    const std::vector<unsigned char> v1{TestSp1AnnexPayload(false)};
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        v1.data(), v1.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_annex_sha256(
        v1.data(), v1.size(), expected_program.data(), values_hash.begin(),
        TestSp1Verifier, &recorder, false));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);

    std::vector<unsigned char> wrong_version{v2};
    wrong_version[7] = 2;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
        wrong_version.data(), wrong_version.size(), expected_program.data(),
        values_hash.begin(), TestSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_incremental_activation_annex_is_disjoint_and_fail_closed)
{
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> values{
        IncrementalActivationPublicValuesVector()};
    const uint256 digest{TestSha256(values)};
    const std::vector<unsigned char> annex{TestIncrementalActivationAnnexPayload()};
    std::array<unsigned char, 32> parsed_program{};
    std::array<unsigned char, 32> parsed_digest{};
    std::array<unsigned char, ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN>
        parsed_values{};
    AnnexVerifierRecorder recorder;

    BOOST_REQUIRE(simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));
    BOOST_CHECK(std::equal(
        expected_program.begin(), expected_program.end(), parsed_program.begin()));
    BOOST_CHECK(std::equal(digest.begin(), digest.end(), parsed_digest.begin()));
    BOOST_CHECK(std::equal(values.begin(), values.end(), parsed_values.begin()));
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalActivationSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::array<unsigned char, ECX_SP1_PUBLIC_VALUES_V5_LEN> normal_values{};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        normal_values.data()));
    const std::vector<unsigned char> normal{TestSp1AnnexPayload(true)};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        normal.data(), normal.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    std::vector<unsigned char> bad_semantics{annex};
    bad_semantics[435 + 348] = 0;
    bad_semantics[435 + 349] = 0;
    bad_semantics[435 + 350] = 0;
    bad_semantics[435 + 351] = 0;
    bad_semantics[435 + 352] = 0;
    bad_semantics[435 + 353] = 0;
    bad_semantics[435 + 354] = 0;
    bad_semantics[435 + 355] = 101;
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        bad_semantics.data(), bad_semantics.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));

    std::vector<unsigned char> wrong_digest{annex};
    wrong_digest[43] ^= 1;
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        wrong_digest.data(), wrong_digest.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> wrong_version{annex};
    wrong_version[7] = 4;
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        wrong_version.data(), wrong_version.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        trailing.data(), trailing.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));

    recorder.reject = true;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalActivationSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_incremental_successor_annex_is_exact_disjoint_and_fail_closed)
{
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> values{
        IncrementalSuccessorPublicValuesVector()};
    const uint256 digest{TestSha256(values)};
    const std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    std::array<unsigned char, 32> parsed_program{};
    std::array<unsigned char, 32> parsed_digest{};
    std::array<unsigned char, ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN>
        parsed_values{};
    AnnexVerifierRecorder recorder;

    BOOST_REQUIRE(simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));
    BOOST_CHECK(std::equal(
        expected_program.begin(), expected_program.end(), parsed_program.begin()));
    BOOST_CHECK(std::equal(digest.begin(), digest.end(), parsed_digest.begin()));
    BOOST_CHECK(std::equal(values.begin(), values.end(), parsed_values.begin()));
    BOOST_REQUIRE(simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalSuccessorSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);

    std::array<unsigned char, ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN>
        activation_values{};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        annex.data(), annex.size(), parsed_program.data(), parsed_digest.data(),
        activation_values.data()));
    const std::vector<unsigned char> activation{TestIncrementalActivationAnnexPayload()};
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        activation.data(), activation.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    const size_t values_offset{435};
    const size_t scalar_offset{values_offset + 4 + 40 * 32};
    const size_t wide_offset{scalar_offset + 12 * 8 + 16};
    const auto recommit = [](std::vector<unsigned char>& candidate) {
        const std::vector<unsigned char> public_values{
            candidate.begin() + 435, candidate.end()};
        const uint256 hash{TestSha256(public_values)};
        std::copy(hash.begin(), hash.end(), candidate.begin() + 43);
    };
    std::vector<unsigned char> wrong_deficit{annex};
    wrong_deficit[wide_offset + 32 + 15] = 9;
    recommit(wrong_deficit);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        wrong_deficit.data(), wrong_deficit.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> wrong_mode{annex};
    wrong_mode[values_offset + 1624] = 0;
    recommit(wrong_mode);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        wrong_mode.data(), wrong_mode.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    std::vector<unsigned char> noncanonical_bool{annex};
    noncanonical_bool.back() = 2;
    recommit(noncanonical_bool);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        noncanonical_bool.data(), noncanonical_bool.size(), parsed_program.data(),
        parsed_digest.data(), parsed_values.data()));
    for (const auto& mutation : std::vector<std::pair<size_t, unsigned char>>{
             {scalar_offset + 48 + 7, 1},       // fixed issued supply
             {wide_offset + 112 + 15, 1},       // NAV
             {wide_offset + 144 + 15, 28},      // queue head > tail
             {wide_offset + 192 + 15, 41},      // inbox cursor > count
             {scalar_offset + 80 + 7, 1},       // funding epoch
             {values_offset + 1625, 4},         // oracle mode
         }) {
        std::vector<unsigned char> candidate{annex};
        candidate[mutation.first] = mutation.second;
        recommit(candidate);
        BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
            candidate.data(), candidate.size(), parsed_program.data(),
            parsed_digest.data(), parsed_values.data()));
    }
    std::vector<unsigned char> trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        trailing.data(), trailing.size(), parsed_program.data(), parsed_digest.data(),
        parsed_values.data()));

    recorder.reject = true;
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
        annex.data(), annex.size(), expected_program.data(), digest.begin(),
        TestIncrementalSuccessorSp1Verifier, &recorder));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(sp1_incremental_successor_jet_frame_routes_to_exact_verifier)
{
    // This tests the real frame adapter and annex parser. The recorder is a
    // test callback, not a substitute for the separately qualified SP1 backend.
    const std::array<unsigned char, 32> expected_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    const std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    const uint256 digest{TestSha256(IncrementalSuccessorPublicValuesVector())};
    AnnexVerifierRecorder recorder;
    const auto evaluate = [&](const std::vector<unsigned char>& candidate,
                              const std::array<unsigned char, 32>& program,
                              const uint256& public_values_digest,
                              bool backend_present = true) {
        bool valid{false};
        BOOST_REQUIRE(ecx_test_successor_jet_frame(
            candidate.data(), candidate.size(), program.data(), public_values_digest.begin(),
            backend_present ? TestIncrementalSuccessorSp1Verifier : nullptr, &recorder, &valid));
        return valid;
    };
    BOOST_CHECK(evaluate(annex, expected_program, digest));
    BOOST_CHECK_EQUAL(recorder.calls, 1U);
    auto wrong_program{expected_program};
    wrong_program[0] ^= 1;
    BOOST_CHECK(!evaluate(annex, wrong_program, digest));
    uint256 wrong_digest{digest};
    wrong_digest.begin()[0] ^= 1;
    BOOST_CHECK(!evaluate(annex, expected_program, wrong_digest));
    BOOST_CHECK(!evaluate(annex, expected_program, digest, false));
    BOOST_CHECK(!evaluate({}, expected_program, digest));
    BOOST_CHECK(!evaluate(TestIncrementalActivationAnnexPayload(), expected_program, digest));
    auto truncated{annex};
    truncated.pop_back();
    BOOST_CHECK(!evaluate(truncated, expected_program, digest));
    auto trailing{annex};
    trailing.push_back(0);
    BOOST_CHECK(!evaluate(trailing, expected_program, digest));
    auto bad_bool{annex};
    bad_bool.back() = 2;
    const uint256 recommitted{TestSha256(std::vector<unsigned char>{bad_bool.begin() + 435, bad_bool.end()})};
    std::copy(recommitted.begin(), recommitted.end(), bad_bool.begin() + 43);
    BOOST_CHECK(!evaluate(bad_bool, expected_program, recommitted));
    BOOST_CHECK_EQUAL(recorder.calls, 1U); // Parser/identity failures never reach the backend.
    recorder.reject = true;
    BOOST_CHECK(!evaluate(annex, expected_program, digest));
    BOOST_CHECK_EQUAL(recorder.calls, 2U);
}

BOOST_AUTO_TEST_CASE(incremental_successor_projection_script_and_u128_snapshot_are_exact)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const auto fill = [](uint256& value, unsigned char byte) {
        std::fill(value.begin(), value.end(), byte);
    };
    const std::array<unsigned char, 32> successor_program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(successor_program.begin(), successor_program.end(),
        consensus.bond_v2.incremental_successor_program_id.begin());
    fill(consensus.bond_v2.incremental_successor_configuration_hash, 1);
    fill(consensus.bond_v2.configuration_hash, 13);
    consensus.chain_id.fill(14);
    fill(consensus.bond_v2.bond_asset_id, 15);
    fill(consensus.bond_v2.bond_deployment_commitment, 16);
    fill(consensus.bond_v2.inventory_covenant_script_sha256, 17);
    fill(consensus.bond_v2.transition_program_id, 80);
    fill(consensus.bond_v2.transition_journal_domain_sha256, 77);
    fill(consensus.bond_v2.transition_cmr, 78);
    fill(consensus.bond_v2.identity_derivation_record_sha256, 79);

    std::vector<unsigned char> annex{TestIncrementalSuccessorAnnexPayload()};
    const size_t public_values_offset{435};
    const size_t wide_offset{4 + 40 * 32 + 112};
    for (const size_t field_offset : {
             size_t{96},  // matcher execution sequence
             size_t{176}, // inbox entry count
             size_t{192}, // inbox processed cursor
             size_t{208}, // inbox outcome count
         }) {
        annex[public_values_offset + wide_offset + field_offset + 7] = 1;
    }
    RecommitIncrementalSuccessorPublicValues(annex);

    ecx::BondV2CapitalSnapshot snapshot;
    std::string error;
    const uint256 active_root{uint256S("52")};
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
            annex, active_root, snapshot, error, consensus),
        error);
    BOOST_CHECK_EQUAL(snapshot.version, ecx::BOND_V2_CAPITAL_SNAPSHOT_VERSION);
    BOOST_CHECK_EQUAL(snapshot.proof_profile, 1U);
    BOOST_CHECK(snapshot.exchange_state_root == active_root);
    BOOST_CHECK(snapshot.configuration_hash ==
        consensus.bond_v2.incremental_successor_configuration_hash);
    uint256 expected_outcome_root;
    uint256 expected_availability_root;
    fill(expected_outcome_root, 25);
    fill(expected_availability_root, 8);
    BOOST_CHECK(snapshot.bond_inbox_outcome_root == expected_outcome_root);
    BOOST_CHECK(snapshot.encrypted_availability_root == expected_availability_root);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == snapshot.bond_inbox_head_root);
    BOOST_CHECK(!snapshot.matcher_execution_sequence.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_entry_count.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_processed_cursor.FitsU64());
    BOOST_CHECK(!snapshot.bond_inbox_outcome_count.FitsU64());

    CScript rendered;
    BOOST_REQUIRE(ecx::ComputeBondV2IncrementalSuccessorScript(
        consensus, snapshot.covenant_state_hash, rendered));
    BOOST_CHECK(rendered == TestBondV2IncrementalSuccessorScript(
        consensus, snapshot.covenant_state_hash));
    BOOST_CHECK(rendered != TestBondV2SuccessorScript(
        consensus, snapshot.covenant_state_hash));

    CDataStream serialized{SER_DISK, 0};
    serialized << snapshot;
    ecx::BondV2CapitalSnapshot round_trip;
    serialized >> round_trip;
    BOOST_CHECK(round_trip.matcher_execution_sequence ==
        snapshot.matcher_execution_sequence);
    BOOST_CHECK(round_trip.bond_inbox_entry_count == snapshot.bond_inbox_entry_count);
    BOOST_CHECK(round_trip.bond_inbox_processed_cursor ==
        snapshot.bond_inbox_processed_cursor);
    BOOST_CHECK(round_trip.bond_inbox_outcome_count ==
        snapshot.bond_inbox_outcome_count);

    std::vector<unsigned char> changed_outcome{annex};
    changed_outcome[public_values_offset + 4 + 24 * 32] ^= 0x80;
    RecommitIncrementalSuccessorPublicValues(changed_outcome);
    ecx::BondV2CapitalSnapshot changed_snapshot;
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
            changed_outcome, active_root, changed_snapshot, error, consensus),
        error);
    BOOST_CHECK(changed_snapshot.bond_inbox_outcome_root !=
        snapshot.bond_inbox_outcome_root);

    std::vector<unsigned char> wrong_configuration{annex};
    wrong_configuration[public_values_offset + 4] ^= 1;
    RecommitIncrementalSuccessorPublicValues(wrong_configuration);
    BOOST_CHECK(!ecx::DecodeBondV2IncrementalSuccessorCapitalProjection(
        wrong_configuration, active_root, changed_snapshot, error, consensus));
    BOOST_CHECK(error.find("frozen program/configuration/deployment") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(incremental_successor_empty_block_preserves_u128_inbox_projection)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    ecx::BondV2CapitalSnapshot snapshot;
    snapshot.proof_profile = 1;
    snapshot.node_bond_inbox_head_root = uint256S("52");
    snapshot.bond_inbox_head_root = snapshot.node_bond_inbox_head_root;
    snapshot.node_bond_inbox_entry_count.bytes[7] = 1;
    snapshot.node_bond_inbox_entry_count.bytes[15] = 9;
    snapshot.bond_inbox_entry_count = snapshot.node_bond_inbox_entry_count;
    const ecx::BigEndianUint128 expected_count{
        snapshot.node_bond_inbox_entry_count};
    const uint256 expected_head{snapshot.node_bond_inbox_head_root};
    CBlock block;
    std::vector<ecx::BondInboxSourceExport> exported;
    std::string error;

    BOOST_REQUIRE_MESSAGE(
        ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, 51, 101, snapshot, error, consensus, &exported),
        error);
    BOOST_CHECK(exported.empty());
    BOOST_CHECK(snapshot.node_bond_inbox_head_root == expected_head);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count == expected_count);
    BOOST_CHECK(!snapshot.node_bond_inbox_entry_count.FitsU64());

    snapshot.proof_profile = 0;
    BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
        block, 51, 101, snapshot, error, consensus));
    BOOST_CHECK(error.find("no canonical predecessor") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(incremental_successor_accepts_real_rust_crypto_source_vector)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const auto assign_array = [](std::array<unsigned char, 32>& target,
                                 const char* raw_hex) {
        const std::vector<unsigned char> bytes{ParseHex(raw_hex)};
        BOOST_REQUIRE_EQUAL(bytes.size(), target.size());
        std::copy(bytes.begin(), bytes.end(), target.begin());
    };
    const auto assign_hash = [](uint256& target, const char* raw_hex) {
        const std::vector<unsigned char> bytes{ParseHex(raw_hex)};
        BOOST_REQUIRE_EQUAL(bytes.size(), target.size());
        std::copy(bytes.begin(), bytes.end(), target.begin());
    };
    assign_array(consensus.chain_id, ECX_SUCCESSOR_BOND_INBOX_V23_CHAIN_ID);
    auto& frozen{consensus.bond_v2};
    assign_hash(
        frozen.configuration_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_CONFIGURATION_HASH);
    assign_hash(frozen.bond_asset_id, ECX_SUCCESSOR_BOND_INBOX_V23_BOND_ASSET);
    assign_hash(
        frozen.bond_inbox_redemption_staging_internal_key,
        ECX_SUCCESSOR_BOND_INBOX_V23_STAGING_INTERNAL_KEY);
    assign_hash(
        frozen.bond_inbox_redemption_staging_process_cmr,
        ECX_SUCCESSOR_BOND_INBOX_V23_PROCESS_CMR);
    assign_hash(
        frozen.bond_inbox_redemption_staging_refund_cmr,
        ECX_SUCCESSOR_BOND_INBOX_V23_REFUND_CMR);
    assign_hash(
        frozen.availability_scheme_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_AVAILABILITY_SCHEME);
    assign_hash(
        frozen.availability_custodian_registry_hash,
        ECX_SUCCESSOR_BOND_INBOX_V23_AVAILABILITY_REGISTRY);
    const std::array<const char*, 5> encryption_keys{{
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_1_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_2_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_3_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_4_ENCRYPTION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_5_ENCRYPTION}};
    const std::array<const char*, 5> attestation_keys{{
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_1_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_2_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_3_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_4_ATTESTATION,
        ECX_SUCCESSOR_BOND_INBOX_V23_CUSTODIAN_5_ATTESTATION}};
    for (size_t index = 0; index < encryption_keys.size(); ++index) {
        assign_array(frozen.custodian_encryption_keys[index], encryption_keys[index]);
        assign_array(frozen.custodian_attestation_keys[index], attestation_keys[index]);
    }
    struct PolicyAssetRestore {
        CAsset original{::policyAsset};
        ~PolicyAssetRestore() { ::policyAsset = original; }
    } policy_asset_restore;
    ::policyAsset = CAsset(RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET));
    BOOST_REQUIRE_MESSAGE(
        ::policyAsset.id == RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET),
        "actual policy asset bytes=" << HexStr(::policyAsset.id) <<
        " vector bytes=" << ECX_SUCCESSOR_BOND_INBOX_V23_POLICY_ASSET);

    const std::vector<unsigned char> source_bytes{
        ParseHex(ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_HEX)};
    BOOST_REQUIRE_EQUAL(
        source_bytes.size(), ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_LEN);
    uint256 source_sha256;
    CSHA256().Write(source_bytes.data(), source_bytes.size())
        .Finalize(source_sha256.begin());
    BOOST_CHECK(source_sha256 ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TRANSACTION_SHA256));
    CDataStream source_stream(source_bytes, SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction source;
    source_stream >> source;
    BOOST_REQUIRE(source_stream.empty());
    const CTransaction immutable_source{source};
    BOOST_CHECK(immutable_source.GetHash() ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TXID));
    BOOST_CHECK(immutable_source.GetWitnessHash() ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_WTXID));

    const auto initial_snapshot = [] {
        ecx::BondV2CapitalSnapshot snapshot;
        snapshot.proof_profile = 1;
        snapshot.node_bond_inbox_head_root = uint256S("52");
        snapshot.bond_inbox_head_root = snapshot.node_bond_inbox_head_root;
        // The frozen Rust vector starts at (u64::MAX + 1) << 32 == 2^96.
        snapshot.node_bond_inbox_entry_count.bytes[3] = 1;
        snapshot.bond_inbox_entry_count = snapshot.node_bond_inbox_entry_count;
        return snapshot;
    };
    ecx::BondV2CapitalSnapshot snapshot{initial_snapshot()};
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(source));
    std::vector<ecx::BondInboxSourceExport> exported;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            block, 10, 1000, snapshot, error, consensus, &exported),
        error);
    BOOST_REQUIRE_EQUAL(exported.size(), 1U);
    BOOST_CHECK_EQUAL(exported[0].proof_profile, 1U);
    BOOST_CHECK(exported[0].entry_index_u128 ==
        initial_snapshot().node_bond_inbox_entry_count);
    BOOST_CHECK_EQUAL(exported[0].canonical_entry.size(), 708U);
    BOOST_CHECK(exported[0].source_transaction == source_bytes);
    BOOST_CHECK(exported[0].source_txid ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_TXID));
    BOOST_CHECK(exported[0].source_wtxid ==
        RawHash(ECX_SUCCESSOR_BOND_INBOX_V23_WTXID));
    BOOST_CHECK_EQUAL(exported[0].marker_vout, 1U);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count.bytes[3] == 1);
    BOOST_CHECK(snapshot.node_bond_inbox_entry_count.bytes[15] == 1);
    BOOST_CHECK(snapshot.node_bond_inbox_head_root != uint256S("52"));

    const auto rejects = [&](CMutableTransaction mutated,
                             const std::string& expected_error) {
        CBlock rejected_block;
        rejected_block.vtx.push_back(MakeTransactionRef(std::move(mutated)));
        ecx::BondV2CapitalSnapshot rejected_snapshot{initial_snapshot()};
        std::string rejected_error;
        BOOST_CHECK(!ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
            rejected_block, 10, 1000, rejected_snapshot, rejected_error,
            consensus));
        BOOST_CHECK_MESSAGE(
            rejected_error.find(expected_error) != std::string::npos,
            rejected_error);
        BOOST_CHECK(rejected_snapshot.node_bond_inbox_head_root == uint256S("52"));
        BOOST_CHECK(rejected_snapshot.node_bond_inbox_entry_count ==
            initial_snapshot().node_bond_inbox_entry_count);
    };

    CMutableTransaction bad_receipt{source};
    BOOST_REQUIRE_EQUAL(
        bad_receipt.witness.vtxinwit[0].scriptWitness.stack.size(), 2U);
    bad_receipt.witness.vtxinwit[0].scriptWitness.stack[1].back() ^= 1;
    rejects(std::move(bad_receipt), "receipt evidence is invalid");

    CMutableTransaction bad_marker_signature{source};
    bad_marker_signature.vout[1].scriptPubKey.back() ^= 1;
    rejects(std::move(bad_marker_signature), "wrapper signature is invalid");

    CMutableTransaction historical_marker_version{source};
    // OP_RETURN PUSHDATA2 length occupies four bytes; byte four is the
    // successor marker version and must never accept the finite-V18 value.
    historical_marker_version.vout[1].scriptPubKey[8] = 1;
    rejects(std::move(historical_marker_version), "exact minimal-PUSHDATA2");
}

BOOST_AUTO_TEST_CASE(sp1_v2_public_capital_semantics_fail_closed)
{
    const std::vector<unsigned char> valid{TestSp1AnnexPayload(true)};
    BOOST_REQUIRE(StrictlyParsesV2(valid));

    const auto rejects_recommitted_mutation = [&valid](
        size_t offset,
        const std::vector<unsigned char>& replacement) {
        std::vector<unsigned char> candidate{valid};
        BOOST_REQUIRE(offset + replacement.size() <= 850U);
        std::copy(
            replacement.begin(), replacement.end(),
            candidate.begin() + 435 + offset);
        RecommitV2PublicValues(candidate);
        BOOST_CHECK(!StrictlyParsesV2(candidate));
    };
    const auto be64 = [](uint64_t value) {
        std::vector<unsigned char> bytes;
        TestPushU64Be(bytes, value);
        return bytes;
    };
    const auto be128 = [](uint64_t high, uint64_t low) {
        std::vector<unsigned char> bytes;
        TestPushU128Be(bytes, high, low);
        return bytes;
    };

    rejects_recommitted_mutation(524, be128(0, 999));       // ceil(125%)
    rejects_recommitted_mutation(540, be128(0, 12499));     // coverage
    rejects_recommitted_mutation(492, be128(0, 999999999)); // NAV
    rejects_recommitted_mutation(484, be64(2100000000000001)); // supply
    rejects_recommitted_mutation(556, std::vector<unsigned char>{1}); // derived mode
    rejects_recommitted_mutation(557, be64(0));               // zero minimum
    rejects_recommitted_mutation(557, be64(24));              // equal bounds
    rejects_recommitted_mutation(585, be64(29));             // head > tail
    rejects_recommitted_mutation(601, be64(101));            // queued > outstanding
    rejects_recommitted_mutation(601, be64(0));              // nonempty queue/zero aggregate
    rejects_recommitted_mutation(593, be64(27));              // empty indices/nonzero aggregate
    rejects_recommitted_mutation(
        581, std::vector<unsigned char>{0, 0, 0x27, 0x11});  // +10001 ppm
    rejects_recommitted_mutation(
        581, std::vector<unsigned char>{0xff, 0xff, 0xd8, 0xef}); // -10001 ppm
    for (const size_t hash_offset : {
             0U, 36U, 68U, 100U, 132U, 164U, 196U,
             244U, 276U, 308U, 340U, 372U, 404U, 436U,
             609U, 650U, 682U, 722U, 762U, 802U}) {
        rejects_recommitted_mutation(
            hash_offset, std::vector<unsigned char>(32, 0));
    }
    rejects_recommitted_mutation(228, be64(0));              // parent height
    rejects_recommitted_mutation(236, be64(0));              // parent MTP
    rejects_recommitted_mutation(641, be64(8));              // stale oracle
    rejects_recommitted_mutation(649, std::vector<unsigned char>{4}); // oracle mode
    rejects_recommitted_mutation(714, be64(2));              // cursor > entry count
    rejects_recommitted_mutation(794, be64(2));              // outcome count != cursor
    rejects_recommitted_mutation(842, be64(4));              // execution rollback

    // Both products below overflow a naive u128 multiply. Exact division is
    // nevertheless representable and must accept the same vector as Rust:
    // reserve == deficit == NAV == 2^120, coverage 10000, mode ReduceOnly.
    std::vector<unsigned char> large_valid{valid};
    const std::vector<unsigned char> two_to_120{
        be128(UINT64_C(0x0100000000000000), 0)};
    const std::vector<unsigned char> five_two_to_118{
        be128(UINT64_C(0x0140000000000000), 0)};
    const std::vector<unsigned char> one_share{be64(100000000)};
    const std::vector<unsigned char> ten_thousand{be128(0, 10000)};
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 468);
    std::copy(one_share.begin(), one_share.end(), large_valid.begin() + 435 + 484);
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 492);
    std::copy(two_to_120.begin(), two_to_120.end(), large_valid.begin() + 435 + 508);
    std::copy(five_two_to_118.begin(), five_two_to_118.end(), large_valid.begin() + 435 + 524);
    std::copy(ten_thousand.begin(), ten_thousand.end(), large_valid.begin() + 435 + 540);
    large_valid[435 + 556] = 1;
    RecommitV2PublicValues(large_valid);
    BOOST_CHECK(StrictlyParsesV2(large_valid));

    // A naive reserve*10000 overflows here. The exact overflow-safe division
    // path must reject instead of wrapping into a plausible coverage value.
    std::vector<unsigned char> extreme{valid};
    const std::vector<unsigned char> max_i128{
        be128(0x7fff'ffff'ffff'ffffULL, 0xffff'ffff'ffff'ffffULL)};
    const std::vector<unsigned char> one128{be128(0, 1)};
    const std::vector<unsigned char> two128{be128(0, 2)};
    const std::vector<unsigned char> zero128{be128(0, 0)};
    const std::vector<unsigned char> zero64{be64(0)};
    std::copy(
        max_i128.begin(), max_i128.end(),
        extreme.begin() + 435 + 468);
    std::copy(one128.begin(), one128.end(), extreme.begin() + 435 + 508);
    std::copy(two128.begin(), two128.end(), extreme.begin() + 435 + 524);
    std::copy(zero64.begin(), zero64.end(), extreme.begin() + 435 + 484);
    std::copy(zero128.begin(), zero128.end(), extreme.begin() + 435 + 492);
    RecommitV2PublicValues(extreme);
    BOOST_CHECK(!StrictlyParsesV2(extreme));

    std::vector<unsigned char> high_bit_reserve{valid};
    high_bit_reserve[435 + 468] = 0x80;
    RecommitV2PublicValues(high_bit_reserve);
    BOOST_CHECK(!StrictlyParsesV2(high_bit_reserve));

    std::vector<unsigned char> high_bit_deficit{valid};
    high_bit_deficit[435 + 508] = 0x80;
    RecommitV2PublicValues(high_bit_deficit);
    BOOST_CHECK(!StrictlyParsesV2(high_bit_deficit));

    std::vector<unsigned char> zero_deficit{valid};
    std::copy(zero128.begin(), zero128.end(), zero_deficit.begin() + 435 + 508);
    std::copy(zero128.begin(), zero128.end(), zero_deficit.begin() + 435 + 524);
    std::copy(ten_thousand.begin(), ten_thousand.end(), zero_deficit.begin() + 435 + 540);
    zero_deficit[435 + 540 + 14] = 0x30;
    zero_deficit[435 + 540 + 15] = 0xd4; // exact 12,500 sentinel
    RecommitV2PublicValues(zero_deficit);
    BOOST_CHECK(StrictlyParsesV2(zero_deficit));
    zero_deficit[435 + 540 + 15] ^= 1;
    RecommitV2PublicValues(zero_deficit);
    BOOST_CHECK(!StrictlyParsesV2(zero_deficit));
}

BOOST_AUTO_TEST_CASE(bond_v2_projection_is_frozen_and_activation_fails_closed)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const std::array<unsigned char, 32> program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(program.begin(), program.end(),
        consensus.bond_v2.transition_program_id.begin());
    std::fill(consensus.bond_v2.configuration_hash.begin(),
        consensus.bond_v2.configuration_hash.end(), 2);
    std::fill(consensus.bond_v2.bond_asset_id.begin(),
        consensus.bond_v2.bond_asset_id.end(), 11);
    std::fill(consensus.bond_v2.bond_deployment_commitment.begin(),
        consensus.bond_v2.bond_deployment_commitment.end(), 12);
    std::fill(consensus.bond_v2.transition_journal_domain_sha256.begin(),
        consensus.bond_v2.transition_journal_domain_sha256.end(), 1);
    std::fill(consensus.bond_v2.transition_cmr.begin(),
        consensus.bond_v2.transition_cmr.end(), 17);
    std::fill(consensus.bond_v2.identity_derivation_record_sha256.begin(),
        consensus.bond_v2.identity_derivation_record_sha256.end(), 18);

    ecx::BondV2CapitalSnapshot snapshot;
    std::string error;
    const std::vector<unsigned char> annex{TestSp1AnnexPayload(true)};
    BOOST_REQUIRE_MESSAGE(
        ecx::DecodeBondV2CapitalProjection(
            annex, uint256S("52"), snapshot, error, consensus),
        error);
    BOOST_CHECK_EQUAL(snapshot.version, 4U);
    BOOST_CHECK_EQUAL(snapshot.outstanding_share_atoms, 100U);
    BOOST_CHECK_EQUAL(snapshot.capital_mode, 0U);
    BOOST_CHECK_EQUAL(snapshot.funding_epoch, 25U);
    BOOST_CHECK_EQUAL(snapshot.redemption_head, 27U);
    BOOST_CHECK_EQUAL(snapshot.redemption_tail, 28U);
    BOOST_CHECK_EQUAL(snapshot.queued_redemption_share_atoms, 29U);
    BOOST_CHECK(std::all_of(
        snapshot.legacy_fee_pool.begin(), snapshot.legacy_fee_pool.end(),
        [](unsigned char byte) { return byte == 0; }));

    ecx::ExchangeConsensus substituted{consensus};
    substituted.bond_v2.configuration_hash.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("source-frozen") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.identity_derivation_record_sha256.SetNull();
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("identity derivation") != std::string::npos);

    using FrozenIdentity = ecx::ExchangeConsensus::BondV2FrozenConsensus;
    for (uint256 FrozenIdentity::* field : {
             &FrozenIdentity::incremental_activation_program_id,
             &FrozenIdentity::incremental_activation_configuration_hash,
             &FrozenIdentity::incremental_activation_cmr,
             &FrozenIdentity::incremental_successor_program_id,
             &FrozenIdentity::incremental_successor_configuration_hash,
             &FrozenIdentity::incremental_successor_transition_cmr,
             &FrozenIdentity::incremental_successor_state_node_domain_sha256,
         }) {
        substituted = consensus;
        (substituted.bond_v2.*field).SetNull();
        BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
            annex, uint256S("52"), snapshot, error, substituted));
        BOOST_CHECK(error.find("missing frozen ECX bond V2") != std::string::npos);
    }

    substituted = consensus;
    substituted.bond_v2.incremental_activation_configuration_hash =
        substituted.bond_v2.configuration_hash;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("configurations collide") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.incremental_successor_program_id =
        substituted.bond_v2.transition_program_id;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("proof program identity collides") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.incremental_successor_transition_cmr =
        substituted.bond_v2.transition_cmr;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("covenant CMR roles collide") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.keyless_internal_key[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("physical activation inputs") != std::string::npos);

    substituted = consensus;
    substituted.bond_v2.bond_inbox_redemption_staging_internal_key.begin()[0] ^= 1;
    BOOST_CHECK(!ecx::DecodeBondV2CapitalProjection(
        annex, uint256S("52"), snapshot, error, substituted));
    BOOST_CHECK(error.find("physical activation inputs") != std::string::npos);

    CBlock activation;
    activation.hashExchangeStateRoot = consensus.genesis_state_root;
    MemoryCoinsView activation_base;
    CCoinsViewCache activation_view{&activation_base};
    BOOST_CHECK(!ecx::DeriveBondV2CapitalProjectionAfterScripts(
        activation,
        nullptr,
        activation_view,
        consensus.activation_height,
        uint256S("53"),
        1,
        2,
        snapshot,
        error,
        consensus));
    BOOST_CHECK(error.find("physical deployment/genesis linkage") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bond_v2_projection_follows_each_verified_reorg_branch)
{
    ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        50, COutPoint{uint256S("50"), 0}, uint256S("51"))};
    PopulateTestBondV2FrozenIdentities(consensus);
    const std::array<unsigned char, 32> program{{
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8}};
    std::copy(program.begin(), program.end(), consensus.bond_v2.transition_program_id.begin());
    std::fill(consensus.bond_v2.configuration_hash.begin(), consensus.bond_v2.configuration_hash.end(), 2);
    std::fill(consensus.bond_v2.bond_asset_id.begin(), consensus.bond_v2.bond_asset_id.end(), 11);
    std::fill(consensus.bond_v2.bond_deployment_commitment.begin(), consensus.bond_v2.bond_deployment_commitment.end(), 12);
    std::fill(consensus.bond_v2.transition_journal_domain_sha256.begin(), consensus.bond_v2.transition_journal_domain_sha256.end(), 1);
    std::fill(consensus.bond_v2.transition_cmr.begin(), consensus.bond_v2.transition_cmr.end(), 17);
    std::fill(consensus.bond_v2.identity_derivation_record_sha256.begin(), consensus.bond_v2.identity_derivation_record_sha256.end(), 18);

    CBlock previous_block;
    std::fill(previous_block.hashExchangeStateRoot.begin(), previous_block.hashExchangeStateRoot.end(), 6);
    CBlockIndex previous{IndexFor(previous_block, 50)};
    ecx::BondV2CapitalSnapshot previous_capital;
    previous_capital.exchange_state_root = previous.hashExchangeStateRoot;
    previous_capital.configuration_hash = consensus.bond_v2.configuration_hash;
    previous_capital.bond_asset_id = consensus.bond_v2.bond_asset_id;
    previous_capital.bond_deployment_commitment = consensus.bond_v2.bond_deployment_commitment;
    previous_capital.transition_program_id = consensus.bond_v2.transition_program_id;
    previous_capital.transition_cmr = consensus.bond_v2.transition_cmr;
    std::fill(
        previous_capital.covenant_state_hash.begin(),
        previous_capital.covenant_state_hash.end(), 3);
    std::fill(
        previous_capital.node_bond_inbox_head_root.begin(),
        previous_capital.node_bond_inbox_head_root.end(), 19);
    previous_capital.node_bond_inbox_entry_count = 4;
    previous_capital.matcher_execution_sequence = 5;
    previous.ecxBondV2Capital = previous_capital;
    uint256 parent_hash;
    std::fill(parent_hash.begin(), parent_hash.end(), 7);
    MemoryCoinsView projection_base;
    CCoinsViewCache projection_view{&projection_base};

    const auto branch = [&](unsigned char script_byte) {
        CMutableTransaction mutable_tx;
        mutable_tx.vin.emplace_back(COutPoint{uint256S("60"), 0});
        mutable_tx.vout.push_back(AuthorityOutput(0x60));
        std::vector<unsigned char> annex{TestSp1AnnexPayload(true)};
        uint256 next_covenant_state_hash;
        std::copy(
            annex.begin() + 435 + 100,
            annex.begin() + 435 + 132,
            next_covenant_state_hash.begin());
        mutable_tx.vout[0].scriptPubKey =
            TestBondV2SuccessorScript(consensus, next_covenant_state_hash);
        BOOST_REQUIRE(!mutable_tx.vout[0].scriptPubKey.empty());
        // A branch-specific non-state output changes txid/outpoint while the
        // same proven next covenant state remains committed at output zero.
        mutable_tx.vout.push_back(AuthorityOutput(script_byte));
        const CTransaction without_witness{mutable_tx};
        std::copy(
            without_witness.GetHash().begin(), without_witness.GetHash().end(),
            annex.begin() + 435 + 132);
        RecommitV2PublicValues(annex);
        std::vector<unsigned char> wire_annex{0x50};
        wire_annex.insert(wire_annex.end(), annex.begin(), annex.end());
        mutable_tx.witness.vtxinwit.resize(1);
        mutable_tx.witness.vtxinwit[0].scriptWitness.stack = {
            std::vector<unsigned char>{0}, std::move(wire_annex)};
        CBlock block;
        block.vtx = {MakeTransactionRef(std::move(mutable_tx))};
        block.hashExchangeStateRoot = ecx::ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            COutPoint{block.vtx[0]->GetHash(), 0},
            block.vtx[0]->vout[0]);
        ecx::BondV2CapitalSnapshot projection;
        std::string error;
        BOOST_REQUIRE_MESSAGE(
            ecx::DeriveBondV2CapitalProjectionAfterScripts(
                block, &previous, projection_view, 51, parent_hash, 8, 9,
                projection, error, consensus),
            error);
        BOOST_CHECK_EQUAL(projection.exchange_state_root, block.hashExchangeStateRoot);
        return std::make_pair(block, projection);
    };

    const auto left{branch(0x61)};
    const auto right{branch(0x62)};
    BOOST_CHECK(left.second.exchange_state_root != right.second.exchange_state_root);

    CBlockIndex left_index{IndexFor(left.first, 51, &previous)};
    left_index.ecxBondV2Capital = left.second;
    CBlock carry;
    carry.hashExchangeStateRoot = left.first.hashExchangeStateRoot;
    ecx::BondV2CapitalSnapshot carried;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::DeriveBondV2CapitalProjectionAfterScripts(
            carry, &left_index, projection_view, 52, parent_hash, 8, 9,
            carried, error, consensus),
        error);
    BOOST_CHECK_EQUAL(carried.exchange_state_root, left.second.exchange_state_root);
    BOOST_CHECK(carried.exchange_state_root != right.second.exchange_state_root);
}

BOOST_AUTO_TEST_CASE(inbox_simplicity_context_presence_is_tristate)
{
    PrecomputedTransactionData txdata;
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 0);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 0);
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 0);

    txdata.m_prior_active_forced_inbox_root = uint256S("01");
    txdata.m_prior_active_deposit_processed_cursor = 0;
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 2);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 2);

    txdata.m_prior_active_forced_processed_cursor = 0;
    txdata.m_prior_active_deposit_inbox_root = uint256S("02");
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 1);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 1);

    txdata.m_prior_active_bond_inbox_root = uint256S("03");
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);
    txdata.m_prior_active_bond_inbox_count = 0;
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);
    txdata.m_current_sidechain_height = 101;
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 1);
    txdata.m_current_sidechain_height.reset();
    BOOST_CHECK_EQUAL(txdata.EcxBondV2ProjectionPresence(), 2);

    txdata.m_prior_active_forced_inbox_root.reset();
    txdata.m_prior_active_deposit_processed_cursor.reset();
    BOOST_CHECK_EQUAL(txdata.EcxForcedInboxPresence(), 2);
    BOOST_CHECK_EQUAL(txdata.EcxDepositInboxPresence(), 2);
}

BOOST_AUTO_TEST_CASE(header_rules_cover_before_activation_boundary_and_descendants)
{
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        10,
        COutPoint{uint256S("11"), 7},
        uint256S("22"))};
    std::string error;

    CBlockHeader before;
    before.nVersion = 0x20000000;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(before, 9, error, consensus),
        error);
    before.nVersion |= CBlockHeader::EXCHANGE_STATE_HF_MASK;
    before.hashExchangeStateRoot = uint256S("03");
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(before, 9, error, consensus));
    BOOST_CHECK(error.find("forbidden before activation") != std::string::npos);

    CBlockHeader activation;
    activation.nVersion = 0x20000000 |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = consensus.genesis_state_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 1;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(activation, 10, error, consensus),
        error);
    CBlockIndex persisted_activation{activation};
    persisted_activation.nHeight = 10;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateIndexHeader(
            persisted_activation, error, consensus),
        error);

    CBlockHeader wrong_activation{activation};
    wrong_activation.hashExchangeStateRoot = uint256S("04");
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(
        wrong_activation, 10, error, consensus));
    BOOST_CHECK(error.find("frozen genesis roots") != std::string::npos);

    CBlockHeader descendant{activation};
    descendant.hashExchangeStateRoot = uint256S("05");
    descendant.hashForcedInboxRoot = uint256S("06");
    descendant.hashDepositInboxRoot = uint256S("07");
    descendant.forcedProcessedCursor = 8;
    descendant.depositProcessedCursor = 9;
    descendant.sourceBacklogOldestParentHeight = 1;
    BOOST_CHECK_MESSAGE(
        ecx::CheckExchangeStateHeader(descendant, 11, error, consensus),
        error);
    descendant.nVersion &= ~CBlockHeader::DEPOSIT_INBOX_HF_MASK;
    BOOST_CHECK(!ecx::CheckExchangeStateHeader(descendant, 11, error, consensus));
    BOOST_CHECK(error.find("required and nonzero") != std::string::npos);
    CBlockIndex persisted_descendant{descendant};
    persisted_descendant.nHeight = 11;
    BOOST_CHECK(!ecx::CheckExchangeStateIndexHeader(
        persisted_descendant, error, consensus));
    BOOST_CHECK(error.find("required and nonzero") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(consensus_rejects_spends_of_all_synthetic_state_outpoints)
{
    MemoryCoinsView base;
    CCoinsViewCache view(&base);
    const std::vector<COutPoint> reserved{
        COutPoint{
            uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9"),
            0},
        COutPoint{
            uint256S("2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1"),
            0},
    };
    BOOST_REQUIRE(drivechain::IsBmmStateInternalOutpoint(reserved[0]));
    BOOST_REQUIRE(drivechain::IsCtipStateInternalOutpoint(reserved[1]));

    for (const COutPoint& outpoint : reserved) {
        for (const bool script_checks : {false, true}) {
            CMutableTransaction mutable_transaction;
            mutable_transaction.vin.emplace_back(outpoint);
            const CTransaction transaction{mutable_transaction};
            TxValidationState state;
            CAmountMap fees;
            std::set<std::pair<uint256, COutPoint>> pegins;
            BOOST_CHECK(!Consensus::CheckTxInputs(
                transaction,
                state,
                view,
                1,
                fees,
                pegins,
                nullptr,
                false,
                script_checks,
                {}));
            BOOST_CHECK_EQUAL(
                state.GetRejectReason(),
                "bad-drivechain-internal-state-spend");
        }
    }

    const std::vector<COutPoint> all_reserved{
        COutPoint{
            uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041"),
            0},
        COutPoint{
            uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1"),
            0},
        COutPoint{
            uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"),
            0},
        reserved[0],
        reserved[1],
    };
    for (size_t index = 0; index < 3; ++index) {
        for (const bool script_checks : {false, true}) {
            CMutableTransaction mutable_transaction;
            mutable_transaction.vin.emplace_back(all_reserved[index]);
            const CTransaction transaction{mutable_transaction};
            TxValidationState state;
            CAmountMap fees;
            std::set<std::pair<uint256, COutPoint>> pegins;
            BOOST_CHECK(!Consensus::CheckTxInputs(
                transaction,
                state,
                view,
                1,
                fees,
                pegins,
                nullptr,
                false,
                script_checks,
                {}));
            BOOST_CHECK_EQUAL(
                state.GetRejectReason(),
                "bad-ecx-internal-state-spend");
        }
    }
    for (const COutPoint& outpoint : all_reserved) {
        const ecx::ExchangeConsensus consensus{
            ConfiguredConsensus(10, outpoint, uint256S("22"))};
        CBlockHeader header;
        std::string error;
        BOOST_CHECK(!ecx::CheckExchangeStateHeader(header, 10, error, consensus));
        BOOST_CHECK(error.find("collides with a reserved chainstate record") !=
                    std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(runtime_consensus_fingerprint_binds_every_field)
{
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(
        10,
        COutPoint{uint256S("11"), 7},
        uint256S("22"))};
    const std::string network_id{"elementsregtest"};
    const uint256 genesis_hash{uint256S("33")};
    const uint256 policy_asset{uint256S("44")};
    const uint256 bmm_fingerprint{uint256S("55")};
    const auto compute = [&](
                             const ecx::ExchangeConsensus& value,
                             const std::string& network,
                             const uint256& genesis,
                             const uint256& policy,
                             const uint256& bmm,
                             const bool private_bmm_enabled,
                             const uint32_t private_bmm_activation_height) {
        return ecx::ComputeRuntimeConsensusFingerprint(
            value,
            network,
            genesis,
            policy,
            bmm,
            private_bmm_enabled,
            private_bmm_activation_height);
    };
    const auto compute_default = [&](const ecx::ExchangeConsensus& value) {
        return compute(
            value,
            network_id,
            genesis_hash,
            policy_asset,
            bmm_fingerprint,
            true,
            20);
    };
    const uint256 expected{compute_default(consensus)};
    BOOST_CHECK_EQUAL(
        expected,
        compute_default(consensus));

    const auto check_consensus_mutation = [&](auto mutate) {
        ecx::ExchangeConsensus changed{consensus};
        mutate(changed);
        BOOST_CHECK_NE(expected, compute_default(changed));
    };
    check_consensus_mutation([](auto& value) { ++value.activation_height; });
    check_consensus_mutation([](auto& value) { value.genesis_state_outpoint.hash = uint256S("12"); });
    check_consensus_mutation([](auto& value) { ++value.genesis_state_outpoint.n; });
    check_consensus_mutation([](auto& value) { value.genesis_state_root = uint256S("23"); });
    check_consensus_mutation([](auto& value) { value.chain_id[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.forced_action_domain[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.deposit_inbox_domain[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.collateral_vault_script.push_back(OP_TRUE); });
    check_consensus_mutation([](auto& value) { value.collateral_vault_script_hash.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_activation_program_id.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_activation_configuration_hash.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_activation_cmr.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_successor_program_id.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_successor_configuration_hash.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_successor_transition_cmr.begin()[0] ^= 1; });
    check_consensus_mutation([](auto& value) { value.bond_v2.incremental_successor_state_node_domain_sha256.begin()[0] ^= 1; });

    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, bmm_fingerprint, false, 0));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, bmm_fingerprint, true, 21));
    BOOST_CHECK_NE(expected, compute(consensus, "regtest", genesis_hash, policy_asset, bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, uint256S("34"), policy_asset, bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, uint256S("45"), bmm_fingerprint, true, 20));
    BOOST_CHECK_NE(expected, compute(consensus, network_id, genesis_hash, policy_asset, uint256S("56"), true, 20));
    BOOST_CHECK_NE(expected, compute(ecx::ExchangeConsensus{}, network_id, genesis_hash, policy_asset, bmm_fingerprint, false, 0));
}

BOOST_AUTO_TEST_CASE(forced_action_relay_policy_is_narrow_and_fail_closed)
{
    const COutPoint genesis{uint256S("11"), 0};
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, uint256S("22"))};
    const CKey key{TestTraderKey()};
    const CTransaction canonical{ForcedCancelTransaction(consensus, key)};
    std::string reason;

    BOOST_REQUIRE_GT(canonical.vout[0].scriptPubKey.size(), nMaxDatacarrierBytes);
    BOOST_CHECK(!IsStandardTx(
        canonical,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason));
    BOOST_CHECK(IsStandardTx(
        canonical,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason,
        &consensus));
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        canonical, 9, reason, consensus));
    BOOST_CHECK(ecx::CheckSourceTransactionPolicy(
        canonical, 10, reason, consensus));

    const CTransaction corrupt{ForcedCancelTransaction(consensus, key, true)};
    BOOST_CHECK(!IsStandardTx(
        corrupt,
        true,
        CFeeRate(DUST_RELAY_TX_FEE_BITCOIN),
        reason,
        &consensus));
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        corrupt, 10, reason, consensus));

    CMutableTransaction duplicate{ForcedCancelTransaction(consensus, key)};
    duplicate.vout.push_back(duplicate.vout[0]);
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(
        CTransaction{duplicate}, 10, reason, consensus));
}

BOOST_AUTO_TEST_CASE(ecx_drivechain_pegout_is_standard_without_pak)
{
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, COutPoint{uint256S("11"), 0}, uint256S("22"))};
    NullData pegout_data;
    const uint256 parent_genesis = Params().ParentGenesisBlockHash();
    pegout_data << std::vector<unsigned char>(parent_genesis.begin(), parent_genesis.end());
    pegout_data << std::vector<unsigned char>(64, 0x51);
    CMutableTransaction tx;
    tx.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        25'000,
        GetScriptForDestination(CTxDestination{pegout_data}));
    std::string reason;
    BOOST_REQUIRE_GT(tx.vout[0].scriptPubKey.size(), nMaxDatacarrierBytes);
    BOOST_CHECK(!IsStandardTx(
        CTransaction{tx}, true, CFeeRate(DUST_RELAY_TX_FEE_BITCOIN), reason));
    BOOST_CHECK(IsStandardTx(
        CTransaction{tx}, true, CFeeRate(DUST_RELAY_TX_FEE_BITCOIN), reason,
        &consensus));
}

BOOST_AUTO_TEST_CASE(source_append_budget_is_chainstate_bounded)
{
    ecx::ExchangeConsensusSnapshot snapshot;
    snapshot.forced_entry_count = 40;
    snapshot.forced_processed_cursor = 10;
    snapshot.deposit_entry_count = 35;
    snapshot.deposit_processed_cursor = 5;
    uint64_t budget{0};
    std::string reason;
    BOOST_REQUIRE(ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 4U);

    snapshot.deposit_entry_count = 40;
    BOOST_CHECK(!ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 0U);

    snapshot = {};
    snapshot.forced_entry_count = 1;
    snapshot.forced_processed_cursor = 2;
    BOOST_CHECK(!ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, 0U);

    snapshot = {};
    BOOST_REQUIRE(ecx::ComputeSourceAppendBudget(snapshot, budget, reason));
    BOOST_CHECK_EQUAL(budget, ecx::MAX_COMBINED_UNCONSUMED);
}

BOOST_AUTO_TEST_CASE(forced_action_source_tranches_are_resource_weighted)
{
    uint32_t work{0};
    std::string reason;
    BOOST_REQUIRE(ecx::ComputeForcedTrancheOrderWork(
        std::vector<uint8_t>(64, 0), work, reason));
    BOOST_CHECK_EQUAL(work, 64U);
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        std::vector<uint8_t>(65, 0), work, reason));

    BOOST_REQUIRE(ecx::ComputeForcedTrancheOrderWork(
        {2, 1, 2}, work, reason));
    BOOST_CHECK_EQUAL(work, 64U);
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {1, 0}, work, reason));
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {1, 1}, work, reason));
    BOOST_CHECK(!ecx::ComputeForcedTrancheOrderWork(
        {0, 3}, work, reason));
    BOOST_CHECK_EQUAL(work, 1U);
}

BOOST_AUTO_TEST_CASE(header_extension_is_append_only_and_bmm_covered)
{
    CBlockHeader legacy;
    legacy.nVersion = 0x20000000 |
        CBlockHeader::WITHDRAWAL_BUNDLE_HF_MASK |
        CBlockHeader::BMM_PROOF_HF_MASK;
    legacy.hashPrevBlock = uint256S("01");
    legacy.hashMerkleRoot = uint256S("02");
    legacy.hashWithdrawalBundle = uint256S("03");
    legacy.hashBmmProof = uint256S("04");
    legacy.nTime = 5;
    legacy.nBits = 6;
    legacy.nNonce = 7;

    CDataStream before(SER_NETWORK, PROTOCOL_VERSION);
    before << legacy;
    CBlockHeader extended{legacy};
    extended.nVersion |= CBlockHeader::EXCHANGE_STATE_HF_MASK;
    extended.hashExchangeStateRoot = uint256S("05");
    CDataStream after(SER_NETWORK, PROTOCOL_VERSION);
    after << extended;

    BOOST_REQUIRE_EQUAL(after.size(), before.size() + 32);
    BOOST_CHECK(std::equal(before.begin() + 4, before.end(), after.begin() + 4));

    CBlockHeader source_extended{extended};
    source_extended.nVersion |= CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
    source_extended.hashForcedInboxRoot = uint256S("06");
    source_extended.hashDepositInboxRoot = uint256S("07");
    source_extended.ecxParentHeight = 8;
    CDataStream source_bytes(SER_NETWORK, PROTOCOL_VERSION);
    source_bytes << source_extended;
    BOOST_REQUIRE_EQUAL(source_bytes.size(), after.size() + 68);
    BOOST_CHECK(std::equal(after.begin() + 4, after.end(), source_bytes.begin() + 4));

    CBlockHeader cursor_extended{source_extended};
    cursor_extended.nVersion |= CBlockHeader::INBOX_CURSOR_HF_MASK;
    cursor_extended.forcedProcessedCursor = 9;
    cursor_extended.depositProcessedCursor = 10;
    cursor_extended.sourceBacklogOldestParentHeight = 11;
    CDataStream cursor_bytes(SER_NETWORK, PROTOCOL_VERSION);
    cursor_bytes << cursor_extended;
    BOOST_REQUIRE_EQUAL(cursor_bytes.size(), source_bytes.size() + 24);
    BOOST_CHECK(std::equal(
        source_bytes.begin() + 4, source_bytes.end(), cursor_bytes.begin() + 4));

    const uint256 critical{source_extended.GetBmmCriticalHash()};
    CBlockHeader proof_mutation{source_extended};
    proof_mutation.hashBmmProof = uint256S("09");
    BOOST_CHECK_EQUAL(proof_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader withdrawal_mutation{source_extended};
    withdrawal_mutation.hashWithdrawalBundle = uint256S("0a");
    BOOST_CHECK_NE(withdrawal_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader state_mutation{source_extended};
    state_mutation.hashExchangeStateRoot = uint256S("0b");
    BOOST_CHECK_NE(state_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader forced_mutation{source_extended};
    forced_mutation.hashForcedInboxRoot = uint256S("0c");
    BOOST_CHECK_NE(forced_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader deposit_mutation{source_extended};
    deposit_mutation.hashDepositInboxRoot = uint256S("0d");
    BOOST_CHECK_NE(deposit_mutation.GetBmmCriticalHash(), critical);
    CBlockHeader height_mutation{source_extended};
    ++height_mutation.ecxParentHeight;
    BOOST_CHECK_NE(height_mutation.GetBmmCriticalHash(), critical);
    const uint256 cursor_critical{cursor_extended.GetBmmCriticalHash()};
    CBlockHeader cursor_mutation{cursor_extended};
    ++cursor_mutation.forcedProcessedCursor;
    BOOST_CHECK_NE(cursor_mutation.GetBmmCriticalHash(), cursor_critical);
    CBlockHeader age_mutation{cursor_extended};
    ++age_mutation.sourceBacklogOldestParentHeight;
    BOOST_CHECK_NE(age_mutation.GetBmmCriticalHash(), cursor_critical);

    CBlockHeader decoded;
    source_bytes >> decoded;
    BOOST_CHECK(source_bytes.empty());
    BOOST_CHECK_EQUAL(decoded.hashWithdrawalBundle, source_extended.hashWithdrawalBundle);
    BOOST_CHECK_EQUAL(decoded.hashBmmProof, source_extended.hashBmmProof);
    BOOST_CHECK_EQUAL(decoded.hashExchangeStateRoot, source_extended.hashExchangeStateRoot);
    BOOST_CHECK_EQUAL(decoded.hashForcedInboxRoot, source_extended.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(decoded.hashDepositInboxRoot, source_extended.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(decoded.ecxParentHeight, source_extended.ecxParentHeight);
}

BOOST_AUTO_TEST_CASE(activation_transition_disconnect_and_reorg_are_symmetric)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{uint256S("11"), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};

    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(activation, nullptr, view, 10, error, consensus, 100),
        error);
    CBlockIndex activation_index{IndexFor(activation, 10)};

    CMutableTransaction transition;
    transition.vin.emplace_back(genesis);
    transition.vout.push_back(AuthorityOutput(0x22));
    transition.vout.push_back(CursorMarker(0, 0));
    CBlock next;
    next.vtx.push_back(MakeTransactionRef(transition));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            next, &activation_index, view, 11, error, consensus, 101),
        error);
    BOOST_CHECK(next.HasExchangeState());
    BOOST_CHECK_NE(next.hashExchangeStateRoot, genesis_root);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            next, &activation_index, view, 11, error, consensus, 101),
        error);

    const COutPoint successor{next.vtx[0]->GetHash(), 0};
    BOOST_REQUIRE(view.SpendCoin(genesis));
    view.AddCoin(successor, Coin(next.vtx[0]->vout[0], 11, false), false);

    CBlockIndex next_index{IndexFor(next, 11, &activation_index)};
    uint256 prior_root;
    BOOST_REQUIRE_MESSAGE(
        ecx::GetPriorActiveExchangeStateRoot(&next_index, prior_root, error),
        error);
    BOOST_CHECK_EQUAL(prior_root, next.hashExchangeStateRoot);

    // Mirror DisconnectBlock ordering: transaction undo runs first.
    BOOST_REQUIRE(view.SpendCoin(successor));
    view.AddCoin(genesis, Coin(genesis_output, 1, false), true);
    BOOST_REQUIRE_MESSAGE(
        ecx::DisconnectExchangeState(
            next, &activation_index, view, 11, error, consensus, 101),
        error);

    CBlock alternative;
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            alternative, &activation_index, view, 11, error, consensus, 102),
        error);
    BOOST_CHECK_EQUAL(alternative.hashExchangeStateRoot, genesis_root);
}

BOOST_AUTO_TEST_CASE(activation_does_not_overwrite_reserved_state_coins)
{
    const COutPoint genesis{uint256S("11"), 0};
    const CTxOut genesis_output{AuthorityOutput(0x21)};
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;

    const std::vector<COutPoint> trackers{
        COutPoint{
            uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041"),
            0},
        COutPoint{
            uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1"),
            0},
        COutPoint{
            uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586"),
            0},
    };
    for (const COutPoint& tracker : trackers) {
        MemoryCoinsView persistent;
        CCoinsViewCache view{&persistent};
        view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
        const CTxOut collision{AuthorityOutput(0x55, 7)};
        view.AddCoin(tracker, Coin(collision, 1, false), false);
        std::string error;
        BOOST_CHECK(!ecx::ConnectExchangeState(
            activation, nullptr, view, 10, error, consensus, 100));
        BOOST_CHECK(error.find("cannot overwrite") != std::string::npos);
        const Coin& preserved{view.AccessCoin(tracker)};
        BOOST_CHECK(!preserved.IsSpent());
        BOOST_CHECK(preserved.out == collision);
    }
}

BOOST_AUTO_TEST_CASE(rejects_bad_header_authority_and_same_block_chaining)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{uint256S("21"), 0};
    const CTxOut genesis_output{AuthorityOutput(0x31)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(10, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 100;
    std::string error;
    BOOST_REQUIRE(ecx::ConnectExchangeState(
        activation, nullptr, view, 10, error, consensus, 100));
    CBlockIndex previous{IndexFor(activation, 10)};

    CMutableTransaction changed_value;
    changed_value.vin.emplace_back(genesis);
    changed_value.vout.push_back(AuthorityOutput(0x32, 2));
    CBlock invalid;
    invalid.vtx.push_back(MakeTransactionRef(changed_value));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("value") != std::string::npos);

    CMutableTransaction first;
    first.vin.emplace_back(genesis);
    first.vout.push_back(AuthorityOutput(0x33));
    CMutableTransaction second;
    second.vin.emplace_back(COutPoint{first.GetHash(), 0});
    second.vout.push_back(AuthorityOutput(0x34));
    invalid.vtx = {MakeTransactionRef(first), MakeTransactionRef(second)};
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("at most one") != std::string::npos);

    CBlock wrong_root;
    wrong_root.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    wrong_root.hashExchangeStateRoot = uint256S("99");
    wrong_root.hashForcedInboxRoot = previous.hashForcedInboxRoot;
    wrong_root.hashDepositInboxRoot = previous.hashDepositInboxRoot;
    wrong_root.ecxParentHeight = 101;
    BOOST_CHECK(!ecx::ConnectExchangeState(
        wrong_root, &previous, view, 11, error, consensus, 101));
    BOOST_CHECK(error.find("deterministic") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(frozen_source_formats_are_verified_and_accumulated)
{
    struct ElementsModeGuard {
        const bool previous{g_con_elementsmode};
        ElementsModeGuard() { g_con_elementsmode = true; }
        ~ElementsModeGuard() { g_con_elementsmode = previous; }
    } elements_mode;

    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{uint256S("31"), 0};
    const CTxOut genesis_output{AuthorityOutput(0x41)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(20, genesis, genesis_root)};

    // These are independent protocol-core-compatible tagged-SHA256 vectors.
    BOOST_CHECK_EQUAL(
        ecx::ComputeForcedInboxGenesis(consensus),
        RawHash("079e7311c6e2b15563b1f7b9007fda9aa633a4596532f63207de98c698e93aff"));
    BOOST_CHECK_EQUAL(
        ecx::ComputeDepositInboxGenesis(consensus),
        RawHash("c1c4a175d3a9fb7f6e1c0f44de8b181d05eda6fb278f0a2744b91427093e2f63"));

    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 500;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            activation, nullptr, view, 20, error, consensus, 500),
        error);
    CBlockIndex previous{IndexFor(activation, 20)};
    const CKey trader{TestTraderKey()};

    CBlock invalid_signature;
    invalid_signature.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader, true)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        invalid_signature, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("signature") != std::string::npos);

    CBlock missing_deposit_proofs;
    missing_deposit_proofs.vtx.push_back(MakeTransactionRef(
        ConfidentialDepositTransaction(consensus, trader, false)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        missing_deposit_proofs, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("confidential collateral vault") != std::string::npos);

    CMutableTransaction duplicate_forced{
        ForcedCancelTransaction(consensus, trader)};
    duplicate_forced.vout.push_back(duplicate_forced.vout[0]);
    CBlock duplicate_block;
    duplicate_block.vtx.push_back(MakeTransactionRef(std::move(duplicate_forced)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        duplicate_block, &previous, view, 21, error, consensus, 501));
    BOOST_CHECK(error.find("only one ECX forced action") != std::string::npos);

    CBlock source_block;
    source_block.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader)));
    source_block.vtx.push_back(MakeTransactionRef(
        ConfidentialDepositTransaction(consensus, trader)));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    BOOST_CHECK_NE(source_block.hashForcedInboxRoot, activation.hashForcedInboxRoot);
    BOOST_CHECK_NE(source_block.hashDepositInboxRoot, activation.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(source_block.ecxParentHeight, 501U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    CBlockIndex source_index{IndexFor(source_block, 21, &previous)};
    ecx::ExchangeConsensusSnapshot snapshot;
    BOOST_REQUIRE_MESSAGE(
        ecx::GetExchangeConsensusSnapshot(
            view, &source_index, snapshot, error),
        error);
    BOOST_CHECK_EQUAL(snapshot.exchange_state_root, genesis_root);
    BOOST_CHECK_EQUAL(snapshot.forced_inbox_root, source_block.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.forced_entry_count, 1U);
    BOOST_CHECK_EQUAL(snapshot.deposit_inbox_root, source_block.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.deposit_entry_count, 1U);

    BOOST_REQUIRE_MESSAGE(
        ecx::DisconnectExchangeState(
            source_block, &previous, view, 21, error, consensus, 501),
        error);
    BOOST_REQUIRE_MESSAGE(
        ecx::GetExchangeConsensusSnapshot(
            view, &previous, snapshot, error),
        error);
    BOOST_CHECK_EQUAL(snapshot.forced_inbox_root, activation.hashForcedInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.forced_entry_count, 0U);
    BOOST_CHECK_EQUAL(snapshot.deposit_inbox_root, activation.hashDepositInboxRoot);
    BOOST_CHECK_EQUAL(snapshot.deposit_entry_count, 0U);
}

BOOST_AUTO_TEST_CASE(public_cursor_liveness_bounds_carry_forward_spam)
{
    MemoryCoinsView persistent;
    CCoinsViewCache view{&persistent};
    const COutPoint genesis{uint256S("41"), 0};
    const CTxOut genesis_output{AuthorityOutput(0x51)};
    view.AddCoin(genesis, Coin(genesis_output, 1, false), false);
    const uint256 genesis_root = ecx::ComputeStateUtxoRoot(
        Params().GetConsensus().hashGenesisBlock,
        genesis,
        genesis_output);
    const ecx::ExchangeConsensus consensus{
        ConfiguredConsensus(30, genesis, genesis_root)};
    CBlock activation;
    activation.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    activation.hashExchangeStateRoot = genesis_root;
    activation.hashForcedInboxRoot = ecx::ComputeForcedInboxGenesis(consensus);
    activation.hashDepositInboxRoot = ecx::ComputeDepositInboxGenesis(consensus);
    activation.ecxParentHeight = 700;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            activation, nullptr, view, 30, error, consensus, 700),
        error);
    CBlockIndex activation_index{IndexFor(activation, 30)};
    const CKey trader{TestTraderKey()};

    CBlock sixty_four;
    for (uint32_t index = 0; index < ecx::MAX_COMBINED_UNCONSUMED; ++index) {
        CMutableTransaction forced{ForcedCancelTransaction(consensus, trader)};
        forced.nLockTime = index;
        sixty_four.vtx.push_back(MakeTransactionRef(std::move(forced)));
    }
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            sixty_four, &activation_index, view, 31, error, consensus, 701),
        error);
    BOOST_CHECK_EQUAL(sixty_four.forcedProcessedCursor, 0U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            sixty_four, &activation_index, view, 31, error, consensus, 701),
        error);
    CBlockIndex backlog_index{IndexFor(sixty_four, 31, &activation_index)};

    CBlock before_deadline;
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            before_deadline, &backlog_index, view, 32, error, consensus, 706),
        error);
    BOOST_CHECK_EQUAL(before_deadline.sourceBacklogOldestParentHeight, 701U);
    CBlock at_deadline;
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        at_deadline, &backlog_index, view, 32, error, consensus, 707));
    BOOST_CHECK(error.find("deadline") != std::string::npos);

    CBlock sixty_fifth;
    sixty_fifth.vtx.push_back(MakeTransactionRef(
        ForcedCancelTransaction(consensus, trader)));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        sixty_fifth, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("backlog") != std::string::npos);

    CMutableTransaction missing_marker;
    missing_marker.vin.emplace_back(genesis);
    missing_marker.vout.push_back(AuthorityOutput(0x52));
    CBlock missing_marker_block;
    missing_marker_block.vtx.push_back(MakeTransactionRef(missing_marker));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        missing_marker_block, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("missing") != std::string::npos);

    CMutableTransaction bad_cursor;
    bad_cursor.vin.emplace_back(genesis);
    bad_cursor.vout.push_back(AuthorityOutput(0x53));
    bad_cursor.vout.push_back(CursorMarker(65, 0));
    CBlock bad_cursor_block;
    bad_cursor_block.vtx.push_back(MakeTransactionRef(bad_cursor));
    BOOST_CHECK(!ecx::PrepareExchangeStateHeader(
        bad_cursor_block, &backlog_index, view, 32, error, consensus, 702));
    BOOST_CHECK(error.find("exceeds") != std::string::npos);

    CMutableTransaction consume;
    consume.vin.emplace_back(genesis);
    consume.vout.push_back(AuthorityOutput(0x54));
    consume.vout.push_back(CursorMarker(64, 0));
    CBlock consumed;
    consumed.vtx.push_back(MakeTransactionRef(consume));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            consumed, &backlog_index, view, 32, error, consensus, 702),
        error);
    BOOST_CHECK_EQUAL(consumed.forcedProcessedCursor, 64U);
    BOOST_REQUIRE_MESSAGE(
        ecx::ConnectExchangeState(
            consumed, &backlog_index, view, 32, error, consensus, 702),
        error);
    const COutPoint successor{consumed.vtx[0]->GetHash(), 0};
    BOOST_REQUIRE(view.SpendCoin(genesis));
    view.AddCoin(successor, Coin(consumed.vtx[0]->vout[0], 32, false), false);
    CBlockIndex consumed_index{IndexFor(consumed, 32, &backlog_index)};

    CBlock after_advance;
    CMutableTransaction next_forced{ForcedCancelTransaction(consensus, trader)};
    next_forced.nLockTime = 99;
    after_advance.vtx.push_back(MakeTransactionRef(std::move(next_forced)));
    BOOST_REQUIRE_MESSAGE(
        ecx::PrepareExchangeStateHeader(
            after_advance, &consumed_index, view, 33, error, consensus, 703),
        error);
    BOOST_CHECK_EQUAL(after_advance.forcedProcessedCursor, 64U);
}

BOOST_AUTO_TEST_CASE(withdrawal_bundle_requires_authenticated_m6_pxst_preimage)
{
    const COutPoint genesis{uint256S("91"), 0};
    const uint256 state_root{uint256S("92")};
    const ecx::ExchangeConsensus consensus{ConfiguredConsensus(30, genesis, state_root)};
    CBlock before_block;
    CBlockIndex before{IndexFor(before_block, 29)};
    const uint256 before_hash{uint256S("93")};
    before.phashBlock = &before_hash;
    CBlock checkpoint_block;
    checkpoint_block.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK;
    checkpoint_block.hashExchangeStateRoot = state_root;
    CBlockIndex checkpoint{IndexFor(checkpoint_block, 30, &before)};
    const uint256 checkpoint_hash{uint256S("94")};
    checkpoint.phashBlock = &checkpoint_hash;
    const std::vector<unsigned char> m6{
        TestM6(30, before.GetBlockHash(), state_root)};
    const ecx::WithdrawalBundleEnvelopeV1 envelope{
        30, checkpoint.GetBlockHash(), m6};

    CBlock block;
    block.nVersion = CBlockHeader::EXCHANGE_STATE_HF_MASK;
    block.hashExchangeStateRoot = state_root;
    block.hashWithdrawalBundle = Hash(m6);
    block.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(envelope))};
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ecx::CheckWithdrawalBundleEnvelope(block, &checkpoint, 31, error, consensus),
        error);

    CBlock missing{block};
    missing.vtx = {TestCoinbase()};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(missing, &checkpoint, 31, error, consensus));
    BOOST_CHECK(error.find("lacks") != std::string::npos);

    CBlock wrong_pxst{block};
    const std::vector<unsigned char> bad_m6{
        TestM6(30, before.GetBlockHash(), state_root, 1)};
    wrong_pxst.hashWithdrawalBundle = Hash(bad_m6);
    wrong_pxst.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(
        ecx::WithdrawalBundleEnvelopeV1{30, checkpoint.GetBlockHash(), bad_m6}))};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(
        wrong_pxst, &checkpoint, 31, error, consensus));
    BOOST_CHECK(error.find("PXST") != std::string::npos);

    CBlockIndex committed{IndexFor(block, 31, &checkpoint)};
    CBlock carry;
    carry.hashWithdrawalBundle = block.hashWithdrawalBundle;
    carry.vtx = {TestCoinbase()};
    BOOST_REQUIRE_MESSAGE(
        ecx::CheckWithdrawalBundleEnvelope(carry, &committed, 32, error, consensus),
        error);
    carry.vtx = {TestCoinbase(ecx::BuildWithdrawalBundleEnvelopeScript(envelope))};
    BOOST_CHECK(!ecx::CheckWithdrawalBundleEnvelope(carry, &committed, 32, error, consensus));
    BOOST_CHECK(error.find("only when") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
