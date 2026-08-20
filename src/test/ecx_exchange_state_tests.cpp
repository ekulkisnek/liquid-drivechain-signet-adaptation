// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include <ecx_exchange_state.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/sha256.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <limits>

namespace {

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

BOOST_FIXTURE_TEST_SUITE(ecx_exchange_state_tests, BasicTestingSetup)

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
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
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
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
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
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
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
        CBlockHeader::DEPOSIT_INBOX_HF_MASK;
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

BOOST_AUTO_TEST_SUITE_END()
