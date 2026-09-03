// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <chainparams.h>
#include <chainparamsbase.h>
#include <chain.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <drivechain_bmm.h>
#include <elements_drivechain_identity.h>
#include <init.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <pegins.h>
#include <policy/policy.h>
#include <rpc/request.h>
#include <signet.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <usdd_sp1_resources.h>
#include <usdd_withdrawal_accumulator.h>
#include <util/chaintype.h>
#include <validation.h>
#include <wallet/drivechain_withdrawal.h>

#include <string>

#include <test/util/setup_common.h>

#include <limits>
#include <cstring>
#include <fstream>

#ifndef WIN32
#include <sys/stat.h>
#endif


#include <boost/test/unit_test.hpp>

namespace Bitcoin = Sidechain::Bitcoin;

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(drivechain_parent_checkpoint_ctip_tuple)
{
    const uint256 null_txid;
    const uint256 populated_txid = uint256S(
        "0100000000000000000000000000000000000000000000000000000000000000");
    const uint32_t absent_vout = std::numeric_limits<uint32_t>::max();

    struct Vector {
        uint256 txid;
        uint32_t vout;
        CAmount value;
        bool valid;
    };
    const std::array<Vector, 11> vectors{{
        {null_txid, absent_vout, 0, true},
        {populated_txid, 0, 1, true},
        {populated_txid, 7, MAX_MONEY, true},
        {null_txid, 0, 0, false},
        {null_txid, absent_vout, 1, false},
        {null_txid, 0, 1, false},
        {populated_txid, absent_vout, 0, false},
        {populated_txid, absent_vout, 1, false},
        {populated_txid, 0, 0, false},
        {populated_txid, 0, -1, false},
        {populated_txid, 0, MAX_MONEY + 1, false},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(IsCanonicalDrivechainParentCheckpointCtip(
            vector.txid, vector.vout, vector.value), vector.valid);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_parent_checkpoint_identity_state)
{
    const uint256 null_hash;
    const uint256 proposal_block = uint256S(
        "0200000000000000000000000000000000000000000000000000000000000000");
    const uint256 activation_block = uint256S(
        "0300000000000000000000000000000000000000000000000000000000000000");
    const uint256 ctip_txid = uint256S(
        "0400000000000000000000000000000000000000000000000000000000000000");
    const std::vector<unsigned char> description{0x01, 0x02, 0x03};
    const std::optional<uint256> description_hash{Hash(description)};
    const uint32_t absent_vout = std::numeric_limits<uint32_t>::max();

    struct Vector {
        std::vector<unsigned char> description;
        std::optional<uint256> proposal_hash;
        uint32_t proposal_height;
        uint256 proposal_block;
        uint32_t activation_height;
        uint256 activation_block;
        uint32_t checkpoint_height;
        uint256 ctip_txid;
        uint32_t ctip_vout;
        CAmount ctip_value;
        bool expected;
    };
    const std::array<Vector, 12> vectors{{
        {{}, std::nullopt, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         true},
        {{}, std::optional<uint256>{null_hash}, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         true},
        {description, description_hash, 1, proposal_block, 2, activation_block, 2, null_hash, absent_vout, 0,
         true},
        {description, description_hash, 1, proposal_block, 2, activation_block, 3, ctip_txid, 0, 1,
         true},
        {description, std::nullopt, 1, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {{}, description_hash, 0, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 1, null_hash, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 0, proposal_block, 0, null_hash, 1, null_hash, absent_vout, 0,
         false},
        {description, description_hash, 2, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {description, description_hash, 1, proposal_block, 4, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {description, std::optional<uint256>{uint256S("0500000000000000000000000000000000000000000000000000000000000000")},
         1, proposal_block, 2, activation_block, 3, null_hash, absent_vout, 0,
         false},
        {{}, std::nullopt, 0, null_hash, 0, null_hash, 1, ctip_txid, 0, 1,
         false},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(IsCanonicalDrivechainParentCheckpointIdentity(
            vector.description, vector.proposal_hash, vector.proposal_height,
            vector.proposal_block, vector.activation_height, vector.activation_block,
            vector.checkpoint_height, vector.ctip_txid, vector.ctip_vout,
            vector.ctip_value), vector.expected);
    }
}

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    consensusParams.genesis_subsidy = 50*COIN;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{2099999997690000});
}

BOOST_AUTO_TEST_CASE(usdd_withdrawal_accumulator_matches_cross_language_transaction_vector)
{
    const auto address20 = [](const std::string& hex) {
        const std::vector<unsigned char> bytes = ParseHex(hex);
        BOOST_REQUIRE_EQUAL(bytes.size(), 20U);
        usdd::EthereumAddress result{};
        std::copy(bytes.begin(), bytes.end(), result.begin());
        return result;
    };

    struct ScopedElementsSerialization {
        const bool previous{g_con_elementsmode};
        ScopedElementsSerialization() { g_con_elementsmode = true; }
        ~ScopedElementsSerialization() { g_con_elementsmode = previous; }
    } elements_serialization;

    const uint256 genesis = uint256S(
        "3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6");
    const CAsset asset(uint256S(
        "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"));
    const std::vector<unsigned char> vault = ParseHex(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    const auto burn_script = [&](const std::string& recipient_hex, const uint64_t amount) {
        std::vector<unsigned char> payload{'U', 'S', 'D', 'D', 1};
        const std::vector<unsigned char> recipient = ParseHex(recipient_hex);
        BOOST_REQUIRE_EQUAL(recipient.size(), 20U);
        payload.insert(payload.end(), vault.begin(), vault.end());
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        for (int shift = 56; shift >= 0; shift -= 8) {
            payload.push_back(static_cast<unsigned char>(amount >> shift));
        }
        BOOST_REQUIRE_EQUAL(payload.size(), 65U);
        return CScript() << OP_RETURN << payload;
    };

    CMutableTransaction mutable_transaction;
    mutable_transaction.vout.emplace_back(
        asset, 777000 * usdd::USDD_UNITS_PER_USDT_MICRO,
        burn_script("000000000000000000000000000000000000beef", 777000));
    mutable_transaction.vout.emplace_back(
        asset, 888000 * usdd::USDD_UNITS_PER_USDT_MICRO,
        burn_script("111122223333444455556666777788889999aaaa", 888000));
    const CTransactionRef transaction = MakeTransactionRef(std::move(mutable_transaction));

    DataStream serialized;
    serialized << TX_NO_WITNESS(*transaction);
    BOOST_CHECK_EQUAL(
        HexStr(serialized),
        "0200000000000201ffeeddccbbaa99887766554433221100ffeeddccbbaa00998877665544332211010000000004a19ba000436a415553444401101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000000000000000beef00000000000bdb2801ffeeddccbbaa99887766554433221100ffeeddccbbaa009988776655443322110100000000054afb0000436a415553444401101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f111122223333444455556666777788889999aaaa00000000000d8cc000000000");
    BOOST_CHECK_EQUAL(
        transaction->GetHash().GetHex(),
        "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2");

    CBlock block;
    block.vtx.push_back(transaction);
    std::vector<usdd::EthereumWithdrawalClaim> claims;
    std::string error;
    BOOST_REQUIRE(usdd::ExtractEthereumWithdrawals(block, genesis, 0, claims, &error));
    BOOST_REQUIRE_EQUAL(claims.size(), 2U);

    const std::array<std::string, 2> expected_recipients{{
        "000000000000000000000000000000000000beef",
        "111122223333444455556666777788889999aaaa",
    }};
    const std::array<uint64_t, 2> expected_amounts{{777000, 888000}};
    const std::array<std::string, 2> expected_burn_ids{{
        "f7961bb911f26f0187638b835f593466c235c99f8c040559e3ca93e3bfe796ff",
        "8a7a3e77f9f85e4c665465e06ad8ddbac07f4e217750f11e27f2a01fec6a84f8",
    }};
    const std::array<std::string, 2> expected_leaves{{
        "8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f",
        "411d36323ee653bda6c17167e4321e2437ae288a42e7786bed84832ba7baa7ec",
    }};
    for (size_t i = 0; i < claims.size(); ++i) {
        BOOST_CHECK_EQUAL(
            HexStr(claims[i].elements_genesis),
            "3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6");
        BOOST_CHECK_EQUAL(
            HexStr(claims[i].asset_id),
            "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff");
        BOOST_CHECK_EQUAL(
            HexStr(claims[i].vault_id),
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
        BOOST_CHECK_EQUAL(
            HexStr(claims[i].burn_txid_display),
            "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2");
        BOOST_CHECK_EQUAL(claims[i].burn_vout, i);
        BOOST_CHECK_EQUAL(claims[i].claim_index, i);
        BOOST_CHECK_EQUAL(claims[i].amount_usdt_micro, expected_amounts[i]);
        BOOST_CHECK(claims[i].recipient == address20(expected_recipients[i]));
        BOOST_CHECK_EQUAL(HexStr(claims[i].burn_id), expected_burn_ids[i]);
        BOOST_CHECK_EQUAL(HexStr(claims[i].leaf), expected_leaves[i]);
    }

    auto state = usdd::WithdrawalAccumulatorState::Empty();
    BOOST_CHECK(state.IsSane());
    BOOST_CHECK_EQUAL(
        HexStr(state.root),
        "c13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db");
    for (const auto& claim : claims) BOOST_REQUIRE(state.Append(claim.leaf));
    BOOST_CHECK_EQUAL(state.count, 2U);
    BOOST_CHECK_EQUAL(HexStr(state.root),
                      "9a9d19c855a9cb649c60024f7de206266056755cc93b4021211870d32a630719");

    DataStream encoded;
    encoded << state;
    BOOST_CHECK_EQUAL(encoded.size(), 73U);
    usdd::WithdrawalAccumulatorState decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded == state);

    usdd::WithdrawalInclusionProof proof;
    usdd::WithdrawalHash proof_root;
    BOOST_REQUIRE(usdd::BuildWithdrawalInclusionProof(claims, 1, proof, proof_root));
    BOOST_CHECK(proof_root == state.root);
    const std::vector<unsigned char> expected_siblings = ParseHex(
        "8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f"
        "fe43d66afa4a9a5c4f9c9da89f4ffb52635c8f342e7ffb731d68e36c5982072a"
        "deb82e155954d6be14592c66ccf7a1ece193eeebcdabaf747b91f44519f09f47"
        "2960044c62f2354e945e8d78fdd220a05f2c0879f24df6f11ef5cc26b5270a0e"
        "4cfabc48c6898a30b1b5d12dda8e09a96e9ea17e80f4b2a050b8a8b4803fbd43"
        "7162ed848f19740e53766ce01ac099523b099d593e0782ddbc5296eece50ec50"
        "2be3cf0551cc6936d461e3dc43f3c4bf50cbee1bc091925254e879f4e7665e94"
        "12db5262a5500d2516b8f82362d2a87278d20f712ff1fce2019d42ecba17241d"
        "1a1a9265f869676c206824aa7bfc2fe8c7fe34691dddfb35797b6a321f977dfc"
        "6e0bb8243e268be3d2fa3ce83234b2f850c85162bd0fced30e919e069bd52df7"
        "0162892fa669b555682d4c5666f42c98f230e76406d646e6dbbcefb5d311e047"
        "fd5593f0bfde08caa41745a8a6b2d5dcaea03a5867e8432a995bea3a1fd4df56"
        "7bbcd27ae0b8f5d7c013dc6d13a2e586b58f83eac62aa62aa56f332288ad8bf4"
        "d6c82f90e341cc36aa0fb5f8d03bbb3e6d5148eb56fcf79eb415574aee7fa99a"
        "e2b649c4fa703c323fc2c929ad269dfdd150bde6862d9bcebe966244b983f20f"
        "48c12a8dd675e9dcd3c63141fbfde6d11056c392b4379c3bbdc79a8511d0e65b"
        "d83389ac9a207fb7dbdc492fbb56b9482f19170699e224be64694cc885a3a2a2"
        "edcc91a8b4993170d5f55d71d4234fe9e59b7c00434012cd023f3cba860ae033"
        "fee8622eba4d639bf3e13854a77a783506089ef2c48b84d6ef7ad254fc955c4a"
        "e2d111ccb9aa33b2a11b8ad27f2652231310c032e8725ceebbd41c481ae4cbe7"
        "10d6c4230824825e7296a4297b43de9bb3df9f42b4b9cd650a39b44fabb22afb"
        "2868f47336780e9cc8046ed4c330cf79fb0c619712208f67c02e48388141e2ed"
        "584db9263738b0d0956515ae3081f295e994dfc6e7a7e7a4d2d1c1b54d60c22f"
        "b9548f3a287dbf425ba32df7080928edc19b1be182eb60ba26257e530071e422"
        "8d6446d4c64ee7ebb1221fed67e95b054036fa2076e31142638b7348e875adc7"
        "703df52a6f4f70dfc70fda8c1f183d5e30c0f2c1930649e8c39314a1b7207eba"
        "9e47ce5eae7fc0685dc458135842c782ab79ec2faf4b44f52d83cb274c805d03"
        "f897013deb772ba3cb7780c0002c38026724bfb236e15e44e2db925f14fe5dbb"
        "2b9eaa148146f83dce634b361d5f5fd9215b48eb98f10cd6f1e022bd9e0a7f07"
        "de3d631c00478d7efa3ae5f05fd92efba8db8c94c7521bf2334d6ec821254311"
        "49f6b68c071995f76408fc063a07173188c4269cf377c6ae2ebb6ffa944c4da6"
        "c802422af536d1fba84e02a6a8f5693778de790f8bcb51dfe220c2820c11279f"
        "a5dfa832364e6e75e05fd480f7561e49e5935eb85736cdd869dd19ebab11b912"
        "1f07df56447be060014f88aebfbf223f81451d2bc7685889acbce997b609e788"
        "545ef2e7c33b35c29cdb17f6793c0ae5c5261bf75c765160c94863f24ff11691"
        "c190017e7a1a58d07bc29a614b60bcf50c456e419e2040402270a75a32293d38"
        "9eebc70a804b6010d61267724a919b9bcc67b7ae8f2e258428d569b987d87605"
        "09bbf2baf387d7f63ed02ff572c91f97dde80cdfcea312a83a2c2c84c28e2c0f"
        "e9120affb610f432b9c99776c6ec40630c7b0580c62444f333689f32487f4f00"
        "fe9a71250d2ddc7e8c5790ef99acef23a8ac7201164e9db46bc8214740df3ed1"
        "c81e6237577496cb0bed049576f0e3e68fa1e2ee61cd396695f48c243d53a15c"
        "367e0f410599fe8aafcde9a4ea9388ce436ddc07bd8670c5b7d8ef37394eccf5"
        "1309b41802c032c7c8877348ea64316544adf55561deb29dcb94145e50892e00"
        "38997c4ee56f891a69233c598c095fe9feafa97576813e69838796a64eeeb2bf"
        "4cbb3f614eaa9ffa44571a74f533082cba654e5fe73905c95a8afbe5c5dc05cd"
        "cb9ba928b1ec4880cf00119d52610e28ad92734d9f972df51d2d0f8a5eb2b9b6"
        "1560da124b100fec4d430bd8264e580d11a6fbb9c01e3e75fc49c86c56c808f9"
        "c5b2e77ea63083407300c1e71bf19d8b84a65bf48879f12440ab05d296b464b7"
        "c268bae2aefe1c818d0bfd533edcb8a217f7466722ad1ab6809e7eaed6ecd529"
        "ac118efae070bbacde8e7badb95642bd7d1268ff272c7e55ca8cce66717e3863"
        "7be150cbed20c3320cceef97bd248a7491b596f5f9c8c52a696cc6bb8c011ceb"
        "179a84258c46051d91aa9c205e718c8bc74d4e1d7ebeb85b88bb657c926c1799"
        "f626273c1abeaa629383a66ef35f21341f51df8bd54cec5d8efebdd5038e3042"
        "96ea4b6920af1ec454a036999d8ca67d730cbc4fbac7a7f8f90227812a90d898"
        "9a40564d2c9b087955dd3aa38e2921f2c78f0ac2ce9d435d96ade6e0f48f9a49"
        "f047b0ed771c9a96abbe42edf2387172ddc87f888f9f038511ef574726173d7f"
        "33dd5ca767b164b9858acf244827a81681306d87533a1472d79b2b874936a99a"
        "626c2d88d3f85d86ff1c8daa1700692206d7eb8e0d8368cd4479fdb7552b2f76"
        "028619a2b9fab6f75eaa59c59554901260e8c20f2812a09fd494f2dfa1975f3c"
        "ac93083c85607e5b70f7e7ff8f186d8ca96ce4335437c609ff4e6c6706367933"
        "1427d95992261f3300dafe74d2a15b2db5eec0b85ec9b1ee8b44fe240f0f196e"
        "2021fe6240918b3c9363c089179c5a10651a65ad6dc2383065aaec6e7a0f3a7b"
        "caf4a28529582ca02c4bd212b18b84f60c24d1ab0ff870627d06ab6b517f8121"
        "c9e8fbff1c491590322411d4dd2901c884f6a46e29f4dfb4f3d811e565c96757");
    BOOST_REQUIRE_EQUAL(expected_siblings.size(),
                        usdd::WITHDRAWAL_ACCUMULATOR_DEPTH * 32U);
    for (size_t level = 0; level < usdd::WITHDRAWAL_ACCUMULATOR_DEPTH; ++level) {
        BOOST_CHECK(std::equal(
            proof.siblings[level].begin(), proof.siblings[level].end(),
            expected_siblings.begin() + level * 32));
    }
}

BOOST_AUTO_TEST_CASE(usdd_withdrawal_extraction_is_exact_ordered_and_unblinded)
{
    const uint256 genesis = uint256S(
        "3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6");
    const CAsset asset(uint256S(
        "0000000000000000000000000000000000000000000000000000000000003003"));
    const std::vector<unsigned char> vault = ParseHex(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    const std::vector<unsigned char> recipient = ParseHex(
        "000000000000000000000000000000000000beef");
    const auto burn_script = [&](const uint64_t amount) {
        std::vector<unsigned char> payload{'U', 'S', 'D', 'D', 1};
        payload.insert(payload.end(), vault.begin(), vault.end());
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        for (int shift = 56; shift >= 0; shift -= 8) {
            payload.push_back(static_cast<unsigned char>(amount >> shift));
        }
        BOOST_REQUIRE_EQUAL(payload.size(), 65U);
        return CScript() << OP_RETURN << payload;
    };

    CMutableTransaction transaction;
    transaction.vout.emplace_back(asset, 777000 * usdd::USDD_UNITS_PER_USDT_MICRO,
                                   burn_script(777000));
    transaction.vout.emplace_back(asset, 888000 * usdd::USDD_UNITS_PER_USDT_MICRO,
                                   burn_script(888000));
    transaction.vout.emplace_back(asset, 1, burn_script(999000));
    transaction.vout.emplace_back(asset, 777000 * usdd::USDD_UNITS_PER_USDT_MICRO,
                                   CScript() << OP_RETURN << std::vector<unsigned char>{'U', 'S', 'D', 'D'});
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(transaction));

    std::vector<usdd::EthereumWithdrawalClaim> claims;
    std::string error;
    BOOST_REQUIRE(usdd::ExtractEthereumWithdrawals(block, genesis, 9, claims, &error));
    BOOST_REQUIRE_EQUAL(claims.size(), 2U);
    BOOST_CHECK_EQUAL(claims[0].claim_index, 9U);
    BOOST_CHECK_EQUAL(claims[0].burn_vout, 0U);
    BOOST_CHECK_EQUAL(claims[0].amount_usdt_micro, 777000U);
    BOOST_CHECK_EQUAL(claims[1].claim_index, 10U);
    BOOST_CHECK_EQUAL(claims[1].burn_vout, 1U);

    CMutableTransaction blinded_nonce = transaction;
    blinded_nonce.vout[0].nNonce.vchCommitment.assign(33, 0);
    blinded_nonce.vout[0].nNonce.vchCommitment[0] = 2;
    CBlock nonce_block;
    nonce_block.vtx.push_back(MakeTransactionRef(std::move(blinded_nonce)));
    BOOST_REQUIRE(usdd::ExtractEthereumWithdrawals(nonce_block, genesis, 0, claims, &error));
    BOOST_REQUIRE_EQUAL(claims.size(), 1U);
    BOOST_CHECK_EQUAL(claims[0].burn_vout, 1U);

    auto parent = usdd::WithdrawalAccumulatorState::Empty();
    usdd::WithdrawalAccumulatorState branch_a = parent;
    usdd::WithdrawalAccumulatorState branch_b = parent;
    BOOST_REQUIRE(branch_a.Append(claims[0].leaf));
    usdd::WithdrawalHash alternate = claims[0].leaf;
    alternate[0] ^= 1;
    BOOST_REQUIRE(branch_b.Append(alternate));
    BOOST_CHECK(branch_a.root != branch_b.root);
    BOOST_CHECK_EQUAL(parent.count, 0U);
}

BOOST_AUTO_TEST_CASE(usdd_bip301_critical_hash_commits_exact_candidate_and_transition)
{
    const uint256 genesis = uint256S(
        "3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6");
    const uint256 candidate_a = uint256S(
        "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2");
    const uint256 candidate_b = uint256S(
        "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab3");
    constexpr uint8_t slot{24};

    const auto hash32 = [](const std::string& hex) {
        const std::vector<unsigned char> bytes = ParseHex(hex);
        BOOST_REQUIRE_EQUAL(bytes.size(), 32U);
        usdd::WithdrawalHash result{};
        std::copy(bytes.begin(), bytes.end(), result.begin());
        return result;
    };

    const auto previous = usdd::WithdrawalAccumulatorState::Empty();
    auto next = previous;
    BOOST_REQUIRE(next.Append(hash32(
        "8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f")));
    BOOST_REQUIRE(next.Append(hash32(
        "411d36323ee653bda6c17167e4321e2437ae288a42e7786bed84832ba7baa7ec")));

    uint256 critical_a;
    uint256 critical_b;
    std::string error;
    BOOST_REQUIRE(usdd::ComputeWithdrawalBip301CriticalHash(
        genesis, slot, candidate_a, previous, next, critical_a, &error));
    BOOST_REQUIRE(usdd::ComputeWithdrawalBip301CriticalHash(
        genesis, slot, candidate_b, previous, next, critical_b, &error));
    BOOST_CHECK_EQUAL(
        critical_a.GetHex(),
        "6b9c9c485cce8a07a5d6d78c81b5566f269f5df03fa38cd29d5c3de7cb985161");
    BOOST_CHECK(critical_a != critical_b);

    uint256 wrong_slot;
    uint256 wrong_genesis;
    BOOST_REQUIRE(usdd::ComputeWithdrawalBip301CriticalHash(
        genesis, slot - 1, candidate_a, previous, next, wrong_slot, &error));
    BOOST_REQUIRE(usdd::ComputeWithdrawalBip301CriticalHash(
        uint256S("01"), slot, candidate_a, previous, next, wrong_genesis,
        &error));
    BOOST_CHECK(critical_a != wrong_slot);
    BOOST_CHECK(critical_a != wrong_genesis);

    // The cross-language checkpoint codec fails closed if only one accumulator
    // identity field changes. A count-only mutation is necessarily an invalid
    // Merkle state absent a hash collision, while two valid same-count states
    // provide the root-only transition case.
    auto count_only = previous;
    count_only.count = 1;
    uint256 rejected;
    error.clear();
    BOOST_CHECK(!usdd::ComputeWithdrawalBip301CriticalHash(
        genesis, slot, candidate_a, previous, count_only, rejected, &error));
    BOOST_CHECK(rejected.IsNull());
    BOOST_CHECK_EQUAL(
        error, "USDD BIP301 checkpoint has a malformed accumulator transition");

    auto alternate_next = previous;
    BOOST_REQUIRE(alternate_next.Append(hash32(
        "8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f")));
    BOOST_REQUIRE(alternate_next.Append(hash32(
        "6dc1c216030073b6d27bc55cc559a2fad953c9dbcd4cdaf83204f85c1fd3355d")));
    BOOST_REQUIRE(alternate_next.IsSane());
    BOOST_REQUIRE(next.IsSane());
    BOOST_REQUIRE_EQUAL(alternate_next.count, next.count);
    BOOST_REQUIRE(alternate_next.root != next.root);
    error.clear();
    BOOST_CHECK(!usdd::ComputeWithdrawalBip301CriticalHash(
        genesis, slot, candidate_a, next, alternate_next, rejected, &error));
    BOOST_CHECK(rejected.IsNull());
    BOOST_CHECK_EQUAL(
        error, "USDD BIP301 checkpoint has a malformed accumulator transition");

    const auto make_m7 = [slot](const uint256& critical_hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(slot);
        const std::vector<unsigned char> display_hash =
            ParseHex(critical_hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_parent_block = [](const CScript& m7) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
        coinbase.vout.emplace_back(0, m7);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    const Bitcoin::CBlock parent_a = make_parent_block(make_m7(critical_a));
    const Bitcoin::CBlock parent_b = make_parent_block(make_m7(critical_b));
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        parent_a, slot, critical_a, nullptr, &error));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        parent_a, slot, critical_b, nullptr, &error));
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        parent_b, slot, critical_b, nullptr, &error));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        parent_b, slot, critical_a, nullptr, &error));

    // A malformed BIP301 lookalike is not an M7 under the enforcer grammar.
    // It must be ignored when the block also carries one exact slot-24 M7.
    std::vector<unsigned char> malformed_payload = ParseHex("d1617368");
    malformed_payload.push_back(slot);
    malformed_payload.insert(malformed_payload.end(), 31, 0x42);
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
    coinbase.vout.emplace_back(
        0, CScript() << OP_RETURN << malformed_payload);
    coinbase.vout.emplace_back(0, make_m7(critical_a));
    Bitcoin::CBlock parent_with_unrelated_invalid_message;
    parent_with_unrelated_invalid_message.vtx.push_back(
        Bitcoin::MakeTransactionRef(std::move(coinbase)));
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        parent_with_unrelated_invalid_message, slot, critical_a, nullptr,
        &error));
}

BOOST_AUTO_TEST_CASE(drivechain_native_deposit_block_cap)
{
    Consensus::Params consensus = Params().GetConsensus();
    consensus.drivechain_slot = 24;
    consensus.signet_blocks = false;

    const auto make_block = [](const unsigned int deposit_count) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
        coinbase.vout.emplace_back(CAsset(uint256::ONE), 0,
                                   CScript() << OP_TRUE);

        CMutableTransaction deposits;
        deposits.vout.emplace_back(CAsset(uint256::ONE), 0,
                                   CScript() << OP_TRUE);
        for (unsigned int i = 0; i < deposit_count; ++i) {
            CTxIn input(COutPoint(Txid::FromUint256(uint256::ONE), i));
            input.m_is_pegin = true;
            deposits.vin.push_back(std::move(input));
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(MakeTransactionRef(std::move(deposits)));
        return block;
    };

    BlockValidationState at_cap_state;
    const CBlock at_cap = make_block(MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK);
    BOOST_CHECK(CheckBlock(at_cap, at_cap_state, consensus,
                           /*fCheckPOW=*/false,
                           /*fCheckMerkleRoot=*/false));

    BlockValidationState above_cap_state;
    const CBlock above_cap =
        make_block(MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK + 1);
    BOOST_CHECK(!CheckBlock(above_cap, above_cap_state, consensus,
                            /*fCheckPOW=*/false,
                            /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(above_cap_state.GetRejectReason(),
                      "bad-drivechain-deposit-count");
}

BOOST_AUTO_TEST_CASE(usdd_sp1_annex_block_resource_gate)
{
    Consensus::Params consensus = Params().GetConsensus();
    consensus.enable_usdd_sp1_annex = true;

    const auto make_block = [](const std::vector<std::vector<unsigned char>>& annexes,
                               const bool tapsimplicity_shape = true,
                               const bool correct_controller_cmr = true) {
        CMutableTransaction transaction;
        transaction.vin.resize(annexes.size());
        transaction.witness.vtxinwit.resize(annexes.size());
        for (size_t i = 0; i < annexes.size(); ++i) {
            if (tapsimplicity_shape) {
                std::vector<unsigned char> control(33, 0);
                control[0] = usdd::SP1_TAPSIMPLICITY_LEAF_VERSION;
                std::vector<unsigned char> controller_cmr(32, 0x21);
                if (!correct_controller_cmr) controller_cmr[0] ^= 1;
                transaction.witness.vtxinwit[i].scriptWitness.stack = {
                    std::vector<unsigned char>{0x01},
                    std::vector<unsigned char>{0x01},
                    std::move(controller_cmr),
                    std::move(control),
                    annexes[i]};
            } else {
                transaction.witness.vtxinwit[i].scriptWitness.stack = {
                    std::vector<unsigned char>(64, 0x11), annexes[i]};
            }
        }
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(transaction)));
        return block;
    };

    const auto canonical_annex = [](const size_t total_size) {
        static constexpr uint32_t PUBLIC_VALUES_SIZE{32};
        BOOST_REQUIRE(total_size >=
                      usdd::SP1_ANNEX_HEADER_SIZE + PUBLIC_VALUES_SIZE + 1);
        std::vector<unsigned char> annex(total_size, 0);
        annex[0] = usdd::SP1_ANNEX_TAG;
        std::copy(usdd::SP1_ANNEX_MAGIC.begin(), usdd::SP1_ANNEX_MAGIC.end(),
                  annex.begin() + 1);
        annex[9] = 1;
        annex[10] = 1;
        annex[11] = static_cast<uint8_t>(
            usdd::Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2);
        annex[12] = 1;
        annex[17] = static_cast<unsigned char>(PUBLIC_VALUES_SIZE >> 8);
        annex[18] = static_cast<unsigned char>(PUBLIC_VALUES_SIZE);
        const uint32_t proof_size =
            total_size - usdd::SP1_ANNEX_HEADER_SIZE - PUBLIC_VALUES_SIZE;
        annex[19] = static_cast<unsigned char>(proof_size >> 24);
        annex[20] = static_cast<unsigned char>(proof_size >> 16);
        annex[21] = static_cast<unsigned char>(proof_size >> 8);
        annex[22] = static_cast<unsigned char>(proof_size);
        std::copy(
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.begin(),
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.end(),
            annex.begin() + 23);
        std::fill(annex.begin() + usdd::SP1_ANNEX_HEADER_SIZE,
                  annex.begin() + usdd::SP1_ANNEX_HEADER_SIZE +
                      PUBLIC_VALUES_SIZE,
                  0x42);
        annex.back() = 1;
        return annex;
    };

    const std::vector<unsigned char> canonical =
        canonical_annex(usdd::SP1_ANNEX_HEADER_SIZE + 32 + 1);
    const std::vector<unsigned char> malformed_namespace{
        usdd::SP1_ANNEX_TAG, 'U', 'S', 'D', 'D'};
    const std::vector<unsigned char> unrelated_annex{
        usdd::SP1_ANNEX_TAG, 'U', 'S', 'D', 'X'};

    BlockValidationState unrelated_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({unrelated_annex, unrelated_annex}), unrelated_state,
        consensus));

    BlockValidationState one_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({canonical}), one_state, consensus));

    BlockValidationState wrong_controller_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({canonical}, /*tapsimplicity_shape=*/true,
                   /*correct_controller_cmr=*/false),
        wrong_controller_state, consensus));

    std::vector<unsigned char> wrong_guest = canonical;
    wrong_guest[23] ^= 1;
    BlockValidationState wrong_guest_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({wrong_guest}), wrong_guest_state, consensus));

    std::vector<unsigned char> malformed_public_values = canonical;
    std::fill(malformed_public_values.begin() + usdd::SP1_ANNEX_HEADER_SIZE,
              malformed_public_values.begin() +
                  usdd::SP1_ANNEX_HEADER_SIZE + 32,
              0);
    BlockValidationState malformed_public_values_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({malformed_public_values}),
        malformed_public_values_state, consensus));
    BOOST_CHECK_EQUAL(malformed_public_values_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-envelope");

    const auto annex_with_public_values_size = [](const uint32_t public_values_size) {
        const uint32_t proof_size{1};
        std::vector<unsigned char> annex(
            usdd::SP1_ANNEX_HEADER_SIZE + public_values_size + proof_size, 0);
        annex[0] = usdd::SP1_ANNEX_TAG;
        std::copy(usdd::SP1_ANNEX_MAGIC.begin(), usdd::SP1_ANNEX_MAGIC.end(),
                  annex.begin() + 1);
        annex[9] = 1;
        annex[10] = 1;
        annex[11] = static_cast<uint8_t>(
            usdd::Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2);
        annex[12] = 1;
        annex[15] = static_cast<unsigned char>(public_values_size >> 24);
        annex[16] = static_cast<unsigned char>(public_values_size >> 16);
        annex[17] = static_cast<unsigned char>(public_values_size >> 8);
        annex[18] = static_cast<unsigned char>(public_values_size);
        annex[22] = proof_size;
        std::copy(
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.begin(),
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.end(),
            annex.begin() + 23);
        std::fill(annex.begin() + usdd::SP1_ANNEX_HEADER_SIZE,
                  annex.begin() + usdd::SP1_ANNEX_HEADER_SIZE + public_values_size,
                  0x42);
        annex.back() = 1;
        return annex;
    };

    const std::vector<unsigned char> oversized_public_values =
        annex_with_public_values_size(usdd::SP1_PUBLIC_VALUES_MAX_SIZE + 1);
    BlockValidationState oversized_public_values_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({oversized_public_values}), oversized_public_values_state,
        consensus));
    BOOST_CHECK_EQUAL(oversized_public_values_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-public-values");

    const std::vector<unsigned char> wrong_width_public_values =
        annex_with_public_values_size(31);
    BlockValidationState wrong_width_public_values_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({wrong_width_public_values}), wrong_width_public_values_state,
        consensus));
    BOOST_CHECK_EQUAL(wrong_width_public_values_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-envelope");

    std::vector<unsigned char> wrong_statement_kind = canonical;
    wrong_statement_kind[11] = 0xff;
    BlockValidationState wrong_statement_kind_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({wrong_statement_kind}), wrong_statement_kind_state,
        consensus));
    BOOST_CHECK_EQUAL(wrong_statement_kind_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-envelope");

    std::vector<unsigned char> legacy_v8_statement = canonical;
    legacy_v8_statement[11] =
        static_cast<uint8_t>(usdd::Sp1StatementKind::ETH_STATE_V1);
    BlockValidationState legacy_v8_statement_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({legacy_v8_statement}), legacy_v8_statement_state,
        consensus));
    BOOST_CHECK_EQUAL(legacy_v8_statement_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-envelope");

    BlockValidationState two_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({canonical, canonical}), two_state,
        consensus));
    BOOST_CHECK_EQUAL(two_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-count");

    BlockValidationState malformed_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({malformed_namespace}), malformed_state, consensus));
    BOOST_CHECK_EQUAL(malformed_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-envelope");

    BlockValidationState wrong_shape_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({canonical}, /*tapsimplicity_shape=*/false),
        wrong_shape_state, consensus));
    BOOST_CHECK_EQUAL(wrong_shape_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-spend-shape");

    std::vector<unsigned char> at_size_limit =
        canonical_annex(usdd::SP1_ANNEX_MAX_SIZE);
    BlockValidationState at_size_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({at_size_limit}), at_size_state, consensus));

    // The reserved transaction is independently capped at one quarter of the
    // repriced block after the generic controller-bound lane is active.
    CBlock overweight_block = make_block({at_size_limit});
    CMutableTransaction overweight_tx{*overweight_block.vtx.front()};
    overweight_tx.witness.vtxinwit[0].scriptWitness.stack[0].resize(
        ElementsDrivechainIdentity::USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT +
            4'096U,
        0x55);
    overweight_block.vtx.front() = MakeTransactionRef(std::move(overweight_tx));
    BOOST_REQUIRE(GetTransactionWeight(*overweight_block.vtx.front()) >
                  static_cast<int64_t>(usdd::SP1_PROOF_TX_MAX_WEIGHT));
    BlockValidationState overweight_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        overweight_block, overweight_state, consensus));
    BOOST_CHECK_EQUAL(overweight_state.GetRejectReason(),
                      "bad-usdd-sp1-tx-weight");

    at_size_limit.push_back(0);
    BlockValidationState oversized_state;
    BOOST_CHECK(!CheckUsddSp1AnnexBlockResources(
        make_block({at_size_limit}), oversized_state, consensus));
    BOOST_CHECK_EQUAL(oversized_state.GetRejectReason(),
                      "bad-usdd-sp1-annex-size");

    consensus.enable_usdd_sp1_annex = false;
    BlockValidationState disabled_state;
    BOOST_CHECK(CheckUsddSp1AnnexBlockResources(
        make_block({malformed_namespace, malformed_namespace}), disabled_state,
        consensus));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_rpc_host_is_loopback_only)
{
    BOOST_CHECK(IsMainchainRPCHostAllowed("127.0.0.1", true));
    BOOST_CHECK(IsMainchainRPCHostAllowed("127.255.255.254", true));
    BOOST_CHECK(IsMainchainRPCHostAllowed("::1", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("0.0.0.0", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("192.168.10.25", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("10.0.0.2", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("::", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("fd00::1", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("localhost", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed("parent.example", true));
    BOOST_CHECK(!IsMainchainRPCHostAllowed(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
        true));

    // Ordinary Elements networks preserve their existing hostname support.
    BOOST_CHECK(IsMainchainRPCHostAllowed("localhost", false));
    BOOST_CHECK(IsMainchainRPCHostAllowed("parent.example", false));
}

BOOST_AUTO_TEST_CASE(drivechain_mempool_epoch_fences_native_pegins)
{
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(0, 0));
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(1, 0));
    BOOST_CHECK(!IsDrivechainMempoolEpochCurrent(2, 1));
    BOOST_CHECK(IsDrivechainMempoolEpochCurrent(1, 1));
    BOOST_CHECK(IsDrivechainMempoolEpochCurrent(
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<uint64_t>::max()));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_rejection_strikes_are_per_edge)
{
    const uint256 p1 = uint256::ONE;
    const uint256 q1 = uint256S("02");
    const uint256 p2 = uint256S("03");
    const uint256 q2 = uint256S("04");

    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          {}, {}, 0, p1, q1),
                      1U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 1, p1, q1),
                      2U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 99, p2, q2),
                      1U);
    BOOST_CHECK_EQUAL(NextDrivechainParentRejectedStrikeCount(
                          p1, q1, 1, {}, q1),
                      0U);
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_bid_selection)
{
    CAmount selected{0};
    std::string error;
    BOOST_CHECK(ComputeDrivechainBmmBid(
        DEFAULT_DRIVECHAIN_BMM_BID, 0, selected, &error));
    BOOST_CHECK_EQUAL(selected, DEFAULT_DRIVECHAIN_BMM_BID);
    BOOST_CHECK(ComputeDrivechainBmmBid(1000, 2500, selected, &error));
    BOOST_CHECK_EQUAL(selected, 2500);
    BOOST_CHECK(ComputeDrivechainBmmBid(MAX_MONEY, MAX_MONEY,
                                        selected, &error));
    BOOST_CHECK_EQUAL(selected, MAX_MONEY);
    BOOST_CHECK(!ComputeDrivechainBmmBid(0, 0, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(-1, 0, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(1, -1, selected, &error));
    BOOST_CHECK(!ComputeDrivechainBmmBid(MAX_MONEY + 1, 0,
                                         selected, &error));

    CAmount parsed{0};
    BOOST_CHECK(ParseDrivechainBmmBid("1000", parsed, &error));
    BOOST_CHECK_EQUAL(parsed, 1000);
    BOOST_CHECK(ParseDrivechainBmmBid(
        util::ToString(MAX_MONEY), parsed, &error));
    BOOST_CHECK_EQUAL(parsed, MAX_MONEY);
    BOOST_CHECK(!ParseDrivechainBmmBid("1000garbage", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(" 1000", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("1000 ", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("0", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("-1", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(
        util::ToString(MAX_MONEY + 1), parsed, &error));
}

BOOST_AUTO_TEST_CASE(elements_production_identity_gate)
{
    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto elements_base = CreateBaseChainParams(CBaseChainParams::ELEMENTS);
    std::string error;
    BOOST_CHECK(IsCanonicalElementsProductionIdentity(*elements, *elements_base, &error));
    BOOST_CHECK(error.empty());

    const auto signet = CreateChainParams(args, CBaseChainParams::SIGNET);
    const auto signet_base = CreateBaseChainParams(CBaseChainParams::SIGNET);
    BOOST_CHECK(!IsCanonicalElementsProductionIdentity(*signet, *signet_base, &error));
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(drivechain_bmm_wait_error_classification)
{
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM successor has no enforcer-recognized M7 for sidechain slot 24"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "cached parent edge has no unique enforcer-recognized M7; await a fresh authenticated edge"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "expected critical hash does not match the cached enforcer-recognized M7; no parent RPC performed"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM block is not the exact successor of committed parent"));
    BOOST_CHECK(IsDefinitiveDrivechainBmmWaitError(
        "BMM block is not the active-chain block at its declared height"));

    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "authenticated parent replay cache is not current"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "authenticated BMM edge cache is busy"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "parent RPC transport failure"));
    BOOST_CHECK(!IsDefinitiveDrivechainBmmWaitError(
        "parent-chain reorg raced BIP301 validation at successor Q"));
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(bounded_direct_child_process)
{
    const BoundedCommandResult echo = RunBoundedCommand(
        {"/bin/echo", "bounded-child-ok"},
        std::chrono::milliseconds{1000}, 1024);
    BOOST_REQUIRE(echo.started);
    BOOST_CHECK(echo.exited);
    BOOST_CHECK_EQUAL(echo.exit_code, 0);
    BOOST_CHECK_EQUAL(echo.output, "bounded-child-ok\n");
    BOOST_CHECK(!echo.timed_out);
    BOOST_CHECK(!echo.output_truncated);

    const BoundedCommandResult truncated = RunBoundedCommand(
        {"/usr/bin/yes", "x"}, std::chrono::milliseconds{1000}, 1024);
    BOOST_REQUIRE(truncated.started);
    BOOST_CHECK(truncated.exited);
    BOOST_CHECK(truncated.output_truncated);
    BOOST_CHECK_EQUAL(truncated.output.size(), 1024U);

    const BoundedCommandResult timed_out = RunBoundedCommand(
        {"/bin/sleep", "5"}, std::chrono::milliseconds{50}, 1024);
    BOOST_REQUIRE(timed_out.started);
    BOOST_CHECK(timed_out.exited);
    BOOST_CHECK(timed_out.timed_out);

    const BoundedCommandResult cancelled = RunBoundedCommand(
        {"/bin/sleep", "5"}, std::chrono::milliseconds{1000}, 1024,
        [] { return true; });
    BOOST_REQUIRE(cancelled.started);
    BOOST_CHECK(cancelled.exited);
    BOOST_CHECK(cancelled.cancelled);
}
#endif

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(CAsset(), 0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

BOOST_AUTO_TEST_CASE(bitcoin_parent_signet_solution_is_checked_without_translation)
{
    Bitcoin::CBlock block;
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);

    std::vector<unsigned char> witness_commitment{0xaa, 0x21, 0xa9, 0xed};
    witness_commitment.resize(36, 0x42);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << witness_commitment);
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));

    std::string error;
    // The exact pinned parent genesis is consensus-special and has no Signet
    // solution. Only exact hash equality may bypass ordinary challenge checks.
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, block.GetHash(), &error));
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, CScript() << OP_TRUE, uint256::ONE, &error));
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(block, CScript() << OP_0, uint256::ONE, &error));

    Bitcoin::CBlock no_commitment = block;
    Bitcoin::CMutableTransaction malformed_coinbase(*no_commitment.vtx[0]);
    malformed_coinbase.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{0x01};
    no_commitment.vtx[0] = Bitcoin::MakeTransactionRef(std::move(malformed_coinbase));
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(no_commitment, CScript() << OP_TRUE, uint256::ONE, &error));
}

BOOST_AUTO_TEST_CASE(layer_two_parent_signet_real_signature_regression)
{
    // LayerTwo-Labs Signet block 5580 is the immutable Elements parent replay
    // checkpoint. This vector exercises the actual P2WPKH challenge and a real
    // ECDSA Signet solution, not the OP_TRUE parser-only fixture above.
    static constexpr const char* RAW_BLOCK_5580 =
        "00000020027d89a3fdacc10943565cfdbc1d5a32fb6f3d638e3a5dc0c9b7fd4546020000f484c8e55e26cd1eb8d279dfbfd56c44a27995cdb4c057344f6b3e0951fc2b3db5c65a6a3d77031e24a88a0001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0302cc15ffffffff090000000000000000276a25d161736804554faf2df2135a463ad1fefdf6ecbffd27f2a2bfabba909376d9d628724dfe900000000000000000276a25d1617368093f9140f0756e966e730317341a8eb3826d0e9ba86f6e22e5a90f4ba4ad2eed390000000000000000276a25d161736862ecce70a22de077e7192456ebfd30ed617fc14eec92782936e5003307a81b27370000000000000000276a25d16173686323f3c921f22f6e4a7f9f8be1664028f2dd75ba3cc24a3794fe4c65e6222428450000000000000000276a25d16173680263c29a2764d747e4d1e94dc4de89aab1a844dcbcbcb0231715656f154a800ad50000000000000000276a25d16173680d82352000588a4ea8444ca7e585bfef39382703d2247a29389d01f9f9106c60d900000000000000000f6a0dd77d177601ffffffffffffffff00f2052a01000000160014fae83223f01759582ffe70f5f770eb8462f04da20000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201e4aef7971e3279353d1c948c0af0a9e6a943a8dc8c9dcc106104c8d782bc09602206a4aadfeea8f8edf14dea5e158977ce1badf76b4faf4ab776081fab3f68738f8012103675b73e701c9dab7de809bb0000b4c1205f9a834d669a7f47c107a7d2c199f560120000000000000000000000000000000000000000000000000000000000000000000000000";

    DataStream stream(ParseHex(RAW_BLOCK_5580));
    Bitcoin::CBlock block;
    stream >> TX_WITH_WITNESS(block);
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(
        block.GetHash(),
        uint256S("000002a28e4f1c4599a7878da30ce0197be99ffd1d8e6d20d1a032011448011e"));

    const std::vector<unsigned char> challenge_bytes =
        ParseHex("00148835832e28c816b7acd8fdb19772ab2199603a56");
    const CScript challenge(challenge_bytes.begin(), challenge_bytes.end());
    const uint256 parent_genesis = uint256S(
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6");
    std::string error;
    BOOST_CHECK(CheckBitcoinSignetBlockSolution(block, challenge, parent_genesis, &error));

    // nTime is covered by the Signet signature. The authentic solution must
    // fail if any signed header field is changed.
    Bitcoin::CBlock tampered = block;
    ++tampered.nTime;
    BOOST_CHECK(!CheckBitcoinSignetBlockSolution(tampered, challenge, parent_genesis, &error));
}

BOOST_AUTO_TEST_CASE(existing_signet_is_not_elements_drivechain)
{
    ArgsManager signet_argsman;
    const auto signet_params = CreateChainParams(signet_argsman, CBaseChainParams::SIGNET);
    const auto& consensus = signet_params->GetConsensus();

    // These values are part of the existing Signet genesis identity. Elements
    // Drivechain uses a newly generated Elements-mode network with Simplicity active;
    // silently changing either setting here would reinterpret an existing
    // chain under different consensus rules.
    BOOST_CHECK(!consensus.elements_mode);
    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime,
        Consensus::BIP9Deployment::NEVER_ACTIVE);
}

BOOST_AUTO_TEST_CASE(elements_is_default_and_prelaunch_usdd_alias_is_rejected)
{
    BOOST_CHECK_EQUAL(CBaseChainParams::DEFAULT, "elements");
    BOOST_CHECK_THROW(CreateBaseChainParams("usdd"), std::runtime_error);
    ArgsManager args;
    BOOST_CHECK_THROW(CreateChainParams(args, "usdd"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(installed_programs_accept_only_elements_chain_selector)
{
    ArgsManager canonical;
    BOOST_CHECK_NO_THROW(EnsureElementsProductionChain(canonical));

    for (const char* const legacy : {"main", "test", "signet", "regtest", "liquidv1", "liquidtestnet", "usdd", "custom"}) {
        ArgsManager args;
        args.ForceSetArg("-chain", legacy);
        BOOST_CHECK_THROW(EnsureElementsProductionChain(args), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(elements_key_namespaces_match_documented_derivation_domains)
{
    const auto domain_hash = [](const char* domain) {
        std::array<unsigned char, CSHA256::OUTPUT_SIZE> result{};
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(domain), std::strlen(domain))
            .Finalize(result.data());
        return result;
    };
    const auto wif = domain_hash(ElementsDrivechainIdentity::WIF_PREFIX_DOMAIN);
    const auto extpub = domain_hash(ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX_DOMAIN);
    const auto extprv = domain_hash(ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX_DOMAIN);
    BOOST_CHECK_EQUAL(wif[0], ElementsDrivechainIdentity::SECRET_KEY_PREFIX);
    BOOST_CHECK(std::equal(
        ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX.begin(),
        ElementsDrivechainIdentity::EXT_PUBLIC_KEY_PREFIX.end(), extpub.begin()));
    BOOST_CHECK(std::equal(
        ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX.begin(),
        ElementsDrivechainIdentity::EXT_SECRET_KEY_PREFIX.end(), extprv.begin()));
}

BOOST_AUTO_TEST_CASE(elements_chain_has_frozen_drivechain_identity)
{
    ArgsManager args;
    // These custom-chain switches must not alter the dedicated Elements network.
    args.ForceSetArg("-con_elementsmode", "0");
    args.ForceSetArg("-con_has_parent_chain", "0");
    args.ForceSetArg("-parentgenesisblockhash", uint256::ONE.GetHex());

    const auto params = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto& consensus = params->GetConsensus();
    const auto base_params = CreateBaseChainParams(CBaseChainParams::ELEMENTS);

    BOOST_CHECK_EQUAL(params->NetworkIDString(), "elements");
    BOOST_CHECK_EQUAL(base_params->DataDir(), "elements-v11");
    BOOST_CHECK_EQUAL(base_params->RPCPort(), 7065);
    BOOST_CHECK_EQUAL(base_params->MainchainRPCPort(), 18302);
    BOOST_CHECK_EQUAL(base_params->OnionServiceTargetPort(), 37066);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 7066);

    BOOST_CHECK(consensus.elements_mode);
    BOOST_CHECK(consensus.has_parent_chain);
    BOOST_REQUIRE(consensus.drivechain_slot.has_value());
    BOOST_CHECK_EQUAL(*consensus.drivechain_slot, 24);
    BOOST_CHECK(consensus.enable_usdd_sp1_annex);
    BOOST_CHECK_EQUAL(
        params->ParentGenesisBlockHash(),
        uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
    BOOST_CHECK_EQUAL(
        HexStr(consensus.parent_signet_challenge),
        "");
    BOOST_CHECK_EQUAL(
        consensus.parentChainPowLimit,
        uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    BOOST_CHECK(!consensus.signet_blocks);
    BOOST_CHECK(consensus.signblockscript == CScript() << OP_TRUE);
    BOOST_CHECK_EQUAL(
        params->HashGenesisBlock(),
        uint256S("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd"));
    BOOST_CHECK_EQUAL(
        params->GenesisBlock().hashMerkleRoot,
        uint256S("0fc01d7c98bda1c73fef20538e2832f0d870cd2da51bfb42d9f9eddded8c2a44"));
    BOOST_CHECK_EQUAL(
        consensus.pegged_asset.GetHex(),
        "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4");
    BOOST_CHECK_EQUAL(params->GenesisBlock().nTime, 1784334600U);
    BOOST_CHECK(params->HashGenesisBlock() != params->ParentGenesisBlockHash());
    BOOST_CHECK(consensus.subsidy_asset == consensus.pegged_asset);

    BOOST_CHECK_EQUAL(
        consensus.drivechain_protocol_manifest_hash,
        uint256S("fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6"));
    BOOST_CHECK_EQUAL(
        HexStr(consensus.drivechain_proposal_description),
        ElementsDrivechainIdentity::PROPOSAL_DESCRIPTION_HEX);
    BOOST_REQUIRE(consensus.drivechain_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_proposal_hash,
        uint256S("866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400"));
    BOOST_REQUIRE(consensus.drivechain_parent_state_active_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_parent_state_active_proposal_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_proposal_height, 0U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_proposal_block_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_activation_height, 0U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_activation_block_hash,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_height, 995347U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_hash,
        uint256S("000000000000000002838070eb876cd37738a069528efc82d946fbd25e763152"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_chainwork,
        uint256S("0000000000000000000000000000000000000001418d991091e5b78fab4ab500"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_ctip_txid,
        uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_vout, 4294967295U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_value, 0);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_proposal_max_age, 36U);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_activation_threshold, 30U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_proposal_max_age, 144U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_activation_threshold, 72U);
    BOOST_CHECK_EQUAL(consensus.drivechain_withdrawal_bundle_max_age, 144U);
    BOOST_CHECK_EQUAL(consensus.drivechain_withdrawal_bundle_inclusion_threshold, 72U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_replay_version, 4U);
    BOOST_CHECK_EQUAL(consensus.drivechain_annex_feature_version, 2U);
    BOOST_CHECK(consensus.drivechain_m6_withdrawal_validation);

    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime,
        Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "elements");
    BOOST_CHECK_EQUAL(params->Blech32HRP(), "elementsl");
    BOOST_CHECK_EQUAL(params->ParentBech32HRP(), "bc");
    BOOST_CHECK_EQUAL(HexStr(params->MessageStart()), "df91d03e");
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 6'000'000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 6'000'000U);
    BOOST_CHECK_EQUAL(usdd::SP1_ANNEX_MAX_SIZE, 1'310'720U);
    BOOST_CHECK_EQUAL(usdd::SP1_PROOF_TX_MAX_WEIGHT, 1'500'000U);
    BOOST_CHECK(ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
    BOOST_CHECK_EQUAL(
        ElementsDrivechainIdentity::USDD_SP1_DEPLOYMENT_BINDING_VERSION, 2U);
    BOOST_CHECK(std::all_of(
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID.begin(),
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID.end(),
        [](const uint8_t byte) { return byte == 0; }));
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::SECRET_KEY)), "37");
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY)), "18717df5");
    BOOST_CHECK_EQUAL(HexStr(params->Base58Prefix(CChainParams::EXT_SECRET_KEY)), "b263bd77");

    std::string identity_error;
    BOOST_CHECK_MESSAGE(
        IsCanonicalElementsProductionIdentity(*params, *base_params, &identity_error),
        identity_error);
}

BOOST_AUTO_TEST_CASE(elements_height_one_uses_simplicity_consensus_flags)
{
    ArgsManager args;
    const auto params = CreateChainParams(args, CBaseChainParams::ELEMENTS);

    CBlockIndex genesis_index{params->GenesisBlock()};
    genesis_index.nHeight = 0;
    const uint256 first_block_hash{};    CBlockIndex first_block_index;    first_block_index.phashBlock = &first_block_hash;
    first_block_index.pprev = &genesis_index;
    first_block_index.nHeight = 1;

    const unsigned int flags = GetBlockScriptFlagsForTesting(
        &first_block_index, params->GetConsensus());
    BOOST_CHECK(flags & SCRIPT_VERIFY_TAPROOT);
    BOOST_CHECK(flags & SCRIPT_VERIFY_SIMPLICITY);
    BOOST_CHECK(flags & SCRIPT_VERIFY_USDD_SP1_ANNEX);
    BOOST_CHECK(!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY));
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_USDD_SP1_ANNEX);
}

BOOST_AUTO_TEST_CASE(drivechain_mempool_parent_mtp_requires_sane_active_anchor)
{
    LOCK(cs_main);
    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto ordinary = CreateChainParams(args, CBaseChainParams::MAIN);

    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        nullptr, elements->GetConsensus()).has_value());

    CBlockIndex genesis{elements->GenesisBlock()};
    genesis.nHeight = 0;
    genesis.m_chain_tx_count = 1;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &genesis, elements->GetConsensus()).has_value());

    CBlockIndex tip;
    tip.pprev = &genesis;
    tip.nHeight = 1;
    tip.m_chain_tx_count = 1;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());

    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("03");
    anchor.bmm_chainwork = uint256S("04");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 123456;
    BOOST_REQUIRE(anchor.IsSane());
    tip.m_drivechain_anchor = anchor;

    const auto mtp = GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus());
    BOOST_REQUIRE(mtp.has_value());
    BOOST_CHECK_EQUAL(*mtp, anchor.parent_median_time_past);
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, ordinary->GetConsensus()).has_value());

    tip.m_chain_tx_count = 0;
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());
    tip.m_chain_tx_count = 1;
    tip.m_drivechain_anchor->bmm_height++;
    BOOST_CHECK(!tip.m_drivechain_anchor->IsSane());
    BOOST_CHECK(!GetDrivechainMempoolParentMtp(
        &tip, elements->GetConsensus()).has_value());
}

BOOST_AUTO_TEST_CASE(v11_prior_active_parent_checkpoint_codec_is_exact_and_fail_closed)
{
    LOCK(cs_main);
    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S(
        "0123456789abcdef1032547698badcfeffeeddccbbaa99887766554433221100");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S(
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff00");
    anchor.bmm_chainwork = uint256S(
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff01");
    anchor.parent_height = 0x01020304;
    anchor.bmm_height = 0x01020305;
    anchor.parent_median_time_past = 0x01020304ULL;
    BOOST_REQUIRE(anchor.IsSane());

    const auto encoded = EncodePriorActiveBmmParentCheckpoint(anchor);
    BOOST_REQUIRE(encoded.has_value());
    const auto expected = ParseHex(
        "0123456789abcdef1032547698badcfeffeeddccbbaa99887766554433221100"
        "0000000001020304"
        "0000000001020304"
        "102030405060708090a0b0c0d0e0f001112233445566778899aabbccddeeff00");
    BOOST_REQUIRE_EQUAL(expected.size(), encoded->size());
    BOOST_CHECK_EQUAL_COLLECTIONS(encoded->begin(), encoded->end(),
                                  expected.begin(), expected.end());

    ArgsManager args;
    const auto elements = CreateChainParams(args, CBaseChainParams::ELEMENTS);
    const auto ordinary = CreateChainParams(args, CBaseChainParams::MAIN);
    CBlockIndex genesis{elements->GenesisBlock()};
    genesis.nHeight = 0;
    genesis.m_chain_tx_count = 1;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &genesis, elements->GetConsensus()).has_value());

    CBlockIndex authenticated_tip;
    authenticated_tip.pprev = &genesis;
    authenticated_tip.nHeight = 1;
    authenticated_tip.m_chain_tx_count = 1;
    authenticated_tip.m_drivechain_anchor = anchor;
    const auto authenticated = GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus());
    BOOST_REQUIRE(authenticated.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(authenticated->begin(), authenticated->end(),
                                  expected.begin(), expected.end());
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, ordinary->GetConsensus()).has_value());

    authenticated_tip.m_chain_tx_count = 0;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus()).has_value());
    authenticated_tip.m_chain_tx_count = 1;
    authenticated_tip.nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!GetPriorActiveBmmParentCheckpoint(
        &authenticated_tip, elements->GetConsensus()).has_value());

    anchor.parent_block_hash.SetNull();
    BOOST_CHECK(!EncodePriorActiveBmmParentCheckpoint(anchor).has_value());
}

BOOST_AUTO_TEST_CASE(v11_atomic_parent_script_cache_suffix_is_exact_and_versioned)
{
    const auto endpoint_bytes = ParseHex(
        "000002574f02cf5ee7d7cb5272f48cdefc2484e8f8b73de99564bfe80b8c0712"
        "0000000000000001"
        "0000000064d54da7"
        "000000000000000000000000000000000000000000000000000000000093a828");
    BOOST_REQUIRE_EQUAL(endpoint_bytes.size(), PriorActiveBmmParentCheckpoint{}.size());
    PriorActiveBmmParentCheckpoint endpoint{};
    std::copy(endpoint_bytes.begin(), endpoint_bytes.end(), endpoint.begin());

    const auto suffix = EncodeV11AtomicBmmScriptCacheSuffix(endpoint);
    BOOST_REQUIRE_EQUAL(suffix.size(), 115U);
    BOOST_CHECK_EQUAL(HexStr(std::vector<unsigned char>(suffix.begin(), suffix.begin() + 32)),
                      "9fa5b41185f7391ffda63b6bb14ba79b138f46396bca42b75efde5dc5503fe26");
    BOOST_CHECK_EQUAL(suffix[32], 0U);
    BOOST_CHECK_EQUAL(suffix[33], 1U);
    BOOST_CHECK_EQUAL(suffix[34], 1U);
    BOOST_CHECK_EQUAL_COLLECTIONS(suffix.begin() + 35, suffix.end(),
                                  endpoint.begin(), endpoint.end());

    std::array<unsigned char, 32> suffix_hash{};
    CSHA256().Write(suffix.data(), suffix.size()).Finalize(suffix_hash.data());
    BOOST_CHECK_EQUAL(HexStr(suffix_hash),
                      "67a4ed04fc537cacdd079efb6d037f764ebc6e4e12fbf7c61f2c4c5aa6af3da0");

    std::array<unsigned char, 124> complete{};
    const auto legacy_prefix = ParseHex("010000000064d54da7");
    std::copy(legacy_prefix.begin(), legacy_prefix.end(), complete.begin());
    std::copy(suffix.begin(), suffix.end(), complete.begin() + 9);
    std::array<unsigned char, 32> complete_hash{};
    CSHA256().Write(complete.data(), complete.size()).Finalize(complete_hash.data());
    BOOST_CHECK_EQUAL(HexStr(complete_hash),
                      "56a6a70fe130fb1875ea9e12bd226780abf3f791366b2433ac727892c59fefcb");

    const auto absent = EncodeV11AtomicBmmScriptCacheSuffix(std::nullopt);
    BOOST_CHECK_EQUAL(absent[34], 0U);
    BOOST_CHECK(std::all_of(absent.begin() + 35, absent.end(),
                            [](unsigned char byte) { return byte == 0; }));
    std::array<unsigned char, 32> absent_hash{};
    CSHA256().Write(absent.data(), absent.size()).Finalize(absent_hash.data());
    BOOST_CHECK_EQUAL(HexStr(absent_hash),
                      "fd83f267b6d1cce359045086b514accdbcf03f6c2e00645fa4f5fb93fd9f3e91");
}

BOOST_AUTO_TEST_CASE(inactive_checktemplateverify_uses_standard_nop_policy)
{
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS);
    BOOST_CHECK(!(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY));
    BOOST_CHECK(!(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DISCOURAGE_CHECKTEMPLATEVERIFY));
}

BOOST_AUTO_TEST_CASE(drivechain_slot_is_not_enabled_on_other_builtin_networks)
{
    ArgsManager args;
    const std::vector<std::string> ordinary_networks{
        CBaseChainParams::MAIN,
        CBaseChainParams::TESTNET,
        CBaseChainParams::SIGNET,
        CBaseChainParams::REGTEST,
        CBaseChainParams::LIQUID1,
        CBaseChainParams::LIQUID1TEST,
        CBaseChainParams::LIQUIDTESTNET,
    };

    for (const auto& network : ordinary_networks) {
        const auto params = CreateChainParams(args, network);
        BOOST_CHECK_MESSAGE(!params->GetConsensus().drivechain_slot.has_value(), network);
        BOOST_CHECK_MESSAGE(!params->GetConsensus().enable_usdd_sp1_annex, network);

        CBlockIndex genesis_index{params->GenesisBlock()};
        genesis_index.nHeight = 0;
        const uint256 first_block_hash{};        CBlockIndex first_block_index;        first_block_index.phashBlock = &first_block_hash;
        first_block_index.pprev = &genesis_index;
        first_block_index.nHeight = 1;
        const unsigned int flags = GetBlockScriptFlagsForTesting(
            &first_block_index, params->GetConsensus());
        BOOST_CHECK_MESSAGE(!(flags & SCRIPT_VERIFY_USDD_SP1_ANNEX), network);
        BOOST_CHECK_MESSAGE(!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY), network);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_sequence_is_strict)
{
    DrivechainAnchor previous;
    previous.parent_block_hash = uint256S("01");
    previous.bmm_block_hash = uint256S("02");
    previous.parent_chainwork = uint256S("10");
    previous.bmm_chainwork = uint256S("20");
    previous.parent_height = 100;
    previous.bmm_height = 101;
    previous.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(previous.IsSane());

    DrivechainAnchor contiguous;
    contiguous.parent_block_hash = previous.bmm_block_hash;
    contiguous.bmm_block_hash = uint256S("03");
    contiguous.parent_chainwork = previous.bmm_chainwork;
    contiguous.bmm_chainwork = uint256S("30");
    contiguous.parent_height = 101;
    contiguous.bmm_height = 102;
    contiguous.parent_median_time_past = previous.parent_median_time_past + 600;
    BOOST_REQUIRE(contiguous.IsSane());
    BOOST_CHECK(contiguous.Follows(previous));

    DrivechainAnchor wrong_contiguous_hash = contiguous;
    wrong_contiguous_hash.parent_block_hash = uint256S("ff");
    BOOST_CHECK(!wrong_contiguous_hash.Follows(previous));

    DrivechainAnchor skipped_parent_blocks = contiguous;
    skipped_parent_blocks.parent_block_hash = uint256S("04");
    skipped_parent_blocks.bmm_block_hash = uint256S("05");
    skipped_parent_blocks.parent_chainwork = uint256S("40");
    skipped_parent_blocks.bmm_chainwork = uint256S("50");
    skipped_parent_blocks.parent_height = 103;
    skipped_parent_blocks.bmm_height = 104;
    BOOST_REQUIRE(skipped_parent_blocks.IsSane());
    BOOST_CHECK(skipped_parent_blocks.Follows(previous));

    skipped_parent_blocks.parent_chainwork = previous.bmm_chainwork;
    BOOST_CHECK(!skipped_parent_blocks.Follows(previous));

    DrivechainAnchor malformed = contiguous;
    malformed.version = DrivechainAnchor::CURRENT_VERSION + 1;
    BOOST_CHECK(!malformed.IsSane());
    BOOST_CHECK(!malformed.Follows(previous));
}

BOOST_AUTO_TEST_CASE(drivechain_anchor_replacement_requires_proven_orphan)
{
    DrivechainAnchor predecessor;
    predecessor.parent_block_hash = uint256S("01");
    predecessor.bmm_block_hash = uint256S("02");
    predecessor.parent_chainwork = uint256S("10");
    predecessor.bmm_chainwork = uint256S("20");
    predecessor.parent_height = 100;
    predecessor.bmm_height = 101;
    predecessor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(predecessor.IsSane());

    DrivechainAnchor old_anchor;
    old_anchor.parent_block_hash = predecessor.bmm_block_hash;
    old_anchor.bmm_block_hash = uint256S("03");
    old_anchor.parent_chainwork = predecessor.bmm_chainwork;
    old_anchor.bmm_chainwork = uint256S("30");
    old_anchor.parent_height = 101;
    old_anchor.bmm_height = 102;
    old_anchor.parent_median_time_past = 1'700'000'600;
    BOOST_REQUIRE(old_anchor.IsSane());

    DrivechainAnchor replacement = old_anchor;
    replacement.bmm_block_hash = uint256S("04");
    replacement.bmm_chainwork = uint256S("31");
    BOOST_REQUIRE(replacement.IsSane());

    BOOST_CHECK(IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ACTIVE, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::UNAVAILABLE, old_anchor, replacement,
        &predecessor));
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, old_anchor,
        &predecessor));

    DrivechainAnchor wrong_parent = replacement;
    wrong_parent.parent_block_hash = uint256S("ff");
    BOOST_CHECK(!IsDrivechainAnchorReplacementAllowed(
        DrivechainAnchorStatus::ORPHANED, old_anchor, wrong_parent,
        &predecessor));
}

BOOST_AUTO_TEST_CASE(drivechain_replacement_anchor_survives_block_index_reload)
{
    DrivechainAnchor old_anchor;
    old_anchor.parent_block_hash = uint256S("01");
    old_anchor.bmm_block_hash = uint256S("02");
    old_anchor.parent_chainwork = uint256S("10");
    old_anchor.bmm_chainwork = uint256S("20");
    old_anchor.parent_height = 100;
    old_anchor.bmm_height = 101;
    old_anchor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(old_anchor.IsSane());

    DrivechainAnchor replacement = old_anchor;
    replacement.bmm_block_hash = uint256S("03");
    replacement.bmm_chainwork = uint256S("21");
    BOOST_REQUIRE(replacement.IsSane());

    CBlockHeader header = Params().GenesisBlock().GetBlockHeader();
    ++header.nNonce;
    const uint256 block_hash = header.GetHash();
    LOCK(cs_main);
    CBlockIndex index(header);
    index.phashBlock = &block_hash;
    index.nHeight = 1;
    index.nStatus = BLOCK_VALID_TRANSACTIONS;
    index.nTx = 1;
    index.m_drivechain_anchor = old_anchor;

    kernel::BlockTreeDB block_tree_db({.path = {}, .cache_bytes = 1 << 20,
                                      .memory_only = true, .wipe_data = true});
    const std::vector<std::pair<int, const CBlockFileInfo*>> no_files;
    const std::vector<const CBlockIndex*> blocks{&index};
    BOOST_REQUIRE(block_tree_db.WriteBatchSync(no_files, 0, blocks));

    // This is the same synchronous batch overwrite used by reconciliation
    // before it makes the stored block reconnectable.
    index.m_drivechain_anchor = replacement;
    BOOST_REQUIRE(block_tree_db.WriteBatchSync(no_files, 0, blocks));

    std::map<uint256, std::unique_ptr<CBlockIndex>> loaded;
    const auto insert = [&](const uint256& hash) -> CBlockIndex* {
        if (hash.IsNull()) return nullptr;
        auto [it, inserted] = loaded.try_emplace(hash);
        if (inserted) {
            it->second = std::make_unique<CBlockIndex>();
            it->second->phashBlock = &it->first;
        }
        return it->second.get();
    };
    BOOST_REQUIRE(block_tree_db.LoadBlockIndexGuts(
        Params().GetConsensus(), insert, *m_node.shutdown_signal, /*trimBelowHeight=*/0));
    BOOST_REQUIRE_EQUAL(loaded.count(block_hash), 1U);
    BOOST_REQUIRE(loaded.at(block_hash)->m_drivechain_anchor.has_value());
    BOOST_CHECK(*loaded.at(block_hash)->m_drivechain_anchor == replacement);
}

BOOST_AUTO_TEST_CASE(drivechain_best_header_requires_admitted_full_block)
{
    LOCK(cs_main);
    Consensus::Params drivechain;
    drivechain.drivechain_slot = uint8_t{24};

    CBlockIndex index;
    index.nHeight = 1;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    // Header metadata alone is insufficient. nChainTx is set only after an
    // admitted full block (and its ancestry) has been processed.
    index.nStatus |= BLOCK_HAVE_DATA;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    DrivechainAnchor anchor;
    anchor.parent_block_hash = uint256S("01");
    anchor.bmm_block_hash = uint256S("02");
    anchor.parent_chainwork = uint256S("10");
    anchor.bmm_chainwork = uint256S("20");
    anchor.parent_height = 100;
    anchor.bmm_height = 101;
    anchor.parent_median_time_past = 1'700'000'000;
    BOOST_REQUIRE(anchor.IsSane());
    index.m_drivechain_anchor = anchor;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    index.nTx = 1;
    index.m_chain_tx_count = 2;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, drivechain));

    // Pruning removes local block bytes, not the fact that this full block was
    // admitted. It must not dead-end later drivechain synchronization.
    index.nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, drivechain));

    index.nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!IsDrivechainHeaderAuthenticated(&index, drivechain));

    Consensus::Params ordinary;
    BOOST_CHECK(IsDrivechainHeaderAuthenticated(&index, ordinary));
}

BOOST_AUTO_TEST_CASE(drivechain_unknown_sibling_headers_are_not_indexed)
{
    class TestDrivechainParams final : public CChainParams
    {
    public:
        TestDrivechainParams()
        {
            consensus = Params().GetConsensus();
            consensus.drivechain_slot = uint8_t{24};
        }
    } drivechain_params;

    // Header admission now reads the manager's immutable chain parameters.
    const ChainstateManager::Options chainman_opts{
        .chainparams = drivechain_params,
        .datadir = m_path_root / "header-admission",
        .check_block_index = 1,
        .notifications = *m_node.notifications,
        .worker_threads_num = 0,
        .script_execution_cache_bytes = 0,
        .signature_cache_bytes = 0,
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = drivechain_params,
        .blocks_dir = chainman_opts.datadir / "blocks",
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = chainman_opts.datadir / "blocks" / "index",
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    fs::create_directories(blockman_opts.blocks_dir);
    ChainstateManager chainman{*m_node.shutdown_signal, chainman_opts, blockman_opts};
    size_t original_index_size;
    {
        LOCK(cs_main);
        chainman.InitializeChainstate(nullptr);
        original_index_size = chainman.m_blockman.m_block_index.size();
    }

    // Each call models another connection/reconnection offering a distinct
    // sibling. None has a full block/BMM proof, so global persistent width
    // must remain exactly unchanged.
    for (uint32_t nonce = 1; nonce <= 128; ++nonce) {
        CBlockHeader sibling;
        sibling.hashPrevBlock =
            drivechain_params.GetConsensus().hashGenesisBlock;
        sibling.nTime = 1'700'000'000;
        sibling.nNonce = nonce;
        BlockValidationState state;
        BOOST_CHECK(!chainman.ProcessNewBlockHeaders(
            std::span{&sibling, 1}, /*min_pow_checked=*/true, state));
        BOOST_CHECK(state.IsError());
    }

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(
        chainman.m_blockman.m_block_index.size(),
        original_index_size);

    // Reindex can populate the index before the active chain has a tip.
    BOOST_REQUIRE(chainman.ActiveChain().Tip() == nullptr);
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == nullptr);
    CBlockIndex* genesis = chainman.m_blockman.InsertBlockIndex(
        drivechain_params.GetConsensus().hashGenesisBlock);
    BOOST_REQUIRE(genesis != nullptr);
    genesis->nTx = 1;
    genesis->m_chain_tx_count = 1;
    genesis->nChainWork = 1;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == genesis);

    CBlockIndex* unauthenticated = chainman.m_blockman.InsertBlockIndex(uint256S("04"));
    BOOST_REQUIRE(unauthenticated != nullptr);
    unauthenticated->nHeight = 1;
    unauthenticated->nChainWork = 2;
    chainman.RecalculateBestHeader();
    BOOST_CHECK(chainman.m_best_header == genesis);
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_capability_is_fail_closed)
{
    Consensus::Params params;
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_slot = uint8_t{24};
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_m6_withdrawal_validation = true;
    BOOST_CHECK(params.DrivechainWithdrawalValidationEnabled());

    // A capability flag alone must never turn the BIP300 wallet path on for
    // an ordinary Elements network.
    params.drivechain_slot.reset();
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(uint256{"696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c"});
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.witness.vtxinwit.resize(1);
        if (include_witness) {
            coinbase.witness.vtxinwit[0].scriptWitness.stack.resize(1);
            coinbase.witness.vtxinwit[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.witness.vtxinwit[0].scriptWitness.stack[0].empty());
            ++mtx.witness.vtxinwit[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

// ELEMENTS: the offline (chainstate-less) SIGHASH_RANGEPROOF gating used by
// elements-tx must treat liquidv1 as known-active even though dynafed there is
// height-activated rather than ALWAYS_ACTIVE.
BOOST_AUTO_TEST_CASE(sighash_rangeproof_by_params_test)
{
    // liquidv1: dynafed is height-activated (nStartTime = 1000000), NOT the
    // ALWAYS_ACTIVE sentinel, but must be treated as active by params.
    const auto liquidv1 = CreateChainParams(*m_node.args, ChainType::LIQUID1);
    BOOST_CHECK(liquidv1->GetConsensus().vDeployments[Consensus::DEPLOYMENT_DYNA_FED].nStartTime
                != Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK(liquidv1->SighashRangeproofActiveByParams());

    // liquidv1test: overrides dynafed to ALWAYS_ACTIVE, so it is active by params
    // via the ALWAYS_ACTIVE branch (independent of the liquidv1 chain-type check).
    const auto liquidv1test = CreateChainParams(*m_node.args, ChainType::LIQUID1TEST);
    BOOST_CHECK_EQUAL(liquidv1test->GetConsensus().vDeployments[Consensus::DEPLOYMENT_DYNA_FED].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK(liquidv1test->SighashRangeproofActiveByParams());

    // regtest: dynafed never active by default; must be inactive by params.
    const auto regtest = CreateChainParams(*m_node.args, ChainType::REGTEST);
    BOOST_CHECK(!regtest->SighashRangeproofActiveByParams());
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_bundle_wire_format)
{
    const CAmount amount{2'000'000};
    const CAmount mainchain_fee{1'000};
    const CScript payout_script = CScript() << OP_0 <<
        std::vector<unsigned char>(20, 0x11);
    const COutPoint withdrawal_outpoint(Txid::FromUint256(uint256::ONE), 7);

    const wallet::DrivechainWithdrawalBundle bundle =
        wallet::BuildDrivechainWithdrawalBundle(
            amount, mainchain_fee, payout_script, withdrawal_outpoint, 42);
    BOOST_CHECK_EQUAL(
        HexStr(bundle.bytes),
        "020000000001000300000000000000000a6a0800000000000003e8"
        "0000000000000000226a20f62b45f18ab38ddcfbd04c0828e56db8"
        "d872235fb4c4780840980aa0a8de0d5e98801e0000000000160014"
        "111111111111111111111111111111111111111100000000");

    BOOST_REQUIRE_GE(bundle.bytes.size(), 7U);
    BOOST_CHECK_EQUAL(bundle.bytes[4], 0); // SegWit marker
    BOOST_CHECK_EQUAL(bundle.bytes[5], 1); // SegWit flag
    BOOST_CHECK_EQUAL(bundle.bytes[6], 0); // actual empty vin

    // The enforcer uses rust-bitcoin's explicit inputless-transaction decoder.
    // Core's generic decoder rejects this deliberately non-broadcastable
    // blinded form, so decode its vector of outputs independently here.
    DataStream payload(
        std::vector<unsigned char>(bundle.bytes.begin() + 7, bundle.bytes.end()));
    std::vector<Bitcoin::CTxOut> outputs;
    uint32_t lock_time{0};
    payload >> outputs >> lock_time;
    BOOST_CHECK(payload.empty());
    BOOST_CHECK_EQUAL(lock_time, 0);
    BOOST_REQUIRE_EQUAL(outputs.size(), 3U);
    BOOST_CHECK_EQUAL(outputs[0].nValue, 0);
    BOOST_CHECK_EQUAL(outputs[1].nValue, 0);
    BOOST_CHECK_EQUAL(outputs[2].nValue, amount - mainchain_fee);
    BOOST_CHECK(outputs[2].scriptPubKey == payout_script);

    std::vector<unsigned char> no_witness_bytes;
    no_witness_bytes.insert(
        no_witness_bytes.end(), bundle.bytes.begin(), bundle.bytes.begin() + 4);
    no_witness_bytes.insert(
        no_witness_bytes.end(), bundle.bytes.begin() + 6, bundle.bytes.end());
    BOOST_CHECK_EQUAL(Hash(no_witness_bytes), bundle.m6id);
    BOOST_CHECK_EQUAL(
        bundle.m6id.GetHex(),
        "ce1626e43b1d163acaf3fac8ab9f6fb78158d99c53e25bbffdde3c9ed75f0e4b");

    std::vector<unsigned char> fee_bytes;
    fee_bytes.reserve(8);
    for (int byte = 7; byte >= 0; --byte) {
        fee_bytes.push_back((static_cast<uint64_t>(mainchain_fee) >>
                             (8 * byte)) & 0xff);
    }
    BOOST_CHECK(outputs[0].scriptPubKey ==
                (CScript() << OP_RETURN << fee_bytes));
}

BOOST_AUTO_TEST_CASE(drivechain_json_rpc_server_is_loopback_only)
{
    ArgsManager args;
    std::string error;
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());

    args.ForceSetArg("-rpcbind", "127.0.0.1");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());
    args.ForceSetArg("-rpcbind", "[::1]:7041");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.empty());

    for (const std::string& unsafe : {
             "0.0.0.0", "[::]:7041", "192.168.1.10", "localhost",
             "rpc.example:7041"}) {
        args.ForceSetArg("-rpcbind", unsafe);
        BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args, &error));
        BOOST_CHECK(error.find("numeric IPv4 127/8 or IPv6 ::1") !=
                    std::string::npos);
    }

    // Existing authenticated local clients may retain explicit static auth or
    // rpcauth; transport remains local even when rpcallowip is also present.
    args.ForceSetArg("-rpcbind", "127.0.0.1");
    args.ForceSetArg("-rpcallowip", "127.0.0.1");
    args.ForceSetArg("-rpcuser", "bitwindow");
    args.ForceSetArg("-rpcpassword", "local-only-test-secret");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
    args.ForceSetArg("-rest", "1");
    BOOST_CHECK(!ValidateNativeDrivechainRpcServerConfig(args, &error));
    BOOST_CHECK(error.find("unauthenticated") != std::string::npos);
    args.ForceSetArg("-rest", "0");
    BOOST_CHECK(ValidateNativeDrivechainRpcServerConfig(args, &error));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_cookie_is_atomic_private_and_canonical)
{
    const fs::path directory = m_path_root / "drivechain-parent-cookie";
    fs::create_directories(directory);
    const fs::path cookie_path = directory / ".cookie";
    const std::string expected = "__cookie__:" + std::string(64, 'a');
    {
        std::ofstream output(cookie_path, std::ios::binary);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);
#endif

    std::string cookie;
    std::string error;
    BOOST_CHECK(ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK_EQUAL(cookie, expected);
    BOOST_CHECK(error.empty());

    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << "static-user:static-password\n";
        BOOST_REQUIRE(output.good());
    }
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("canonical rotating") != std::string::npos);

#ifndef WIN32
    {
        std::ofstream output(cookie_path, std::ios::binary | std::ios::trunc);
        output << expected << '\n';
        BOOST_REQUIRE(output.good());
    }
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0644), 0);
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_path, cookie, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(cookie_path).c_str(), 0600), 0);

    const fs::path cookie_link = directory / "linked-cookie";
    fs::create_symlink(cookie_path, cookie_link);
    BOOST_CHECK(!ReadNativeDrivechainCookieFile(cookie_link, cookie, &error));
    BOOST_CHECK(error.find("securely open") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(drivechain_parent_static_credentials_are_private_and_explicit)
{
    const fs::path directory = m_path_root / "drivechain-parent-static-auth";
    fs::create_directories(directory);
    const fs::path path = directory / "credentials";
    std::string credentials{"stale credentials"};
    std::string error{"stale error"};
#ifdef WIN32
    // Do not promise POSIX ownership/mode guarantees on a platform without
    // them. The native rotating-cookie path remains a distinct interface.
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("POSIX") != std::string::npos);
#else
    const auto write_credentials = [&](const std::string& contents) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << contents;
        BOOST_REQUIRE(output.good());
        output.close();
        BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0600), 0);
    };

    for (const std::string& suffix : {"", "\n", "\r\n"}) {
        write_credentials("bridge-user:bridge-password" + suffix);
        BOOST_REQUIRE(ReadMainchainRpcCredentialFile(path, credentials, &error));
        BOOST_CHECK_EQUAL(credentials, "bridge-user:bridge-password");
        BOOST_CHECK(error.empty());
        BOOST_CHECK(!ReadNativeDrivechainCookieFile(path, credentials, &error));
        BOOST_CHECK(credentials.empty());
        BOOST_CHECK(error.find("canonical rotating") != std::string::npos);
    }

    const std::vector<std::string> invalid{
        "", "user", ":password", "user:", "user:one:two",
        "user:pass word", "user:pass\tword", "user:pass\nword",
        "user:pass\n\n", std::string("user:pass\0word", 14),
        "__cookie__:" + std::string(64, 'a'),
        "user:" + std::string(1020, 'a'), std::string(4097, 'a'),
    };
    for (const std::string& contents : invalid) {
        write_credentials(contents);
        credentials = "stale credentials";
        BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
        BOOST_CHECK(credentials.empty());
        BOOST_CHECK(!error.empty());
    }

    write_credentials("bridge-user:bridge-password");
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0640), 0);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(path, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(path).c_str(), 0600), 0);

    const fs::path link = directory / "linked-credentials";
    fs::create_symlink(path, link);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(link, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("securely open") != std::string::npos);

    const fs::path fifo = directory / "credential-fifo";
    BOOST_REQUIRE_EQUAL(mkfifo(fs::PathToString(fifo).c_str(), 0600), 0);
    BOOST_CHECK(!ReadMainchainRpcCredentialFile(fifo, credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("regular file") != std::string::npos);

    BOOST_CHECK(!ReadMainchainRpcCredentialFile("relative-file", credentials, &error));
    BOOST_CHECK(credentials.empty());
    BOOST_CHECK(error.find("absolute") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(drivechain_grpc_requires_authenticated_tls)
{
    const fs::path credentials = m_path_root / "drivechain-grpc-tls";
    fs::create_directories(credentials);
    const fs::path ca = credentials / "ca.pem";
    const fs::path certificate = credentials / "elements-client.pem";
    const fs::path key = credentials / "elements-client-key.pem";
    for (const fs::path& path : {ca, certificate, key}) {
        std::ofstream output(fs::PathToString(path));
        output << "test credential\n";
        BOOST_REQUIRE(output.good());
    }

#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(ca).c_str(), 0644), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(certificate).c_str(), 0644), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0600), 0);
#endif

    ArgsManager args;
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));
    args.ForceSetArg("-drivechainbmmgrpccert", fs::PathToString(certificate));
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key));

    std::string error;
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.empty());

    args.ForceSetArg("-drivechainbmmgrpcaddr", "http://127.0.0.1:55051");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("without a URL scheme") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");

    for (const std::string& address : {"192.168.1.2:55051", "localhost:55051", "[::]:55051", "rpc.example:55051"}) {
        args.ForceSetArg("-drivechainbmmgrpcaddr", address);
        BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    }
    args.ForceSetArg("-drivechainbmmgrpcaddr", "[::1]:55051");
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));
    args.ForceSetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051");
    args.ForceSetArg("-drivechainbmmwalletaddr", "127.0.0.1:30301");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    args.ForceSetArg("-drivechainbmmwalletaddr", "127.0.0.1:55051");
    BOOST_CHECK(ValidateDrivechainGrpcTLSConfig(args, &error));

    args.ForceSetArg("-drivechainbmmgrpcauthority", "enforcer.local\nplaintext");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("control characters") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcauthority", "enforcer.local");

    args.ForceSetArg("-drivechainbmmgrpcca",
                     fs::PathToString(credentials / "missing-ca.pem"));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("non-symlink regular file") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpcca", fs::PathToString(ca));

#ifndef WIN32
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0770), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("credential directory") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0700), 0);

    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0644), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("deny all group and other access") != std::string::npos);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(key).c_str(), 0600), 0);

    const fs::path key_link = credentials / "linked-key.pem";
    fs::create_symlink(key, key_link);
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key_link));
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
    BOOST_CHECK(error.find("non-symlink") != std::string::npos);
    args.ForceSetArg("-drivechainbmmgrpckey", fs::PathToString(key));

    const fs::path fake_grpcurl = credentials / "grpcurl";
    {
        std::ofstream output(fs::PathToString(fake_grpcurl));
        output << "#!/bin/sh\nfor argument in \"$@\"; do printf '%s\\n' \"$argument\"; done\n";
        BOOST_REQUIRE(output.good());
    }
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(fake_grpcurl).c_str(), 0700), 0);
    args.ForceSetArg("-drivechainbmmgrpcurl", fs::PathToString(fake_grpcurl));
    const BoundedCommandResult invocation = RunAuthenticatedDrivechainGrpc(
        args,
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        "{\"sidechainId\":24}", std::chrono::seconds{2}, 4096);
    BOOST_CHECK(invocation.started);
    BOOST_CHECK(invocation.exited);
    BOOST_CHECK_EQUAL(invocation.exit_code, 0);
    BOOST_CHECK(invocation.error.empty());
    BOOST_CHECK(invocation.output.find("-cacert\n") != std::string::npos);
    BOOST_CHECK(invocation.output.find("-cert\n") != std::string::npos);
    BOOST_CHECK(invocation.output.find("-key\n") != std::string::npos);
    BOOST_CHECK(invocation.output.find("-plaintext") == std::string::npos);
    BOOST_CHECK(invocation.output.find("127.0.0.1:55051\n") != std::string::npos);

    const auto read = RunAuthenticatedDrivechainGrpc(
        args, "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData", "{}",
        std::chrono::seconds{2}, 4096);
    BOOST_CHECK(read.started && read.exited && read.exit_code == 0);
    BOOST_CHECK(read.output.find("-plaintext") == std::string::npos);

    for (const std::string& path : {std::string{}, std::string{"grpcurl"}, fs::PathToString(credentials / "missing")}) {
        args.ForceSetArg("-drivechainbmmgrpcurl", path);
        BOOST_CHECK(!ValidateDrivechainGrpcExecutable(args, &error));
    }
    const fs::path executable_link = credentials / "grpcurl-link";
    fs::create_symlink(fake_grpcurl, executable_link);
    args.ForceSetArg("-drivechainbmmgrpcurl", fs::PathToString(executable_link));
    BOOST_CHECK(!ValidateDrivechainGrpcExecutable(args, &error));
    args.ForceSetArg("-drivechainbmmgrpcurl", fs::PathToString(fake_grpcurl));
    for (const auto mode : {0755, 0770, 0600}) {
        BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(fake_grpcurl).c_str(), mode), 0);
        BOOST_CHECK(!ValidateDrivechainGrpcExecutable(args, &error));
        const auto rejected = RunAuthenticatedDrivechainGrpc(
            args, "cusf.mainchain.v1.ValidatorService/GetChainTip", "{}",
            std::chrono::seconds{1}, 1024);
        BOOST_CHECK(!rejected.started);
    }
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(fake_grpcurl).c_str(), 0700), 0);
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0770), 0);
    BOOST_CHECK(!ValidateDrivechainGrpcExecutable(args, &error));
    BOOST_REQUIRE_EQUAL(chmod(fs::PathToString(credentials).c_str(), 0700), 0);
    BOOST_CHECK(ValidateDrivechainGrpcExecutable(args, &error));
#endif

    const BoundedCommandResult unknown_method = RunAuthenticatedDrivechainGrpc(
        args, "grpc.health.v1.Health/Check", "{}",
        std::chrono::seconds{1}, 1024);
    BOOST_CHECK(!unknown_method.started);
    BOOST_CHECK(unknown_method.error.find("unrecognized") != std::string::npos);

    const BoundedCommandResult non_object_payload = RunAuthenticatedDrivechainGrpc(
        args,
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        "[]", std::chrono::seconds{1}, 1024);
    BOOST_CHECK(!non_object_payload.started);
    BOOST_CHECK(non_object_payload.error.find("JSON object") != std::string::npos);
    args.ForceSetArg("-drivechainbmmconnectauthcookie", "obsolete-cookie");
    BOOST_CHECK(!ValidateDrivechainGrpcTLSConfig(args, &error));
}

BOOST_AUTO_TEST_CASE(drivechain_reward_script_requires_wallet_owned_key_address)
{
    const CPubKey pubkey(ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    const std::vector<CTxDestination> destinations{
        PKHash(pubkey), WitnessV0KeyHash(pubkey)};
    for (const auto& destination : destinations) {
        const std::string address = EncodeDestination(destination);
        CScript reward_script(OP_TRUE);
        std::string error{"stale error"};
        unsigned int ownership_checks{0};
        BOOST_REQUIRE(BuildDrivechainRewardScript(
            address,
            [&](const CTxDestination& decoded) {
                ++ownership_checks;
                return decoded == destination;
            },
            reward_script, &error));
        BOOST_CHECK(error.empty());
        BOOST_CHECK_EQUAL(ownership_checks, 1U);
        BOOST_CHECK(reward_script == GetScriptForDestination(destination));
        BOOST_CHECK(reward_script != CScript(OP_TRUE));

        // A valid address alone is not permission to pay a bid. Failure must
        // erase any previous script, including the old OP_TRUE fallback.
        BOOST_CHECK(!BuildDrivechainRewardScript(
            address, [](const CTxDestination&) { return false; },
            reward_script, &error));
        BOOST_CHECK(reward_script.empty());
        BOOST_CHECK(!error.empty());
        reward_script = CScript(OP_TRUE);
        BOOST_CHECK(!BuildDrivechainRewardScript(address, {}, reward_script));
        BOOST_CHECK(reward_script.empty());
    }
}

BOOST_AUTO_TEST_CASE(drivechain_reward_script_rejects_unsafe_destinations)
{
    const CPubKey pubkey(ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    WitnessV0KeyHash confidential(pubkey);
    confidential.blinding_pubkey = pubkey;
    std::vector<unsigned char> future_program(32, 0);
    future_program[0] = 1;
    const WitnessUnknown future{2, future_program};
    const CScript anyone_can_spend = CScript() << OP_TRUE;
    const std::vector<std::string> rejected{
        "", "not-an-address", "51", "null",
        // A testnet address is not valid on this fixture's mainnet network.
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        EncodeDestination(ScriptHash(anyone_can_spend)),
        EncodeDestination(WitnessV0ScriptHash(anyone_can_spend)),
        EncodeDestination(WitnessV1Taproot(XOnlyPubKey(pubkey))),
        EncodeDestination(future),
        EncodeDestination(confidential),
    };
    for (const auto& address : rejected) {
        CScript reward_script(OP_TRUE);
        std::string error;
        bool ownership_checked{false};
        BOOST_CHECK(!BuildDrivechainRewardScript(
            address,
            [&](const CTxDestination&) {
                ownership_checked = true;
                return true;
            },
            reward_script, &error));
        BOOST_CHECK(reward_script.empty());
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!ownership_checked);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_withdrawal_capability_requires_replay_or_explicit_flag)
{
    Consensus::Params params;
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_slot = uint8_t{24};
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    // A version number alone does not establish complete M3/M4/M6 and CTIP
    // validation. Even the current replay version requires the explicit,
    // identity-checked capability; the older version-2 shortcut was unsafe.
    for (const uint32_t replay_version : {2U, ElementsDrivechainIdentity::PARENT_REPLAY_VERSION}) {
        params.drivechain_parent_state_replay_version = replay_version;
        BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());
    }

    params.drivechain_parent_state_replay_version = 0;
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());

    params.drivechain_m6_withdrawal_validation = true;
    BOOST_CHECK(params.DrivechainWithdrawalValidationEnabled());

    // A capability flag alone must never turn the BIP300 wallet path on for
    // an ordinary Elements network.
    params.drivechain_slot.reset();
    BOOST_CHECK(!params.DrivechainWithdrawalValidationEnabled());
}

BOOST_AUTO_TEST_SUITE_END()

struct ElementsTestingSetup : public TestingSetup {
    ElementsTestingSetup() : TestingSetup{ChainType::ELEMENTS} {}
};

BOOST_FIXTURE_TEST_SUITE(elements_startup_validation_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(activates_genesis_from_empty_chain)
{
    LOCK(cs_main);
    const CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK_EQUAL(tip->nHeight, 0);
    BOOST_CHECK_EQUAL(tip->GetBlockHash(), Params().HashGenesisBlock());
}

BOOST_AUTO_TEST_CASE(native_parent_replay_cannot_use_historical_signet_bmm)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    CBlockIndex previous;
    const uint256 historical = uint256S("ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998");
    previous.phashBlock = &historical;
    previous.nVersion = CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK(!drivechain::BmmProofRequiredAfter(&previous));
    CCoinsView base;
    CCoinsViewCache view(&base);
    drivechain::BmmL1State parent;
    std::string error;
    BOOST_CHECK(!drivechain::GetEffectiveBmmState(view, &previous, parent, error));
    CBlock block;
    block.nVersion = CBlockHeader::BMM_PROOF_HF_MASK;
    block.hashBmmProof = uint256::ONE;
    BOOST_CHECK(!drivechain::CheckBmmHeader(block, &previous, error, true));
    BOOST_CHECK(!drivechain::ConnectBmmState(block, &previous, view, 1, true, error));
    block.nVersion = 1;
    block.hashBmmProof.SetNull();
    BOOST_CHECK(drivechain::CheckBmmHeader(block, &previous, error, false));
    BOOST_CHECK(drivechain::ConnectBmmState(block, &previous, view, 1, false, error));
    block.m_bmm_proof = {1};
    BOOST_CHECK(!drivechain::ConnectBmmState(block, &previous, view, 1, false, error));
}

BOOST_AUTO_TEST_CASE(native_alpha_rejects_ecx_deposit_codecs_without_parent_rpc)
{
    BOOST_REQUIRE(Params().GetConsensus().drivechain_slot.has_value());
    Sidechain::Bitcoin::CMutableTransaction parent;
    parent.vin.emplace_back(Sidechain::Bitcoin::COutPoint(uint256::ONE, 0));
    parent.vout.emplace_back(2'000, CScript() << OP_TRUE);
    const COutPoint outpoint(Txid::FromUint256(parent.GetHash()), 0);
    DrivechainDepositEvidence evidence;
    VectorWriter writer(evidence.deposit_tx, 0);
    writer << TX_WITH_WITNESS(parent);
    const auto legacy = CreateDrivechainDepositPeginWitness(
        2'000, Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, outpoint.hash);
    const auto deterministic = CreateDrivechainDepositPeginWitness(
        2'000, Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(), CScript() << OP_TRUE, evidence);

    for (const CScriptWitness& witness : {legacy, deterministic}) {
        BOOST_REQUIRE(IsEcxDrivechainDepositPeginWitness(witness, outpoint));
        bool parent_unavailable{true};
        bool depth_failed{true};
        std::string error;
        // Matching asset and parent genesis do not authorize the foreign
        // codec on Alpha. It must fail before any mutable parent query.
        BOOST_CHECK(!IsValidPeginWitness(
            witness, {}, outpoint, error, true, &depth_failed, &parent_unavailable));
        BOOST_CHECK(error.find("not a native Alpha CTIP witness") != std::string::npos);
        BOOST_CHECK(!parent_unavailable);
        BOOST_CHECK(!depth_failed);
    }
}

BOOST_AUTO_TEST_SUITE_END()
