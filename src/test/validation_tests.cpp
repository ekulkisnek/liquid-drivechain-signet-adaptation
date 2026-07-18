// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <chain.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <elements_drivechain_identity.h>
#include <init.h>
#include <mainchainrpc.h>
#include <net.h>
#include <net_processing.h>
#include <policy/policy.h>
#include <signet.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <limits>
#include <cstring>

#include <boost/test/unit_test.hpp>

namespace Bitcoin = Sidechain::Bitcoin;

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

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
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{2099999997690000});
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
            CTxIn input(COutPoint(uint256::ONE, i));
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
        ToString(MAX_MONEY), parsed, &error));
    BOOST_CHECK_EQUAL(parsed, MAX_MONEY);
    BOOST_CHECK(!ParseDrivechainBmmBid("1000garbage", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(" 1000", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("1000 ", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("0", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid("-1", parsed, &error));
    BOOST_CHECK(!ParseDrivechainBmmBid(
        ToString(MAX_MONEY + 1), parsed, &error));
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
    const auto signet_params = CreateChainParams(signet_argsman, CBaseChainParams::SIGNET);
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

    CDataStream stream(ParseHex(RAW_BLOCK_5580), SER_NETWORK, PROTOCOL_VERSION);
    Bitcoin::CBlock block;
    stream >> block;
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
    BOOST_CHECK_EQUAL(base_params->DataDir(), "elements-v1");
    BOOST_CHECK_EQUAL(base_params->RPCPort(), 7045);
    BOOST_CHECK_EQUAL(base_params->MainchainRPCPort(), 38332);
    BOOST_CHECK_EQUAL(base_params->OnionServiceTargetPort(), 37046);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 7046);

    BOOST_CHECK(consensus.elements_mode);
    BOOST_CHECK(consensus.has_parent_chain);
    BOOST_REQUIRE(consensus.drivechain_slot.has_value());
    BOOST_CHECK_EQUAL(*consensus.drivechain_slot, 24);
    BOOST_CHECK(consensus.enable_usdd_sp1_annex);
    BOOST_CHECK_EQUAL(
        params->ParentGenesisBlockHash(),
        uint256S("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"));
    BOOST_CHECK_EQUAL(
        HexStr(consensus.parent_signet_challenge),
        "00148835832e28c816b7acd8fdb19772ab2199603a56");
    BOOST_CHECK_EQUAL(
        consensus.parentChainPowLimit,
        uint256S("00000377ae000000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK(!consensus.signet_blocks);
    BOOST_CHECK(consensus.signblockscript == CScript() << OP_TRUE);
    BOOST_CHECK_EQUAL(
        params->HashGenesisBlock(),
        uint256S("d758e40eace8dc9c95a9dd44f7be84c241a4f8c5a3bd72812f2346a5801e3e9e"));
    BOOST_CHECK_EQUAL(
        params->GenesisBlock().hashMerkleRoot,
        uint256S("39e74e4f8248c056e9765ba9d725b045daa2727f0352a89d8be0737b63c14823"));
    BOOST_CHECK_EQUAL(
        consensus.pegged_asset.GetHex(),
        "3ec133267a9eef1e20cfc949ef05f0d9eac944050d2151275bc9fd57a123fc3e");
    BOOST_CHECK_EQUAL(params->GenesisBlock().nTime, 1784334600U);
    BOOST_CHECK(params->HashGenesisBlock() != params->ParentGenesisBlockHash());
    BOOST_CHECK(consensus.subsidy_asset == consensus.pegged_asset);

    BOOST_CHECK_EQUAL(
        consensus.drivechain_protocol_manifest_hash,
        uint256S("66502fac27a0e0628ea950b056b55bab0cfd3974c24f964f9ffc3a11c42aeca8"));
    BOOST_CHECK_EQUAL(
        HexStr(consensus.drivechain_proposal_description),
        "0008456c656d656e7473456c656d656e7473204472697665636861696e2076313b206e617469766520555344443b207265706c61792076323b2053696d706c6963697479206163746976653b20736c6f74203234a8ec2ac4113afc9f4f964fc27439fd0cab5bb556b050a98e62e0a027ac2f5066f49d0cbac06d5a79012d6dc343d96b5181a1d00d");
    BOOST_REQUIRE(consensus.drivechain_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_proposal_hash,
        uint256S("b27b2b233f9db48be36046b72cac4876efd24a3055bbb0c25392f52e55042f98"));
    BOOST_REQUIRE(consensus.drivechain_parent_state_active_proposal_hash.has_value());
    BOOST_CHECK_EQUAL(
        *consensus.drivechain_parent_state_active_proposal_hash,
        uint256S("169a8a4dc3b3c57df20620306d05486bedadf5aa2ddee2314ee1313bf5ccaab8"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_proposal_height, 257U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_proposal_block_hash,
        uint256S("000000093777d0d4b242a14af82db56cbabee4580cd9efe90320fd599bf1363e"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_activation_height, 263U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_activation_block_hash,
        uint256S("000002863c2d984711924c0514badf736fe2630b3d0426e92e8bd44366643484"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_height, 5580U);
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_hash,
        uint256S("000002a28e4f1c4599a7878da30ce0197be99ffd1d8e6d20d1a032011448011e"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_chainwork,
        uint256S("0000000000000000000000000000000000000000000000000000000649bd5c3f"));
    BOOST_CHECK_EQUAL(
        consensus.drivechain_parent_state_ctip_txid,
        uint256S("010a70b5ea6e545af594dad90ce1886387f5b4418577800644a65dd244e4edab"));
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_vout, 0U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_ctip_value, 14400000);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_proposal_max_age, 10U);
    BOOST_CHECK_EQUAL(consensus.drivechain_unused_slot_activation_threshold, 5U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_proposal_max_age, 10U);
    BOOST_CHECK_EQUAL(consensus.drivechain_used_slot_activation_threshold, 5U);
    BOOST_CHECK_EQUAL(consensus.drivechain_parent_state_replay_version, 2U);
    BOOST_CHECK_EQUAL(consensus.drivechain_annex_feature_version, 1U);
    BOOST_CHECK(!consensus.drivechain_m6_withdrawal_validation);

    BOOST_CHECK_EQUAL(
        consensus.vDeployments[Consensus::DEPLOYMENT_SIMPLICITY].nStartTime,
        Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(params->Bech32HRP(), "elements");
    BOOST_CHECK_EQUAL(params->Blech32HRP(), "elementsl");
    BOOST_CHECK_EQUAL(params->ParentBech32HRP(), "tb");
    BOOST_CHECK_EQUAL(HexStr(params->MessageStart()), "2ac59d38");
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
    CBlockIndex first_block_index;
    first_block_index.pprev = &genesis_index;
    first_block_index.nHeight = 1;

    const unsigned int flags = GetBlockScriptFlagsForTesting(
        &first_block_index, params->GetConsensus());
    BOOST_CHECK(flags & SCRIPT_VERIFY_TAPROOT);
    BOOST_CHECK(flags & SCRIPT_VERIFY_SIMPLICITY);
    BOOST_CHECK(flags & SCRIPT_VERIFY_USDD_SP1_ANNEX);
    BOOST_CHECK(!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY));
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
        CBlockIndex first_block_index;
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

    CBlockTreeDB block_tree_db(/*nCacheSize=*/1 << 20,
                               /*fMemory=*/true,
                               /*fWipe=*/true);
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
        Params().GetConsensus(), insert, /*trimBelowHeight=*/0));
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
    index.nChainTx = 2;
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

    size_t original_index_size;
    {
        LOCK(cs_main);
        original_index_size =
            m_node.chainman->m_blockman.m_block_index.size();
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
        BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(
            {sibling}, state, drivechain_params));
        BOOST_CHECK(state.IsError());
    }

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(
        m_node.chainman->m_blockman.m_block_index.size(),
        original_index_size);
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
    const auto params = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = ExpectedAssumeutxo(empty, *params);
        BOOST_CHECK(!out);
    }

    const auto out110 = *ExpectedAssumeutxo(110, *params);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "09a3e443dbf48f3b95207c9ce529062d9764395232c482aa7d3a0bf274d282d9");
    BOOST_CHECK_EQUAL(out110.nChainTx, 110U);

    const auto out210 = *ExpectedAssumeutxo(200, *params);
    BOOST_CHECK_EQUAL(out210.hash_serialized.ToString(), "51c8d11d8b5c1de51543c579736e786aa2736206d1e11e627568029ce092cf62");
    BOOST_CHECK_EQUAL(out210.nChainTx, 200U);
}

BOOST_AUTO_TEST_SUITE_END()
