// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_bmm.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

struct ElementsTestingSetup : BasicTestingSetup {
    ElementsTestingSetup()
        : BasicTestingSetup(ChainTypeMetaFrom("elementsregtest"))
    {
    }
};

template <typename T>
std::vector<unsigned char> SerializeValue(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

drivechain::BmmL1State AuthenticState6399()
{
    return {
        uint256S("000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"),
        6399,
        1784825405,
        0x1e0376cc,
        6048,
        1784614805,
        {
            1784819405,
            1784820005,
            1784820605,
            1784821205,
            1784821805,
            1784822405,
            1784823005,
            1784823605,
            1784824205,
            1784824805,
            1784825405,
        }};
}

drivechain::BmmProof AuthenticProof6400()
{
    const std::string coinbase_hex{
        "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03020019ffffffff0b0000000000000000276a25d16173680455ac64b9a5f6a28521c319379ecedfd436b5734fb6ec85aab4168738fd4685ba0000000000000000276a25d1617368094ed23c4ff5c783923cf1ae96b4eff6c85d466c3129fa9996cf8f149710c642400000000000000000276a25d161736862741449c742d45808126397a716bcc81bf9add9f8bb94b6b5e62b585469b67d590000000000000000276a25d161736863c4381671acc63c1281879c7b3f5dfad439a3f2b8933e93f11e11d5568a86651a0000000000000000276a25d1617368020c8c11ed67c0a0f06f078377c51127aaa5592f60b65a414be4e5f9f90efd98bf0000000000000000276a25d1617368ff7dbb40767d35826afdd53ec64334edfde50c00d688f84c1d69e32c1bafe148bc0000000000000000276a25d16173680d8c5c5ce2ad2dea77630824786c1b1c38e45940bc2dbe18715ebb81e1e90b355d00000000000000000f6a0dd77d177601ffffffffffffffff0000000000000000276a25d161736818ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998bdf2052a01000000160014fae83223f01759582ffe70f5f770eb8462f04da20000000000000000986a24aa21a9edfa53326790c56b7b9ccb48914d00fe7edac8cc01712824b2e008620eed22dcb54c70ecc7daa2000247304402204c28ded7cc42bee894128afca0e87aa16bbd361f76a22e792e20b61cac065edf0220407dec66676adeeebe06b567f763e0f44818ed266f1e2edc8f66f88b4ad6fef4012103675b73e701c9dab7de809bb0000b4c1205f9a834d669a7f47c107a7d2c199f560120000000000000000000000000000000000000000000000000000000000000000000000000"};
    const std::string proof_hex{
        "0000002065b02d1e36215e6a264830d0d722ad3d893142fd63e7515d43398298d901000037476252e051ca3d0e1f1757e3e2a4f2e91f19c091430dedec09b5279e96e6b09548626acc76031e5e7525000200000002ec6c869bd1b88b9c3f038d949183429c5d0ec7cc352252bf62e0457606480198528a562cb457d9d04371d471d0504d84b7431e890d289e2974dcbcb0aa27f6350103"};
    drivechain::BmmProof proof;
    proof.previous_state = AuthenticState6399();
    proof.entries.push_back({ParseHex(coinbase_hex), ParseHex(proof_hex)});
    return proof;
}

drivechain::BmmConsensus EasyConsensus()
{
    return {
        uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        14 * 24 * 60 * 60,
        10 * 60,
        CScript() << OP_TRUE,
        drivechain::BMM_SIDECHAIN_SLOT,
        8,
        100'000,
        true};
}

drivechain::BmmL1State EasyState()
{
    return {
        uint256S("01"),
        100,
        100'000,
        UintToArith256(EasyConsensus().pow_limit).GetCompact(),
        0,
        40'000,
        {
            94'000,
            94'600,
            95'200,
            95'800,
            96'400,
            97'000,
            97'600,
            98'200,
            98'800,
            99'400,
            100'000,
        }};
}

CBlock SidechainCandidate(const uint256& parent_hash)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        0,
        CScript() << OP_TRUE);
    coinbase.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        0,
        CScript() << OP_RETURN <<
            std::vector<unsigned char>(parent_hash.begin(), parent_hash.end()));

    CBlock block;
    block.nVersion = 0x20000000 | CBlockHeader::BMM_PROOF_HF_MASK;
    block.hashPrevBlock = uint256S("02");
    block.nTime = 101'000;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

drivechain::BmmProof EasyProof(
    const drivechain::BmmL1State& previous,
    const uint256& critical_hash)
{
    Sidechain::Bitcoin::CMutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 101;

    std::vector<unsigned char> witness_commitment{
        0xaa, 0x21, 0xa9, 0xed};
    witness_commitment.resize(36, 0);
    coinbase.vout.emplace_back(
        0,
        CScript() << OP_RETURN << witness_commitment);

    std::vector<unsigned char> m8{
        0xd1, 0x61, 0x73, 0x68,
        static_cast<unsigned char>(drivechain::BMM_SIDECHAIN_SLOT)};
    const std::vector<unsigned char> critical_bytes{
        ParseHex(critical_hash.GetHex())};
    m8.insert(m8.end(), critical_bytes.begin(), critical_bytes.end());
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << m8);

    Sidechain::Bitcoin::CBlockHeader header;
    header.nVersion = 0x20000000;
    header.hashPrevBlock = previous.block_hash;
    header.hashMerkleRoot = coinbase.GetHash();
    header.nTime = previous.block_time + 600;
    header.nBits = previous.n_bits;
    while (UintToArith256(header.GetHash()) >
           UintToArith256(EasyConsensus().pow_limit)) {
        ++header.nNonce;
    }

    Sidechain::Bitcoin::CMerkleBlock merkle;
    merkle.header = header;
    merkle.txn = Sidechain::Bitcoin::CPartialMerkleTree(
        {coinbase.GetHash()},
        {true});

    drivechain::BmmProof proof;
    proof.previous_state = previous;
    proof.entries.push_back({
        SerializeValue(coinbase),
        SerializeValue(merkle)});
    return proof;
}

Sidechain::Bitcoin::CMerkleBlock DecodeMerkleProof(
    const drivechain::BmmProofEntry& entry)
{
    Sidechain::Bitcoin::CMerkleBlock merkle;
    DataStream stream(
        entry.coinbase_proof);
    stream >> merkle;
    BOOST_REQUIRE(stream.empty());
    return merkle;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_bmm_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(header_wire_and_hash_compatibility)
{
    // Generated with the pre-CMake e90b9afee3 build, not this serializer.
    // Each digest commits to 128 (block hash, critical hash, wire bytes) tuples.
    constexpr const char* expected[] = {
        "449d03ee9b142f6200ff32dde7f829d4e9600e8f3f9acff60113e32852c4035a",
        "98245a37992e04f34f719f27b4bc7604b4931bdcd79a3794f644b7bac66634b4",
        "c175b966e32d866a1d478a2525dd21015e6e687d51f15ff4a14d3ab42da113dc",
        "32d44945248839b16a9b98a1d79478a72ce05a3e343681bf7183f3c9bf770831",
        "ecb912ee618ab49ff4ecd75496ebda052faf5e77185ff516dd34112a9879da55",
        "6e7cd222f4ebdafad2a6ea4820508209458759bd38a3aa2928d3b3235d02b87b",
        "6062e4ccbf91b134efd1b8699e2fe3c723fa1e75362011b210186a9d84ca4026",
        "3375f70f47e62eb45d43d726b42fc1be1d10801d7c1ddff2fdbabd4562acdf17",
    };
    constexpr uint32_t masks[] = {
        CBlockHeader::BMM_PROOF_HF_MASK,
        CBlockHeader::EXCHANGE_STATE_HF_MASK,
        CBlockHeader::FORCED_INBOX_HF_MASK,
        CBlockHeader::DEPOSIT_INBOX_HF_MASK,
        CBlockHeader::INBOX_CURSOR_HF_MASK,
    };
    for (unsigned mode = 0; mode < 8; ++mode) {
        g_con_elementsmode = mode & 1;
        g_con_blockheightinheader = mode & 2;
        g_signed_blocks = mode & 4;
        HashWriter aggregate;
        for (unsigned variant = 0; variant < 128; ++variant) {
            CBlockHeader header;
            header.nVersion = 0x20000000 | CBlockHeader::DYNAFED_HF_MASK |
                CBlockHeader::WITHDRAWAL_BUNDLE_HF_MASK;
            for (unsigned bit = 0; bit < 5; ++bit) {
                if (variant & (1U << bit)) header.nVersion |= masks[bit];
            }
            header.hashPrevBlock = uint256S("01");
            header.hashMerkleRoot = uint256S("02");
            if (variant & 32) header.hashWithdrawalBundle = uint256S("03");
            header.hashBmmProof = uint256S("04");
            header.hashExchangeStateRoot = uint256S("05");
            header.hashForcedInboxRoot = uint256S("06");
            header.hashDepositInboxRoot = uint256S("07");
            header.nTime = 1784825405;
            header.nBits = 0x1e0376cc;
            header.nNonce = 0x12345678;
            header.block_height = 6400;
            header.ecxParentHeight = 995347;
            header.forcedProcessedCursor = 0x0102030405060708ULL;
            header.depositProcessedCursor = 0x1112131415161718ULL;
            header.sourceBacklogOldestParentHeight = 0x2122232425262728ULL;
            header.proof.challenge = CScript() << OP_TRUE;
            header.proof.solution = CScript() << OP_2;
            if (variant & 64) {
                header.m_dynafed_params.m_current = DynaFedParamEntry(
                    CScript() << OP_TRUE, 1000, uint256S("08"));
            }
            DataStream wire;
            wire << header;
            aggregate << header.GetHash() << header.GetBmmCriticalHash()
                      << std::vector<unsigned char>(
                          UCharCast(wire.data()), UCharCast(wire.data()) + wire.size());
        }
        BOOST_TEST_CONTEXT("serialization mode " << mode) {
            BOOST_CHECK_EQUAL(aggregate.GetHash().GetHex(), expected[mode]);
        }
    }
}

BOOST_AUTO_TEST_CASE(verifies_authentic_layer_two_labs_successor)
{
    BOOST_CHECK(drivechain::LayerTwoLabsBmmConsensus().require_signet_solution);
    const drivechain::BmmProof proof{AuthenticProof6400()};
    drivechain::BmmL1State next;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            drivechain::LayerTwoLabsPublicSidechainBlock2(),
            proof.previous_state.block_hash,
            next,
            error,
            drivechain::LayerTwoLabsBmmConsensus()),
        error);
    BOOST_CHECK(next == drivechain::LayerTwoLabsInitialBmmState());
}

BOOST_AUTO_TEST_CASE(commits_and_roundtrips_synthetic_proof)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    BOOST_CHECK_EQUAL(block.GetBmmCriticalHash(), critical_hash);
    BOOST_CHECK_NE(block.GetHash(), critical_hash);
    BOOST_CHECK_EQUAL(
        block.hashBmmProof,
        drivechain::BmmProofCommitment(block.m_bmm_proof));

    drivechain::BmmL1State next;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            block,
            previous,
            next,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK_EQUAL(next.height, previous.height + 1);
    BOOST_CHECK_EQUAL(next.block_hash, proof.entries.empty()
        ? uint256()
        : [&] {
            Sidechain::Bitcoin::CMerkleBlock merkle;
            DataStream stream(
                proof.entries[0].coinbase_proof);
            stream >> merkle;
            return merkle.header.GetHash();
        }());
    drivechain::BmmParentContext previous_context;
    BOOST_REQUIRE_MESSAGE(
        drivechain::GetBmmParentContext(previous, previous_context, error),
        error);
    BOOST_CHECK_EQUAL(previous_context.height, 100U);
    BOOST_CHECK_EQUAL(previous_context.median_time_past, 97'000U);
    BOOST_CHECK_EQUAL(previous_context.block_hash, previous.block_hash);
    drivechain::BmmParentContext next_context;
    BOOST_REQUIRE_MESSAGE(
        drivechain::GetBmmParentContext(next, next_context, error),
        error);
    BOOST_CHECK_EQUAL(next_context.height, 101U);
    BOOST_CHECK_EQUAL(next_context.median_time_past, 97'600U);
    BOOST_CHECK_EQUAL(next_context.block_hash, next.block_hash);

    DataStream encoded;
    encoded << TX_WITH_WITNESS(block);
    CBlock decoded;
    encoded >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK_EQUAL(decoded.GetHash(), block.GetHash());
    BOOST_CHECK_EQUAL(decoded.GetBmmCriticalHash(), critical_hash);
    BOOST_CHECK(decoded.m_bmm_proof == block.m_bmm_proof);
}

BOOST_AUTO_TEST_CASE(accepts_non_monotonic_parent_timestamps_above_median)
{
    drivechain::BmmL1State previous{EasyState()};
    previous.recent_times = {
        94'000,
        97'000,
        95'200,
        98'800,
        96'400,
        99'400,
        97'600,
        95'800,
        98'200,
        94'600,
        100'000,
    };
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    const drivechain::BmmProof proof{EasyProof(previous, critical_hash)};

    drivechain::BmmL1State next;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            critical_hash,
            previous.block_hash,
            next,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK_EQUAL(next.height, previous.height + 1);
}

BOOST_AUTO_TEST_CASE(rejects_mismatches_replays_and_corruption)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    drivechain::BmmL1State next;
    CBlock corrupted{block};
    corrupted.m_bmm_proof.back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyBmmProof(
        corrupted, previous, next, error, EasyConsensus()));
    BOOST_CHECK(error.find("exact BMM proof") != std::string::npos);

    drivechain::BmmL1State stale{previous};
    --stale.height;
    BOOST_CHECK(!drivechain::VerifyBmmProof(
        block, stale, next, error, EasyConsensus()));
    BOOST_CHECK(error.find("locally authenticated") != std::string::npos);

    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        uint256S("03"),
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("critical hash") != std::string::npos);

    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        uint256S("04"),
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("successor") != std::string::npos);

    drivechain::BmmProof replay{proof};
    replay.previous_state = next;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        replay,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));

    drivechain::BmmProof reorged{proof};
    reorged.previous_state.block_hash = uint256S("05");
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        reorged,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("does not extend") != std::string::npos);

    drivechain::BmmProof bad_merkle{proof};
    bad_merkle.entries[0].coinbase_proof.back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        bad_merkle,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("Merkle proof") != std::string::npos ||
        error.find("malformed") != std::string::npos);

    drivechain::BmmProof old_timestamp{proof};
    Sidechain::Bitcoin::CMerkleBlock merkle{
        DecodeMerkleProof(old_timestamp.entries[0])};
    merkle.header.nTime = 97'000;
    merkle.header.hashMerkleRoot = uint256S("06");
    old_timestamp.entries[0].coinbase_proof = SerializeValue(merkle);
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        old_timestamp,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));

    drivechain::BmmConsensus wrong_slot{EasyConsensus()};
    wrong_slot.sidechain_slot = 23;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_slot));
    BOOST_CHECK(error.find("no M8 commitment") != std::string::npos);

    drivechain::BmmConsensus wrong_signet{EasyConsensus()};
    wrong_signet.signet_challenge = CScript() << OP_FALSE;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_signet));
    BOOST_CHECK(error.find("signet solution is invalid") != std::string::npos);

    drivechain::BmmConsensus explicit_no_signet{wrong_signet};
    explicit_no_signet.require_signet_solution = false;
    drivechain::BmmL1State no_signet_next;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            critical_hash,
            previous.block_hash,
            no_signet_next,
            error,
            explicit_no_signet),
        error);
    BOOST_CHECK_EQUAL(no_signet_next.height, previous.height + 1);

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
    // The verifier result is a property of the explicit consensus object. A
    // process-global private-E2E flag must not weaken a public/signet check.
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "1");
    gArgs.ForceSetArg("-ecxprivatebmmactivationheight", "110");
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_signet));
    BOOST_CHECK(error.find("signet solution is invalid") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(two_verifiers_converge_from_serialized_evidence)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    const drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    DataStream wire;
    wire << TX_WITH_WITNESS(block);
    CBlock peer_a;
    CBlock peer_b;
    wire >> TX_WITH_WITNESS(peer_a);
    DataStream second_wire;
    second_wire << TX_WITH_WITNESS(peer_a);
    second_wire >> TX_WITH_WITNESS(peer_b);

    drivechain::BmmL1State state_a;
    drivechain::BmmL1State state_b;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            peer_a,
            previous,
            state_a,
            error,
            EasyConsensus()),
        error);
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            peer_b,
            previous,
            state_b,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK(state_a == state_b);
    BOOST_CHECK_EQUAL(peer_a.GetHash(), peer_b.GetHash());
    BOOST_CHECK_EQUAL(peer_a.GetBmmCriticalHash(), peer_b.GetBmmCriticalHash());
}

BOOST_AUTO_TEST_CASE(enforces_public_checkpoint_activation)
{
    const std::vector<unsigned char> height_two_header_bytes{ParseHex(
        "000000a043e5de39494df3a659e2ffd2610049ef5e4067032af44a0642132489cb312f94343f07c20d76afcd71dfd94dfb09a4afb9df7d197e1227e9e5cc58f2224621f09746626a02000000012200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332604a000000fbee9cea00d8efdc49cfbec328537e0d7032194de6ebf3cf42e5c05bb89a08b100010151")};
    DataStream height_two_stream(
        height_two_header_bytes);
    CBlockHeader height_two;
    height_two_stream >> height_two;
    BOOST_REQUIRE(height_two_stream.empty());
    BOOST_CHECK_EQUAL(
        height_two.GetHash(),
        drivechain::LayerTwoLabsPublicSidechainBlock2());

    CBlockIndex public_height_one;
    const uint256 public_height_one_hash{
        drivechain::LayerTwoLabsPublicSidechainBlock1()};
    public_height_one.phashBlock = &public_height_one_hash;
    std::string error;
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(
            height_two,
            &public_height_one,
            error),
        error);
    CBlockIndex persisted_height_two{height_two};
    persisted_height_two.pprev = &public_height_one;
    persisted_height_two.nHeight = 2;
    const uint256 persisted_height_two_hash{height_two.GetHash()};
    persisted_height_two.phashBlock = &persisted_height_two_hash;
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmIndexHeader(persisted_height_two, error),
        error);

    CBlockHeader alternate_height_two{height_two};
    ++alternate_height_two.nTime;
    BOOST_CHECK(!drivechain::CheckBmmHeader(
        alternate_height_two,
        &public_height_one,
        error));
    BOOST_CHECK(error.find("immutable checkpoint") != std::string::npos);
    CBlockIndex persisted_alternate{alternate_height_two};
    persisted_alternate.pprev = &public_height_one;
    persisted_alternate.nHeight = 2;
    const uint256 persisted_alternate_hash{alternate_height_two.GetHash()};
    persisted_alternate.phashBlock = &persisted_alternate_hash;
    BOOST_CHECK(!drivechain::CheckBmmIndexHeader(persisted_alternate, error));
    BOOST_CHECK(error.find("immutable checkpoint") != std::string::npos);

    CBlockIndex public_tip;
    const uint256 public_tip_hash{
        drivechain::LayerTwoLabsPublicSidechainBlock2()};
    public_tip.phashBlock = &public_tip_hash;

    CBlockHeader child;
    child.nVersion = 0x20000000;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &public_tip, error));
    BOOST_CHECK(error.find("does not signal") != std::string::npos);

    child.nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &public_tip, error));
    BOOST_CHECK(error.find("no proof commitment") != std::string::npos);
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(child, &public_tip, error, true),
        error);
    CBlockIndex persisted_child{child};
    persisted_child.pprev = &public_tip;
    persisted_child.nHeight = 3;
    const uint256 persisted_child_hash{child.GetHash()};
    persisted_child.phashBlock = &persisted_child_hash;
    BOOST_CHECK(!drivechain::CheckBmmIndexHeader(persisted_child, error));
    BOOST_CHECK(error.find("no proof commitment") != std::string::npos);
    child.hashBmmProof = uint256S("02");
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(child, &public_tip, error),
        error);

    CBlockIndex unrelated;
    const uint256 unrelated_hash{uint256S("01")};
    unrelated.phashBlock = &unrelated_hash;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &unrelated, error));
    BOOST_CHECK(error.find("cannot activate") != std::string::npos);
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
BOOST_AUTO_TEST_CASE(private_activation_height_does_not_invalidate_history)
{
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "1");
    gArgs.ForceSetArg("-ecxprivatebmmactivationheight", "110");
    BOOST_CHECK(!drivechain::LayerTwoLabsBmmConsensus().require_signet_solution);

    CBlockIndex previous;
    const uint256 previous_hash{uint256S("03")};
    previous.phashBlock = &previous_hash;
    previous.nHeight = 108;
    CBlockHeader legacy;
    legacy.nVersion = 0x20000000;
    std::string error;
    BOOST_CHECK_MESSAGE(drivechain::CheckBmmHeader(legacy, &previous, error), error);

    previous.nHeight = 109;
    BOOST_CHECK(!drivechain::CheckBmmHeader(legacy, &previous, error));
    BOOST_CHECK(error.find("does not signal") != std::string::npos);
    legacy.nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(legacy, &previous, error, true),
        error);
    legacy.hashBmmProof = uint256S("04");
    BOOST_CHECK_MESSAGE(drivechain::CheckBmmHeader(legacy, &previous, error), error);

}
#endif

BOOST_AUTO_TEST_SUITE_END()
