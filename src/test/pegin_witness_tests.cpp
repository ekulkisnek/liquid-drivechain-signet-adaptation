// Copyright (c) 2017-2017 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <dbwrapper.h>
#include <drivechain_parent_replay.h>
#include <hash.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <validation.h> // For CheckTransaction
#include <pegins.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/script_error.h>
#include <util/strencodings.h>
#include <validation.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/system.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

namespace Bitcoin = Sidechain::Bitcoin;

std::vector<std::vector<unsigned char> > witness_stack = {
    ParseHex("00ca9a3b00000000"),
    ParseHex("ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e47"),
    ParseHex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
    ParseHex("00141eef6361cd1507a303834285d1521d6baf1b19ae"),
    ParseHex("0200000001b399292c8100b8a1b66eb23896f799c1712390d560af0f70e81acd2d17a3b06e0000000049483045022100c3c749623486ea57ea93dfaf78d85590d78c7590a25768fe80f0ea4d6047419002202a0a00a90392b86c53c0fdda908c4591ba28040c16c25734c23b7df3c8b70acd01feffffff0228196bee000000001976a914470dd41542ee1a1bd75f1a838878648c8d65622488ac00ca9a3b0000000017a914cb60b1d7f76ba12b45a116c482c165a74c5d7e388765000000"),
    ParseHex("000000205e3913a320cd2e3a2efa141e47419f54cb9e82320cf8dbc812fc19b9a1b2413a57f5e9fb4fa22de191454a241387f5d10cc794ee0fbf72ae2841baf3129a4eab8133025affff7f20000000000200000002f9d0be670007d38fceece999cb6144658a99c307ccc37f6d8f69129ed0f4545ff321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce0105")
};

std::vector<unsigned char> pegin_transaction = ParseHex("020000000101f321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce0100004000ffffffff0201ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e4701000000003b9ab2e0001976a914809326f7628dc976fbe63806479a1b8dfcc8c4b988ac01ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e47010000000000001720000000000000000002483045022100ae17064745d80650a6a5cbcbe15c8c45ba498d1c6f45a7c0f5f32d871b463fc60220799f2836471702c21f7cfe124651727b530ad41f7af4dc213c65f5030a2f6fc4012103a9d3c6c7c161a565a76113632fe13330cf2c0207ba79a76d1154cdc3cb94d940060800ca9a3b0000000020ef4699c160d014d5ff79636d8a4cb990b9df4ebab649f144d19f5c495c585e472006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600141eef6361cd1507a303834285d1521d6baf1b19aebe0200000001b399292c8100b8a1b66eb23896f799c1712390d560af0f70e81acd2d17a3b06e0000000049483045022100c3c749623486ea57ea93dfaf78d85590d78c7590a25768fe80f0ea4d6047419002202a0a00a90392b86c53c0fdda908c4591ba28040c16c25734c23b7df3c8b70acd01feffffff0228196bee000000001976a914470dd41542ee1a1bd75f1a838878648c8d65622488ac00ca9a3b0000000017a914cb60b1d7f76ba12b45a116c482c165a74c5d7e38876500000097000000205e3913a320cd2e3a2efa141e47419f54cb9e82320cf8dbc812fc19b9a1b2413a57f5e9fb4fa22de191454a241387f5d10cc794ee0fbf72ae2841baf3129a4eab8133025affff7f20000000000200000002f9d0be670007d38fceece999cb6144658a99c307ccc37f6d8f69129ed0f4545ff321df9790633bc33c67239c4174df8142ee616ee6a2e2788fe4820fe70e9bce010500000000");

COutPoint prevout(uint256S("ce9b0ee70f82e48f78e2a2e66e61ee4281df74419c23673cc33b639097df21f3"), 1);

const std::string fedpegscript_str = "512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b2186451ae";

// Needed for easier parent PoW check, and setting fedpegscript
struct FedpegSetup : public BasicTestingSetup {
        FedpegSetup() : BasicTestingSetup("custom", fedpegscript_str) {}
};

BOOST_FIXTURE_TEST_SUITE(pegin_witness_tests, FedpegSetup)

BOOST_AUTO_TEST_CASE(witness_valid)
{
    CScriptWitness witness;
    witness.stack = witness_stack;

    std::string err;

    std::vector<unsigned char> fedpegscript_bytes = ParseHex(fedpegscript_str);
    CScript fedpegscript(fedpegscript_bytes.begin(), fedpegscript_bytes.end());
    // Test sample was generated as "legacy" with p2sh-p2wsh fedpegscript
    CScript fedpeg_program(GetScriptForDestination(ScriptHash(GetScriptForDestination(WitnessV0ScriptHash(fedpegscript)))));
    std::vector<std::pair<CScript, CScript>> fedpegscripts;
    // TODO test with additional scripts
    fedpegscripts.push_back(std::make_pair(fedpeg_program, fedpegscript));

    bool valid = IsValidPeginWitness(witness, fedpegscripts, prevout, err, false);
    BOOST_CHECK(err == "");
    BOOST_CHECK(valid);

    // Missing byte on each field to make claim ill-formatted
    // This will break deserialization and other data-matching checks
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack[i].pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
        witness.stack = witness_stack;
        BOOST_CHECK(IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    }

    // Test mismatched but valid nOut to proof
    COutPoint fake_prevout = prevout;
    fake_prevout.n = 0;
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, fake_prevout, err, false));

    // Test mismatched but valid txid
    fake_prevout = prevout;
    fake_prevout.hash = uint256S("2f103ee04a5649eecb932b4da4ca9977f53a12bbe04d9d1eb5ccc0f4a06334");
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, fake_prevout, err, false));

    // Ensure that all witness stack sizes are handled
    BOOST_CHECK(IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack.pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    }
    witness.stack = witness_stack;

    // Extra element causes failure
    witness.stack.push_back(witness.stack.back());
    BOOST_CHECK(!IsValidPeginWitness(witness, fedpegscripts, prevout, err, false));
    witness.stack = witness_stack;

    // Check validation of peg-in transaction's inputs and balance
    CDataStream ssTx(pegin_transaction, SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef txRef;
    try {
        ssTx >> txRef;
    } catch (...) {
        BOOST_CHECK(false);
        return;
    }
    CTransaction tx(*txRef);

    // Only one(valid) input witness should exist, and should match
    BOOST_CHECK(tx.witness.vtxinwit.size() == 1);
    BOOST_CHECK(tx.witness.vtxinwit[0].m_pegin_witness.stack == witness_stack);
    BOOST_CHECK(tx.vin[0].m_is_pegin);
    // Check that serialization doesn't cause issuance to become non-null
    BOOST_CHECK(tx.vin[0].assetIssuance.IsNull());
    BOOST_CHECK(IsValidPeginWitness(tx.witness.vtxinwit[0].m_pegin_witness, fedpegscripts, prevout, err, false));

    CAmountMap fee_map;

    std::set<std::pair<uint256, COutPoint>> setPeginsSpent;
    TxValidationState state;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Get the latest block index to look up fedpegscripts
    // For these tests, should be genesis-block-hardcoded consensus.fedpegscript
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state, coins, 0, fee_map, setPeginsSpent, NULL, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.size() == 1);
    setPeginsSpent.clear();

    // Strip pegin_witness
    CMutableTransaction mtxn(tx);
    mtxn.witness.vtxinwit[0].m_pegin_witness.SetNull();
    CTransaction tx2(mtxn);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx2, state, coins, 0, fee_map, setPeginsSpent, NULL, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.empty());

    // Invalidate peg-in (and spending) authorization by pegin marker.
    // This only checks for peg-in authorization, with the only input marked
    // as m_is_pegin
    CMutableTransaction mtxn2(tx);
    mtxn2.vin[0].m_is_pegin = false;
    CTransaction tx3(mtxn2);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx3, state, coins, 0, fee_map, setPeginsSpent, NULL, false, true, fedpegscripts));
    BOOST_CHECK(setPeginsSpent.empty());


    // TODO Test mixed pegin/non-pegin input case
    // TODO Test spending authorization in conjunction with valid witness program in pegin auth

}

BOOST_AUTO_TEST_CASE(drivechain_bmm_m7_requires_exact_canonical_commitment)
{
    const uint256 sidechain_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");

    const auto make_m7 = [](const int slot, const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(static_cast<unsigned char>(slot));
        payload.insert(payload.end(), hash.begin(), hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& scripts) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0, 0);
        for (const CScript& script : scripts) coinbase.vout.emplace_back(0, script);
        Bitcoin::CBlock block;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    std::string err;
    uint32_t output_index{99};
    uint256 parsed_hash;
    BOOST_CHECK(ExtractCanonicalDrivechainBmmCommitmentInBlock(
        make_block({CScript() << OP_RETURN << std::vector<unsigned char>{0x01},
                    make_m7(24, sidechain_hash)}),
        24, parsed_hash, &output_index, &err));
    BOOST_CHECK_EQUAL(parsed_hash, sidechain_hash);
    BOOST_CHECK_EQUAL(output_index, 1U);

    output_index = 99;
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        make_block({CScript() << OP_RETURN << std::vector<unsigned char>{0x01}, make_m7(24, sidechain_hash)}),
        24, sidechain_hash, &output_index, &err));
    BOOST_CHECK_EQUAL(output_index, 1U);

    // Fixed cross-codec fixture: rust-bitcoin's enforcer ReverseHex-decodes
    // the gRPC display hash and serializes these internal-order commitment
    // bytes. This fixture is deliberately not produced by make_m7().
    const std::vector<unsigned char> enforcer_fixture_bytes = ParseHex(
        "6a25d1617368188070605040302010ffeeddccbbaa99887766554433221100efcdab8967452301");
    const CScript enforcer_fixture(
        enforcer_fixture_bytes.begin(), enforcer_fixture_bytes.end());
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(
        make_block({enforcer_fixture}), 24, sidechain_hash, nullptr, &err));

    const uint256 wrong_hash = uint256S("1123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({make_m7(24, wrong_hash)}),
                                                     24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({make_m7(23, sidechain_hash)}),
                                                     24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), make_m7(24, sidechain_hash)}),
        24, sidechain_hash, nullptr, &err));

    CScript trailing = make_m7(24, sidechain_hash);
    trailing << OP_TRUE;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({trailing}),
                                                     24, sidechain_hash, nullptr, &err));

    std::vector<unsigned char> payload = ParseHex("d1617368");
    payload.push_back(24);
    payload.insert(payload.end(), sidechain_hash.begin(), sidechain_hash.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({nonminimal}),
                                                     24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), nonminimal}),
        24, sidechain_hash, nullptr, &err));

    CScript display_endian;
    display_endian << OP_RETURN;
    std::vector<unsigned char> display_payload = ParseHex("d1617368");
    display_payload.push_back(24);
    const std::vector<unsigned char> display_hash = ParseHex(sidechain_hash.GetHex());
    display_payload.insert(display_payload.end(), display_hash.begin(), display_hash.end());
    display_endian << display_payload;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({display_endian}),
                                                     24, sidechain_hash, nullptr, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_commitment_is_domain_separated_and_canonical)
{
    const uint256 parent_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
    const auto make_block = [](const std::vector<CScript>& scripts) {
        CMutableTransaction coinbase;
        coinbase.vin.emplace_back(COutPoint(), CScript() << OP_0, 0);
        for (const CScript& script : scripts) {
            coinbase.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, script);
        }
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        return block;
    };

    const CScript canonical = CreateDrivechainParentCommitmentScript(parent_hash);
    BOOST_REQUIRE_EQUAL(canonical.size(), 39U);
    BOOST_CHECK_EQUAL(HexStr(Span<const unsigned char>{canonical}.first(7)), "6a25454c4d5450");

    uint256 extracted;
    std::string err;
    BOOST_CHECK(ExtractDrivechainParentHashFromBlock(make_block({canonical}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted, parent_hash);

    const std::vector<unsigned char> unrelated_data(32, 0x42);
    BOOST_CHECK(ExtractDrivechainParentHashFromBlock(
        make_block({CScript() << OP_RETURN << unrelated_data, canonical}), extracted, &err));
    BOOST_CHECK_EQUAL(extracted, parent_hash);
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({CScript() << OP_RETURN << unrelated_data}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, canonical}), extracted, &err));

    CScript trailing = canonical;
    trailing << OP_TRUE;
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(make_block({trailing}), extracted, &err));

    std::vector<unsigned char> payload(canonical.begin() + 2, canonical.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(make_block({nonminimal}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, nonminimal}), extracted, &err));
    BOOST_CHECK(!ExtractDrivechainParentHashFromBlock(
        make_block({canonical, trailing}), extracted, &err));
}

BOOST_AUTO_TEST_CASE(explicit_bmm_snapshot_narrows_warmer_tip_for_deposits)
{
    // A cached BMM hit for Q=100 must replace a prior non-explicit warmer-tip
    // snapshot at 200. Otherwise a deposit at 150 (after Q) could be accepted
    // on the cache-hit path while the cold path correctly rejects it.
    BOOST_CHECK(ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/200,
        /*current_explicit_target=*/false,
        /*next_explicit_target=*/true, /*next_height=*/100));
    BOOST_CHECK(!ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/200,
        /*current_explicit_target=*/false,
        /*next_explicit_target=*/false, /*next_height=*/100));
    BOOST_CHECK(!ShouldReplaceDrivechainReplaySnapshot(
        /*current_authenticated=*/true, /*current_height=*/100,
        /*current_explicit_target=*/true,
        /*next_explicit_target=*/false, /*next_height=*/200));

    constexpr uint32_t q_height{100};
    constexpr uint32_t post_q_deposit_height{150};
    BOOST_CHECK(post_q_deposit_height > q_height);
}

BOOST_AUTO_TEST_CASE(persistent_parent_replay_store_restart_identity_and_corruption)
{
    const fs::path path = m_args.GetDataDirBase() / "parent_replay_store";
    const uint256 identity = uint256S("01");
    const uint256 wrong_identity = uint256S("02");
    const uint256 genesis_hash = uint256S("03");
    const uint256 block_hash = uint256S("04");
    const uint256 deposit_txid = uint256S("05");
    const uint256 committed_child = uint256S("06");
    const uint256 pending_proposal = uint256S("07");
    const uint256 ctip_txid = uint256S("08");
    const uint256 active_proposal = uint256S("09");

    DrivechainParentReplayTip genesis;
    genesis.hash = genesis_hash;
    DrivechainParentReplayTip next = genesis;
    next.height = 1;
    next.hash = block_hash;
    next.state.active_proposal_hash = active_proposal;
    next.state.pending_proposals.emplace(
        pending_proposal, DrivechainPendingProposal{1, 2});
    next.state.ctip = Bitcoin::COutPoint{ctip_txid, 1};
    next.state.ctip_value = 2000;

    DrivechainMintableDeposit deposit{
        Bitcoin::COutPoint{deposit_txid, 0}, block_hash, 1, 1000,
        std::vector<unsigned char>{0x51}};
    DrivechainReplayedBmmEdge edge{
        block_hash, 0, 1, true, committed_child};
    std::string error;

    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/true);
        BOOST_REQUIRE(store.Reset(identity, genesis, &error));
        BOOST_REQUIRE(store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)), &error));
        BOOST_CHECK(!store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)), &error));
    }

    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/false);
        DrivechainParentReplayTip loaded;
        BOOST_REQUIRE(store.Load(identity, loaded, &error) ==
                      DrivechainReplayStoreLoadStatus::LOADED);
        BOOST_CHECK_EQUAL(loaded.height, 1U);
        BOOST_CHECK(loaded.hash == block_hash);
        BOOST_REQUIRE(loaded.state.ctip.has_value());
        BOOST_CHECK(loaded.state.ctip->hash == ctip_txid);
        BOOST_CHECK_EQUAL(loaded.state.ctip_value, 2000);
        const auto pending = loaded.state.pending_proposals.find(pending_proposal);
        BOOST_REQUIRE(pending != loaded.state.pending_proposals.end());
        BOOST_CHECK_EQUAL(pending->second.proposal_height, 1U);
        BOOST_CHECK_EQUAL(pending->second.votes, 2U);
        BOOST_CHECK(store.Load(wrong_identity, loaded, &error) ==
                    DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH);

        DrivechainMintableDeposit loaded_deposit;
        BOOST_REQUIRE(store.ReadDeposit(deposit.outpoint, loaded_deposit, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK(loaded_deposit.block_hash == block_hash);
        BOOST_CHECK_EQUAL(loaded_deposit.value, deposit.value);

        DrivechainReplayedBmmEdge loaded_edge;
        BOOST_REQUIRE(store.ReadBmmEdge(genesis_hash, loaded_edge, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK(loaded_edge.successor_hash == block_hash);
        BOOST_CHECK(loaded_edge.committed_sidechain_hash == committed_child);
    }

    // A malformed durable tip is never interpreted as an empty or usable
    // index. The caller can safely rebuild this derived database from genesis.
    {
        CDBWrapper raw(path, 1 << 20, /*fMemory=*/false,
                       /*fWipe=*/false, /*obfuscate=*/false);
        BOOST_REQUIRE(raw.Write(uint8_t{'T'}, std::string{"malformed"}, true));
    }
    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/false);
        DrivechainParentReplayTip loaded;
        BOOST_CHECK(store.Load(identity, loaded, &error) ==
                    DrivechainReplayStoreLoadStatus::CORRUPT);
        BOOST_REQUIRE(store.Reset(identity, genesis, &error));
        BOOST_REQUIRE(store.Load(identity, loaded, &error) ==
                      DrivechainReplayStoreLoadStatus::LOADED);
        DrivechainMintableDeposit removed;
        BOOST_CHECK(store.ReadDeposit(deposit.outpoint, removed, &error) ==
                    DrivechainReplayStoreReadStatus::NOT_FOUND);
    }
}

BOOST_AUTO_TEST_CASE(drivechain_m5_address_output_value_is_not_part_of_deposit_amount)
{
    constexpr int sidechain_slot{24};
    constexpr CAmount old_treasury_value{50000};
    constexpr CAmount deposit_value{100000};
    constexpr CAmount address_output_burn{7000};
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{sidechain_slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's', '-', 'r', 'e', 'c', 'i', 'p', 'i', 'e', 'n', 't'};

    Bitcoin::CMutableTransaction previous;
    previous.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 1));
    previous.vout.emplace_back(old_treasury_value, treasury_script);
    const Bitcoin::COutPoint previous_treasury(previous.GetHash(), 0);

    Bitcoin::CMutableTransaction deposit;
    deposit.vin.emplace_back(previous_treasury);
    deposit.vout.emplace_back(old_treasury_value + deposit_value, treasury_script);
    // BIP300 derives the deposit amount only from the treasury delta.  The
    // immediately following address output's nValue is ignored, even when it
    // provably burns additional BTC.
    deposit.vout.emplace_back(address_output_burn, CScript() << OP_RETURN << address);
    const Bitcoin::CTransactionRef deposit_ref = Bitcoin::MakeTransactionRef(std::move(deposit));

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(deposit_ref);

    const COutPoint claimed_outpoint(deposit_ref->GetHash(), 0);
    const std::map<Bitcoin::COutPoint, Bitcoin::CTxOut> previous_outputs{
        {previous_treasury, previous.vout[0]},
    };
    std::string err;
    BOOST_CHECK(MatchDrivechainDepositInBlock(block, sidechain_slot, claimed_outpoint,
                                              deposit_value, address, previous_outputs, &err));
    BOOST_CHECK(!MatchDrivechainDepositInBlock(block, sidechain_slot, claimed_outpoint,
                                               deposit_value + address_output_burn, address,
                                               previous_outputs, &err));

    Bitcoin::CMutableTransaction fabricated_coinbase;
    fabricated_coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    fabricated_coinbase.vout.emplace_back(deposit_value, treasury_script);
    fabricated_coinbase.vout.emplace_back(address_output_burn, CScript() << OP_RETURN << address);
    const Bitcoin::CTransactionRef fabricated_ref =
        Bitcoin::MakeTransactionRef(std::move(fabricated_coinbase));
    Bitcoin::CBlock fabricated_block;
    fabricated_block.vtx.push_back(fabricated_ref);
    const COutPoint fabricated_outpoint(fabricated_ref->GetHash(), 0);
    BOOST_CHECK(!MatchDrivechainDepositInBlock(
        fabricated_block, sidechain_slot, fabricated_outpoint, deposit_value,
        address, {}, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_state_replay_matches_slot_voting_rules)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 old_proposal = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    const std::vector<unsigned char> required_description{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const uint256 required_proposal = Hash(required_description);

    const auto make_m1 = [](const std::vector<unsigned char>& description) {
        std::vector<unsigned char> payload = ParseHex("d5e0c4af");
        payload.push_back(slot);
        payload.insert(payload.end(), description.begin(), description.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m2 = [](const uint256& proposal) {
        std::vector<unsigned char> payload = ParseHex("d6e1c5df");
        payload.push_back(slot);
        payload.insert(payload.end(), proposal.begin(), proposal.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages, const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            state, nullptr, &error);
    };

    std::string error;
    DrivechainParentReplayState state;
    state.active_proposal_hash = old_proposal;

    // Same-block ACK is ignored, then six later ACKs activate the exact
    // Elements proposal. Unknown ACKs have no effect.
    BOOST_CHECK(apply(make_block({make_m1(required_description), make_m2(required_proposal)}, 100),
                      100, state, error));
    BOOST_REQUIRE_EQUAL(state.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK_EQUAL(state.pending_proposals.at(required_proposal).votes, 0U);
    const uint256 unknown = uint256S(
        "2222222222222222222222222222222222222222222222222222222222222222");
    BOOST_CHECK(apply(make_block({make_m2(unknown)}, 101), 101, state, error));
    BOOST_CHECK_EQUAL(state.pending_proposals.at(required_proposal).votes, 0U);
    for (uint32_t height = 102; height <= 107; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height),
                          height, state, error));
    }
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, 107U);
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);

    // A re-proposal of the same required identity may reactivate harmlessly.
    BOOST_CHECK(apply(make_block({make_m1(required_description)}, 108), 108, state, error));
    for (uint32_t height = 109; height <= 114; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height),
                          height, state, error));
    }
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);

    // The enforcer accepts empty M1 descriptions. Before Elements activation an
    // arbitrary replacement is replayed but cannot authorize a mint; after
    // activation, its sixth ACK must terminal-halt V1.
    const std::vector<unsigned char> empty_description;
    const uint256 empty_proposal = Hash(empty_description);
    DrivechainParentReplayState preactivation;
    preactivation.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({make_m1(empty_description)}, 200), 200,
                      preactivation, error));
    for (uint32_t height = 201; height <= 206; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(empty_proposal)}, height),
                          height, preactivation, error));
    }
    BOOST_CHECK(!preactivation.required_proposal_activated);
    BOOST_CHECK_EQUAL(preactivation.active_proposal_hash, empty_proposal);

    BOOST_CHECK(apply(make_block({make_m1(empty_description)}, 300), 300, state, error));
    for (uint32_t height = 301; height < 306; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(empty_proposal)}, height), height, state, error));
    }
    BOOST_CHECK(!apply(make_block({make_m2(empty_proposal)}, 306), 306, state, error));

    // Coinbase message uniqueness is consensus-visible.
    DrivechainParentReplayState duplicate_ack;
    duplicate_ack.active_proposal_hash = old_proposal;
    BOOST_CHECK(!apply(make_block({make_m2(unknown), make_m2(unknown)}, 400),
                       400, duplicate_ack, error));

    DrivechainParentReplayState duplicate_m1;
    duplicate_m1.active_proposal_hash = old_proposal;
    BOOST_CHECK(!apply(
        make_block({make_m1(required_description), make_m1(required_description)}, 401),
        401, duplicate_m1, error));

    const std::vector<unsigned char> second_description{'o', 't', 'h', 'e', 'r'};
    const uint256 second_proposal = Hash(second_description);
    DrivechainParentReplayState distinct_m1s;
    distinct_m1s.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(
        make_block({make_m1(required_description), make_m1(second_description)}, 402),
        402, distinct_m1s, error));
    BOOST_CHECK_EQUAL(distinct_m1s.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK_EQUAL(distinct_m1s.pending_proposals.count(second_proposal), 1U);

    // The enforcer's ordinary instruction parser accepts a nonminimal push for
    // M1, while exact one-push/no-trailing framing still applies.
    const std::vector<unsigned char> nonminimal_description{'n'};
    std::vector<unsigned char> nonminimal_payload = ParseHex("d5e0c4af");
    nonminimal_payload.push_back(slot);
    nonminimal_payload.insert(nonminimal_payload.end(),
                              nonminimal_description.begin(),
                              nonminimal_description.end());
    CScript nonminimal_m1;
    nonminimal_m1.push_back(OP_RETURN);
    nonminimal_m1.push_back(OP_PUSHDATA1);
    nonminimal_m1.push_back(nonminimal_payload.size());
    nonminimal_m1.insert(nonminimal_m1.end(),
                         nonminimal_payload.begin(), nonminimal_payload.end());
    DrivechainParentReplayState nonminimal_state;
    nonminimal_state.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({nonminimal_m1}, 403), 403,
                      nonminimal_state, error));
    BOOST_CHECK_EQUAL(
        nonminimal_state.pending_proposals.count(Hash(nonminimal_description)), 1U);

    // Malformed-length or trailing M2-shaped scripts are ordinary scripts and
    // do not consume the one-valid-M2-per-slot allowance.
    std::vector<unsigned char> short_m2_payload = ParseHex("d6e1c5df");
    short_m2_payload.push_back(slot);
    short_m2_payload.insert(short_m2_payload.end(), 31, 0x00);
    CScript trailing_m2 = make_m2(unknown);
    trailing_m2 << OP_TRUE;
    DrivechainParentReplayState malformed_m2;
    malformed_m2.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(
        make_block({CScript() << OP_RETURN << short_m2_payload,
                    trailing_m2, make_m2(unknown)}, 404),
        404, malformed_m2, error));

    // With no ACKs, a used-slot proposal is present through age five and is
    // removed at age six when five votes are no longer attainable.
    DrivechainParentReplayState expiring;
    expiring.active_proposal_hash = old_proposal;
    BOOST_CHECK(apply(make_block({make_m1(required_description)}, 500), 500,
                      expiring, error));
    for (uint32_t height = 501; height <= 505; ++height) {
        BOOST_CHECK(apply(make_block({}, height), height, expiring, error));
    }
    BOOST_CHECK_EQUAL(expiring.pending_proposals.count(required_proposal), 1U);
    BOOST_CHECK(apply(make_block({}, 506), 506, expiring, error));
    BOOST_CHECK_EQUAL(expiring.pending_proposals.count(required_proposal), 0U);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_starts_unused_and_preserves_pending_state)
{
    constexpr int slot{24};
    constexpr uint16_t unused_max_age{4};
    constexpr uint16_t unused_threshold{1};
    constexpr uint16_t used_max_age{10};
    constexpr uint16_t used_threshold{5};
    const std::vector<unsigned char> first_description{'f', 'i', 'r', 's', 't'};
    const std::vector<unsigned char> required_description{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const std::vector<unsigned char> pending_description{'p', 'e', 'n', 'd'};
    const uint256 first_proposal = Hash(first_description);
    const uint256 required_proposal = Hash(required_description);
    const uint256 pending_proposal = Hash(pending_description);

    const auto make_m1 = [](const std::vector<unsigned char>& description) {
        std::vector<unsigned char> payload = ParseHex("d5e0c4af");
        payload.push_back(slot);
        payload.insert(payload.end(), description.begin(), description.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m2 = [](const uint256& proposal) {
        std::vector<unsigned char> payload = ParseHex("d6e1c5df");
        payload.push_back(slot);
        payload.insert(payload.end(), proposal.begin(), proposal.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state,
                           std::vector<DrivechainMintableDeposit>* deposits,
                           std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            unused_max_age, unused_threshold, used_max_age, used_threshold,
            state, deposits, &error);
    };

    DrivechainParentReplayState state;
    std::vector<DrivechainMintableDeposit> deposits;
    std::string error;

    // Authenticate and apply height zero from truly empty state. A treasury-
    // shaped output in an inactive slot is ordinary anyone-can-spend output,
    // even though it would be malformed as an active-slot deposit.
    Bitcoin::CBlock genesis_like = make_block(
        {make_m1(first_description), make_m2(first_proposal)}, 0);
    Bitcoin::CMutableTransaction inactive_treasury;
    inactive_treasury.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    inactive_treasury.vout.emplace_back(
        5000, CScript() << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE);
    genesis_like.vtx.push_back(
        Bitcoin::MakeTransactionRef(std::move(inactive_treasury)));
    BOOST_CHECK(apply(genesis_like, 0, state, &deposits, error));
    BOOST_CHECK(state.active_proposal_hash.IsNull());
    BOOST_CHECK(!state.ctip.has_value());
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.pending_proposals.at(first_proposal).votes, 0U);

    // The unused-slot pair (threshold 1) activates on the second later ACK.
    BOOST_CHECK(apply(make_block({make_m2(first_proposal)}, 1), 1,
                      state, nullptr, error));
    BOOST_CHECK(state.active_proposal_hash.IsNull());
    BOOST_CHECK(apply(make_block({make_m2(first_proposal)}, 2), 2,
                      state, nullptr, error));
    BOOST_CHECK_EQUAL(state.active_proposal_hash, first_proposal);

    // Replacement now uses the used-slot pair (threshold 5). Five ACKs do not
    // activate; the sixth does, without clearing unrelated pending proposals.
    BOOST_CHECK(apply(
        make_block({make_m1(required_description), make_m2(required_proposal)}, 3),
        3, state, nullptr, error));
    for (uint32_t height = 4; height <= 7; ++height) {
        BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, height), height,
                          state, nullptr, error));
    }
    BOOST_CHECK(apply(
        make_block({make_m1(pending_description), make_m2(required_proposal)}, 8),
        8, state, nullptr, error));
    BOOST_CHECK_EQUAL(state.active_proposal_hash, first_proposal);
    BOOST_CHECK(apply(make_block({make_m2(required_proposal)}, 9), 9,
                      state, nullptr, error));
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, 9U);
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);
    BOOST_CHECK_EQUAL(state.pending_proposals.count(pending_proposal), 1U);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_ctip_replay_rejects_fabricated_transitions)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);

    const auto make_block = [](Bitcoin::CMutableTransaction transaction, const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(transaction)));
        return block;
    };
    const auto active_state = [&]() {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial_ctip;
        state.ctip_value = 5000;
        return state;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, DrivechainParentReplayState& state,
                           std::vector<DrivechainMintableDeposit>& deposits, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, 10, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            state, &deposits, &error);
    };

    std::string error;
    std::vector<DrivechainMintableDeposit> deposits;
    Bitcoin::CMutableTransaction positive;
    positive.vin.emplace_back(initial_ctip);
    positive.vout.emplace_back(6000, treasury_script);
    positive.vout.emplace_back(700, CScript() << OP_RETURN << address);
    DrivechainParentReplayState state = active_state();
    BOOST_CHECK(apply(make_block(positive, 1), state, deposits, error));
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits[0].value, 1000);
    BOOST_CHECK(deposits[0].address == address);
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    Bitcoin::CMutableTransaction parallel;
    parallel.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    parallel.vout.emplace_back(6000, treasury_script);
    parallel.vout.emplace_back(0, CScript() << OP_RETURN << address);
    state = active_state();
    BOOST_CHECK(!apply(make_block(parallel, 2), state, deposits, error));

    Bitcoin::CMutableTransaction theft;
    theft.vin.emplace_back(initial_ctip);
    theft.vout.emplace_back(5000, CScript() << OP_TRUE);
    state = active_state();
    BOOST_CHECK(!apply(make_block(theft, 3), state, deposits, error));

    Bitcoin::CMutableTransaction multiple;
    multiple.vin.emplace_back(initial_ctip);
    multiple.vout.emplace_back(5500, treasury_script);
    multiple.vout.emplace_back(5501, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(multiple, 4), state, deposits, error));

    Bitcoin::CMutableTransaction zero_delta;
    zero_delta.vin.emplace_back(initial_ctip);
    zero_delta.vout.emplace_back(5000, treasury_script);
    zero_delta.vout.emplace_back(0, CScript() << OP_RETURN << address);
    state = active_state();
    BOOST_CHECK(!apply(make_block(zero_delta, 5), state, deposits, error));

    Bitcoin::CMutableTransaction decrease;
    decrease.vin.emplace_back(initial_ctip);
    decrease.vout.emplace_back(4999, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(decrease, 6), state, deposits, error));

    // Empty pushed addresses are overlay-valid backing surplus, never a child
    // mint authorization. Missing the address output entirely remains invalid.
    Bitcoin::CMutableTransaction empty_address;
    empty_address.vin.emplace_back(initial_ctip);
    empty_address.vout.emplace_back(6000, treasury_script);
    empty_address.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{});
    state = active_state();
    BOOST_CHECK(apply(make_block(empty_address, 7), state, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    // The parent permits arbitrary OP_RETURN address bytes, but the native
    // witness codec is capped at 128. Larger commitments remain backing
    // surplus and must not grow the mintable-deposit index.
    Bitcoin::CMutableTransaction oversized_address;
    oversized_address.vin.emplace_back(initial_ctip);
    oversized_address.vout.emplace_back(6000, treasury_script);
    oversized_address.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(129, 0x42));
    state = active_state();
    BOOST_CHECK(apply(make_block(oversized_address, 8), state, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(state.ctip_value, 6000);

    Bitcoin::CMutableTransaction missing_address;
    missing_address.vin.emplace_back(initial_ctip);
    missing_address.vout.emplace_back(6000, treasury_script);
    state = active_state();
    BOOST_CHECK(!apply(make_block(missing_address, 9), state, deposits, error));

    // Before the frozen Elements proposal activates, exact increases update the
    // inherited CTIP but remain non-mintable backing surplus.
    DrivechainParentReplayState preactivation;
    preactivation.active_proposal_hash = uint256S(
        "5555555555555555555555555555555555555555555555555555555555555555");
    preactivation.ctip = initial_ctip;
    preactivation.ctip_value = 5000;
    BOOST_CHECK(apply(make_block(positive, 10), preactivation, deposits, error));
    BOOST_CHECK(deposits.empty());
    BOOST_CHECK_EQUAL(preactivation.ctip_value, 6000);
}

BOOST_AUTO_TEST_CASE(drivechain_activation_block_deposit_is_mintable)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr uint32_t activation_height{7};
    const uint256 old_proposal = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);

    std::vector<unsigned char> m2 = ParseHex("d6e1c5df");
    m2.push_back(slot);
    m2.insert(m2.end(), required_proposal.begin(), required_proposal.end());
    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << m2);

    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;
    const std::vector<unsigned char> address{'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
    Bitcoin::CMutableTransaction deposit;
    deposit.vin.emplace_back(initial_ctip);
    deposit.vout.emplace_back(6000, treasury_script);
    deposit.vout.emplace_back(0, CScript() << OP_RETURN << address);

    Bitcoin::CBlock block;
    block.nNonce = activation_height;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(deposit)));

    DrivechainParentReplayState state;
    state.active_proposal_hash = old_proposal;
    state.pending_proposals.emplace(
        required_proposal, DrivechainPendingProposal{/* proposal_height= */ 1, /* votes= */ 5});
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    std::vector<DrivechainMintableDeposit> deposits;
    std::string error;
    BOOST_CHECK(ApplyDrivechainParentBlockState(
        block, activation_height, slot, required_proposal,
        max_age, threshold, max_age, threshold,
        state, &deposits, &error));
    BOOST_CHECK(state.required_proposal_activated);
    BOOST_CHECK_EQUAL(state.required_activation_height, activation_height);
    BOOST_CHECK_EQUAL(state.required_activation_block_hash, block.GetHash());
    BOOST_CHECK_EQUAL(state.active_proposal_hash, required_proposal);
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits[0].value, 1000);
    BOOST_CHECK(deposits[0].address == address);
    BOOST_CHECK_EQUAL(deposits[0].block_height, activation_height);
}

BOOST_AUTO_TEST_CASE(drivechain_deposit_outputs_are_bound_to_mainchain_address)
{
    const COutPoint deposit_outpoint(
        uint256S("00000000000000000000000000000000000000000000000000000000000000dd"), 2);
    const uint256 block_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000ee");
    const CAmount deposit_value = 100000;
    const CAmount fee = 1000;
    uint160 destination_hash;
    destination_hash.SetHex("0000000000000000000000000000000000001234");
    const CTxDestination destination = WitnessV0KeyHash(destination_hash);
    const std::string address_string = EncodeDestination(destination);
    const std::vector<unsigned char> address(address_string.begin(), address_string.end());

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn pegin_input(deposit_outpoint, CScript(), CTxIn::SEQUENCE_FINAL);
    pegin_input.m_is_pegin = true;
    mtx.vin.push_back(pegin_input);
    mtx.vout.push_back(CTxOut(
        Params().GetConsensus().pegged_asset,
        deposit_value,
        GetScriptForDestination(destination)));
    mtx.witness.vtxinwit.resize(1);
    mtx.witness.vtxoutwit.resize(mtx.vout.size());
    mtx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        deposit_value,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        deposit_outpoint,
        block_hash,
        address);

    std::string err;
    BOOST_CHECK(CheckDrivechainDepositOutputs(CTransaction(mtx), 0, err));
    BOOST_CHECK(IsCanonicalFeeFreeDrivechainDeposit(CTransaction(mtx)));

    CMutableTransaction deducted = mtx;
    deducted.vout[0].nValue = CConfidentialValue(deposit_value - fee);
    deducted.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, fee, CScript()));
    deducted.witness.vtxoutwit.resize(deducted.vout.size());
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(deducted), 0, err));
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(deducted)));

    CMutableTransaction redirected = mtx;
    redirected.vout[0].scriptPubKey = CScript() << OP_TRUE;
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(redirected), 0, err));

    CMutableTransaction inflated = mtx;
    inflated.vout[0].nValue = CConfidentialValue(deposit_value + 1);
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(inflated), 0, err));

    CMutableTransaction extra_input = mtx;
    extra_input.vin.push_back(CTxIn(COutPoint(uint256::ONE, 0)));
    extra_input.witness.vtxinwit.resize(2);
    BOOST_CHECK(CheckDrivechainDepositOutputs(CTransaction(extra_input), 0, err));
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(extra_input)));

    CMutableTransaction extra_output = mtx;
    extra_output.vout.emplace_back(Params().GetConsensus().pegged_asset, 0, CScript() << OP_RETURN);
    extra_output.witness.vtxoutwit.resize(extra_output.vout.size());
    BOOST_CHECK(!IsCanonicalFeeFreeDrivechainDeposit(CTransaction(extra_output)));

    CMutableTransaction mixed_pegin = extra_input;
    mixed_pegin.vin[1].m_is_pegin = true;
    BOOST_CHECK(!CheckDrivechainDepositOutputs(CTransaction(mixed_pegin), 0, err));

    CMutableTransaction forged_marker = mtx;
    forged_marker.witness.vtxinwit[0].m_pegin_witness.stack[4].back() = '1';
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        forged_marker.witness.vtxinwit[0].m_pegin_witness,
        forged_marker.vin[0].prevout));

    // Native witnesses use one canonical int64 amount encoding. The legacy
    // pegin parser remains unchanged, but a trailing byte cannot create a
    // second byte representation of the same BIP300 mint authorization.
    CMutableTransaction noncanonical_amount = mtx;
    BOOST_REQUIRE_EQUAL(
        noncanonical_amount.witness.vtxinwit[0].m_pegin_witness.stack[0].size(),
        sizeof(CAmount));
    noncanonical_amount.witness.vtxinwit[0].m_pegin_witness.stack[0].push_back(0);
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        noncanonical_amount.witness.vtxinwit[0].m_pegin_witness,
        noncanonical_amount.vin[0].prevout));

    CMutableTransaction empty_address = mtx;
    empty_address.witness.vtxinwit[0].m_pegin_witness.stack[7].clear();
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        empty_address.witness.vtxinwit[0].m_pegin_witness,
        empty_address.vin[0].prevout));

    CMutableTransaction oversized_address = mtx;
    oversized_address.witness.vtxinwit[0].m_pegin_witness.stack[7].assign(129, 'a');
    BOOST_CHECK(!IsDrivechainDepositPeginWitness(
        oversized_address.witness.vtxinwit[0].m_pegin_witness,
        oversized_address.vin[0].prevout));

    BOOST_CHECK_THROW(
        CreateDrivechainDepositPeginWitness(
            deposit_value, Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(), CScript() << OP_TRUE,
            deposit_outpoint, block_hash, {}),
        std::invalid_argument);
    BOOST_CHECK_THROW(
        CreateDrivechainDepositPeginWitness(
            deposit_value, Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(), CScript() << OP_TRUE,
            deposit_outpoint, block_hash, std::vector<unsigned char>(129, 'a')),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_header_mtp_is_strict)
{
    constexpr int test_slot{24};
    const std::optional<uint8_t>& configured_slot = Params().GetConsensus().drivechain_slot;
    BOOST_CHECK_EQUAL(IsDrivechainSidechainSlot(test_slot),
                      configured_slot.has_value() && *configured_slot == test_slot);
    BOOST_CHECK(!IsDrivechainSidechainSlot(-1));
    BOOST_CHECK(!IsDrivechainSidechainSlot(256));

    const uint256 expected_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000aa");
    uint64_t mtp{0};
    std::string err;

    UniValue header;
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", expected_hash.GetHex())));
    BOOST_CHECK(ParseDrivechainParentHeader(header, expected_hash, mtp, &err));
    BOOST_CHECK_EQUAL(mtp, 1700000000U);

    const uint256 wrong_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000bb");
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", wrong_hash.GetHex())));
    BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));

    std::string uppercase_hash = expected_hash.GetHex();
    uppercase_hash.replace(62, 2, "AA");
    BOOST_REQUIRE(header.read(strprintf("{\"hash\":\"%s\",\"mediantime\":1700000000}", uppercase_hash)));
    BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));

    const std::vector<std::string> invalid_headers{
        "{}",
        "{\"hash\":1,\"mediantime\":1700000000}",
        "{\"hash\":\"00\",\"mediantime\":1700000000}",
        strprintf("{\"hash\":\"%s\"}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":\"1700000000\"}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":-1}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":1.5}", expected_hash.GetHex()),
        strprintf("{\"hash\":\"%s\",\"mediantime\":4294967296}", expected_hash.GetHex()),
    };
    for (const std::string& json : invalid_headers) {
        BOOST_REQUIRE(header.read(json));
        BOOST_CHECK(!ParseDrivechainParentHeader(header, expected_hash, mtp, &err));
    }
}

BOOST_AUTO_TEST_SUITE_END()
