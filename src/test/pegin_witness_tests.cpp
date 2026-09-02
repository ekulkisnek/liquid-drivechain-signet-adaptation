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
#include <drivechain_withdrawal.h>
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

BOOST_AUTO_TEST_CASE(drivechain_bmm_m7_matches_pinned_enforcer_push_parsing)
{
    const uint256 sidechain_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");

    const auto make_m7 = [](const int slot, const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(static_cast<unsigned char>(slot));
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
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

    // Fixed cross-codec fixture: the enforcer decodes `critical_hash` as
    // ConsensusHex into an opaque BmmCommitment and serializes those exact
    // display-order bytes into M7. This fixture is deliberately not produced
    // by make_m7().
    const std::vector<unsigned char> enforcer_fixture_bytes = ParseHex(
        "6a25d1617368180123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
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
    const std::vector<unsigned char> nonminimal_display_hash = ParseHex(sidechain_hash.GetHex());
    payload.insert(payload.end(), nonminimal_display_hash.begin(), nonminimal_display_hash.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    // CoinbaseMessage::parse in the pinned rust-bitcoin enforcer accepts a
    // single non-minimal push. Elements must recognize the same M7.
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(make_block({nonminimal}),
                                                    24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), nonminimal}),
        24, sidechain_hash, nullptr, &err));

    CScript internal_endian;
    internal_endian << OP_RETURN;
    std::vector<unsigned char> internal_payload = ParseHex("d1617368");
    internal_payload.push_back(24);
    internal_payload.insert(internal_payload.end(), sidechain_hash.begin(), sidechain_hash.end());
    internal_endian << internal_payload;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({internal_endian}),
                                                     24, sidechain_hash, nullptr, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_validates_pinned_enforcer_m8)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S("11");
    const uint256 sidechain_hash = uint256S("22");
    const uint256 previous_parent = uint256S("33");

    const auto make_m7 = [](const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(slot);
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m8_script = [](const uint256& hash, const uint256& previous,
                                   const bool nonminimal) {
        std::vector<unsigned char> payload = ParseHex("00bf00");
        payload.push_back(slot);
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
        payload.insert(payload.end(), previous.begin(), previous.end());
        if (!nonminimal) return CScript() << OP_RETURN << payload;
        CScript script;
        script.push_back(OP_RETURN);
        script.push_back(OP_PUSHDATA1);
        script.push_back(payload.size());
        script.insert(script.end(), payload.begin(), payload.end());
        return script;
    };
    const auto make_block = [&](const std::vector<CScript>& coinbase_messages,
                                const CScript& request_script) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : coinbase_messages) {
            coinbase.vout.emplace_back(0, message);
        }
        Bitcoin::CMutableTransaction request;
        request.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
        request.vout.emplace_back(0, request_script);
        Bitcoin::CBlock block;
        block.hashPrevBlock = previous_parent;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(request)));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, std::string& error) {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        return ApplyDrivechainParentBlockState(
            block, 1, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold, state, nullptr, &error);
    };

    std::string error;
    BOOST_CHECK(apply(make_block(
        {make_m7(sidechain_hash)},
        make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {}, make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {make_m7(uint256S("44"))},
        make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/false)), error));
    BOOST_CHECK(!apply(make_block(
        {make_m7(sidechain_hash)},
        make_m8_script(sidechain_hash, uint256S("55"), /*nonminimal=*/false)), error));

    // M8BmmRequest::parse requires the exact PUSHBYTES_68 form. A PUSHDATA1
    // lookalike is not an M8 at all, so both implementations ignore it.
    BOOST_CHECK(apply(make_block(
        {}, make_m8_script(sidechain_hash, previous_parent, /*nonminimal=*/true)), error));
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
    const uint256 pending_m6id = uint256S("0a");
    const uint256 other_active_proposal = uint256S("0b");
    const uint256 other_pending_proposal = uint256S("0c");
    const uint256 other_pending_m6id = uint256S("0d");
    const uint256 other_ctip_txid = uint256S("0e");
    const uint256 second_block_hash = uint256S("0f");
    const uint256 successful_m6id = uint256S("10");

    DrivechainParentReplayTip genesis;
    genesis.hash = genesis_hash;
    DrivechainParentReplayTip next = genesis;
    next.height = 1;
    next.hash = block_hash;
    next.state.active_proposal_hash = active_proposal;
    next.state.pending_proposals.emplace(
        pending_proposal, DrivechainPendingProposal{0, 1});
    next.state.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{pending_m6id, 1, 2});
    next.state.ctip = Bitcoin::COutPoint{ctip_txid, 1};
    next.state.ctip_value = 0;
    DrivechainOtherSlotReplayState other_slot;
    other_slot.active_proposal_hash = other_active_proposal;
    other_slot.pending_proposals.emplace(
        other_pending_proposal, DrivechainPendingProposal{0, 1});
    other_slot.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{other_pending_m6id, 1, 2});
    other_slot.ctip = Bitcoin::COutPoint{other_ctip_txid, 2};
    other_slot.ctip_value = 0;
    next.state.other_slots.emplace(25, std::move(other_slot));
    next.state.previous_m4_actions.emplace(
        24, DrivechainM4Action{DrivechainM4ActionType::UPVOTE, pending_m6id});
    next.state.previous_m4_actions.emplace(
        25, DrivechainM4Action{DrivechainM4ActionType::ALARM, uint256{}});

    DrivechainMintableDeposit deposit{
        Bitcoin::COutPoint{deposit_txid, 0}, block_hash, 1, 1000,
        std::vector<unsigned char>{0x51}};
    DrivechainReplayedBmmEdge edge{
        block_hash, 0, 1, true, committed_child};
    DrivechainSuccessfulWithdrawal successful_withdrawal{
        24, successful_m6id, 1, block_hash};
    std::string error;

    {
        DrivechainParentReplayStore store(path, 1 << 20, /*wipe=*/true);
        BOOST_REQUIRE(store.Reset(identity, genesis, &error));
        BOOST_REQUIRE(store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)),
            {successful_withdrawal}, &error));
        BOOST_CHECK(!store.Append(
            genesis, next, {deposit},
            std::make_optional(std::make_pair(genesis_hash, edge)),
            {successful_withdrawal}, &error));

        // A paid M6 remains permanently spent while this parent branch is
        // active, even if a later block proposes the same blinded id again.
        DrivechainParentReplayTip replay = next;
        replay.height = 2;
        replay.hash = second_block_hash;
        DrivechainSuccessfulWithdrawal duplicate_success{
            24, successful_m6id, 2, second_block_hash};
        BOOST_CHECK(!store.Append(
            next, replay, {}, std::nullopt, {duplicate_success}, &error));
        BOOST_CHECK(!store.Append(
            next, replay, {}, std::nullopt, {},
            {DrivechainWithdrawalProposalIdentity{24, successful_m6id}},
            &error));
        BOOST_CHECK(error.find("already succeeded") != std::string::npos);

        // Height/hash equality is insufficient: appends must also bind the
        // caller's complete previous replay state to the durable tip.
        DrivechainParentReplayTip altered_previous = next;
        altered_previous.state.ctip_value = 1;
        DrivechainParentReplayTip second = altered_previous;
        second.height = 2;
        second.hash = second_block_hash;
        BOOST_CHECK(!store.Append(altered_previous, second, {}, std::nullopt, &error));
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
        BOOST_CHECK_EQUAL(loaded.state.ctip_value, 0);
        const auto pending = loaded.state.pending_proposals.find(pending_proposal);
        BOOST_REQUIRE(pending != loaded.state.pending_proposals.end());
        BOOST_CHECK_EQUAL(pending->second.proposal_height, 0U);
        BOOST_CHECK_EQUAL(pending->second.votes, 1U);
        BOOST_REQUIRE_EQUAL(loaded.state.pending_withdrawals.size(), 1U);
        BOOST_CHECK(loaded.state.pending_withdrawals[0].m6id == pending_m6id);
        BOOST_CHECK_EQUAL(loaded.state.pending_withdrawals[0].votes, 2U);
        const auto loaded_other = loaded.state.other_slots.find(25);
        BOOST_REQUIRE(loaded_other != loaded.state.other_slots.end());
        BOOST_CHECK(loaded_other->second.active_proposal_hash == other_active_proposal);
        const auto loaded_other_proposal =
            loaded_other->second.pending_proposals.find(other_pending_proposal);
        BOOST_REQUIRE(loaded_other_proposal !=
                      loaded_other->second.pending_proposals.end());
        BOOST_CHECK_EQUAL(loaded_other_proposal->second.votes, 1U);
        BOOST_REQUIRE(loaded_other->second.ctip.has_value());
        BOOST_CHECK(loaded_other->second.ctip->hash == other_ctip_txid);
        BOOST_CHECK_EQUAL(loaded_other->second.ctip_value, 0);
        BOOST_REQUIRE_EQUAL(loaded_other->second.pending_withdrawals.size(), 1U);
        BOOST_CHECK(loaded_other->second.pending_withdrawals[0].m6id == other_pending_m6id);
        BOOST_REQUIRE_EQUAL(loaded.state.previous_m4_actions.size(), 2U);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(24).type ==
                    DrivechainM4ActionType::UPVOTE);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(24).m6id == pending_m6id);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(25).type ==
                    DrivechainM4ActionType::ALARM);
        BOOST_CHECK(loaded.state.previous_m4_actions.at(25).m6id.IsNull());
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

        DrivechainSuccessfulWithdrawal loaded_withdrawal;
        BOOST_REQUIRE(store.ReadSuccessfulWithdrawal(
                          24, successful_m6id, loaded_withdrawal, &error) ==
                      DrivechainReplayStoreReadStatus::FOUND);
        BOOST_CHECK_EQUAL(loaded_withdrawal.sidechain_slot, 24U);
        BOOST_CHECK(loaded_withdrawal.m6id == successful_m6id);
        BOOST_CHECK_EQUAL(loaded_withdrawal.block_height, 1U);
        BOOST_CHECK(loaded_withdrawal.block_hash == block_hash);
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
        DrivechainSuccessfulWithdrawal removed_withdrawal;
        BOOST_CHECK(store.ReadSuccessfulWithdrawal(
                        24, successful_m6id, removed_withdrawal, &error) ==
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
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
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
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
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
            /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
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

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_accepts_only_miner_approved_m6)
{
    constexpr int slot{24};
    constexpr uint8_t other_slot{3};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const uint256 other_proposal = uint256S(
        "0303030303030303030303030303030303030303030303030303030303030303");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    Bitcoin::CMutableTransaction withdrawal;
    withdrawal.vin.emplace_back(initial_ctip);
    withdrawal.vout.emplace_back(4000, treasury_script);
    withdrawal.vout.emplace_back(900, CScript() << OP_TRUE);
    const Bitcoin::CTransaction withdrawal_tx(withdrawal);
    uint256 m6id;
    uint8_t derived_slot{0};
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(
        withdrawal_tx, 5000, m6id, &derived_slot, &error));
    BOOST_CHECK_EQUAL(derived_slot, slot);

    const auto make_m3 = [](const uint8_t message_slot, const uint256& id) {
        std::vector<unsigned char> payload = ParseHex("d45aa943");
        payload.push_back(message_slot);
        payload.insert(payload.end(), id.begin(), id.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_explicit_m4 = [](const std::vector<unsigned char>& votes) {
        std::vector<unsigned char> payload = ParseHex("d77d177601");
        payload.insert(payload.end(), votes.begin(), votes.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto repeat_previous_m4 = []() {
        return CScript() << OP_RETURN << ParseHex("d77d177600");
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce,
                               const Bitcoin::CMutableTransaction* transaction = nullptr) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        if (transaction) block.vtx.push_back(Bitcoin::MakeTransactionRef(*transaction));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block,
                           const uint32_t height,
                           DrivechainParentReplayState& state,
                           std::vector<DrivechainSuccessfulWithdrawal>*
                               successful_withdrawals = nullptr,
                           std::vector<DrivechainWithdrawalProposalIdentity>*
                               withdrawal_proposals = nullptr) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold, state, nullptr, &error,
            successful_withdrawals, withdrawal_proposals);
    };

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    state.other_slots[other_slot].active_proposal_hash = other_proposal;

    std::vector<DrivechainWithdrawalProposalIdentity> withdrawal_proposals;
    BOOST_REQUIRE(apply(
        make_block({make_m3(slot, m6id)}, 100), 100, state,
        nullptr, &withdrawal_proposals));
    BOOST_REQUIRE_EQUAL(state.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, 1U);
    BOOST_REQUIRE_EQUAL(withdrawal_proposals.size(), 1U);
    BOOST_CHECK_EQUAL(withdrawal_proposals[0].sidechain_slot, slot);
    BOOST_CHECK(withdrawal_proposals[0].m6id == m6id);

    // Active slots are globally sorted [3, 24]. A slot-24-only vote vector is
    // invalid; the correct vector abstains for slot 3 and selects index 0 for
    // slot 24. RepeatPrevious then reproduces that effective upvote.
    DrivechainParentReplayState wrong_vector = state;
    BOOST_CHECK(!apply(make_block({make_explicit_m4({0})}, 101), 101, wrong_vector));
    BOOST_REQUIRE(apply(make_block({make_explicit_m4({0xff, 0})}, 101), 101, state));
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, 2U);
    for (uint32_t height = 102; height <= 104; ++height) {
        BOOST_REQUIRE(apply(make_block({repeat_previous_m4()}, height), height, state));
    }
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, threshold);

    // BIP300 requires strictly more than the threshold.
    DrivechainParentReplayState exactly_threshold = state;
    BOOST_CHECK(!apply(make_block({}, 105, &withdrawal), 105, exactly_threshold));

    BOOST_REQUIRE(apply(make_block({repeat_previous_m4()}, 105), 105, state));
    BOOST_CHECK_EQUAL(state.pending_withdrawals[0].votes, threshold + 1);

    // Any payout mutation changes the blinded M6id and therefore cannot spend
    // the approved bundle.
    Bitcoin::CMutableTransaction tampered = withdrawal;
    tampered.vout[1].nValue += 1;
    DrivechainParentReplayState tampered_state = state;
    BOOST_CHECK(!apply(make_block({}, 106, &tampered), 106, tampered_state));

    const Bitcoin::CBlock successful_block =
        make_block({}, 106, &withdrawal);
    std::vector<DrivechainSuccessfulWithdrawal> successful_withdrawals;
    BOOST_REQUIRE(apply(
        successful_block, 106, state, &successful_withdrawals));
    BOOST_CHECK(state.pending_withdrawals.empty());
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK_EQUAL(state.ctip->hash, withdrawal_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, 4000);
    BOOST_REQUIRE_EQUAL(successful_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(successful_withdrawals[0].sidechain_slot, slot);
    BOOST_CHECK(successful_withdrawals[0].m6id == m6id);
    BOOST_CHECK_EQUAL(successful_withdrawals[0].block_height, 106U);
    BOOST_CHECK(successful_withdrawals[0].block_hash ==
                successful_block.GetHash());
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_accepts_exact_native_elwd_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr CAmount old_ctip_value{200000};
    constexpr CAmount burn_amount{100000};
    constexpr CAmount parent_fee{1000};
    constexpr CAmount successor_ctip_value{old_ctip_value - burn_amount};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const uint256 elements_genesis = uint256S(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const uint256 burn_txid = uint256S(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    drivechain::NativeWithdrawal withdrawal;
    withdrawal.destination = CScript() << OP_0 << ParseHex(
        "606162636465666768696a6b6c6d6e6f70717273");
    withdrawal.burn_amount = burn_amount;
    withdrawal.parent_fee = parent_fee;
    withdrawal.payout_amount = burn_amount - parent_fee;

    drivechain::NativeWithdrawalM6 blinded;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            elements_genesis, slot, burn_txid, 7, withdrawal, blinded, &error),
        error);

    Bitcoin::CMutableTransaction actual = blinded.blinded_transaction;
    actual.vin.emplace_back(initial_ctip);
    actual.vout[0] = Bitcoin::CTxOut(successor_ctip_value, treasury_script);
    const Bitcoin::CTransaction actual_tx(actual);
    uint256 actual_m6id;
    uint8_t actual_slot{0};
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            actual_tx, old_ctip_value, actual_m6id, &actual_slot, &error),
        error);
    BOOST_CHECK_EQUAL(actual_slot, slot);
    BOOST_CHECK(actual_m6id == blinded.m6id);

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = old_ctip_value;
    state.pending_withdrawals = {
        {blinded.m6id, 99, threshold + 1},
    };

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(actual));

    std::vector<DrivechainSuccessfulWithdrawal> successful;
    BOOST_REQUIRE_MESSAGE(
        ApplyDrivechainParentBlockState(
            block, 100, slot, required_proposal,
            max_age, threshold, max_age, threshold, max_age, threshold,
            state, nullptr, &error, &successful),
        error);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == actual_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, successor_ctip_value);
    BOOST_CHECK(state.pending_withdrawals.empty());
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK_EQUAL(successful[0].sidechain_slot, slot);
    BOOST_CHECK(successful[0].m6id == blinded.m6id);
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_sequences_usdd_root_and_native_elwd_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    constexpr CAmount initial_ctip_value{10000};
    constexpr CAmount root_successor_value{8999};
    constexpr CAmount native_burn_amount{4000};
    constexpr CAmount native_parent_fee{100};
    constexpr CAmount native_successor_value{
        root_successor_value - native_burn_amount};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    // Canonical two-output USDD accumulator M6 fixed across Elements, Rust,
    // Solidity, and the enforcer. Its CTIP successor is always vout zero.
    const std::vector<unsigned char> root_raw = ParseHex(
        "02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
        "030201000700000000ffffffff02272300000000000004b401185101000000000000"
        "00296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e"
        "8fc8717e3f7974186b36700000000");
    CDataStream root_stream(root_raw, SER_NETWORK, PROTOCOL_VERSION);
    Bitcoin::CMutableTransaction root_m6;
    root_stream >> root_m6;
    BOOST_REQUIRE(root_stream.empty());
    const Bitcoin::CTransaction root_tx(root_m6);
    BOOST_REQUIRE_EQUAL(root_tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(root_tx.vout.size(), 2U);
    BOOST_CHECK_EQUAL(root_tx.vout[0].nValue, root_successor_value);

    uint256 root_m6id;
    uint8_t root_slot{0};
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            root_tx, initial_ctip_value, root_m6id, &root_slot, &error),
        error);
    BOOST_CHECK_EQUAL(root_slot, slot);

    drivechain::NativeWithdrawal native_withdrawal;
    native_withdrawal.destination = CScript() << OP_0 << ParseHex(
        "606162636465666768696a6b6c6d6e6f70717273");
    native_withdrawal.burn_amount = native_burn_amount;
    native_withdrawal.parent_fee = native_parent_fee;
    native_withdrawal.payout_amount = native_burn_amount - native_parent_fee;

    drivechain::NativeWithdrawalM6 native_blinded;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            uint256S(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            slot,
            uint256S(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
            7, native_withdrawal, native_blinded, &error),
        error);
    Bitcoin::CMutableTransaction native_m6 = native_blinded.blinded_transaction;
    native_m6.vin.emplace_back(Bitcoin::COutPoint(root_tx.GetHash(), 0));
    native_m6.vout[0] = Bitcoin::CTxOut(native_successor_value, treasury_script);
    const Bitcoin::CTransaction native_tx(native_m6);
    uint256 native_m6id;
    uint8_t native_slot{0};
    BOOST_REQUIRE_MESSAGE(
        ComputeDrivechainM6Id(
            native_tx, root_successor_value, native_m6id, &native_slot, &error),
        error);
    BOOST_CHECK_EQUAL(native_slot, slot);
    BOOST_CHECK(native_m6id == native_blinded.m6id);

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = root_tx.vin[0].prevout;
    state.ctip_value = initial_ctip_value;
    state.pending_withdrawals = {
        {root_m6id, 99, threshold + 1},
        {native_m6id, 99, threshold + 1},
    };

    const auto make_block = [](const Bitcoin::CMutableTransaction& transaction,
                               const uint32_t nonce) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        block.vtx.push_back(Bitcoin::MakeTransactionRef(transaction));
        return block;
    };
    const auto apply = [&](const Bitcoin::CBlock& block,
                           const uint32_t height,
                           std::vector<DrivechainSuccessfulWithdrawal>& successful) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold, max_age, threshold,
            state, nullptr, &error, &successful);
    };

    std::vector<DrivechainSuccessfulWithdrawal> successful;
    BOOST_REQUIRE_MESSAGE(apply(make_block(root_m6, 100), 100, successful), error);
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK(successful[0].m6id == root_m6id);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == root_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, root_successor_value);

    successful.clear();
    BOOST_REQUIRE_MESSAGE(apply(make_block(native_m6, 101), 101, successful), error);
    BOOST_REQUIRE_EQUAL(successful.size(), 1U);
    BOOST_CHECK(successful[0].m6id == native_m6id);
    BOOST_REQUIRE(state.ctip.has_value());
    BOOST_CHECK(state.ctip->hash == native_tx.GetHash());
    BOOST_CHECK_EQUAL(state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(state.ctip_value, native_successor_value);
    BOOST_CHECK(state.pending_withdrawals.empty());
}

BOOST_AUTO_TEST_CASE(drivechain_m6id_matches_usdd_and_enforcer_vector)
{
    const std::vector<unsigned char> raw = ParseHex(
        "02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
        "030201000700000000ffffffff02272300000000000004b401185101000000000000"
        "00296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e"
        "8fc8717e3f7974186b36700000000");
    CDataStream stream(raw, SER_NETWORK, PROTOCOL_VERSION);
    Bitcoin::CMutableTransaction mutable_tx;
    stream >> mutable_tx;
    BOOST_REQUIRE(stream.empty());
    const Bitcoin::CTransaction transaction(mutable_tx);
    BOOST_CHECK_EQUAL(
        transaction.GetHash(),
        uint256S("641c51cde9625227dd15e9f8482d0c62700b3824d7bef9f5e83a689120f8acca"));

    uint256 m6id;
    uint8_t slot{0};
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(
        transaction, /* previous_treasury_value= */ 10000,
        m6id, &slot, &error));
    BOOST_CHECK_EQUAL(slot, 24U);
    BOOST_CHECK_EQUAL(
        m6id,
        uint256S("9cf04f94106990b941c4cd437435e376bf4bbd08671ddd8549169f251af6b5a9"));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_replay_rejects_two_configured_slot_m6s_in_one_block)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    Bitcoin::CMutableTransaction first;
    first.vin.emplace_back(initial_ctip);
    first.vout.emplace_back(4000, treasury_script);
    first.vout.emplace_back(999, CScript() << OP_TRUE);
    const Bitcoin::CTransaction first_tx(first);

    Bitcoin::CMutableTransaction second;
    second.vin.emplace_back(Bitcoin::COutPoint(first_tx.GetHash(), 0));
    second.vout.emplace_back(3000, treasury_script);
    second.vout.emplace_back(999, CScript() << OP_TRUE);
    const Bitcoin::CTransaction second_tx(second);

    uint256 first_m6id;
    uint256 second_m6id;
    std::string error;
    BOOST_REQUIRE(ComputeDrivechainM6Id(first_tx, 5000, first_m6id, nullptr, &error));
    BOOST_REQUIRE(ComputeDrivechainM6Id(second_tx, 4000, second_m6id, nullptr, &error));

    DrivechainParentReplayState state;
    state.active_proposal_hash = required_proposal;
    state.required_proposal_activated = true;
    state.required_activation_height = 1;
    state.ctip = initial_ctip;
    state.ctip_value = 5000;
    state.pending_withdrawals = {
        {first_m6id, 99, threshold + 1},
        {second_m6id, 99, threshold + 1},
    };

    Bitcoin::CMutableTransaction coinbase;
    coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
    Bitcoin::CBlock block;
    block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(first));
    block.vtx.push_back(Bitcoin::MakeTransactionRef(second));

    BOOST_CHECK(!ApplyDrivechainParentBlockState(
        block, 100, slot, required_proposal,
        max_age, threshold, max_age, threshold, max_age, threshold,
        state, nullptr, &error));
    BOOST_CHECK(error.find("multiple successful M6 withdrawals") != std::string::npos);

    DrivechainParentReplayState one_state;
    one_state.active_proposal_hash = required_proposal;
    one_state.required_proposal_activated = true;
    one_state.required_activation_height = 1;
    one_state.ctip = initial_ctip;
    one_state.ctip_value = 5000;
    one_state.pending_withdrawals = {{first_m6id, 99, threshold + 1}};
    Bitcoin::CBlock one_block;
    one_block.vtx.push_back(block.vtx[0]);
    one_block.vtx.push_back(block.vtx[1]);
    BOOST_CHECK(ApplyDrivechainParentBlockState(
        one_block, 100, slot, required_proposal,
        max_age, threshold, max_age, threshold, max_age, threshold,
        one_state, nullptr, &error));
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
        /* withdrawal_max_age= */ 10, /* withdrawal_threshold= */ 5,
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

BOOST_AUTO_TEST_CASE(drivechain_bmm_m7_requires_exact_canonical_commitment)
{
    const uint256 sidechain_hash = uint256S("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");

    const auto make_m7 = [](const int slot, const uint256& hash) {
        std::vector<unsigned char> payload = ParseHex("d1617368");
        payload.push_back(static_cast<unsigned char>(slot));
        const std::vector<unsigned char> display_hash = ParseHex(hash.GetHex());
        payload.insert(payload.end(), display_hash.begin(), display_hash.end());
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

    // The pinned enforcer decodes critical_hash as ConsensusHex into an
    // opaque BmmCommitment, not a ReverseHex block hash. Preserve a fixed
    // cross-codec fixture independent of make_m7().
    const std::vector<unsigned char> enforcer_fixture_bytes = ParseHex(
        "6a25d1617368180123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
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
    const std::vector<unsigned char> display_hash = ParseHex(sidechain_hash.GetHex());
    payload.insert(payload.end(), display_hash.begin(), display_hash.end());
    CScript nonminimal;
    nonminimal.push_back(OP_RETURN);
    nonminimal.push_back(OP_PUSHDATA1);
    nonminimal.push_back(payload.size());
    nonminimal.insert(nonminimal.end(), payload.begin(), payload.end());
    // Exact commitment and single-push framing are required, but the pinned
    // enforcer intentionally permits non-minimal push opcodes.
    BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(make_block({nonminimal}),
                                                    24, sidechain_hash, nullptr, &err));
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), nonminimal}),
        24, sidechain_hash, nullptr, &err));

    for (const unsigned int length_bytes : {2U, 4U}) {
        CScript pushed;
        pushed.push_back(OP_RETURN);
        pushed.push_back(length_bytes == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
        for (unsigned int byte = 0; byte < length_bytes; ++byte) {
            pushed.push_back(byte == 0 ? payload.size() : 0);
        }
        pushed.insert(pushed.end(), payload.begin(), payload.end());
        BOOST_CHECK(MatchDrivechainBmmCommitmentInBlock(make_block({pushed}),
                                                        24, sidechain_hash, nullptr, &err));
        // Removing payload bytes must not turn an incomplete push into M7.
        pushed.pop_back();
        BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({pushed}),
                                                         24, sidechain_hash, nullptr, &err));
    }
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(
        make_block({make_m7(24, sidechain_hash), make_m7(24, wrong_hash)}),
        24, sidechain_hash, nullptr, &err));

    CScript internal_endian;
    internal_endian << OP_RETURN;
    std::vector<unsigned char> internal_payload = ParseHex("d1617368");
    internal_payload.push_back(24);
    internal_payload.insert(internal_payload.end(), sidechain_hash.begin(), sidechain_hash.end());
    internal_endian << internal_payload;
    BOOST_CHECK(!MatchDrivechainBmmCommitmentInBlock(make_block({internal_endian}),
                                                     24, sidechain_hash, nullptr, &err));
}

BOOST_AUTO_TEST_CASE(drivechain_parent_withdrawal_replay_requires_approved_m6)
{
    constexpr int slot{24};
    constexpr uint16_t max_age{10};
    constexpr uint16_t threshold{5};
    const uint256 required_proposal = uint256S(
        "3333333333333333333333333333333333333333333333333333333333333333");
    const Bitcoin::COutPoint initial_ctip(
        uint256S("4444444444444444444444444444444444444444444444444444444444444444"), 0);
    const CScript treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{slot} << OP_TRUE;

    const CAmount old_treasury_value{5000};
    const CAmount new_treasury_value{3900};
    const CAmount payout_value{1000};
    const CAmount mainchain_fee{
        old_treasury_value - new_treasury_value - payout_value};
    std::vector<unsigned char> fee_bytes;
    for (int byte = 7; byte >= 0; --byte) {
        fee_bytes.push_back(
            (static_cast<uint64_t>(mainchain_fee) >> (8 * byte)) & 0xff);
    }

    Bitcoin::CMutableTransaction blinded;
    blinded.nVersion = 2;
    blinded.vout.emplace_back(0, CScript() << OP_RETURN << fee_bytes);
    blinded.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x42));
    blinded.vout.emplace_back(payout_value, CScript() << OP_TRUE);
    const uint256 m6id = blinded.GetHash();

    Bitcoin::CMutableTransaction m6;
    m6.nVersion = 2;
    m6.vin.emplace_back(initial_ctip);
    m6.vout.emplace_back(new_treasury_value, treasury_script);
    m6.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x42));
    m6.vout.emplace_back(payout_value, CScript() << OP_TRUE);

    const auto make_m3 = [&](const uint8_t message_slot, const uint256& bundle_id) {
        std::vector<unsigned char> payload = ParseHex("d45aa943");
        payload.push_back(message_slot);
        payload.insert(payload.end(), bundle_id.begin(), bundle_id.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_m4 = [](const std::vector<unsigned char>& votes) {
        std::vector<unsigned char> payload = ParseHex("d77d177601");
        payload.insert(payload.end(), votes.begin(), votes.end());
        return CScript() << OP_RETURN << payload;
    };
    const auto make_block = [](const std::vector<CScript>& messages,
                               const uint32_t nonce,
                               const std::optional<Bitcoin::CMutableTransaction>& transaction = std::nullopt) {
        Bitcoin::CMutableTransaction coinbase;
        coinbase.vin.emplace_back(Bitcoin::COutPoint(), CScript() << OP_0);
        for (const CScript& message : messages) coinbase.vout.emplace_back(0, message);
        Bitcoin::CBlock block;
        block.nNonce = nonce;
        block.vtx.push_back(Bitcoin::MakeTransactionRef(std::move(coinbase)));
        if (transaction) {
            block.vtx.push_back(Bitcoin::MakeTransactionRef(*transaction));
        }
        return block;
    };
    const auto active_state = [&] {
        DrivechainParentReplayState state;
        state.active_proposal_hash = required_proposal;
        state.required_proposal_activated = true;
        state.required_activation_height = 1;
        state.ctip = initial_ctip;
        state.ctip_value = old_treasury_value;
        return state;
    };
    const auto apply = [&](const Bitcoin::CBlock& block, const uint32_t height,
                           DrivechainParentReplayState& state, std::string& error) {
        return ApplyDrivechainParentBlockState(
            block, height, slot, required_proposal,
            max_age, threshold, max_age, threshold,
            max_age, threshold,
            state, nullptr, &error);
    };

    std::string error;

    // A matching M3 is not enough. The finalized M6 remains invalid until its
    // score is strictly greater than the network's inclusion threshold.
    DrivechainParentReplayState unapproved = active_state();
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 10), 10, unapproved, error));
    BOOST_REQUIRE_EQUAL(unapproved.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(unapproved.pending_withdrawals.front().votes, 1U);
    BOOST_CHECK(!apply(make_block({}, 11, m6), 11, unapproved, error));

    // M4 indexes the sorted global active-slot list. Slot 5 precedes slot 24,
    // so each vector abstains for slot 5 and upvotes bundle index zero for 24.
    DrivechainParentReplayState approved = active_state();
    approved.other_slots[5].active_proposal_hash = uint256::ONE;
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 20), 20, approved, error));
    for (uint32_t height = 21; height <= 24; ++height) {
        BOOST_CHECK(apply(make_block({make_m4({0xff, 0x00})}, height),
                          height, approved, error));
    }
    BOOST_CHECK_EQUAL(approved.pending_withdrawals.front().votes, 5U);
    BOOST_CHECK(!apply(make_block({}, 25, m6), 25, approved, error));

    // The fifth later upvote raises the initial score of one to six. M4 is
    // processed before M6 in the same block, matching the enforcer.
    BOOST_CHECK(apply(
        make_block({make_m4({0xff, 0x00})}, 25, m6), 25, approved, error));
    BOOST_CHECK(approved.pending_withdrawals.empty());
    BOOST_REQUIRE(approved.ctip.has_value());
    BOOST_CHECK_EQUAL(approved.ctip->hash, Bitcoin::CTransaction(m6).GetHash());
    BOOST_CHECK_EQUAL(approved.ctip->n, 0U);
    BOOST_CHECK_EQUAL(approved.ctip_value, new_treasury_value);

    // A different fee produces a different blinded M6id and cannot consume
    // approval for the original bundle.
    DrivechainParentReplayState mismatched = active_state();
    mismatched.pending_withdrawals.push_back(
        DrivechainPendingWithdrawal{m6id, 30, threshold + 1});
    Bitcoin::CMutableTransaction wrong_fee = m6;
    wrong_fee.vout[0].nValue = new_treasury_value - 1;
    BOOST_CHECK(!apply(make_block({}, 30, wrong_fee), 30, mismatched, error));

    // A malformed global vote vector cannot be interpreted as a vote for the
    // configured slot.
    DrivechainParentReplayState malformed_votes = active_state();
    malformed_votes.other_slots[5].active_proposal_hash = uint256::ONE;
    BOOST_CHECK(apply(make_block({make_m3(slot, m6id)}, 40), 40,
                      malformed_votes, error));
    BOOST_CHECK(!apply(make_block({make_m4({0x00})}, 41), 41,
                       malformed_votes, error));

    // Executing an approved M6 for another active sidechain must advance that
    // slot's CTIP and remove its bundle. Otherwise subsequent global M4 indices
    // drift even though this slot's own state is unchanged.
    constexpr uint8_t auxiliary_slot{5};
    const Bitcoin::COutPoint auxiliary_initial_ctip(
        uint256S("5555555555555555555555555555555555555555555555555555555555555555"), 0);
    const CAmount auxiliary_old_value{6000};
    const CAmount auxiliary_new_value{4900};
    const CScript auxiliary_treasury_script = CScript()
        << OP_NOP5 << std::vector<unsigned char>{auxiliary_slot} << OP_TRUE;

    Bitcoin::CMutableTransaction auxiliary_blinded;
    auxiliary_blinded.nVersion = 2;
    auxiliary_blinded.vout.emplace_back(0, CScript() << OP_RETURN << fee_bytes);
    auxiliary_blinded.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x43));
    auxiliary_blinded.vout.emplace_back(payout_value, CScript() << OP_TRUE);
    const uint256 auxiliary_m6id = auxiliary_blinded.GetHash();

    Bitcoin::CMutableTransaction auxiliary_m6;
    auxiliary_m6.nVersion = 2;
    auxiliary_m6.vin.emplace_back(auxiliary_initial_ctip);
    auxiliary_m6.vout.emplace_back(auxiliary_new_value, auxiliary_treasury_script);
    auxiliary_m6.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(32, 0x43));
    auxiliary_m6.vout.emplace_back(payout_value, CScript() << OP_TRUE);

    DrivechainParentReplayState cross_slot = active_state();
    auto& auxiliary_state = cross_slot.other_slots[auxiliary_slot];
    auxiliary_state.active_proposal_hash = uint256::ONE;
    auxiliary_state.ctip = auxiliary_initial_ctip;
    auxiliary_state.ctip_value = auxiliary_old_value;
    BOOST_CHECK(apply(
        make_block({make_m3(auxiliary_slot, auxiliary_m6id),
                    make_m3(slot, m6id)}, 50),
        50, cross_slot, error));
    for (uint32_t height = 51; height <= 54; ++height) {
        BOOST_CHECK(apply(make_block({make_m4({0x00, 0xff})}, height),
                          height, cross_slot, error));
    }
    BOOST_CHECK(apply(
        make_block({make_m4({0x00, 0xff})}, 55, auxiliary_m6),
        55, cross_slot, error));
    BOOST_CHECK(auxiliary_state.pending_withdrawals.empty());
    BOOST_REQUIRE(auxiliary_state.ctip.has_value());
    BOOST_CHECK_EQUAL(
        auxiliary_state.ctip->hash, Bitcoin::CTransaction(auxiliary_m6).GetHash());
    BOOST_CHECK_EQUAL(auxiliary_state.ctip->n, 0U);
    BOOST_CHECK_EQUAL(auxiliary_state.ctip_value, auxiliary_new_value);
    BOOST_REQUIRE_EQUAL(cross_slot.pending_withdrawals.size(), 1U);
    BOOST_CHECK_EQUAL(cross_slot.pending_withdrawals.front().votes, 1U);

    // Slot 5 remains in the vector because it is still active, but slot 24's
    // bundle is still index zero and receives the intended vote.
    BOOST_CHECK(apply(make_block({make_m4({0xff, 0x00})}, 56),
                      56, cross_slot, error));
    BOOST_CHECK_EQUAL(cross_slot.pending_withdrawals.front().votes, 2U);
}

BOOST_AUTO_TEST_SUITE_END()
