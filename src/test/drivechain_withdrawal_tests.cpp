// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_withdrawal.h>

#include <asset.h>
#include <coins.h>
#include <consensus/amount.h>
#include <primitives/txwitness.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>
#include <string>
#include <vector>

namespace Bitcoin = Sidechain::Bitcoin;

namespace {

struct NativeWithdrawalSetup : public BasicTestingSetup
{
    NativeWithdrawalSetup() : BasicTestingSetup(ChainType::CUSTOM) {}
};

const CAsset PEGGED_ASSET{uint256S(
    "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff")};
const CAsset OTHER_ASSET{uint256S(
    "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211")};
const uint256 PARENT_GENESIS{uint256S(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")};
const uint256 ELEMENTS_GENESIS{uint256S(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")};
const uint256 BURN_TXID{uint256S(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")};
const CScript DESTINATION = CScript() << OP_0 << ParseHex(
    "606162636465666768696a6b6c6d6e6f70717273");

drivechain::NativeWithdrawal BuildAndParseWithdrawal(const CAmount burn_amount = 100000,
                                                      const CAmount parent_fee = 1000)
{
    CTxOut output;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalOutput(
            PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
            burn_amount, parent_fee, output, &error),
        error);
    drivechain::NativeWithdrawal withdrawal;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalOutput(
            output, nullptr, PEGGED_ASSET, PARENT_GENESIS,
            withdrawal, &error),
        error);
    return withdrawal;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_withdrawal_tests, NativeWithdrawalSetup)

BOOST_AUTO_TEST_CASE(native_burn_output_round_trip)
{
    CTxOut output;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalOutput(
            PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
            100000, 1000, output, &error),
        error);

    BOOST_REQUIRE(output.nAsset.IsExplicit());
    BOOST_CHECK(output.nAsset.GetAsset() == PEGGED_ASSET);
    BOOST_REQUIRE(output.nValue.IsExplicit());
    BOOST_CHECK_EQUAL(output.nValue.GetAmount(), 100000);
    BOOST_CHECK(output.nNonce.IsNull());
    BOOST_CHECK(output.scriptPubKey.IsUnspendable());
    BOOST_CHECK_EQUAL(
        HexStr(output.scriptPubKey),
        "6a201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
        "00160014606162636465666768696a6b6c6d6e6f707172730800000000000003e8");

    // ConnectBlock reaches this same AddCoin primitive. Unspendable outputs
    // are deliberately never inserted into the UTXO set, so the pegged asset
    // cannot be recovered or spent after this transaction confirms.
    CCoinsView base;
    CCoinsViewCache coins(&base);
    const COutPoint burn_outpoint(Txid::FromUint256(BURN_TXID), 7);
    coins.AddCoin(burn_outpoint, Coin(output, 1, false), false);
    BOOST_CHECK(!coins.HaveCoinInCache(burn_outpoint));
    BOOST_CHECK(!coins.HaveCoin(burn_outpoint));

    CTxOutWitness empty_witness;
    drivechain::NativeWithdrawal parsed;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalOutput(
            output, &empty_witness, PEGGED_ASSET, PARENT_GENESIS,
            parsed, &error),
        error);
    BOOST_CHECK(parsed.parent_genesis == PARENT_GENESIS);
    BOOST_CHECK(parsed.destination == DESTINATION);
    BOOST_CHECK_EQUAL(parsed.burn_amount, 100000);
    BOOST_CHECK_EQUAL(parsed.parent_fee, 1000);
    BOOST_CHECK_EQUAL(parsed.payout_amount, 99000);
}

BOOST_AUTO_TEST_CASE(native_burn_output_rejects_noncanonical_forms)
{
    CTxOut canonical;
    std::string error;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        100000, 1000, canonical, &error));

    const auto rejected = [&](const CTxOut& output,
                              const CTxOutWitness* witness = nullptr) {
        drivechain::NativeWithdrawal parsed;
        return !drivechain::ParseNativeWithdrawalOutput(
            output, witness, PEGGED_ASSET, PARENT_GENESIS, parsed, &error);
    };

    CTxOut mutated = canonical;
    mutated.nAsset.SetToAsset(OTHER_ASSET);
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nAsset.vchCommitment.assign(33, 0);
    mutated.nAsset.vchCommitment[0] = 10;
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nValue.vchCommitment.assign(33, 0);
    mutated.nValue.vchCommitment[0] = 8;
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nNonce.vchCommitment.assign(33, 0);
    mutated.nNonce.vchCommitment[0] = 2;
    BOOST_CHECK(rejected(mutated));

    CTxOutWitness nonempty_witness;
    nonempty_witness.vchRangeproof = {1};
    BOOST_CHECK(rejected(canonical, &nonempty_witness));
    nonempty_witness.SetNull();
    nonempty_witness.vchSurjectionproof = {1};
    BOOST_CHECK(rejected(canonical, &nonempty_witness));

    mutated = canonical;
    mutated.nValue.SetToAmount(1000);
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.scriptPubKey << OP_0;
    BOOST_CHECK(rejected(mutated));

    // Re-encode the 32-byte genesis with OP_PUSHDATA1. It is semantically the
    // same push but not the one canonical byte serialization.
    std::vector<unsigned char> nonminimal{OP_RETURN, OP_PUSHDATA1, 32};
    nonminimal.insert(nonminimal.end(), PARENT_GENESIS.begin(), PARENT_GENESIS.end());
    const std::vector<unsigned char> destination(DESTINATION.begin(), DESTINATION.end());
    nonminimal.push_back(destination.size());
    nonminimal.insert(nonminimal.end(), destination.begin(), destination.end());
    nonminimal.push_back(8);
    const std::vector<unsigned char> fee = ParseHex("00000000000003e8");
    nonminimal.insert(nonminimal.end(), fee.begin(), fee.end());
    mutated = canonical;
    mutated.scriptPubKey = CScript(nonminimal.begin(), nonminimal.end());
    BOOST_CHECK(rejected(mutated));

    CScript script;
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalScript(
        PARENT_GENESIS, CScript(), 1, script, &error));
    CScript oversized_destination;
    oversized_destination.insert(oversized_destination.end(), 129, OP_TRUE);
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalScript(
        PARENT_GENESIS, oversized_destination, 1, script, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        0, 0, mutated, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        1000, 1000, mutated, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        999, 1000, mutated, &error));
}

BOOST_AUTO_TEST_CASE(native_blinded_m6_is_unique_and_legacy_serialized)
{
    const auto withdrawal = BuildAndParseWithdrawal();
    drivechain::NativeWithdrawalM6 m6;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            ELEMENTS_GENESIS, 24, BURN_TXID, 7,
            withdrawal, m6, &error),
        error);

    BOOST_CHECK_EQUAL(m6.blinded_transaction.version, 2);
    BOOST_CHECK(m6.blinded_transaction.vin.empty());
    BOOST_REQUIRE_EQUAL(m6.blinded_transaction.vout.size(), 3U);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[0].nValue, 0);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[1].nValue, 0);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[2].nValue, 99000);
    BOOST_CHECK(m6.blinded_transaction.vout[2].scriptPubKey == DESTINATION);
    BOOST_CHECK_LE(m6.blinded_transaction.vout[1].scriptPubKey.size(), 83U);
    BOOST_CHECK_EQUAL(HexStr(m6.burn_commitment),
                      "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
                      "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007");
    BOOST_CHECK_EQUAL(
        HexStr(m6.legacy_serialization),
        "02000000000300000000000000000a6a0800000000000003e8"
        "00000000000000004c6a4a"
        "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
        "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007"
        "b882010000000000160014606162636465666768696a6b6c6d6e6f7071727300000000");
    BOOST_CHECK_EQUAL(
        m6.m6id.GetHex(),
        "a7e1da09da7c62eda3f3bcb3902d6a79bb1d4a348858346c4152c10b714d3572");
    BOOST_CHECK(m6.m6id == drivechain::ComputeNativeWithdrawalM6Id(
                              m6.blinded_transaction));
    BOOST_CHECK(m6.m6id == m6.blinded_transaction.GetHash());

    uint256 parsed_elements_genesis;
    uint8_t parsed_slot{0};
    uint256 parsed_burn_txid;
    uint32_t parsed_burn_vout{0};
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalM6Commitment(
            m6.blinded_transaction.vout[1].scriptPubKey,
            parsed_elements_genesis, parsed_slot, parsed_burn_txid,
            parsed_burn_vout, &error),
        error);
    BOOST_CHECK(parsed_elements_genesis == ELEMENTS_GENESIS);
    BOOST_CHECK_EQUAL(parsed_slot, 24U);
    BOOST_CHECK(parsed_burn_txid == BURN_TXID);
    BOOST_CHECK_EQUAL(parsed_burn_vout, 7U);

    Bitcoin::CMutableTransaction decoded;
    BOOST_REQUIRE_MESSAGE(
        drivechain::DeserializeNativeWithdrawalM6Legacy(
            m6.legacy_serialization, decoded, &error),
        error);
    BOOST_CHECK_EQUAL(HexStr(drivechain::SerializeNativeWithdrawalM6Legacy(decoded)),
                      HexStr(m6.legacy_serialization));

    drivechain::NativeWithdrawalM6 parsed;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalM6(
            decoded, ELEMENTS_GENESIS, 24, BURN_TXID, 7,
            parsed, &error),
        error);
    BOOST_CHECK_EQUAL(parsed.burn_amount, withdrawal.burn_amount);
    BOOST_CHECK_EQUAL(parsed.parent_fee, withdrawal.parent_fee);
    BOOST_CHECK_EQUAL(parsed.payout_amount, withdrawal.payout_amount);
    BOOST_CHECK(parsed.destination == withdrawal.destination);
    BOOST_CHECK(parsed.m6id == m6.m6id);
}

BOOST_AUTO_TEST_CASE(native_blinded_m6_rejects_mutation_and_replay_aliases)
{
    const auto withdrawal = BuildAndParseWithdrawal();
    drivechain::NativeWithdrawalM6 canonical;
    std::string error;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID, 7,
        withdrawal, canonical, &error));

    const auto parse_rejected = [&](const Bitcoin::CMutableTransaction& tx,
                                    const uint256& burn_txid = BURN_TXID,
                                    const uint32_t burn_vout = 7) {
        drivechain::NativeWithdrawalM6 parsed;
        return !drivechain::ParseNativeWithdrawalM6(
            tx, ELEMENTS_GENESIS, 24, burn_txid, burn_vout,
            parsed, &error);
    };

    Bitcoin::CMutableTransaction mutated = canonical.blinded_transaction;
    mutated.version = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.nLockTime = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[0].nValue = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[0].scriptPubKey << OP_0;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey[2] ^= 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey[6] = 2;
    BOOST_CHECK(parse_rejected(mutated));

    std::vector<unsigned char> nonminimal_reference{
        OP_RETURN, OP_PUSHDATA1,
        static_cast<unsigned char>(
            drivechain::NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE)};
    nonminimal_reference.insert(nonminimal_reference.end(),
                                canonical.burn_commitment.begin(),
                                canonical.burn_commitment.end());
    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey = CScript(nonminimal_reference.begin(),
                                           nonminimal_reference.end());
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[2].nValue++;
    drivechain::NativeWithdrawalM6 amount_mutation;
    BOOST_REQUIRE(drivechain::ParseNativeWithdrawalM6(
        mutated, ELEMENTS_GENESIS, 24, BURN_TXID, 7,
        amount_mutation, &error));
    BOOST_CHECK(amount_mutation.m6id != canonical.m6id);

    BOOST_CHECK(parse_rejected(canonical.blinded_transaction,
                               uint256S("01"), 7));
    BOOST_CHECK(parse_rejected(canonical.blinded_transaction,
                               BURN_TXID, 8));

    drivechain::NativeWithdrawalM6 distinct;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID, 8,
        withdrawal, distinct, &error));
    BOOST_CHECK(distinct.burn_commitment != canonical.burn_commitment);
    BOOST_CHECK(distinct.m6id != canonical.m6id);

    BOOST_CHECK(!drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, uint256(), 7,
        withdrawal, distinct, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID,
        std::numeric_limits<uint32_t>::max(),
        withdrawal, distinct, &error));

    std::vector<unsigned char> with_trailing = canonical.legacy_serialization;
    with_trailing.push_back(0);
    Bitcoin::CMutableTransaction decoded;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        with_trailing, decoded, &error));

    std::vector<unsigned char> oversized(
        drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE + 1, 0);
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        oversized, decoded, &error));

    // A huge attacker-controlled CompactSize count must be rejected by the
    // fixed-frame preflight before the generic deserializer can allocate.
    std::vector<unsigned char> huge_vout_count = canonical.legacy_serialization;
    huge_vout_count[5] = 0xff;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        huge_vout_count, decoded, &error));

    std::vector<unsigned char> huge_script = canonical.legacy_serialization;
    huge_script[14] = 0xfd;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        huge_script, decoded, &error));
}

BOOST_AUTO_TEST_SUITE_END()
