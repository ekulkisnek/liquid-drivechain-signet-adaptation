// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_peg.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <key_io.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <pegins.h>
#include <primitives/bitcoin/block.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <map>

namespace {

const std::string MAINCHAIN_TIP{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const std::string DEPOSIT_BLOCK{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
const std::string DEPOSIT_TXID{"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
const std::string NEXT_CTIP_TXID{"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"};
const std::string SIGNET_CHALLENGE{"00148835832e28c816b7acd8fdb19772ab2199603a56"};
const std::string HASH_ID_1{"5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b"};
const std::string HASH_ID_2{"b2b7b20f3fbc4baf50e9d39f58661c6168e279d4"};

UniValue ParseJson(const std::string& json)
{
    UniValue result;
    if (!result.read(json)) throw std::runtime_error("invalid test JSON: " + json);
    return result;
}

std::string TestDepositAddress()
{
    return EncodeDestination(WitnessV0KeyHash(uint160(ParseHex("00112233445566778899aabbccddeeff00112233"))));
}

UniValue MainchainInfo(
    const std::string& chain = "signet",
    const std::string& challenge = SIGNET_CHALLENGE,
    bool ibd = false)
{
    return ParseJson(strprintf(
        R"json({"chain":"%s","blocks":100,"bestblockhash":"%s","initialblockdownload":%s,"signet_challenge":"%s"})json",
        chain,
        MAINCHAIN_TIP,
        ibd ? "true" : "false",
        challenge));
}

UniValue EnforcerChainInfo(const std::string& network = "NETWORK_SIGNET")
{
    return ParseJson(strprintf(R"json({"network":"%s"})json", network));
}

UniValue EnforcerTip(const std::string& hash = MAINCHAIN_TIP, int64_t height = 100)
{
    return ParseJson(strprintf(
        R"json({"blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":"%d"}})json",
        hash,
        height));
}

UniValue Sidechains(
    int slot = 24,
    const std::string& title = "Elements",
    const std::string& hash_id_1 = HASH_ID_1,
    const std::string& hash_id_2 = HASH_ID_2)
{
    return ParseJson(strprintf(
        R"json({"sidechains":[{"sidechainNumber":%d,"activationHeight":50,"declaration":{"v0":{"title":"%s","hashId1":{"hex":"%s"},"hashId2":{"hex":"%s"}}}}]})json",
        slot,
        title,
        hash_id_1,
        hash_id_2));
}

UniValue TwoWayPegData(
    const std::string& txid = DEPOSIT_TXID,
    int64_t vout = 0,
    const std::string& address = TestDepositAddress(),
    int64_t value = 2000,
    int64_t sequence = 8,
    bool include_event = true)
{
    const std::string address_hex = HexStr(address);
    const std::string events = include_event
        ? strprintf(
            R"json([{"deposit":{"sequenceNumber":"%d","outpoint":{"txid":{"hex":"%s"},"vout":%d},"output":{"address":{"hex":"%s"},"valueSats":"%d"}}}])json",
            sequence,
            txid,
            vout,
            address_hex,
            value)
        : "[]";
    return ParseJson(strprintf(
        R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"%s"},"height":90},"blockInfo":{"events":%s}}]})json",
        DEPOSIT_BLOCK,
        events));
}

UniValue Ctip(
    const std::string& txid = DEPOSIT_TXID,
    int64_t value = 14'402'000,
    int64_t sequence = 8,
    int64_t vout = 0)
{
    return ParseJson(strprintf(
        R"json({"ctip":{"txid":{"hex":"%s"},"vout":%d,"value":"%d","sequenceNumber":"%d"}})json",
        txid,
        vout,
        value,
        sequence));
}

drivechain::DepositIdentity Identity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = 24;
    identity.sidechain_network = Params().NetworkIDString();
    identity.mainchain_network = "signet";
    identity.mainchain_signet_challenge = SIGNET_CHALLENGE;
    identity.enforcer_network = "NETWORK_SIGNET";
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = "Elements";
    identity.hash_id_1 = HASH_ID_1;
    identity.hash_id_2 = HASH_ID_2;
    return identity;
}

bool Authenticate(
    drivechain::AuthenticatedDeposit& authenticated,
    std::string& error,
    const UniValue& mainchain_info = MainchainInfo(),
    const UniValue& enforcer_chain_info = EnforcerChainInfo(),
    const UniValue& enforcer_tip = EnforcerTip(),
    const UniValue& sidechains = Sidechains(),
    const UniValue& two_way_peg_data = TwoWayPegData(),
    const UniValue& ctip = Ctip(),
    const std::string& sidechain_network = Params().NetworkIDString(),
    const drivechain::DepositIdentity& identity = Identity(),
    const COutPoint& outpoint = COutPoint(uint256S(DEPOSIT_TXID), 0),
    CAmount value = 2000)
{
    return drivechain::AuthenticateDepositEvidence(
        mainchain_info,
        Params().ParentGenesisBlockHash(),
        enforcer_chain_info,
        enforcer_tip,
        sidechains,
        two_way_peg_data,
        ctip,
        sidechain_network,
        identity,
        outpoint,
        value,
        authenticated,
        error);
}

CMutableTransaction DepositTransaction(
    const drivechain::AuthenticatedDeposit& authenticated,
    const CScript& destination_script,
    CAmount credit = 1900,
    CAmount fee = 100)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn input(authenticated.outpoint, CScript(), CTxIn::SEQUENCE_FINAL);
    input.m_is_pegin = true;
    tx.vin.push_back(input);
    tx.vout.emplace_back(Params().GetConsensus().pegged_asset, credit, destination_script);
    if (fee > 0) {
        tx.vout.emplace_back(Params().GetConsensus().pegged_asset, fee, CScript());
    }
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxoutwit.resize(tx.vout.size());
    tx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        authenticated.value,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        authenticated.outpoint.hash);
    return tx;
}

template <typename T>
std::vector<unsigned char> Serialize(const T& value)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << value;
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

CScript CtipScript()
{
    return CScript() << OP_NOP5 << std::vector<unsigned char>{24} << OP_1;
}

class DrivechainPegTestingSetup : public BasicTestingSetup
{
public:
    DrivechainPegTestingSetup()
        : BasicTestingSetup(
              "liquid-signet",
              "",
              {
                  "-con_elementsmode=1",
                  "-con_has_parent_chain=1",
                  "-parentgenesisblockhash=00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
                  "-parentpubkeyprefix=111",
                  "-parentscriptprefix=196",
                  "-parent_bech32_hrp=tb",
                  "-parent_blech32_hrp=tb",
                  "-bech32_hrp=ert",
                  "-blech32_hrp=el",
              })
    {
    }
};

CTransaction LegacyPublicDeposit()
{
    CMutableTransaction tx;
    CDataStream stream(
        ParseHex("020000000101ea6bf0d0cd29414c524e1bfb175299dcb945f438200d596bbe4ba547b7aee47d0000004000ffffffff0201579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b71101000000000000076c001600142ab51216604aace97fd71de08cbb29078f42b8b101579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b7110100000000000000640000000000000000000608d00700000000000020579008c2884b22c31d545e3887d73efd5a412d16aeb9bd8ccbeba8eaa605b71120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881080000000151156472697665636861696e2d6465706f7369742d763120ea6bf0d0cd29414c524e1bfb175299dcb945f438200d596bbe4ba547b7aee47d00000000"),
        SER_NETWORK,
        PROTOCOL_VERSION);
    stream >> tx;
    BOOST_REQUIRE(stream.empty());
    return CTransaction(tx);
}

struct DeterministicFixture
{
    DrivechainDepositEvidence evidence;
    CTransactionRef transaction;
    uint256 anchor;

    DeterministicFixture()
    {
        const std::vector<unsigned char> previous_raw = ParseHex(
            "02000000000102ba1b6b0b25cbed783a2bb5bcfcb18d54115388b1a53454417ea20ce06c2de8dd0100000000fdffffffabede444d25da6440680778541b4f5876388e10cd9da94f55a546eeab5700a010000000000ffffffff03d0c1db000000000004b401185100000000000000002d6a2b65727431713932363379396e7166326b776a6c3768726873676577656671373835397739337a356e3878388f1c00000000000016001420ee25f486b457599d671fec23be2a2ffbb8efc20247304402203cdbeac736b8c0b97fe7f9ad9b1d76fc7b60d2a7ef907942c52fd7481c509c5702201f27991af112244d8e159546587f0d2dd98f49e5a8eaed5919932a2d5f8f6dfa012103ddd93dd5a45116fb7febe151d9b4d9f7cdccc84ffb94dbe7d5665aa2bafed1dd00fe180000");
        Sidechain::Bitcoin::CMutableTransaction previous_tx;
        {
            CDataStream stream(previous_raw, SER_NETWORK, PROTOCOL_VERSION);
            stream >> previous_tx;
            BOOST_REQUIRE(stream.empty());
            BOOST_REQUIRE_EQUAL(
                previous_tx.GetHash().GetHex(),
                "7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea");
        }

        Sidechain::Bitcoin::CMutableTransaction deposit_tx;
        deposit_tx.nVersion = 2;
        deposit_tx.vin.emplace_back(
            Sidechain::Bitcoin::COutPoint(previous_tx.GetHash(), 0));
        deposit_tx.vout.emplace_back(14'404'000, CtipScript());
        const std::string address = TestDepositAddress();
        deposit_tx.vout.emplace_back(
            0,
            CScript() << OP_RETURN << std::vector<unsigned char>(address.begin(), address.end()));

        Sidechain::Bitcoin::CBlock l1_block;
        l1_block.nVersion = 1;
        l1_block.hashPrevBlock = uint256S("01");
        l1_block.hashMerkleRoot = deposit_tx.GetHash();
        l1_block.nTime = 1;
        l1_block.nBits = UintToArith256(Params().GetConsensus().parentChainPowLimit).GetCompact();
        while (!CheckParentProofOfWork(
            l1_block.GetHash(),
            l1_block.nBits,
            Params().GetConsensus())) {
            ++l1_block.nNonce;
        }
        l1_block.vtx = {Sidechain::Bitcoin::MakeTransactionRef(deposit_tx)};

        Sidechain::Bitcoin::CMerkleBlock proof;
        proof.header = l1_block.GetBlockHeader();
        proof.txn = Sidechain::Bitcoin::CPartialMerkleTree(
            {deposit_tx.GetHash()},
            {true});
        evidence.deposit_tx = Serialize(deposit_tx);
        evidence.txout_proof = Serialize(proof);
        evidence.previous_ctip_tx = previous_raw;
        evidence.sequence_number = 9;
        evidence.previous_sequence_number = 8;
        evidence.headers = {l1_block.GetBlockHeader()};
        anchor = l1_block.GetHash();

        drivechain::AuthenticatedDeposit authenticated;
        authenticated.outpoint = COutPoint(deposit_tx.GetHash(), 0);
        authenticated.value = 2'000;
        authenticated.destination_script = GetScriptForDestination(
            DecodeDestination(address));
        CMutableTransaction side_tx = DepositTransaction(
            authenticated,
            authenticated.destination_script);
        side_tx.witness.vtxinwit[0].m_pegin_witness =
            CreateDrivechainDepositPeginWitness(
                authenticated.value,
                Params().GetConsensus().pegged_asset,
                Params().ParentGenesisBlockHash(),
                CScript() << OP_TRUE,
                evidence);
        transaction = MakeTransactionRef(side_tx);
    }
};

class RestartablePeginView final : public CCoinsView
{
public:
    std::set<std::pair<uint256, COutPoint>> spent;
    std::map<COutPoint, Coin> coins;

    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override
    {
        const auto it = coins.find(outpoint);
        if (it == coins.end() || it->second.IsSpent()) return false;
        coin = it->second;
        return true;
    }

    bool IsPeginSpent(const std::pair<uint256, COutPoint>& outpoint) const override
    {
        return spent.count(outpoint) != 0;
    }

    bool BatchWrite(CCoinsMap& map_coins, const uint256&) override
    {
        for (auto it = map_coins.begin(); it != map_coins.end();) {
            if ((it->second.flags & CCoinsCacheEntry::PEGIN) &&
                (it->second.flags & CCoinsCacheEntry::DIRTY)) {
                if (it->second.peginSpent) {
                    spent.insert(it->first);
                } else {
                    spent.erase(it->first);
                }
            } else if (it->second.flags & CCoinsCacheEntry::DIRTY) {
                if (it->second.coin.IsSpent()) {
                    coins.erase(it->first.second);
                } else {
                    coins[it->first.second] = it->second.coin;
                }
            }
            it = map_coins.erase(it);
        }
        return true;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_peg_tests, DrivechainPegTestingSetup)

BOOST_AUTO_TEST_CASE(normalizes_l1_lifecycle_and_deduplicates)
{
    UniValue response;
    BOOST_REQUIRE(response.read(R"json({
      "blocks": [
        {
          "blockHeaderInfo": {"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":10,"timestamp":"20"},
          "blockInfo": {"events":[
            {"deposit":{"sequenceNumber":"2","outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"abcd"},"valueSats":"1000"}}},
            {"deposit":{"sequenceNumber":"2","outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"abcd"},"valueSats":"1000"}}},
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"submitted":{}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"height":"11","timestamp":"21"},
          "blockInfo": {"events":[
            {"withdrawalBundle":{"m6id":{"hex":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"event":{"succeeded":{"sequenceNumber":"3","transaction":{"hex":"00"}}}}}
          ]}
        },
        {
          "blockHeaderInfo": {"blockHash":{"hex":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"height":12},
          "blockInfo": {}
        }
      ]
    })json"));

    const UniValue events = drivechain::NormalizeL1PegEvents(response, 24);
    BOOST_REQUIRE(events.isArray());
    BOOST_CHECK_EQUAL(events.size(), 3U);
    BOOST_CHECK_EQUAL(events[0]["kind"].get_str(), "deposit");
    BOOST_CHECK_EQUAL(events[0]["value_sats"].get_int64(), 1000);
    BOOST_CHECK_EQUAL(events[1]["status"].get_str(), "submitted");
    BOOST_CHECK_EQUAL(events[1]["acknowledgement"].get_str(), "pending");
    BOOST_CHECK_EQUAL(events[2]["status"].get_str(), "succeeded");
    BOOST_CHECK_EQUAL(events[2]["acknowledgement"].get_str(), "accepted");
}

BOOST_AUTO_TEST_CASE(rejects_malformed_l1_contract)
{
    UniValue missing_blocks;
    BOOST_REQUIRE(missing_blocks.read("{}"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(missing_blocks, 24), std::runtime_error);

    UniValue ambiguous_status;
    BOOST_REQUIRE(ambiguous_status.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"withdrawalBundle":{"m6id":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"event":{"submitted":{},"failed":{}}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(ambiguous_status, 24), std::runtime_error);

    UniValue bad_txid;
    BOOST_REQUIRE(bad_txid.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"nope"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":1}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(bad_txid, 24), std::runtime_error);

    UniValue conflicting_duplicate;
    BOOST_REQUIRE(conflicting_duplicate.read(R"json({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"height":1},"blockInfo":{"events":[{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":1}}},{"deposit":{"sequenceNumber":0,"outpoint":{"txid":{"hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"vout":0},"output":{"address":{"hex":"00"},"valueSats":2}}}]}}]})json"));
    BOOST_CHECK_THROW(drivechain::NormalizeL1PegEvents(conflicting_duplicate, 24), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(extracts_consensus_anchored_sidechain_events)
{
    const uint256 mainchain_txid = uint256S("01");
    CMutableTransaction deposit;
    deposit.nVersion = 2;
    CTxIn deposit_input(COutPoint(mainchain_txid, 0));
    deposit_input.m_is_pegin = true;
    deposit.vin.push_back(deposit_input);
    deposit.vout.emplace_back(Params().GetConsensus().pegged_asset, 99'000, CScript() << OP_TRUE);
    deposit.vout.emplace_back(Params().GetConsensus().pegged_asset, 1'000, CScript());
    deposit.witness.vtxinwit.resize(1);
    deposit.witness.vtxoutwit.resize(2);
    deposit.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        100'000,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        mainchain_txid);

    CMutableTransaction withdrawal;
    withdrawal.nVersion = 2;
    const CScript destination = CScript() << OP_TRUE;
    const CScript pegout = CScript()
        << OP_RETURN
        << std::vector<unsigned char>(Params().ParentGenesisBlockHash().begin(), Params().ParentGenesisBlockHash().end())
        << std::vector<unsigned char>(destination.begin(), destination.end());
    withdrawal.vout.emplace_back(Params().GetConsensus().pegged_asset, 25'000, pegout);

    CBlock block;
    block.nVersion = 1;
    block.vtx = {MakeTransactionRef(deposit), MakeTransactionRef(withdrawal)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.hashWithdrawalBundle = uint256S("02");

    const UniValue events = drivechain::ExtractSidechainPegEvents(block, 7, uint256::ZERO);
    BOOST_REQUIRE_EQUAL(events.size(), 3U);
    BOOST_CHECK_EQUAL(events[0]["kind"].get_str(), "bundle_commitment");
    BOOST_CHECK_EQUAL(events[1]["kind"].get_str(), "deposit");
    BOOST_CHECK_EQUAL(events[1]["value_sats"].get_int64(), 100'000);
    BOOST_CHECK_EQUAL(events[2]["kind"].get_str(), "withdrawal");
    BOOST_CHECK_EQUAL(events[2]["value_sats"].get_int64(), 25'000);

    const UniValue repeated_bundle = drivechain::ExtractSidechainPegEvents(block, 7, block.hashWithdrawalBundle);
    BOOST_REQUIRE_EQUAL(repeated_bundle.size(), 2U);
    BOOST_CHECK_EQUAL(repeated_bundle[0]["event_id"].get_str(), events[1]["event_id"].get_str());

    CBlock replacement = block;
    replacement.vtx = {MakeTransactionRef(withdrawal)};
    replacement.hashMerkleRoot = BlockMerkleRoot(replacement);
    replacement.hashWithdrawalBundle.SetNull();
    const UniValue replacement_events = drivechain::ExtractSidechainPegEvents(replacement, 7, uint256::ZERO);
    BOOST_REQUIRE_EQUAL(replacement_events.size(), 1U);
    BOOST_CHECK_EQUAL(replacement_events[0]["kind"].get_str(), "withdrawal");
    BOOST_CHECK(replacement_events[0]["event_id"].get_str() != events[1]["event_id"].get_str());
}

BOOST_AUTO_TEST_CASE(restores_active_bundle_after_restart)
{
    const uint256 bundle_hash = uint256S("03");
    node::RestoreCurrentDrivechainWithdrawalBundleHash(bundle_hash);
    BOOST_CHECK(node::GetCurrentDrivechainWithdrawalBundleHash() == bundle_hash);
    node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(authenticates_exact_deposit_and_transaction)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    BOOST_CHECK(authenticated.outpoint == COutPoint(uint256S(DEPOSIT_TXID), 0));
    BOOST_CHECK_EQUAL(authenticated.value, 2000);
    BOOST_CHECK_EQUAL(authenticated.sequence_number, 8);
    BOOST_CHECK_EQUAL(authenticated.address, TestDepositAddress());
    BOOST_CHECK(authenticated.current_ctip == authenticated.outpoint);

    const UniValue header = ParseJson(strprintf(
        R"json({"hash":"%s","height":90,"confirmations":11})json",
        DEPOSIT_BLOCK));
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositBlockConfirmation(header, authenticated, error), error);
    BOOST_CHECK_MESSAGE(
        drivechain::VerifyCurrentCtipOutput(
            ParseJson(R"json({"value":0.14402000,"confirmations":2})json"),
            authenticated,
            error),
        error);

    const CTransaction tx(DepositTransaction(authenticated, authenticated.destination_script));
    BOOST_CHECK_MESSAGE(drivechain::VerifyDepositTransaction(tx, 0, authenticated, error), error);
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_txid_vout_address_and_value)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(uint256S("01"), 0),
        2000));
    BOOST_CHECK(error.find("absent") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(uint256S(DEPOSIT_TXID), 1),
        2000));
    BOOST_CHECK(error.find("absent") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        Params().NetworkIDString(),
        Identity(),
        COutPoint(uint256S(DEPOSIT_TXID), 0),
        1999));
    BOOST_CHECK(error.find("value") != std::string::npos);

    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    const CTransaction wrong_destination(
        DepositTransaction(authenticated, CScript() << OP_TRUE));
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(wrong_destination, 0, authenticated, error));
    BOOST_CHECK(error.find("destination script") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_stale_or_contradictory_ctip)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(DEPOSIT_TXID, 14'400'000, 7)));
    BOOST_CHECK(error.find("predates") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(NEXT_CTIP_TXID, 14'402'000, 8)));
    BOOST_CHECK(error.find("does not match") != std::string::npos);

    BOOST_CHECK(Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(NEXT_CTIP_TXID, 14'401'000, 9)));
    BOOST_CHECK_EQUAL(authenticated.current_ctip_sequence, 9);
}

BOOST_AUTO_TEST_CASE(rejects_alternate_slot_identity_and_networks)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(23),
        TwoWayPegData(),
        Ctip()));
    BOOST_CHECK(error.find("slot") != std::string::npos);

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(24, "Not Elements"),
        TwoWayPegData(),
        Ctip()));
    BOOST_CHECK(error.find("identity") != std::string::npos);

    BOOST_CHECK(!Authenticate(authenticated, error, MainchainInfo("regtest")));
    BOOST_CHECK(error.find("mainchain network") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo("signet", "51")));
    BOOST_CHECK(error.find("challenge") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo("NETWORK_REGTEST")));
    BOOST_CHECK(error.find("enforcer network") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        Ctip(),
        "alternate-sidechain"));
    BOOST_CHECK(error.find("sidechain network") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_missing_enforcer_data_and_confirmation_loss)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    const UniValue missing;

    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        missing));
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(DEPOSIT_TXID, 0, TestDepositAddress(), 2000, 8, false)));
    BOOST_CHECK(error.find("absent") != std::string::npos);
    BOOST_CHECK(!Authenticate(
        authenticated,
        error,
        MainchainInfo(),
        EnforcerChainInfo(),
        EnforcerTip(),
        Sidechains(),
        TwoWayPegData(),
        missing));

    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);
    const UniValue reorged = ParseJson(strprintf(
        R"json({"hash":"%s","height":90,"confirmations":-1})json",
        DEPOSIT_BLOCK));
    BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(reorged, authenticated, error));
    BOOST_CHECK(error.find("no longer confirmed") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyDepositBlockConfirmation(
        ParseJson(R"json({"height":90,"confirmations":11})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("hash is missing") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyCurrentCtipOutput(
        ParseJson(R"json({"value":0.14401000,"confirmations":2})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("value") != std::string::npos);
    BOOST_CHECK(!drivechain::VerifyCurrentCtipOutput(
        ParseJson(R"json({"value":0.14402000,"confirmations":0})json"),
        authenticated,
        error));
    BOOST_CHECK(error.find("not confirmed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_value_smuggling_and_persists_replay_state)
{
    drivechain::AuthenticatedDeposit authenticated;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Authenticate(authenticated, error), error);

    CMutableTransaction wrong_total = DepositTransaction(
        authenticated,
        authenticated.destination_script,
        1800,
        100);
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(
        CTransaction(wrong_total),
        0,
        authenticated,
        error));
    BOOST_CHECK(error.find("value and fee") != std::string::npos);

    CMutableTransaction extra_input = DepositTransaction(
        authenticated,
        authenticated.destination_script);
    extra_input.vin.emplace_back(COutPoint(uint256S("01"), 0));
    extra_input.witness.vtxinwit.resize(2);
    BOOST_CHECK(!drivechain::VerifyDepositTransaction(
        CTransaction(extra_input),
        0,
        authenticated,
        error));
    BOOST_CHECK(error.find("exactly one input") != std::string::npos);

    const CTransaction valid_tx(DepositTransaction(authenticated, authenticated.destination_script));
    const auto replay_key = GetPeginSpentKey(
        valid_tx.witness.vtxinwit[0].m_pegin_witness,
        valid_tx.vin[0].prevout);
    RestartablePeginView persistent;
    {
        CCoinsViewCache first_process(&persistent);
        BOOST_CHECK(!first_process.IsPeginSpent(replay_key));
        first_process.SetPeginSpent(replay_key, true);
        BOOST_REQUIRE(first_process.Flush());
    }
    {
        CCoinsViewCache restarted_process(&persistent);
        BOOST_CHECK(restarted_process.IsPeginSpent(replay_key));
        const auto other_vout = std::make_pair(
            replay_key.first,
            COutPoint(replay_key.second.hash, replay_key.second.n + 1));
        BOOST_CHECK(!restarted_process.IsPeginSpent(other_vout));
    }
}

BOOST_AUTO_TEST_CASE(validates_persisted_v2_evidence_without_external_services)
{
    RestartablePeginView persistent;
    std::string error;
    {
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDeterministicDeposit(checkpoint, 0, view, error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDepositEvidenceAnchor(
                checkpoint,
                0,
                uint256S("000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"),
                error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::ConnectDepositState(checkpoint, 0, view, 2, error),
            error);
        BOOST_REQUIRE(view.Flush());
    }

    DeterministicFixture fixture;
    {
        CCoinsViewCache restarted(&persistent);
        drivechain::CtipState state;
        BOOST_REQUIRE(drivechain::GetCtipState(restarted, state, &error));
        BOOST_CHECK_EQUAL(state.sequence_number, 8);
        BOOST_CHECK_EQUAL(state.value, 14'402'000);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDeterministicDeposit(
                *fixture.transaction,
                0,
                restarted,
                error),
            error);
        BOOST_REQUIRE_MESSAGE(
            drivechain::VerifyDepositEvidenceAnchor(
                *fixture.transaction,
                0,
                fixture.anchor,
                error),
            error);
        BOOST_CHECK(!drivechain::VerifyDepositEvidenceAnchor(
            *fixture.transaction,
            0,
            uint256S("02"),
            error));
        BOOST_REQUIRE_MESSAGE(
            drivechain::ConnectDepositState(
                *fixture.transaction,
                0,
                restarted,
                3,
                error),
            error);
        BOOST_REQUIRE(restarted.Flush());
    }

    {
        CCoinsViewCache restarted(&persistent);
        drivechain::CtipState state;
        BOOST_REQUIRE(drivechain::GetCtipState(restarted, state, &error));
        BOOST_CHECK_EQUAL(state.sequence_number, 9);
        BOOST_CHECK_EQUAL(state.value, 14'404'000);
        BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
            *fixture.transaction,
            0,
            restarted,
            error));
        BOOST_CHECK(error.find("stale") != std::string::npos);
        BOOST_REQUIRE_MESSAGE(
            drivechain::DisconnectDepositState(
                *fixture.transaction,
                0,
                restarted,
                3,
                error),
            error);
        BOOST_REQUIRE(restarted.Flush());
    }

    CCoinsViewCache rolled_back(&persistent);
    drivechain::CtipState restored;
    BOOST_REQUIRE(drivechain::GetCtipState(rolled_back, restored, &error));
    BOOST_CHECK_EQUAL(restored.sequence_number, 8);
    BOOST_CHECK_EQUAL(restored.value, 14'402'000);
}

BOOST_AUTO_TEST_CASE(rejects_corrupted_stale_and_noncanonical_v2_evidence)
{
    RestartablePeginView persistent;
    std::string error;
    CCoinsViewCache view(&persistent);
    const CTransaction checkpoint = LegacyPublicDeposit();
    BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));

    DeterministicFixture fixture;
    CMutableTransaction corrupted(*fixture.transaction);
    corrupted.witness.vtxinwit[0].m_pegin_witness.stack[6].back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(corrupted),
        0,
        view,
        error));

    CMutableTransaction stale(*fixture.transaction);
    DrivechainDepositEvidence stale_evidence = fixture.evidence;
    stale_evidence.previous_sequence_number = 7;
    stale.witness.vtxinwit[0].m_pegin_witness =
        CreateDrivechainDepositPeginWitness(
            2'000,
            Params().GetConsensus().pegged_asset,
            Params().ParentGenesisBlockHash(),
            CScript() << OP_TRUE,
            stale_evidence);
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(stale),
        0,
        view,
        error));
    BOOST_CHECK(error.find("sequence") != std::string::npos);

    CMutableTransaction trailing(*fixture.transaction);
    trailing.witness.vtxinwit[0].m_pegin_witness.stack[8].push_back(0);
    BOOST_CHECK(!drivechain::VerifyDeterministicDeposit(
        CTransaction(trailing),
        0,
        view,
        error));
    BOOST_CHECK(error.find("non-canonical") != std::string::npos);

    BOOST_CHECK_EQUAL(
        HexStr(fixture.transaction->witness.vtxinwit[0].m_pegin_witness.stack[8]),
        "0900000000000000");
    BOOST_CHECK_EQUAL(
        HexStr(fixture.transaction->witness.vtxinwit[0].m_pegin_witness.stack[9]),
        "0800000000000000");
}

BOOST_AUTO_TEST_CASE(persists_zero_value_state_and_fails_closed_on_corruption)
{
    RestartablePeginView persistent;
    std::string error;
    {
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));
        BOOST_REQUIRE(view.Flush());
    }

    BOOST_REQUIRE_EQUAL(persistent.coins.size(), size_t{1});
    const Coin& state_coin = persistent.coins.begin()->second;
    BOOST_REQUIRE(state_coin.out.nValue.IsExplicit());
    BOOST_CHECK_EQUAL(state_coin.out.nValue.GetAmount(), 0);

    persistent.coins.begin()->second.out.scriptPubKey.back() ^= 1;
    CCoinsViewCache restarted(&persistent);
    drivechain::CtipState state;
    BOOST_CHECK(!drivechain::GetCtipState(restarted, state, &error));
    BOOST_CHECK(error.find("malformed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(converges_across_independent_views_and_reorg_rollback)
{
    RestartablePeginView first;
    RestartablePeginView second;
    DeterministicFixture fixture;

    const auto connect = [&](RestartablePeginView& persistent) {
        std::string error;
        CCoinsViewCache view(&persistent);
        const CTransaction checkpoint = LegacyPublicDeposit();
        BOOST_REQUIRE(drivechain::ConnectDepositState(checkpoint, 0, view, 2, error));
        BOOST_REQUIRE(drivechain::VerifyDeterministicDeposit(
            *fixture.transaction,
            0,
            view,
            error));
        BOOST_REQUIRE(drivechain::ConnectDepositState(
            *fixture.transaction,
            0,
            view,
            3,
            error));
        BOOST_REQUIRE(view.Flush());
    };
    connect(first);
    connect(second);

    BOOST_REQUIRE_EQUAL(first.coins.size(), size_t{1});
    BOOST_REQUIRE_EQUAL(second.coins.size(), size_t{1});
    BOOST_CHECK(first.coins.begin()->first == second.coins.begin()->first);
    BOOST_CHECK(first.coins.begin()->second.out == second.coins.begin()->second.out);

    const auto disconnect = [&](RestartablePeginView& persistent) {
        std::string error;
        CCoinsViewCache view(&persistent);
        BOOST_REQUIRE(drivechain::DisconnectDepositState(
            *fixture.transaction,
            0,
            view,
            3,
            error));
        BOOST_REQUIRE(view.Flush());
    };
    disconnect(first);
    disconnect(second);

    CCoinsViewCache first_restarted(&first);
    CCoinsViewCache second_restarted(&second);
    drivechain::CtipState first_state;
    drivechain::CtipState second_state;
    std::string error;
    BOOST_REQUIRE(drivechain::GetCtipState(first_restarted, first_state, &error));
    BOOST_REQUIRE(drivechain::GetCtipState(second_restarted, second_state, &error));
    BOOST_CHECK(first_state == second_state);
    BOOST_CHECK_EQUAL(first_state.sequence_number, 8);
}

BOOST_AUTO_TEST_SUITE_END()
