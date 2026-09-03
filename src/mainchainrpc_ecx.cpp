#include <mainchainrpc.h>
#include <init.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <util/fs.h>
#include <logging.h>
#include <pegins.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/block.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <common/args.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <rpc/request.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <optional>
#include <vector>

bool CallAuthenticatedDrivechainJSON(
    const std::string& endpoint,
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error)
{
    response = UniValue();
    if (error) error->clear();
    if (endpoint != GetDrivechainGrpcAddress(gArgs)) {
        if (error) *error = "enforcer endpoint differs from the configured mTLS endpoint";
        return false;
    }
    const auto result = RunAuthenticatedDrivechainGrpc(
        method, request.write(), std::chrono::seconds{30}, 16U * 1024U * 1024U);
    if (!result.started || !result.exited || result.exit_code != 0 ||
        result.timed_out || result.cancelled || result.output_truncated ||
        !result.error.empty()) {
        if (error) *error = result.error.empty()
            ? "authenticated enforcer request failed, timed out, or exceeded its output limit"
            : result.error;
        return false;
    }
    if (!response.read(result.output) || !response.isObject()) {
        response = UniValue();
        if (error) *error = "authenticated enforcer returned non-object JSON";
        return false;
    }
    return true;
}
bool SubmitDrivechainBmmBid(
    const int sidechain_slot,
    const uint64_t bid_sats,
    const uint32_t parent_height,
    const uint256& critical_hash,
    const uint256& previous_parent_hash,
    uint256& request_txid,
    std::string* error)
{
    try {
        if (sidechain_slot < 0 || sidechain_slot > 255) {
            throw std::runtime_error("BMM sidechain slot is outside uint8 range");
        }
        if (bid_sats == 0 || bid_sats > static_cast<uint64_t>(MAX_MONEY)) {
            throw std::runtime_error("BMM bid must be positive and within the money range");
        }
        if (parent_height == 0 || critical_hash.IsNull() || previous_parent_hash.IsNull()) {
            throw std::runtime_error("BMM bid identity is incomplete");
        }

        UniValue request(UniValue::VOBJ);
        request.pushKV("sidechainId", sidechain_slot);
        // uint64 wrapper values are strings in canonical protobuf JSON.
        request.pushKV("valueSats", std::to_string(bid_sats));
        request.pushKV("height", static_cast<uint64_t>(parent_height));
        UniValue critical(UniValue::VOBJ);
        critical.pushKV("hex", critical_hash.GetHex());
        request.pushKV("criticalHash", critical);
        UniValue previous(UniValue::VOBJ);
        previous.pushKV("hex", previous_parent_hash.GetHex());
        request.pushKV("prevBytes", previous);

        UniValue response;
        if (!CallAuthenticatedDrivechainJSON(
                GetDrivechainGrpcAddress(gArgs),
                "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
                request,
                response,
                error)) {
            return false;
        }
        const UniValue& txid_value = response.get_obj()["txid"];
        if (!txid_value.isObject()) {
            throw std::runtime_error("BMM wallet response has no transaction id");
        }
        const UniValue& hex = txid_value.get_obj()["hex"];
        if (!hex.isStr() || !IsHex(hex.get_str()) || hex.get_str().size() != 64) {
            throw std::runtime_error("BMM wallet returned a malformed transaction id");
        }
        request_txid = uint256S(hex.get_str());
        return true;
    } catch (const std::exception& exception) {
        if (error != nullptr) *error = exception.what();
        return false;
    }
}

static UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params)
{
    const UniValue reply = CallMainChainRPC(method, params);
    const UniValue& error = reply["error"];
    if (!error.isNull()) {
        throw std::runtime_error(strprintf("%s returned error: %s", method, error.write()));
    }
    const UniValue& result = reply["result"];
    if (result.isNull()) {
        throw std::runtime_error(strprintf("%s returned no result", method));
    }
    return result;
}

static const UniValue& FindField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& lower_value = obj.get_obj()[lower_camel];
    if (!lower_value.isNull()) {
        return lower_value;
    }
    return obj.get_obj()[snake_case];
}

static bool GetDrivechainGrpcJSON(
    const std::string& method,
    const std::string& request,
    UniValue& response,
    std::string* error)
{
    UniValue payload;
    if (!payload.read(request) || !payload.isObject()) {
        if (error != nullptr) {
            *error = "internal drivechain request is not object JSON";
        }
        return false;
    }
    return CallAuthenticatedDrivechainJSON(
        GetDrivechainGrpcAddress(gArgs),
        "cusf.mainchain.v1.ValidatorService/" + method,
        payload,
        response,
        error);
}

static bool GetDrivechainTwoWayPegDataAtTip(
    const int sidechain_slot,
    const uint256& mainchain_tip,
    UniValue& response,
    std::string* error)
{
    try {
        const std::string request = strprintf(
            "{\"sidechainId\":%d,\"endBlockHash\":{\"hex\":\"%s\"}}",
            sidechain_slot,
            mainchain_tip.GetHex());
        if (!GetDrivechainGrpcJSON("GetTwoWayPegData", request, response, error)) {
            return false;
        }

        size_t block_count{0};
        size_t event_count{0};
        const UniValue& blocks = FindField(response, "blocks", "blocks");
        if (blocks.isArray()) {
            block_count = blocks.size();
            for (const UniValue& block : blocks.getValues()) {
                if (!block.isObject()) continue;
                const UniValue& block_info = FindField(block, "blockInfo", "block_info");
                if (!block_info.isObject()) continue;
                const UniValue& events = FindField(block_info, "events", "events");
                if (events.isArray()) event_count += events.size();
            }
        }
        LogPrintf("GetTwoWayPegData returned %u blocks and %u raw events for sidechain %d\n", block_count, event_count, sidechain_slot);
        return true;
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

bool GetDrivechainTwoWayPegData(const int sidechain_slot, UniValue& response, std::string* error)
{
    try {
        UniValue no_params(UniValue::VARR);
        const uint256 mainchain_tip = uint256S(CallMainChainRPCChecked("getbestblockhash", no_params).get_str());
        return GetDrivechainTwoWayPegDataAtTip(sidechain_slot, mainchain_tip, response, error);
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

static std::string Lowercase(std::string value)
{
    for (char& c : value) c = std::tolower(static_cast<unsigned char>(c));
    return value;
}

static drivechain::DepositIdentity ConfiguredDepositIdentity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = gArgs.GetIntArg("-drivechainbmmslot", 24);
    identity.sidechain_network = gArgs.GetArg("-drivechainsidechainnetwork", "liquid-signet");
    identity.mainchain_network = gArgs.GetArg("-drivechainmainchainnetwork", "signet");
    identity.mainchain_signet_challenge = Lowercase(gArgs.GetArg(
        "-drivechainmainchainsignetchallenge",
        "00148835832e28c816b7acd8fdb19772ab2199603a56"));
    identity.enforcer_network = gArgs.GetArg("-drivechainenforcernetwork", "NETWORK_SIGNET");
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = gArgs.GetArg("-drivechainsidechaintitle", "Elements");
    identity.hash_id_1 = Lowercase(gArgs.GetArg(
        "-drivechainsidechainhashid1",
        "5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b"));
    identity.hash_id_2 = Lowercase(gArgs.GetArg(
        "-drivechainsidechainhashid2",
        "b2b7b20f3fbc4baf50e9d39f58661c6168e279d4"));
    return identity;
}

bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    const size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated_out,
    std::string* error)
{
    try {
        if (input_index >= tx.vin.size() || input_index >= tx.witness.vtxinwit.size()) {
            throw std::runtime_error("drivechain deposit input or witness index is out of range");
        }

        CAmount value{0};
        CScript claim_script;
        uint256 mainchain_txid;
        if (!GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout,
                value,
                claim_script,
                mainchain_txid)) {
            throw std::runtime_error("transaction input is not a valid drivechain deposit witness");
        }

        UniValue no_params(UniValue::VARR);
        const UniValue mainchain_info = CallMainChainRPCChecked("getblockchaininfo", no_params);
        UniValue genesis_params(UniValue::VARR);
        genesis_params.push_back(0);
        const uint256 mainchain_genesis = uint256S(CallMainChainRPCChecked("getblockhash", genesis_params).get_str());
        const uint256 mainchain_tip = uint256S(mainchain_info.get_obj()["bestblockhash"].get_str());

        UniValue enforcer_chain_info(UniValue::VOBJ);
        UniValue enforcer_tip(UniValue::VOBJ);
        UniValue sidechains(UniValue::VOBJ);
        UniValue ctip(UniValue::VOBJ);
        UniValue two_way_peg_data(UniValue::VOBJ);
        std::string lookup_error;
        if (!GetDrivechainGrpcJSON("GetChainInfo", "{}", enforcer_chain_info, &lookup_error) ||
            !GetDrivechainGrpcJSON("GetChainTip", "{}", enforcer_tip, &lookup_error) ||
            !GetDrivechainGrpcJSON("GetSidechains", "{}", sidechains, &lookup_error)) {
            throw std::runtime_error("unable to obtain enforcer chain identity: " + lookup_error);
        }

        const drivechain::DepositIdentity identity = ConfiguredDepositIdentity();
        const std::string ctip_request = strprintf(
            "{\"sidechainNumber\":%d}",
            identity.sidechain_slot);
        if (!GetDrivechainGrpcJSON("GetCtip", ctip_request, ctip, &lookup_error)) {
            throw std::runtime_error("unable to obtain current CTIP state: " + lookup_error);
        }
        if (!GetDrivechainTwoWayPegDataAtTip(
                identity.sidechain_slot,
                mainchain_tip,
                two_way_peg_data,
                &lookup_error)) {
            throw std::runtime_error("unable to obtain confirmed two-way-peg data: " + lookup_error);
        }

        drivechain::AuthenticatedDeposit authenticated;
        std::string verify_error;
        if (!drivechain::AuthenticateDepositEvidence(
                mainchain_info,
                mainchain_genesis,
                enforcer_chain_info,
                enforcer_tip,
                sidechains,
                two_way_peg_data,
                ctip,
                Params().NetworkIDString(),
                identity,
                tx.vin[input_index].prevout,
                value,
                authenticated,
                verify_error)) {
            throw std::runtime_error(verify_error);
        }

        UniValue block_params(UniValue::VARR);
        block_params.push_back(authenticated.confirmation_block.GetHex());
        block_params.push_back(true);
        const UniValue block_header = CallMainChainRPCChecked("getblockheader", block_params);
        if (!drivechain::VerifyDepositBlockConfirmation(block_header, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }

        UniValue ctip_params(UniValue::VARR);
        ctip_params.push_back(authenticated.current_ctip.hash.GetHex());
        ctip_params.push_back(static_cast<int64_t>(authenticated.current_ctip.n));
        ctip_params.push_back(false);
        const UniValue ctip_txout = CallMainChainRPCChecked("gettxout", ctip_params);
        if (!drivechain::VerifyCurrentCtipOutput(ctip_txout, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }

        if (!drivechain::VerifyDepositTransaction(tx, input_index, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }
        if (authenticated_out) {
            *authenticated_out = std::move(authenticated);
        }
        return true;
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

static bool IsDrivechainCtipScript(const CScript& script, const int sidechain_slot)
{
    if (sidechain_slot < 0 || sidechain_slot > 255) return false;
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_NOP5) return false;
    if (!script.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
        data.size() != 1 || data[0] != static_cast<unsigned char>(sidechain_slot)) {
        return false;
    }
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_1) return false;
    return cursor == script.end();
}

bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error)
{
    try {
        if (authenticated.sequence_number <= 0 ||
            authenticated.outpoint.hash.IsNull() ||
            authenticated.confirmation_block.IsNull() ||
            authenticated.confirmation_height < 0) {
            throw std::runtime_error("authenticated deposit cannot form a v2 CTIP transition");
        }

        UniValue raw_params(UniValue::VARR);
        raw_params.push_back(authenticated.outpoint.hash.GetHex());
        raw_params.push_back(false);
        raw_params.push_back(authenticated.confirmation_block.GetHex());
        const UniValue raw_result = CallMainChainRPCChecked("getrawtransaction", raw_params);
        if (!raw_result.isStr() || !IsHex(raw_result.get_str())) {
            throw std::runtime_error("getrawtransaction returned malformed deposit transaction hex");
        }
        evidence.deposit_tx = ParseHex(raw_result.get_str());

        Sidechain::Bitcoin::CMutableTransaction deposit_tx;
        {
            DataStream stream{evidence.deposit_tx};
            stream >> TX_WITH_WITNESS(deposit_tx);
            if (!stream.empty() || deposit_tx.GetHash() != authenticated.outpoint.hash ||
                authenticated.outpoint.n >= deposit_tx.vout.size()) {
                throw std::runtime_error("L1 deposit transaction does not contain the authenticated outpoint");
            }
        }

        UniValue proof_params(UniValue::VARR);
        UniValue proof_txids(UniValue::VARR);
        proof_txids.push_back(authenticated.outpoint.hash.GetHex());
        proof_params.push_back(proof_txids);
        proof_params.push_back(authenticated.confirmation_block.GetHex());
        const UniValue proof_result = CallMainChainRPCChecked("gettxoutproof", proof_params);
        if (!proof_result.isStr() || !IsHex(proof_result.get_str())) {
            throw std::runtime_error("gettxoutproof returned malformed proof hex");
        }
        evidence.txout_proof = ParseHex(proof_result.get_str());

        std::optional<std::vector<unsigned char>> previous_ctip;
        for (const auto& input : deposit_tx.vin) {
            try {
                UniValue previous_params(UniValue::VARR);
                previous_params.push_back(input.prevout.hash.GetHex());
                previous_params.push_back(false);
                const UniValue previous_result = CallMainChainRPCChecked("getrawtransaction", previous_params);
                if (!previous_result.isStr() || !IsHex(previous_result.get_str())) continue;
                const std::vector<unsigned char> previous_bytes = ParseHex(previous_result.get_str());
                Sidechain::Bitcoin::CMutableTransaction previous_tx;
                DataStream stream{previous_bytes};
                stream >> TX_WITH_WITNESS(previous_tx);
                if (!stream.empty() || input.prevout.n >= previous_tx.vout.size() ||
                    !IsDrivechainCtipScript(
                        previous_tx.vout[input.prevout.n].scriptPubKey,
                        authenticated.sidechain_slot)) {
                    continue;
                }
                if (previous_ctip) {
                    throw std::runtime_error("deposit transaction spends multiple slot CTIP outputs");
                }
                previous_ctip = previous_bytes;
            } catch (const std::runtime_error& exception) {
                if (std::string(exception.what()).find("multiple slot CTIP") != std::string::npos) throw;
            } catch (...) {
            }
        }
        if (!previous_ctip) {
            throw std::runtime_error("deposit transaction's prior CTIP transaction is unavailable");
        }
        evidence.previous_ctip_tx = std::move(*previous_ctip);
        evidence.sequence_number = authenticated.sequence_number;
        evidence.previous_sequence_number = authenticated.sequence_number - 1;

        UniValue chain_info_params(UniValue::VARR);
        const UniValue chain_info = CallMainChainRPCChecked("getblockchaininfo", chain_info_params);
        const int64_t tip_height = chain_info.get_obj()["blocks"].getInt<int64_t>();
        if (tip_height < authenticated.confirmation_height ||
            tip_height - authenticated.confirmation_height > 2016) {
            throw std::runtime_error("deposit confirmation is outside the bounded v2 L1 header window");
        }
        evidence.headers.clear();
        for (int64_t height = authenticated.confirmation_height; height <= tip_height; ++height) {
            UniValue hash_params(UniValue::VARR);
            hash_params.push_back(height);
            const UniValue hash_result = CallMainChainRPCChecked("getblockhash", hash_params);
            UniValue header_params(UniValue::VARR);
            header_params.push_back(hash_result.get_str());
            header_params.push_back(false);
            const UniValue header_result = CallMainChainRPCChecked("getblockheader", header_params);
            if (!header_result.isStr() || !IsHex(header_result.get_str())) {
                throw std::runtime_error("getblockheader returned malformed serialized header");
            }
            const std::vector<unsigned char> header_bytes = ParseHex(header_result.get_str());
            Sidechain::Bitcoin::CBlockHeader header;
            DataStream stream{header_bytes};
            stream >> header;
            if (!stream.empty()) {
                throw std::runtime_error("serialized L1 header contains trailing data");
            }
            evidence.headers.push_back(header);
        }
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    const int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error)
{
    try {
        if (parent_height < 0 ||
            static_cast<uint64_t>(parent_height) < previous_state.height ||
            static_cast<uint64_t>(parent_height + 1 - previous_state.height) >
                drivechain::MAX_BMM_PROOF_ENTRIES) {
            throw std::runtime_error("BMM successor is outside the bounded parent-header window");
        }

        UniValue anchor_params(UniValue::VARR);
        anchor_params.push_back(static_cast<int64_t>(previous_state.height));
        const uint256 active_anchor{
            uint256S(CallMainChainRPCChecked("getblockhash", anchor_params).get_str())};
        if (active_anchor != previous_state.block_hash) {
            throw std::runtime_error(strprintf(
                "authenticated BMM anchor %s at height %u is not on the active L1 chain",
                previous_state.block_hash.GetHex(),
                previous_state.height));
        }

        UniValue parent_params(UniValue::VARR);
        parent_params.push_back(parent_height);
        const uint256 active_parent{
            uint256S(CallMainChainRPCChecked("getblockhash", parent_params).get_str())};
        if (active_parent != parent_hash) {
            throw std::runtime_error("sidechain parent commitment is no longer the active L1 block");
        }

        proof = drivechain::BmmProof{};
        proof.previous_state = previous_state;
        for (int64_t height = previous_state.height + 1;
             height <= parent_height + 1;
             ++height) {
            UniValue hash_params(UniValue::VARR);
            hash_params.push_back(height);
            const uint256 block_hash{
                uint256S(CallMainChainRPCChecked("getblockhash", hash_params).get_str())};

            UniValue block_params(UniValue::VARR);
            block_params.push_back(block_hash.GetHex());
            block_params.push_back(1);
            const UniValue block{
                CallMainChainRPCChecked("getblock", block_params)};
            const UniValue& transactions = block.get_obj()["tx"];
            if (!transactions.isArray() ||
                transactions.empty() ||
                !transactions[0].isStr()) {
                throw std::runtime_error("getblock returned no parent-chain coinbase txid");
            }
            const std::string coinbase_txid = transactions[0].get_str();

            UniValue raw_params(UniValue::VARR);
            raw_params.push_back(coinbase_txid);
            raw_params.push_back(false);
            raw_params.push_back(block_hash.GetHex());
            const UniValue raw{
                CallMainChainRPCChecked("getrawtransaction", raw_params)};
            if (!raw.isStr() || !IsHex(raw.get_str())) {
                throw std::runtime_error("getrawtransaction returned malformed coinbase hex");
            }

            UniValue proof_params(UniValue::VARR);
            UniValue proof_txids(UniValue::VARR);
            proof_txids.push_back(coinbase_txid);
            proof_params.push_back(proof_txids);
            proof_params.push_back(block_hash.GetHex());
            const UniValue merkle{
                CallMainChainRPCChecked("gettxoutproof", proof_params)};
            if (!merkle.isStr() || !IsHex(merkle.get_str())) {
                throw std::runtime_error("gettxoutproof returned malformed coinbase proof hex");
            }
            proof.entries.push_back({
                ParseHex(raw.get_str()),
                ParseHex(merkle.get_str())});
        }

        drivechain::BmmL1State next_state;
        std::string verify_error;
        if (!drivechain::VerifyBmmProofEntries(
                proof,
                critical_hash,
                parent_hash,
                next_state,
                verify_error,
                drivechain::LayerTwoLabsBmmConsensus())) {
            throw std::runtime_error(
                "constructed BMM successor proof failed self-verification: " +
                verify_error);
        }
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}
