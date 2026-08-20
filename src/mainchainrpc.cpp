#include <mainchainrpc.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <fs.h>
#include <logging.h>
#include <pegins.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/block.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <rpc/request.h>

#include <support/events.h>

#include <rpc/client.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <optional>
#include <vector>

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params)
{
    std::string host = gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT);
    int port = gArgs.GetIntArg("-mainchainrpcport", BaseParams().MainchainRPCPort());

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (gArgs.GetArg("-mainchainrpcpassword", "") == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetMainchainAuthCookie(&strRPCUserColonPass)) {
            throw std::runtime_error(strprintf(
                _("Could not locate mainchain RPC credentials. No authentication cookie could be found, and no mainchainrpcpassword is set in the configuration file (%s)").translated,
                    gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME).c_str()));
        }
    } else {
        strRPCUserColonPass = gArgs.GetArg("-mainchainrpcuser", "") + ":" + gArgs.GetArg("-mainchainrpcpassword", "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

static UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params)
{
    const UniValue reply = CallMainChainRPC(method, params);
    const UniValue& error = find_value(reply, "error");
    if (!error.isNull()) {
        throw std::runtime_error(strprintf("%s returned error: %s", method, error.write()));
    }
    const UniValue& result = find_value(reply, "result");
    if (result.isNull()) {
        throw std::runtime_error(strprintf("%s returned no result", method));
    }
    return result;
}

static std::string ResolveDrivechainBmmGrpcurlPath()
{
    const std::string configured_path = gArgs.GetArg("-drivechainbmmgrpcurl", "");
    if (!configured_path.empty()) {
        return configured_path;
    }

    const std::vector<fs::path> candidates{
        gArgs.GetDataDirBase().parent_path() / "assets" / "bin" / "grpcurl",
        gArgs.GetDataDirBase().parent_path() / "bin" / "grpcurl",
        fs::PathFromString("/opt/homebrew/bin/grpcurl"),
        fs::PathFromString("/usr/local/bin/grpcurl"),
        fs::PathFromString("/usr/bin/grpcurl"),
    };
    for (const fs::path& candidate : candidates) {
        if (fs::exists(candidate)) {
            return fs::PathToString(candidate);
        }
    }

    return "grpcurl";
}

static const UniValue& FindField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& lower_value = find_value(obj.get_obj(), lower_camel);
    if (!lower_value.isNull()) {
        return lower_value;
    }
    return find_value(obj.get_obj(), snake_case);
}

static bool RunCommandJSON(const std::string& command, UniValue& json, std::string* error)
{
#ifdef WIN32
    if (error) {
        *error = "drivechain enforcer proof lookup is not supported on Windows builds";
    }
    return false;
#else
    std::array<char, 512> buffer;
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        if (error) {
            *error = "failed to launch command";
        }
        return false;
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }
    const int exit_code = pclose(pipe);
    if (exit_code != 0) {
        if (error) {
            *error = strprintf("command exited with status %d: %s", exit_code, output);
        }
        return false;
    }
    if (!json.read(output) || !json.isObject()) {
        if (error) {
            *error = strprintf("unable to parse JSON response: %s", output);
        }
        return false;
    }
    return true;
#endif
}

static bool GetDrivechainGrpcJSON(
    const std::string& method,
    const std::string& request,
    UniValue& response,
    std::string* error)
{
    const std::string grpcurl_path = ResolveDrivechainBmmGrpcurlPath();
    const std::string grpc_addr = gArgs.GetArg("-drivechainbmmgrpcaddr", "127.0.0.1:50051");
    const std::string command = strprintf("%s -plaintext -d %s %s %s 2>&1",
        ShellEscape(grpcurl_path),
        ShellEscape(request),
        ShellEscape(grpc_addr),
        ShellEscape("cusf.mainchain.v1.ValidatorService/" + method));
    return RunCommandJSON(command, response, error);
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
        const uint256 mainchain_tip = uint256S(find_value(mainchain_info.get_obj(), "bestblockhash").get_str());

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
            CDataStream stream(evidence.deposit_tx, SER_NETWORK, PROTOCOL_VERSION);
            stream >> deposit_tx;
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
                CDataStream stream(previous_bytes, SER_NETWORK, PROTOCOL_VERSION);
                stream >> previous_tx;
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
        const int64_t tip_height = find_value(chain_info.get_obj(), "blocks").get_int64();
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
            CDataStream stream(header_bytes, SER_NETWORK, PROTOCOL_VERSION);
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
            const UniValue& transactions = find_value(block.get_obj(), "tx");
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

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error)
{
    if (block.vtx.empty()) {
        if (error) {
            *error = "block has no coinbase transaction";
        }
        return false;
    }

    bool found = false;
    for (const CTxOut& txout : block.vtx[0]->vout) {
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        std::vector<unsigned char> data;
        opcodetype opcode;

        if (!txout.scriptPubKey.GetOp(pc, opcode, data) || opcode != OP_RETURN) {
            continue;
        }
        if (!txout.scriptPubKey.GetOp(pc, opcode, data) || opcode > OP_PUSHDATA4 || data.size() != 32) {
            continue;
        }
        if (pc != txout.scriptPubKey.end()) {
            continue;
        }

        if (found) {
            if (error) {
                *error = "block coinbase contains multiple drivechain parent commitments";
            }
            return false;
        }
        parent_hash = uint256(data);
        found = true;
    }

    if (!found && error) {
        *error = "block coinbase does not contain a drivechain parent commitment";
    }
    return found;
}

bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs)
{
    LogPrintf("Checking for confirmed bitcoin block with hash %s, mindepth %d, nbtxs %d\n", hash.ToString().c_str(), nMinConfirmationDepth, nbTxs);
    try {
        UniValue params(UniValue::VARR);
        params.push_back(hash.GetHex());
        UniValue reply = CallMainChainRPC("getblockheader", params);
        UniValue errval = find_value(reply, "error");
        if (!errval.isNull()) {
            LogPrintf("WARNING: Got error reply from bitcoind getblockheader: %s\n", errval.write());
            return false;
        }
        UniValue result = find_value(reply, "result");
        if (!result.isObject()) {
            LogPrintf("ERROR: bitcoind getblockheader result was malformed (not object): %s\n", result.write());
            return false;
        }

        UniValue confirmations = find_value(result.get_obj(), "confirmations");
        if (!confirmations.isNum() || confirmations.get_int64() < nMinConfirmationDepth) {
            LogPrintf("Insufficient confirmations (got %s, need at least %d).\n", confirmations.write(), nMinConfirmationDepth);
            return false;
        }

        // Only perform extra test if nbTxs has been provided (non-zero).
        if (nbTxs != 0) {
            UniValue nTx = find_value(result.get_obj(), "nTx");
            if (!nTx.isNum() || nTx.get_int64() != nbTxs) {
                LogPrintf("ERROR: Invalid number of transactions in merkle block for %s (got %s, need exactly %d)\n",
                        hash.GetHex(), nTx.write(), nbTxs);
                return false;
            }
        }
    } catch (CConnectionFailed&) {
        LogPrintf("WARNING: Lost connection to mainchain daemon RPC; will retry.\n");
        return false;
    } catch (...) {
        LogPrintf("WARNING: Failure connecting to mainchain daemon RPC; will retry.\n");
        return false;
    }
    return true;
}
