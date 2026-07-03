#include <mainchainrpc.h>

#include <chainparamsbase.h>
#include <fs.h>
#include <logging.h>
#include <primitives/block.h>
#include <script/script.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <rpc/request.h>

#include <support/events.h>

#include <rpc/client.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <array>
#include <cstdio>
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

static std::string GetHexField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    if (!obj.isObject()) {
        return "";
    }

    const UniValue& field = FindField(obj, lower_camel, snake_case);
    if (field.isStr()) {
        return field.get_str();
    }
    if (!field.isObject()) {
        return "";
    }

    const UniValue& hex = find_value(field.get_obj(), "hex");
    if (hex.isStr()) {
        return hex.get_str();
    }
    return "";
}

static bool RunCommandJSON(const std::string& command, UniValue& json, std::string* error)
{
#ifdef WIN32
    if (error) {
        *error = "GetTwoWayPegData proof lookup is not supported on Windows builds";
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

bool IsDrivechainBmmCommitmentMined(const CBlock& block, const int sidechain_slot, std::string* error)
{
    uint256 parent_hash;
    if (!ExtractDrivechainParentHashFromBlock(block, parent_hash, error)) {
        return false;
    }
    return IsDrivechainBmmCommitmentMined(block.GetHash(), parent_hash, sidechain_slot, error);
}

bool IsDrivechainBmmCommitmentMined(const uint256& sidechain_block_hash, const uint256& parent_hash, const int sidechain_slot, std::string* error)
{
    try {
        UniValue no_params(UniValue::VARR);
        const uint256 mainchain_tip = uint256S(CallMainChainRPCChecked("getbestblockhash", no_params).get_str());
        const std::string grpcurl_path = ResolveDrivechainBmmGrpcurlPath();
        const std::string grpc_addr = gArgs.GetArg("-drivechainbmmgrpcaddr", "127.0.0.1:50051");
        const std::string request = strprintf(
            "{\"sidechainId\":%d,\"startBlockHash\":{\"hex\":\"%s\"},\"endBlockHash\":{\"hex\":\"%s\"}}",
            sidechain_slot,
            parent_hash.GetHex(),
            mainchain_tip.GetHex());
        const std::string command = strprintf("%s -plaintext -d %s %s cusf.mainchain.v1.ValidatorService/GetTwoWayPegData 2>&1",
            ShellEscape(grpcurl_path),
            ShellEscape(request),
            ShellEscape(grpc_addr));

        UniValue response(UniValue::VOBJ);
        std::string command_error;
        if (!RunCommandJSON(command, response, &command_error)) {
            if (error) {
                *error = strprintf("GetTwoWayPegData failed: %s", command_error);
            }
            return false;
        }

        const UniValue& blocks = FindField(response, "blocks", "blocks");
        if (!blocks.isArray()) {
            if (error) {
                *error = strprintf("GetTwoWayPegData response does not contain blocks array: %s", response.write());
            }
            return false;
        }

        bool saw_successor = false;
        std::string mismatched_commitment;
        for (const UniValue& item : blocks.get_array().getValues()) {
            if (!item.isObject()) {
                continue;
            }
            const UniValue& header_info = FindField(item, "blockHeaderInfo", "block_header_info");
            const std::string prev_hash = GetHexField(header_info, "prevBlockHash", "prev_block_hash");
            if (prev_hash != parent_hash.GetHex()) {
                continue;
            }

            saw_successor = true;
            const UniValue& block_info = FindField(item, "blockInfo", "block_info");
            const std::string bmm_commitment = GetHexField(block_info, "bmmCommitment", "bmm_commitment");
            if (bmm_commitment.empty()) {
                continue;
            }
            if (bmm_commitment == sidechain_block_hash.GetHex()) {
                return true;
            }
            mismatched_commitment = bmm_commitment;
        }

        if (error) {
            if (!mismatched_commitment.empty()) {
                *error = strprintf("L1 successor of parent %s mined BMM commitment %s, expected %s",
                    parent_hash.GetHex(), mismatched_commitment, sidechain_block_hash.GetHex());
            } else if (!saw_successor) {
                *error = strprintf("no L1 successor of parent %s found through current mainchain tip %s",
                    parent_hash.GetHex(), mainchain_tip.GetHex());
            } else {
                *error = strprintf("L1 successor of parent %s has no BMM commitment for expected sidechain block %s",
                    parent_hash.GetHex(), sidechain_block_hash.GetHex());
            }
        }
        return false;
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
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
