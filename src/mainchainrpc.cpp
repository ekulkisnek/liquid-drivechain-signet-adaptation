#include <mainchainrpc.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <consensus/merkle.h>
#include <drivechain_parent_replay.h>
#include <elements_drivechain_identity.h>
#include <hash.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <script/script.h>
#include <signet.h>
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
#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

namespace Bitcoin = Sidechain::Bitcoin;

static constexpr size_t MAX_MAINCHAIN_RPC_RESPONSE_SIZE{16 * 1024 * 1024};
static constexpr size_t MAX_MAINCHAIN_RPC_HEADER_SIZE{64 * 1024};

namespace {

/**
 * One validation operation may spend at most two seconds in synchronous
 * parent work and replay at most two not-yet-warmed parent blocks. libevent's
 * timeval timeout is set to the exact remaining deadline for every request.
 */
static constexpr auto DRIVECHAIN_LOCKED_PARENT_DEADLINE{std::chrono::seconds{2}};
static constexpr uint32_t DRIVECHAIN_LOCKED_MAX_REPLAY_STEPS{2};

struct DrivechainParentBudgetState {
    uint32_t depth{0};
    std::chrono::steady_clock::time_point deadline;
    uint32_t replay_steps_remaining{0};
    bool replay_snapshot_authenticated{false};
    bool replay_snapshot_is_explicit_target{false};
    uint32_t replay_snapshot_height{0};
    uint256 replay_snapshot_hash;
    uint64_t replay_snapshot_epoch{0};
};

thread_local DrivechainParentBudgetState g_drivechain_parent_budget;
thread_local uint32_t g_drivechain_untrusted_parent_admission_depth{0};
std::atomic<int64_t> g_drivechain_parent_rpc_unavailable_until{0};
static constexpr auto DRIVECHAIN_PARENT_RPC_BACKOFF{std::chrono::seconds{5}};
std::mutex g_mainchain_rpc_cookie_mutex;
std::string g_mainchain_rpc_cached_cookie;

class MainchainRPCAuthFailure : public std::runtime_error
{
public:
    explicit MainchainRPCAuthFailure(const std::string& message)
        : std::runtime_error(message) {}
};

bool DrivechainParentBudgetActive();

bool DrivechainUntrustedParentAdmissionActive()
{
    return g_drivechain_untrusted_parent_admission_depth != 0;
}

int64_t ParentSteadyClockTicks()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void MarkDrivechainParentRpcUnavailable()
{
    const int64_t retry_at = ParentSteadyClockTicks() +
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            DRIVECHAIN_PARENT_RPC_BACKOFF).count();
    g_drivechain_parent_rpc_unavailable_until.store(retry_at, std::memory_order_relaxed);
}

void MarkDrivechainParentRpcAvailable()
{
    g_drivechain_parent_rpc_unavailable_until.store(0, std::memory_order_relaxed);
}

void CheckDrivechainParentRpcCircuit()
{
    if (DrivechainParentBudgetActive() &&
        ParentSteadyClockTicks() <
            g_drivechain_parent_rpc_unavailable_until.load(std::memory_order_relaxed)) {
        throw CConnectionFailed(
            "drivechain parent RPC is in fail-fast backoff after an availability failure");
    }
}

bool DrivechainParentBudgetActive()
{
    return g_drivechain_parent_budget.depth != 0;
}

void CheckDrivechainParentDeadline()
{
    if (DrivechainParentBudgetActive() &&
        std::chrono::steady_clock::now() >= g_drivechain_parent_budget.deadline) {
        throw CConnectionFailed("drivechain parent validation work budget exhausted");
    }
}

std::string GetMainchainRPCCredentials()
{
    const std::string configured_password =
        gArgs.GetArg("-mainchainrpcpassword", "");
    if (!configured_password.empty()) {
        return gArgs.GetArg("-mainchainrpcuser", "") + ":" +
               configured_password;
    }

    {
        std::unique_lock<std::mutex> lock(
            g_mainchain_rpc_cookie_mutex, std::defer_lock);
        if (DrivechainParentBudgetActive()) {
            if (!lock.try_lock()) {
                throw CConnectionFailed(
                    "mainchain RPC cookie cache is busy refreshing");
            }
        } else {
            lock.lock();
        }
        if (!g_mainchain_rpc_cached_cookie.empty()) {
            return g_mainchain_rpc_cached_cookie;
        }
    }

    // Filesystem access is forbidden once a locked validation budget exists.
    // Startup/periodic warming populates this cache outside cs_main.
    if (DrivechainParentBudgetActive()) {
        throw CConnectionFailed(
            "mainchain RPC cookie credentials are not warmed");
    }
    std::string loaded_cookie;
    if (!GetMainchainAuthCookie(&loaded_cookie)) {
        throw std::runtime_error(strprintf(
            _("Could not locate mainchain RPC credentials. No authentication cookie could be found, and no mainchainrpcpassword is set in the configuration file (%s)").translated,
            gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME).c_str()));
    }
    {
        std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
        g_mainchain_rpc_cached_cookie = loaded_cookie;
    }
    return loaded_cookie;
}

void InvalidateMainchainRPCCookie()
{
    std::lock_guard<std::mutex> lock(g_mainchain_rpc_cookie_mutex);
    g_mainchain_rpc_cached_cookie.clear();
}

bool ConsumeDrivechainReplayBudget(const uint32_t steps, std::string* error)
{
    if (!DrivechainParentBudgetActive()) return true;
    CheckDrivechainParentDeadline();
    if (steps > g_drivechain_parent_budget.replay_steps_remaining) {
        if (error) {
            *error = strprintf(
                "parent replay needs %u uncached blocks; locked validation permits at most %u before background warming",
                steps, g_drivechain_parent_budget.replay_steps_remaining);
        }
        return false;
    }
    g_drivechain_parent_budget.replay_steps_remaining -= steps;
    return true;
}

void RecordDrivechainReplaySnapshot(const uint32_t height,
                                    const uint256& hash,
                                    const uint64_t epoch,
                                    const bool explicit_target)
{
    if (!DrivechainParentBudgetActive()) return;
    // Non-explicit background-style lookups may widen only another
    // non-explicit snapshot and can never overwrite an exact BMM boundary.
    // An explicit BMM target overrides a warmer snapshot even when Q is lower:
    // deposits in that child are bounded by its exact authenticated successor.
    if (!ShouldReplaceDrivechainReplaySnapshot(
            g_drivechain_parent_budget.replay_snapshot_authenticated,
            g_drivechain_parent_budget.replay_snapshot_height,
            g_drivechain_parent_budget.replay_snapshot_is_explicit_target,
            explicit_target, height)) {
        return;
    }
    g_drivechain_parent_budget.replay_snapshot_authenticated = true;
    g_drivechain_parent_budget.replay_snapshot_is_explicit_target = explicit_target;
    g_drivechain_parent_budget.replay_snapshot_height = height;
    g_drivechain_parent_budget.replay_snapshot_hash = hash;
    g_drivechain_parent_budget.replay_snapshot_epoch = epoch;
}

} // namespace

bool ShouldReplaceDrivechainReplaySnapshot(
    const bool current_authenticated,
    const uint32_t current_height,
    const bool current_explicit_target,
    const bool next_explicit_target,
    const uint32_t next_height)
{
    if (!current_authenticated || next_explicit_target) return true;
    if (current_explicit_target) return false;
    return next_height >= current_height;
}

DrivechainParentValidationBudget::DrivechainParentValidationBudget(const bool enable)
    : m_enabled(enable)
{
    if (!m_enabled) return;
    if (g_drivechain_parent_budget.depth++ == 0) {
        g_drivechain_parent_budget.deadline =
            std::chrono::steady_clock::now() + DRIVECHAIN_LOCKED_PARENT_DEADLINE;
        g_drivechain_parent_budget.replay_steps_remaining =
            DRIVECHAIN_LOCKED_MAX_REPLAY_STEPS;
        g_drivechain_parent_budget.replay_snapshot_authenticated = false;
        g_drivechain_parent_budget.replay_snapshot_is_explicit_target = false;
        g_drivechain_parent_budget.replay_snapshot_height = 0;
        g_drivechain_parent_budget.replay_snapshot_hash.SetNull();
        g_drivechain_parent_budget.replay_snapshot_epoch = 0;
    }
}

DrivechainParentValidationBudget::~DrivechainParentValidationBudget()
{
    if (!m_enabled) return;
    assert(g_drivechain_parent_budget.depth > 0);
    --g_drivechain_parent_budget.depth;
    if (g_drivechain_parent_budget.depth == 0) {
        g_drivechain_parent_budget.replay_steps_remaining = 0;
        g_drivechain_parent_budget.replay_snapshot_authenticated = false;
        g_drivechain_parent_budget.replay_snapshot_is_explicit_target = false;
        g_drivechain_parent_budget.replay_snapshot_hash.SetNull();
        g_drivechain_parent_budget.replay_snapshot_epoch = 0;
    }
}

DrivechainUntrustedParentAdmission::DrivechainUntrustedParentAdmission(
    const bool enable)
    : m_enabled(enable)
{
    if (m_enabled) ++g_drivechain_untrusted_parent_admission_depth;
}

DrivechainUntrustedParentAdmission::~DrivechainUntrustedParentAdmission()
{
    if (!m_enabled) return;
    assert(g_drivechain_untrusted_parent_admission_depth > 0);
    --g_drivechain_untrusted_parent_admission_depth;
}

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    bool body_too_large{false};
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
        if (size > MAX_MAINCHAIN_RPC_RESPONSE_SIZE) {
            reply->body_too_large = true;
        } else if (data) {
            reply->body = std::string(data, size);
        }
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

static UniValue CallMainChainRPCUncircuit(const std::string& strMethod, const UniValue& params)
{
    CheckDrivechainParentDeadline();
    std::string host = gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT);
    int port = gArgs.GetIntArg("-mainchainrpcport", BaseParams().MainchainRPCPort());

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_max_headers_size(
        evcon.get(), MAX_MAINCHAIN_RPC_HEADER_SIZE);
    evhttp_connection_set_max_body_size(
        evcon.get(), MAX_MAINCHAIN_RPC_RESPONSE_SIZE);
    if (DrivechainParentBudgetActive()) {
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            g_drivechain_parent_budget.deadline - std::chrono::steady_clock::now());
        if (remaining <= std::chrono::microseconds::zero()) {
            throw CConnectionFailed("drivechain parent validation work budget exhausted");
        }
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
        const auto microseconds = remaining - seconds;
        timeval timeout{};
        timeout.tv_sec = seconds.count();
        timeout.tv_usec = microseconds.count();
        evhttp_connection_set_timeout_tv(evcon.get(), &timeout);
    } else {
        evhttp_connection_set_timeout(
            evcon.get(), gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));
    }

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Cookie files are loaded only by startup/background calls. Locked
    // validation consumes the already-warmed credential cache in memory.
    const std::string strRPCUserColonPass = GetMainchainRPCCredentials();

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
    CheckDrivechainParentDeadline();

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw MainchainRPCAuthFailure("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body_too_large)
        throw std::runtime_error(strprintf("mainchain RPC response exceeds %u bytes", MAX_MAINCHAIN_RPC_RESPONSE_SIZE));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    CheckDrivechainParentDeadline();
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params)
{
    CheckDrivechainParentRpcCircuit();
    try {
        UniValue reply = CallMainChainRPCUncircuit(strMethod, params);
        MarkDrivechainParentRpcAvailable();
        return reply;
    } catch (const MainchainRPCAuthFailure&) {
        const bool cookie_auth =
            gArgs.GetArg("-mainchainrpcpassword", "").empty();
        if (cookie_auth) InvalidateMainchainRPCCookie();
        if (cookie_auth && !DrivechainParentBudgetActive()) {
            // Cookie rotation is repaired only outside consensus locks. The
            // retried call reloads the cookie before opening a new request.
            try {
                UniValue reply =
                    CallMainChainRPCUncircuit(strMethod, params);
                MarkDrivechainParentRpcAvailable();
                return reply;
            } catch (...) {
                MarkDrivechainParentRpcUnavailable();
                throw;
            }
        }
        MarkDrivechainParentRpcUnavailable();
        throw;
    } catch (...) {
        MarkDrivechainParentRpcUnavailable();
        throw;
    }
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

bool IsDrivechainSidechainSlot(const int slot)
{
    const std::optional<uint8_t>& configured = Params().GetConsensus().drivechain_slot;
    return configured.has_value() && slot >= 0 && slot <= std::numeric_limits<uint8_t>::max() &&
           static_cast<uint8_t>(slot) == *configured;
}

namespace {

struct VerifiedMainchainHeader {
    Bitcoin::CBlockHeader header;
    uint256 chainwork;
    uint32_t height{0};
    int64_t confirmations{0};
    uint64_t median_time_past{0};
};

bool SetError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

bool CheckConfiguredDrivechainSlot(const int sidechain_slot, std::string* error)
{
    const std::optional<uint8_t>& configured = Params().GetConsensus().drivechain_slot;
    if (!configured.has_value()) {
        return SetError(error, "this network has no configured BIP300/301 sidechain slot");
    }
    if (sidechain_slot < 0 || sidechain_slot > std::numeric_limits<uint8_t>::max() ||
        static_cast<uint8_t>(sidechain_slot) != *configured) {
        return SetError(error, strprintf("drivechain sidechain slot must match configured slot %u, got %d",
                                        static_cast<unsigned int>(*configured), sidechain_slot));
    }
    return true;
}

bool ParseCanonicalHash(const UniValue& value, uint256& hash)
{
    if (!value.isStr() || value.get_str().size() != 64 || !IsHex(value.get_str())) return false;
    hash = uint256S(value.get_str());
    return value.get_str() == hash.GetHex();
}

bool CheckParentProofOfWork(const uint256& hash, const uint32_t n_bits, std::string* error)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target;
    target.SetCompact(n_bits, &negative, &overflow);
    if (negative || target == 0 || overflow ||
        target > UintToArith256(Params().GetConsensus().parentChainPowLimit)) {
        return SetError(error, "parent header has an invalid proof-of-work target");
    }
    if (UintToArith256(hash) > target) {
        return SetError(error, "parent header does not satisfy its proof-of-work target");
    }
    return true;
}

arith_uint256 GetParentBlockProof(const uint32_t n_bits)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target;
    target.SetCompact(n_bits, &negative, &overflow);
    if (negative || overflow || target == 0) return 0;
    return (~target / (target + 1)) + 1;
}

bool CheckParentChainworkStep(const VerifiedMainchainHeader& parent,
                              const VerifiedMainchainHeader& successor,
                              std::string* error)
{
    const arith_uint256 successor_proof = GetParentBlockProof(successor.header.nBits);
    if (successor_proof == 0 ||
        UintToArith256(successor.chainwork) != UintToArith256(parent.chainwork) + successor_proof) {
        return SetError(error, "parent RPC chainwork does not match the authenticated successor header");
    }
    return true;
}

bool ReadRawBitcoinHeader(const uint256& hash, Bitcoin::CBlockHeader& header, std::string* error)
{
    UniValue params(UniValue::VARR);
    params.push_back(hash.GetHex());
    params.push_back(false);
    const UniValue raw = CallMainChainRPCChecked("getblockheader", params);
    if (!raw.isStr() || !IsHex(raw.get_str())) {
        return SetError(error, "getblockheader returned non-hex raw header data");
    }
    CheckDrivechainParentDeadline();
    try {
        CDataStream stream(ParseHex(raw.get_str()), SER_NETWORK, PROTOCOL_VERSION);
        stream >> header;
        if (!stream.empty()) return SetError(error, "raw parent header has trailing bytes");
    } catch (const std::exception& e) {
        return SetError(error, strprintf("cannot decode raw parent header: %s", e.what()));
    }
    CheckDrivechainParentDeadline();
    if (header.GetHash() != hash) {
        return SetError(error, strprintf("raw parent header hashes to %s, expected %s", header.GetHash().GetHex(), hash.GetHex()));
    }
    return CheckParentProofOfWork(hash, header.nBits, error);
}

bool ComputeVerifiedMedianTimePast(const uint256& start_hash, const uint32_t start_height,
                                   uint64_t& median_time_past, std::string* error)
{
    std::vector<uint32_t> times;
    times.reserve(11);
    uint256 expected_hash = start_hash;
    const uint32_t count = std::min<uint32_t>(11, start_height + 1);
    for (uint32_t i = 0; i < count; ++i) {
        CheckDrivechainParentDeadline();
        Bitcoin::CBlockHeader header;
        if (!ReadRawBitcoinHeader(expected_hash, header, error)) return false;
        times.push_back(header.nTime);
        expected_hash = header.hashPrevBlock;
    }
    std::sort(times.begin(), times.end());
    CheckDrivechainParentDeadline();
    median_time_past = times[times.size() / 2];
    return true;
}

bool GetVerifiedActiveMainchainHeader(const uint256& expected_hash, const int min_confirmations,
                                      VerifiedMainchainHeader& verified, std::string* error)
{
    if (min_confirmations < 1) return SetError(error, "minimum parent confirmations must be positive");

    UniValue genesis_params(UniValue::VARR);
    genesis_params.push_back(0);
    uint256 rpc_genesis;
    const UniValue genesis = CallMainChainRPCChecked("getblockhash", genesis_params);
    if (!ParseCanonicalHash(genesis, rpc_genesis) || rpc_genesis != Params().ParentGenesisBlockHash()) {
        return SetError(error, strprintf("mainchain RPC genesis does not match pinned parent genesis %s",
                                        Params().ParentGenesisBlockHash().GetHex()));
    }

    UniValue params(UniValue::VARR);
    params.push_back(expected_hash.GetHex());
    params.push_back(true);
    const UniValue metadata = CallMainChainRPCChecked("getblockheader", params);
    if (!metadata.isObject()) return SetError(error, "getblockheader result is not an object");

    uint256 returned_hash;
    if (!ParseCanonicalHash(find_value(metadata.get_obj(), "hash"), returned_hash) || returned_hash != expected_hash) {
        return SetError(error, "getblockheader hash does not match requested parent block");
    }
    const UniValue& height = find_value(metadata.get_obj(), "height");
    const UniValue& confirmations = find_value(metadata.get_obj(), "confirmations");
    const UniValue& chainwork = find_value(metadata.get_obj(), "chainwork");
    uint256 parsed_chainwork;
    if (!height.isNum() || !confirmations.isNum() || !ParseCanonicalHash(chainwork, parsed_chainwork)) {
        return SetError(error, "getblockheader is missing canonical height, confirmations, or chainwork");
    }
    const int64_t parsed_height = height.get_int64();
    const int64_t parsed_confirmations = confirmations.get_int64();
    if (parsed_height < 0 || parsed_height > std::numeric_limits<uint32_t>::max() ||
        parsed_confirmations < min_confirmations) {
        return SetError(error, strprintf("parent block has %d confirmations; %d required",
                                        parsed_confirmations, min_confirmations));
    }

    UniValue active_hash_params(UniValue::VARR);
    active_hash_params.push_back(parsed_height);
    uint256 active_hash;
    const UniValue active_hash_result = CallMainChainRPCChecked("getblockhash", active_hash_params);
    if (!ParseCanonicalHash(active_hash_result, active_hash) || active_hash != expected_hash) {
        return SetError(error, "parent block is not the active-chain block at its declared height");
    }

    Bitcoin::CBlockHeader raw_header;
    if (!ReadRawBitcoinHeader(expected_hash, raw_header, error)) return false;

    const UniValue& previous = find_value(metadata.get_obj(), "previousblockhash");
    if (parsed_height == 0) {
        if (!previous.isNull() || !raw_header.hashPrevBlock.IsNull()) {
            return SetError(error, "parent genesis unexpectedly has a predecessor");
        }
        if (UintToArith256(parsed_chainwork) != GetParentBlockProof(raw_header.nBits)) {
            return SetError(error, "parent genesis chainwork does not match its authenticated header");
        }
    } else {
        uint256 previous_hash;
        if (!ParseCanonicalHash(previous, previous_hash) || previous_hash != raw_header.hashPrevBlock) {
            return SetError(error, "verbose and raw parent headers disagree about previous block");
        }

        UniValue previous_params(UniValue::VARR);
        previous_params.push_back(previous_hash.GetHex());
        previous_params.push_back(true);
        const UniValue previous_metadata = CallMainChainRPCChecked("getblockheader", previous_params);
        if (!previous_metadata.isObject()) return SetError(error, "previous getblockheader result is not an object");
        uint256 returned_previous_hash;
        uint256 previous_chainwork;
        const UniValue& previous_height = find_value(previous_metadata.get_obj(), "height");
        if (!ParseCanonicalHash(find_value(previous_metadata.get_obj(), "hash"), returned_previous_hash) ||
            returned_previous_hash != previous_hash ||
            !ParseCanonicalHash(find_value(previous_metadata.get_obj(), "chainwork"), previous_chainwork) ||
            !previous_height.isNum() || previous_height.get_int64() != parsed_height - 1) {
            return SetError(error, "previous parent metadata is not canonical or contiguous");
        }
        const arith_uint256 block_proof = GetParentBlockProof(raw_header.nBits);
        if (block_proof == 0 ||
            UintToArith256(parsed_chainwork) != UintToArith256(previous_chainwork) + block_proof) {
            return SetError(error, "parent chainwork does not match its authenticated header and predecessor");
        }
    }

    uint64_t median_time_past{0};
    if (!ComputeVerifiedMedianTimePast(expected_hash, parsed_height, median_time_past, error)) return false;
    CheckDrivechainParentDeadline();

    verified.header = raw_header;
    verified.chainwork = parsed_chainwork;
    verified.height = static_cast<uint32_t>(parsed_height);
    verified.confirmations = parsed_confirmations;
    verified.median_time_past = median_time_past;
    if (verified.chainwork.IsNull()) return SetError(error, "parent chainwork cannot be zero");
    return true;
}

bool ReadAuthenticatedRawMainchainBlock(const uint256& hash,
                                        Bitcoin::CBlock& block,
                                        std::string* error)
{
    UniValue params(UniValue::VARR);
    params.push_back(hash.GetHex());
    params.push_back(0);
    const UniValue raw = CallMainChainRPCChecked("getblock", params);
    if (!raw.isStr() || !IsHex(raw.get_str())) return SetError(error, "getblock returned non-hex raw block data");
    CheckDrivechainParentDeadline();
    try {
        CDataStream stream(ParseHex(raw.get_str()), SER_NETWORK, PROTOCOL_VERSION);
        stream >> block;
        if (!stream.empty()) return SetError(error, "raw parent block has trailing bytes");
    } catch (const std::exception& e) {
        return SetError(error, strprintf("cannot decode raw parent block: %s", e.what()));
    }
    CheckDrivechainParentDeadline();
    if (block.GetHash() != hash) {
        return SetError(error, "raw parent block header does not match its requested hash");
    }
    if (!CheckParentProofOfWork(hash, block.nBits, error)) {
        return false;
    }
    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
        return SetError(error, "raw parent block has no coinbase transaction");
    }
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if ((i & 0xffU) == 0) CheckDrivechainParentDeadline();
        if (!block.vtx[i] || block.vtx[i]->IsCoinBase()) {
            return SetError(error, "raw parent block has a null transaction or multiple coinbases");
        }
    }
    bool mutated{false};
    std::vector<uint256> transaction_hashes;
    transaction_hashes.reserve(block.vtx.size());
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        if ((i & 0xffU) == 0) CheckDrivechainParentDeadline();
        transaction_hashes.push_back(block.vtx[i]->GetHash());
    }
    if (ComputeMerkleRoot(std::move(transaction_hashes), &mutated) != block.hashMerkleRoot || mutated) {
        return SetError(error, "raw parent block has an invalid or mutated transaction Merkle tree");
    }
    CheckDrivechainParentDeadline();
    const std::vector<uint8_t>& parent_signet_challenge = Params().GetConsensus().parent_signet_challenge;
    if (!parent_signet_challenge.empty()) {
        const CScript challenge(parent_signet_challenge.begin(), parent_signet_challenge.end());
        if (!CheckBitcoinSignetBlockSolution(block, challenge, Params().ParentGenesisBlockHash(), error)) {
            return false;
        }
        CheckDrivechainParentDeadline();
    }
    return true;
}

bool ReadVerifiedMainchainBlock(const uint256& hash, const int min_confirmations,
                                Bitcoin::CBlock& block, VerifiedMainchainHeader& verified,
                                std::string* error)
{
    if (!GetVerifiedActiveMainchainHeader(hash, min_confirmations, verified, error)) return false;
    if (!ReadAuthenticatedRawMainchainBlock(hash, block, error)) return false;
    if (block.GetBlockHeader().GetHash() != verified.header.GetHash()) {
        return SetError(error, "raw parent block header does not match authenticated header");
    }
    return true;
}

bool IsDrivechainTreasuryScript(const CScript& script, const int sidechain_slot)
{
    const std::vector<unsigned char> expected{
        static_cast<unsigned char>(OP_NOP5), 0x01,
        static_cast<unsigned char>(sidechain_slot), static_cast<unsigned char>(OP_TRUE)};
    return std::vector<unsigned char>(script.begin(), script.end()) == expected;
}

bool IsExactOpReturnAddress(const Bitcoin::CTxOut& output, const std::vector<unsigned char>& address)
{
    CScript::const_iterator pc = output.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> pushed;
    return output.scriptPubKey.GetOp(pc, opcode, pushed) && opcode == OP_RETURN &&
           output.scriptPubKey.GetOp(pc, opcode, pushed) && opcode <= OP_PUSHDATA4 &&
           pushed == address && pc == output.scriptPubKey.end();
}

bool ExtractSingleOpReturnPush(const CScript& script, std::vector<unsigned char>& payload)
{
    payload.clear();
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> pushed;
    if (!script.GetOp(pc, opcode, pushed) || opcode != OP_RETURN ||
        !script.GetOp(pc, opcode, pushed) || opcode > OP_PUSHDATA4 ||
        pc != script.end()) {
        return false;
    }
    payload = std::move(pushed);
    return true;
}

enum class DrivechainParentMessageType {
    NONE,
    PROPOSAL,
    ACK,
};

struct DrivechainParentMessage {
    DrivechainParentMessageType type{DrivechainParentMessageType::NONE};
    uint8_t slot{0};
    uint256 proposal_hash;
};

DrivechainParentMessage ParseDrivechainParentMessage(const CScript& script)
{
    static constexpr std::array<uint8_t, 4> M1_TAG{{0xd5, 0xe0, 0xc4, 0xaf}};
    static constexpr std::array<uint8_t, 4> M2_TAG{{0xd6, 0xe1, 0xc5, 0xdf}};

    std::vector<unsigned char> payload;
    if (!ExtractSingleOpReturnPush(script, payload) || payload.size() < 5) return {};
    if (std::equal(M1_TAG.begin(), M1_TAG.end(), payload.begin())) {
        const std::vector<unsigned char> description(payload.begin() + 5, payload.end());
        return {DrivechainParentMessageType::PROPOSAL, payload[4], Hash(description)};
    }
    if (payload.size() == M2_TAG.size() + 1 + uint256::size() &&
        std::equal(M2_TAG.begin(), M2_TAG.end(), payload.begin())) {
        uint256 proposal_hash;
        std::copy(payload.begin() + 5, payload.end(), proposal_hash.begin());
        return {DrivechainParentMessageType::ACK, payload[4], proposal_hash};
    }
    return {};
}

DrivechainDepositStatus SetDepositError(std::string* error,
                                        DrivechainDepositStatus status,
                                        const std::string& message);

bool ReadActiveMainchainHash(uint32_t height, uint256& hash, std::string* error);

struct DrivechainParentReplayCache {
    bool initialized{false};
    uint64_t epoch{0};
    uint8_t slot{0};
    uint256 proposal_hash;
    uint256 checkpoint_active_proposal_hash;
    uint256 checkpoint_hash;
    uint16_t unused_proposal_max_age{0};
    uint16_t unused_activation_threshold{0};
    uint16_t used_proposal_max_age{0};
    uint16_t used_activation_threshold{0};
    uint32_t replay_version{0};
    uint32_t height{0};
    uint256 hash;
    DrivechainParentReplayState state;
};

std::mutex g_drivechain_parent_replay_mutex;
DrivechainParentReplayCache g_drivechain_parent_replay_cache;
std::unique_ptr<DrivechainParentReplayStore> g_drivechain_parent_replay_store;
bool g_drivechain_parent_replay_store_rebuild_required{false};
uint64_t g_drivechain_parent_replay_epoch_counter{0};
std::atomic<uint64_t> g_drivechain_parent_replay_published_epoch{0};
static constexpr size_t DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES{4U << 20};

bool ReplayCacheMatchesConfiguredIdentity(
    const DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus);

bool RequireConfiguredElementsProposalActive(
    const DrivechainParentReplayCache& cache,
    uint32_t target_height,
    std::string* error);

bool EnsurePinnedDrivechainParentStateThrough(uint32_t target_height,
                                              const uint256& target_hash,
                                              bool require_elements_active,
                                              std::string* error);

} // namespace

bool ExtractCanonicalDrivechainBmmCommitmentInBlock(
    const Bitcoin::CBlock& block,
    const int sidechain_slot,
    uint256& committed_sidechain_hash,
    uint32_t* output_index,
    std::string* error)
{
    committed_sidechain_hash.SetNull();
    if (output_index) *output_index = 0;
    if (sidechain_slot < 0 || sidechain_slot > std::numeric_limits<uint8_t>::max()) {
        return SetError(error, "BIP301 M7 sidechain slot is outside the uint8 range");
    }
    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
        return SetError(error, "raw BMM block has no coinbase transaction");
    }

    // The enforcer's canonical encoding is the exact minimal-push script
    //   OP_RETURN || PUSHBYTES_37 || d1617368 || slot || h*
    static constexpr std::array<uint8_t, 4> M7_TAG{{0xd1, 0x61, 0x73, 0x68}};
    static constexpr uint8_t M7_PAYLOAD_SIZE{M7_TAG.size() + 1 + uint256::size()};
    static constexpr size_t M7_SCRIPT_SIZE{1 + 1 + M7_PAYLOAD_SIZE};
    size_t matches{0};
    size_t noncanonical_matches{0};
    uint32_t matched_index{0};
    uint256 parsed_hash;
    for (size_t i = 0; i < block.vtx[0]->vout.size(); ++i) {
        const CScript& script = block.vtx[0]->vout[i].scriptPubKey;
        std::vector<unsigned char> payload;
        if (!ExtractSingleOpReturnPush(script, payload) ||
            payload.size() != M7_PAYLOAD_SIZE ||
            !std::equal(M7_TAG.begin(), M7_TAG.end(), payload.begin()) ||
            payload[M7_TAG.size()] != static_cast<uint8_t>(sidechain_slot)) {
            continue;
        }
        ++matches;
        if (script.size() != M7_SCRIPT_SIZE || script[0] != OP_RETURN ||
            script[1] != M7_PAYLOAD_SIZE) {
            ++noncanonical_matches;
        }
        matched_index = static_cast<uint32_t>(i);
        std::copy(payload.begin() + M7_TAG.size() + 1,
                  payload.end(), parsed_hash.begin());
    }

    if (noncanonical_matches != 0) {
        return SetError(error, strprintf(
            "BMM successor has %u noncanonical but enforcer-recognized M7 outputs for sidechain slot %d",
            noncanonical_matches, sidechain_slot));
    }
    if (matches == 0) {
        return SetError(error, strprintf("BMM successor has no canonical M7 for sidechain slot %d", sidechain_slot));
    }
    if (matches != 1) {
        return SetError(error, strprintf("BMM successor has %u canonical M7 outputs for sidechain slot %d",
                                        matches, sidechain_slot));
    }
    committed_sidechain_hash = parsed_hash;
    if (output_index) *output_index = matched_index;
    return true;
}

bool MatchDrivechainBmmCommitmentInBlock(const Bitcoin::CBlock& block,
                                         const int sidechain_slot,
                                         const uint256& sidechain_block_hash,
                                         uint32_t* output_index,
                                         std::string* error)
{
    uint256 committed_hash;
    if (!ExtractCanonicalDrivechainBmmCommitmentInBlock(
            block, sidechain_slot, committed_hash, output_index, error)) {
        return false;
    }
    // The enforcer ReverseHex-decodes the display hash supplied over gRPC and
    // serializes BmmCommitment in uint256/internal byte order. The parser
    // copies those wire bytes directly into uint256 before this comparison.
    if (committed_hash != sidechain_block_hash) {
        return SetError(error, strprintf(
            "BMM successor commits to sidechain block %s, expected %s",
            committed_hash.GetHex(), sidechain_block_hash.GetHex()));
    }
    return true;
}

bool MatchDrivechainDepositInBlock(
    const Bitcoin::CBlock& block,
    const int sidechain_slot,
    const COutPoint& outpoint,
    const CAmount value,
    const std::vector<unsigned char>& address,
    const std::map<Bitcoin::COutPoint, Bitcoin::CTxOut>& previous_outputs,
    std::string* error)
{
    // This pure matcher deliberately has no global Params dependency.  Its
    // authenticated consensus entry point checks the network's configured
    // slot before calling it.
    if (sidechain_slot < 0 || sidechain_slot > std::numeric_limits<uint8_t>::max() ||
        value <= 0 || !MoneyRange(value) || address.empty()) {
        return SetError(error, "invalid slot, amount, or address for drivechain deposit");
    }

    const Bitcoin::CTransaction* deposit{nullptr};
    for (const auto& transaction : block.vtx) {
        if (transaction->GetHash() == outpoint.hash) {
            if (deposit) return SetError(error, "raw parent block contains duplicate deposit txids");
            deposit = transaction.get();
        }
    }
    if (!deposit || outpoint.n >= deposit->vout.size()) return SetError(error, "deposit outpoint is absent from raw parent block");
    if (deposit->IsCoinBase()) return SetError(error, "BIP300 M5 deposit cannot be a coinbase transaction");
    if (!IsDrivechainTreasuryScript(deposit->vout[outpoint.n].scriptPubKey, sidechain_slot)) {
        return SetError(error, "deposit outpoint is not the slot-specific BIP300 treasury output");
    }
    if (outpoint.n + 1 >= deposit->vout.size() || !IsExactOpReturnAddress(deposit->vout[outpoint.n + 1], address)) {
        return SetError(error, "BIP300 deposit does not contain the exact following address commitment");
    }

    size_t treasury_outputs{0};
    for (const auto& output : deposit->vout) {
        if (IsDrivechainTreasuryScript(output.scriptPubKey, sidechain_slot)) ++treasury_outputs;
    }
    if (treasury_outputs != 1) return SetError(error, "BIP300 deposit must create exactly one treasury output for the slot");

    CAmount old_treasury_value{0};
    size_t treasury_inputs{0};
    for (const auto& input : deposit->vin) {
        const auto previous = previous_outputs.find(input.prevout);
        if (previous == previous_outputs.end()) continue;
        if (IsDrivechainTreasuryScript(previous->second.scriptPubKey, sidechain_slot)) {
            ++treasury_inputs;
            old_treasury_value = previous->second.nValue;
        }
    }
    if (treasury_inputs > 1) return SetError(error, "BIP300 deposit spends multiple treasury outputs for one slot");
    const CAmount new_treasury_value = deposit->vout[outpoint.n].nValue;
    if (!MoneyRange(new_treasury_value) || new_treasury_value <= old_treasury_value ||
        new_treasury_value - old_treasury_value != value) {
        return SetError(error, "BIP300 treasury value delta does not equal the claimed deposit amount");
    }
    return true;
}

bool ApplyDrivechainParentBlockState(
    const Bitcoin::CBlock& block,
    const uint32_t height,
    const int sidechain_slot,
    const uint256& required_active_proposal,
    const uint16_t unused_slot_proposal_max_age,
    const uint16_t unused_slot_activation_threshold,
    const uint16_t used_slot_proposal_max_age,
    const uint16_t used_slot_activation_threshold,
    DrivechainParentReplayState& state,
    std::vector<DrivechainMintableDeposit>* deposits,
    std::string* error)
{
    CheckDrivechainParentDeadline();
    if (deposits) deposits->clear();
    if (sidechain_slot < 0 || sidechain_slot > std::numeric_limits<uint8_t>::max() ||
        required_active_proposal.IsNull() ||
        unused_slot_proposal_max_age == 0 ||
        unused_slot_activation_threshold == 0 ||
        unused_slot_activation_threshold >= unused_slot_proposal_max_age ||
        used_slot_proposal_max_age == 0 || used_slot_activation_threshold == 0 ||
        used_slot_activation_threshold >= used_slot_proposal_max_age) {
        return SetError(error, "invalid slot or proposal identity for parent-state replay");
    }
    if ((state.required_proposal_activated &&
         state.active_proposal_hash != required_active_proposal) ||
        (state.active_proposal_hash.IsNull() && state.ctip.has_value())) {
        return SetError(error, "parent-state replay began with an inconsistent active proposal");
    }
    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
        return SetError(error, "parent-state replay block has no coinbase transaction");
    }
    if ((state.ctip && (state.ctip_value < 0 || !MoneyRange(state.ctip_value))) ||
        (!state.ctip && state.ctip_value != 0)) {
        return SetError(error, "parent-state replay began with malformed CTIP state");
    }

    // Select the enforcer's unused-slot or used-slot thresholds from the live
    // replay state. A proposal activates on votes > threshold, not >=.
    std::set<uint256> proposals_created_in_block;
    std::set<uint256> proposal_messages_in_block;
    bool saw_slot_ack{false};
    size_t coinbase_output_index{0};
    for (const auto& output : block.vtx[0]->vout) {
        if ((coinbase_output_index++ & 0xffU) == 0) {
            CheckDrivechainParentDeadline();
        }
        const DrivechainParentMessage message = ParseDrivechainParentMessage(output.scriptPubKey);
        if (message.type == DrivechainParentMessageType::NONE ||
            message.slot != static_cast<uint8_t>(sidechain_slot)) {
            continue;
        }
        if (message.type == DrivechainParentMessageType::PROPOSAL) {
            if (!proposal_messages_in_block.insert(message.proposal_hash).second) {
                return SetError(error, "parent block contains a duplicate slot proposal message");
            }
            if (state.pending_proposals.count(message.proposal_hash) == 0) {
                state.pending_proposals.emplace(
                    message.proposal_hash, DrivechainPendingProposal{height, 0});
                proposals_created_in_block.insert(message.proposal_hash);
            }
            continue;
        }

        if (saw_slot_ack) {
            return SetError(error, "parent block contains multiple slot ACK messages");
        }
        saw_slot_ack = true;
        auto proposal = state.pending_proposals.find(message.proposal_hash);
        if (proposal == state.pending_proposals.end() ||
            proposals_created_in_block.count(message.proposal_hash) != 0) {
            // Unknown ACKs and ACKs in the proposal's own block are ignored.
            continue;
        }
        ++proposal->second.votes;
        const bool slot_is_used = !state.active_proposal_hash.IsNull();
        const uint16_t activation_threshold = slot_is_used
            ? used_slot_activation_threshold
            : unused_slot_activation_threshold;
        if (proposal->second.votes > activation_threshold) {
            state.active_proposal_hash = message.proposal_hash;
            state.pending_proposals.erase(proposal);
            if (state.required_proposal_activated &&
                state.active_proposal_hash != required_active_proposal) {
                return SetError(error, strprintf(
                    "parent slot %d was replaced by proposal %s",
                    sidechain_slot, state.active_proposal_hash.GetHex()));
            }
            if (!state.required_proposal_activated &&
                state.active_proposal_hash == required_active_proposal) {
                state.required_proposal_activated = true;
                state.required_activation_height = height;
                state.required_activation_block_hash = block.GetHash();
            }
        }
    }

    // The enforcer expires proposals after applying all coinbase messages, so
    // an activation in this block makes the used-slot pair apply here.
    const bool slot_is_used = !state.active_proposal_hash.IsNull();
    const uint16_t proposal_max_age = slot_is_used
        ? used_slot_proposal_max_age
        : unused_slot_proposal_max_age;
    const uint16_t activation_threshold = slot_is_used
        ? used_slot_activation_threshold
        : unused_slot_activation_threshold;
    for (auto proposal = state.pending_proposals.begin(); proposal != state.pending_proposals.end();) {
        if (height < proposal->second.proposal_height) {
            return SetError(error, "parent proposal height is ahead of replay height");
        }
        const uint32_t age = height - proposal->second.proposal_height;
        if (proposal->second.votes > age) {
            return SetError(error, "parent proposal has more votes than elapsed blocks");
        }
        const uint32_t misses = age - proposal->second.votes;
        const uint32_t max_fails = proposal_max_age - activation_threshold;
        if (age > proposal_max_age ||
            (age > max_fails && misses >= max_fails)) {
            proposal = state.pending_proposals.erase(proposal);
        } else {
            ++proposal;
        }
    }
    const bool required_proposal_active_for_transactions =
        state.required_proposal_activated &&
        state.active_proposal_hash == required_active_proposal;

    // OP_DRIVECHAIN is anyone-can-spend script syntax. The enforcer treats it
    // as a treasury output only after this slot has an active sidechain.
    if (state.active_proposal_hash.IsNull()) {
        CheckDrivechainParentDeadline();
        return true;
    }

    // Follow only the unique output chain descending from the pinned CTIP.
    // Once it exists, the enforcer rejects parallel slot outputs and requires
    // every spend to create exactly one replacement.  We conservatively halt
    // on decreases because independently validating M6 votes is outside this
    // mint-only replay; accepting an unproven withdrawal could break backing.
    for (size_t transaction_index = 1; transaction_index < block.vtx.size(); ++transaction_index) {
        CheckDrivechainParentDeadline();
        const Bitcoin::CTransaction& transaction = *block.vtx[transaction_index];
        size_t current_ctip_inputs{0};
        if (state.ctip) {
            size_t input_index{0};
            for (const auto& input : transaction.vin) {
                if ((input_index++ & 0xffU) == 0) {
                    CheckDrivechainParentDeadline();
                }
                if (input.prevout == *state.ctip) ++current_ctip_inputs;
            }
            if (current_ctip_inputs > 1) {
                return SetError(error, "parent transaction spends the canonical CTIP more than once");
            }
        }

        std::vector<uint32_t> treasury_outputs;
        for (uint32_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
            if ((output_index & 0xffU) == 0) {
                CheckDrivechainParentDeadline();
            }
            const Bitcoin::CTxOut& output = transaction.vout[output_index];
            if (!IsDrivechainTreasuryScript(output.scriptPubKey, sidechain_slot)) continue;
            if (output.nValue < 0 || !MoneyRange(output.nValue)) {
                return SetError(error, "parent transaction has an invalid slot treasury value");
            }
            treasury_outputs.push_back(output_index);
        }

        if (treasury_outputs.size() > 1) {
            return SetError(error, "canonical CTIP transition creates multiple slot treasury outputs");
        }

        if (state.ctip && current_ctip_inputs == 0 && !treasury_outputs.empty()) {
            return SetError(error, "parent transaction creates a parallel slot output without spending the canonical CTIP");
        }
        if (state.ctip && current_ctip_inputs == 1 && treasury_outputs.empty()) {
            return SetError(error, "parent transaction spends the canonical CTIP without a replacement");
        }
        if ((state.ctip && current_ctip_inputs == 0) ||
            (!state.ctip && treasury_outputs.empty())) {
            continue;
        }

        const CAmount old_value = state.ctip ? state.ctip_value : 0;
        const uint32_t output_index = treasury_outputs.front();
        const Bitcoin::CTxOut& treasury = transaction.vout[output_index];
        if (treasury.nValue == old_value) {
            return SetError(error, "canonical CTIP replacement has zero value delta");
        }
        if (treasury.nValue < old_value) {
            return SetError(error, "canonical CTIP decrease cannot be accepted without independent M6 vote validation");
        }

        std::vector<unsigned char> address;
        if (output_index + 1 >= transaction.vout.size() ||
            !ExtractSingleOpReturnPush(transaction.vout[output_index + 1].scriptPubKey, address)) {
            return SetError(error, "positive CTIP replacement has no exact following address commitment");
        }
        const CAmount delta = treasury.nValue - old_value;
        if (!MoneyRange(delta)) {
            return SetError(error, "parent CTIP increase is outside the money range");
        }
        state.ctip = Bitcoin::COutPoint(transaction.GetHash(), output_index);
        state.ctip_value = treasury.nValue;
        // The enforcer applies coinbase M2 activation before ordinary
        // transactions, so a later M5 in the activation block belongs to the
        // newly active Elements Drivechain proposal.
        if (deposits && required_proposal_active_for_transactions &&
            !address.empty() && address.size() <= 128) {
            deposits->push_back(DrivechainMintableDeposit{
                *state.ctip, block.GetHash(), height, delta, std::move(address)});
        }
    }

    if (state.required_proposal_activated &&
        state.active_proposal_hash != required_active_proposal) {
        return SetError(error, "parent slot no longer has the required active proposal");
    }
    CheckDrivechainParentDeadline();
    return true;
}

DrivechainDepositStatus GetConfirmedDrivechainDepositStatus(
    const uint256& mainchain_block_hash,
    const int sidechain_slot,
    const COutPoint& outpoint,
    const CAmount value,
    const std::vector<unsigned char>& address,
    std::string* error)
{
    if (error) error->clear();
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error) ||
        value <= 0 || !MoneyRange(value) || address.empty() || address.size() > 128) {
        if (error && error->empty()) *error = "invalid slot, amount, or address for drivechain deposit";
        return DrivechainDepositStatus::INVALID;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    if (!consensus.drivechain_proposal_hash.has_value() ||
        consensus.drivechain_proposal_hash->IsNull() ||
        consensus.drivechain_protocol_manifest_hash.IsNull() ||
        consensus.drivechain_parent_state_hash.IsNull() ||
        consensus.drivechain_parent_state_chainwork.IsNull() ||
        !consensus.drivechain_parent_state_active_proposal_hash.has_value() ||
        consensus.drivechain_parent_state_active_proposal_hash->IsNull() ||
        consensus.drivechain_parent_state_ctip_txid.IsNull() ||
        consensus.drivechain_parent_state_ctip_vout == std::numeric_limits<uint32_t>::max() ||
        consensus.drivechain_parent_state_ctip_value <= 0 ||
        consensus.drivechain_unused_slot_proposal_max_age == 0 ||
        consensus.drivechain_unused_slot_activation_threshold == 0 ||
        consensus.drivechain_used_slot_proposal_max_age == 0 ||
        consensus.drivechain_used_slot_activation_threshold == 0 ||
        consensus.drivechain_parent_state_replay_version != 2) {
        return SetDepositError(
            error, DrivechainDepositStatus::UNAVAILABLE,
            "native deposits require a complete immutable parent genesis-replay identity");
    }

    try {
        std::unique_lock<std::mutex> lock(
            g_drivechain_parent_replay_mutex, std::defer_lock);
        if (DrivechainParentBudgetActive()) {
            if (!lock.try_lock()) {
                return SetDepositError(
                    error, DrivechainDepositStatus::UNAVAILABLE,
                    "authenticated parent replay cache is busy warming");
            }
        } else {
            lock.lock();
        }

        DrivechainParentReplayCache& cache =
            g_drivechain_parent_replay_cache;
        if (!ReplayCacheMatchesConfiguredIdentity(cache, consensus)) {
            return SetDepositError(
                error, DrivechainDepositStatus::UNAVAILABLE,
                "authenticated parent replay cache is not warmed");
        }

        uint32_t confirmed_through_height{cache.height};
        uint64_t snapshot_epoch{cache.epoch};
        bool explicit_target{false};
        bool needs_standalone_tip_auth{true};
        if (DrivechainParentBudgetActive() &&
            g_drivechain_parent_budget.replay_snapshot_authenticated) {
            needs_standalone_tip_auth = false;
            confirmed_through_height =
                g_drivechain_parent_budget.replay_snapshot_height;
            snapshot_epoch =
                g_drivechain_parent_budget.replay_snapshot_epoch;
            explicit_target =
                g_drivechain_parent_budget.replay_snapshot_is_explicit_target;
            if (snapshot_epoch != cache.epoch) {
                return SetDepositError(
                    error, DrivechainDepositStatus::UNAVAILABLE,
                    "authenticated parent replay cache changed during validation");
            }
        }

        if (!RequireConfiguredElementsProposalActive(
                cache, confirmed_through_height, error)) {
            return DrivechainDepositStatus::UNAVAILABLE;
        }

        if (!g_drivechain_parent_replay_store) {
            return SetDepositError(
                error, DrivechainDepositStatus::UNAVAILABLE,
                "persistent authenticated parent replay index is not open");
        }
        DrivechainMintableDeposit deposit;
        const auto deposit_status =
            g_drivechain_parent_replay_store->ReadDeposit(
                Bitcoin::COutPoint(outpoint.hash, outpoint.n),
                deposit, error);
        if (deposit_status == DrivechainReplayStoreReadStatus::CORRUPT) {
            g_drivechain_parent_replay_published_epoch.store(
                0, std::memory_order_release);
            cache = {};
            g_drivechain_parent_replay_store_rebuild_required = true;
            return DrivechainDepositStatus::UNAVAILABLE;
        }
        if (deposit_status == DrivechainReplayStoreReadStatus::NOT_FOUND) {
            return SetDepositError(
                error,
                explicit_target ? DrivechainDepositStatus::INVALID
                                : DrivechainDepositStatus::UNAVAILABLE,
                explicit_target
                    ? "deposit is not a genesis-replay-derived canonical CTIP increase before the block's authenticated parent anchor"
                    : "deposit is not present in the currently warmed parent replay snapshot");
        }

        if (deposit.block_hash != mainchain_block_hash ||
            deposit.value != value || deposit.address != address) {
            return SetDepositError(
                error,
                explicit_target ? DrivechainDepositStatus::INVALID
                                : DrivechainDepositStatus::UNAVAILABLE,
                "deposit does not exactly match the genesis-replay-derived canonical CTIP increase");
        }
        if (deposit.block_height < cache.state.required_activation_height) {
            return SetDepositError(
                error,
                explicit_target ? DrivechainDepositStatus::INVALID
                                : DrivechainDepositStatus::UNAVAILABLE,
                strprintf(
                    "native deposit at parent height %u predates Elements proposal activation at height %u",
                    deposit.block_height, cache.state.required_activation_height));
        }

        const uint32_t required_depth =
            std::max<uint32_t>(1, consensus.pegin_min_depth);
        const bool sufficiently_deep =
            deposit.block_height <= confirmed_through_height &&
            confirmed_through_height - deposit.block_height >=
                required_depth - 1;
        if (!sufficiently_deep) {
            return SetDepositError(
                error,
                explicit_target ? DrivechainDepositStatus::INVALID
                                : DrivechainDepositStatus::UNAVAILABLE,
                strprintf(
                    "deposit at parent height %u does not have %u confirmations through authenticated parent height %u",
                    deposit.block_height, required_depth,
                    confirmed_through_height));
        }

        // Only a known, exact, activated, sufficiently deep deposit may cause
        // standalone mempool validation to touch parent RPC. Random claims are
        // rejected by the authenticated replay map above at in-memory cost.
        if (needs_standalone_tip_auth) {
            uint256 active_cache_hash;
            if (!ReadActiveMainchainHash(cache.height, active_cache_hash, error)) {
                return DrivechainDepositStatus::UNAVAILABLE;
            }
            if (active_cache_hash != cache.hash) {
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                return SetDepositError(
                    error, DrivechainDepositStatus::UNAVAILABLE,
                    "authenticated parent replay cache is stale after a parent reorganization");
            }
            if (DrivechainParentBudgetActive()) {
                RecordDrivechainReplaySnapshot(
                    cache.height, cache.hash, cache.epoch,
                    /*explicit_target=*/false);
            }
        }
        CheckDrivechainParentDeadline();
        return DrivechainDepositStatus::VALID;
    } catch (const std::exception& e) {
        return SetDepositError(error, DrivechainDepositStatus::UNAVAILABLE, e.what());
    }
}

bool IsConfirmedDrivechainDeposit(const uint256& mainchain_block_hash,
                                  const int sidechain_slot,
                                  const COutPoint& outpoint,
                                  const CAmount value,
                                  const std::vector<unsigned char>& address,
                                  std::string* error)
{
    return GetConfirmedDrivechainDepositStatus(mainchain_block_hash, sidechain_slot,
                                                outpoint, value, address, error) ==
           DrivechainDepositStatus::VALID;
}

bool ParseDrivechainParentHeader(const UniValue& header,
                                 const uint256& expected_hash,
                                 uint64_t& median_time_past,
                                 std::string* error)
{
    median_time_past = 0;
    if (!header.isObject()) {
        if (error) *error = "getblockheader result is not an object";
        return false;
    }

    const UniValue& hash = find_value(header.get_obj(), "hash");
    if (!hash.isStr() || hash.get_str().size() != 64 || !IsHex(hash.get_str())) {
        if (error) *error = "getblockheader result has no canonical 32-byte hash";
        return false;
    }
    if (hash.get_str() != expected_hash.GetHex() || uint256S(hash.get_str()) != expected_hash) {
        if (error) *error = strprintf("getblockheader returned hash %s, expected committed parent %s",
                                     hash.get_str(), expected_hash.GetHex());
        return false;
    }

    // Do not accept strings or a fallback `time` field.  This value becomes
    // consensus-visible, so only Bitcoin Core's numeric `mediantime` result is
    // accepted and it must fit the uint32 timestamps from which MTP is formed.
    const UniValue& mtp = find_value(header.get_obj(), "mediantime");
    if (!mtp.isNum()) {
        if (error) *error = "getblockheader result has no numeric mediantime";
        return false;
    }
    try {
        const int64_t parsed = mtp.get_int64();
        if (parsed < 0 || static_cast<uint64_t>(parsed) > std::numeric_limits<uint32_t>::max()) {
            if (error) *error = "getblockheader mediantime is outside the uint32 timestamp range";
            return false;
        }
        median_time_past = static_cast<uint64_t>(parsed);
    } catch (const std::exception&) {
        if (error) *error = "getblockheader mediantime is not a canonical integer";
        return false;
    }
    return true;
}

namespace {

bool ReadActiveMainchainHash(const uint32_t height, uint256& hash, std::string* error)
{
    UniValue params(UniValue::VARR);
    params.push_back(static_cast<int64_t>(height));
    const UniValue result = CallMainChainRPCChecked("getblockhash", params);
    if (!ParseCanonicalHash(result, hash)) {
        return SetError(error, strprintf("getblockhash(%u) returned a noncanonical hash", height));
    }
    return true;
}

bool HasPinnedDrivechainParentState(const Consensus::Params& consensus)
{
    return consensus.drivechain_slot.has_value() &&
           consensus.drivechain_proposal_hash.has_value() &&
           !consensus.drivechain_parent_state_hash.IsNull();
}

bool BlockContainsExactDrivechainMessage(const Bitcoin::CBlock& block,
                                         const std::vector<unsigned char>& expected_payload,
                                         std::string* error)
{
    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
        return SetError(error, "pinned parent identity block has no coinbase transaction");
    }
    size_t matches{0};
    for (const auto& output : block.vtx[0]->vout) {
        std::vector<unsigned char> payload;
        if (ExtractSingleOpReturnPush(output.scriptPubKey, payload) && payload == expected_payload) {
            ++matches;
        }
    }
    if (matches != 1) {
        return SetError(error, strprintf(
            "pinned parent identity block contains %u copies of its expected drivechain message",
            matches));
    }
    return true;
}

bool CheckDrivechainParentReplayMilestone(
    const Consensus::Params& consensus,
    const uint32_t height,
    const Bitcoin::CBlock& block,
    const DrivechainParentReplayState& state,
    std::string* error)
{
    const auto require_block_hash = [&](const uint256& expected) {
        return block.GetHash() == expected || SetError(error, strprintf(
            "authenticated parent milestone height %u hashes to %s, expected %s",
            height, block.GetHash().GetHex(), expected.GetHex()));
    };

    if (height == consensus.drivechain_parent_state_proposal_height) {
        if (!require_block_hash(consensus.drivechain_parent_state_proposal_block_hash)) {
            return false;
        }
        static constexpr std::array<uint8_t, 4> M1_TAG{{0xd5, 0xe0, 0xc4, 0xaf}};
        std::vector<unsigned char> expected_m1(M1_TAG.begin(), M1_TAG.end());
        expected_m1.push_back(*consensus.drivechain_slot);
        expected_m1.insert(
            expected_m1.end(),
            consensus.drivechain_parent_state_active_proposal_description.begin(),
            consensus.drivechain_parent_state_active_proposal_description.end());
        if (!BlockContainsExactDrivechainMessage(block, expected_m1, error)) return false;
        const auto proposal = state.pending_proposals.find(
            *consensus.drivechain_parent_state_active_proposal_hash);
        if (proposal == state.pending_proposals.end() ||
            proposal->second.proposal_height != height ||
            proposal->second.votes != 0) {
            return SetError(error,
                "authenticated parent proposal milestone did not derive the expected pending proposal state");
        }
    }

    if (height == consensus.drivechain_parent_state_activation_height) {
        if (!require_block_hash(consensus.drivechain_parent_state_activation_block_hash)) {
            return false;
        }
        static constexpr std::array<uint8_t, 4> M2_TAG{{0xd6, 0xe1, 0xc5, 0xdf}};
        std::vector<unsigned char> expected_m2(M2_TAG.begin(), M2_TAG.end());
        expected_m2.push_back(*consensus.drivechain_slot);
        expected_m2.insert(
            expected_m2.end(),
            consensus.drivechain_parent_state_active_proposal_hash->begin(),
            consensus.drivechain_parent_state_active_proposal_hash->end());
        if (!BlockContainsExactDrivechainMessage(block, expected_m2, error)) return false;
        if (state.active_proposal_hash !=
                *consensus.drivechain_parent_state_active_proposal_hash ||
            state.pending_proposals.count(
                *consensus.drivechain_parent_state_active_proposal_hash) != 0) {
            return SetError(error,
                "authenticated parent activation milestone did not derive the expected active proposal state");
        }
    }

    if (height == consensus.drivechain_parent_state_height) {
        if (!require_block_hash(consensus.drivechain_parent_state_hash)) return false;
        if (state.active_proposal_hash !=
                *consensus.drivechain_parent_state_active_proposal_hash ||
            !state.ctip ||
            state.ctip->hash != consensus.drivechain_parent_state_ctip_txid ||
            state.ctip->n != consensus.drivechain_parent_state_ctip_vout ||
            state.ctip_value != consensus.drivechain_parent_state_ctip_value) {
            return SetError(error,
                "authenticated parent checkpoint milestone did not derive the asserted active proposal and CTIP");
        }
    }
    return true;
}

uint256 DrivechainParentReplayStoreIdentity(const Consensus::Params& consensus)
{
    assert(consensus.drivechain_slot.has_value());
    assert(consensus.drivechain_proposal_hash.has_value());
    assert(consensus.drivechain_parent_state_active_proposal_hash.has_value());
    CHashWriter writer(SER_GETHASH, 0);
    writer << std::string{"ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V1"}
           << Params().HashGenesisBlock()
           << Params().ParentGenesisBlockHash()
           << consensus.parentChainPowLimit
           << consensus.parent_signet_challenge
           << consensus.pegin_min_depth
           << *consensus.drivechain_slot
           << consensus.drivechain_protocol_manifest_hash
           << consensus.drivechain_proposal_description
           << *consensus.drivechain_proposal_hash
           << consensus.drivechain_parent_state_active_proposal_description
           << *consensus.drivechain_parent_state_active_proposal_hash
           << consensus.drivechain_parent_state_proposal_height
           << consensus.drivechain_parent_state_proposal_block_hash
           << consensus.drivechain_parent_state_activation_height
           << consensus.drivechain_parent_state_activation_block_hash
           << consensus.drivechain_parent_state_height
           << consensus.drivechain_parent_state_hash
           << consensus.drivechain_parent_state_chainwork
           << consensus.drivechain_parent_state_ctip_txid
           << consensus.drivechain_parent_state_ctip_vout
           << consensus.drivechain_parent_state_ctip_value
           << consensus.drivechain_unused_slot_proposal_max_age
           << consensus.drivechain_unused_slot_activation_threshold
           << consensus.drivechain_used_slot_proposal_max_age
           << consensus.drivechain_used_slot_activation_threshold
           << consensus.drivechain_parent_state_replay_version;
    return writer.GetHash();
}

void ConfigureDrivechainParentReplayCacheIdentity(
    DrivechainParentReplayCache& cache,
    const Consensus::Params& consensus)
{
    cache = {};
    cache.initialized = true;
    cache.epoch = ++g_drivechain_parent_replay_epoch_counter;
    cache.slot = *consensus.drivechain_slot;
    cache.proposal_hash = *consensus.drivechain_proposal_hash;
    cache.checkpoint_active_proposal_hash =
        *consensus.drivechain_parent_state_active_proposal_hash;
    cache.checkpoint_hash = consensus.drivechain_parent_state_hash;
    cache.unused_proposal_max_age = consensus.drivechain_unused_slot_proposal_max_age;
    cache.unused_activation_threshold = consensus.drivechain_unused_slot_activation_threshold;
    cache.used_proposal_max_age = consensus.drivechain_used_slot_proposal_max_age;
    cache.used_activation_threshold = consensus.drivechain_used_slot_activation_threshold;
    cache.replay_version = consensus.drivechain_parent_state_replay_version;
}

bool InitializeDrivechainParentReplayCache(DrivechainParentReplayCache& cache,
                                           std::string* error,
                                           const bool force_rebuild = false)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!HasPinnedDrivechainParentState(consensus)) return true;
    if (consensus.drivechain_proposal_description.empty() ||
        consensus.drivechain_proposal_hash->IsNull() ||
        Hash(consensus.drivechain_proposal_description) != *consensus.drivechain_proposal_hash ||
        consensus.drivechain_protocol_manifest_hash.IsNull() ||
        consensus.drivechain_parent_state_active_proposal_description.empty() ||
        !consensus.drivechain_parent_state_active_proposal_hash ||
        Hash(consensus.drivechain_parent_state_active_proposal_description) !=
            *consensus.drivechain_parent_state_active_proposal_hash ||
        consensus.drivechain_parent_state_proposal_height >=
            consensus.drivechain_parent_state_activation_height ||
        consensus.drivechain_parent_state_activation_height >=
            consensus.drivechain_parent_state_height ||
        consensus.drivechain_parent_state_proposal_block_hash.IsNull() ||
        consensus.drivechain_parent_state_activation_block_hash.IsNull() ||
        consensus.drivechain_parent_state_chainwork.IsNull() ||
        consensus.drivechain_parent_state_ctip_txid.IsNull() ||
        consensus.drivechain_parent_state_ctip_vout == std::numeric_limits<uint32_t>::max() ||
        consensus.drivechain_parent_state_ctip_value <= 0 ||
        !MoneyRange(consensus.drivechain_parent_state_ctip_value) ||
        consensus.drivechain_unused_slot_proposal_max_age == 0 ||
        consensus.drivechain_unused_slot_activation_threshold == 0 ||
        consensus.drivechain_unused_slot_activation_threshold >=
            consensus.drivechain_unused_slot_proposal_max_age ||
        consensus.drivechain_used_slot_proposal_max_age == 0 ||
        consensus.drivechain_used_slot_activation_threshold == 0 ||
        consensus.drivechain_used_slot_activation_threshold >=
            consensus.drivechain_used_slot_proposal_max_age ||
        consensus.drivechain_parent_state_replay_version != 2) {
        return SetError(error, "native drivechain parent launch identity is incomplete or internally inconsistent");
    }

    uint256 active_genesis;
    if (!ReadActiveMainchainHash(0, active_genesis, error)) return false;
    if (active_genesis != Params().ParentGenesisBlockHash()) {
        return SetError(error, "mainchain RPC does not serve the pinned parent genesis");
    }

    Bitcoin::CBlock checkpoint_block;
    VerifiedMainchainHeader checkpoint_header;
    if (!ReadVerifiedMainchainBlock(consensus.drivechain_parent_state_hash, 1,
                                    checkpoint_block, checkpoint_header, error)) {
        return false;
    }
    if (checkpoint_header.height != consensus.drivechain_parent_state_height ||
        checkpoint_header.chainwork != consensus.drivechain_parent_state_chainwork) {
        return SetError(error, "authenticated parent launch checkpoint height or chainwork is not pinned value");
    }

    ConfigureDrivechainParentReplayCacheIdentity(cache, consensus);

    if (!g_drivechain_parent_replay_store) {
        g_drivechain_parent_replay_store =
            std::make_unique<DrivechainParentReplayStore>(
                gArgs.GetDataDirNet() / "parent-replay",
                DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES,
                /*wipe=*/gArgs.GetBoolArg("-reindex", false));
    }
    const uint256 store_identity =
        DrivechainParentReplayStoreIdentity(consensus);
    if (!force_rebuild &&
        !g_drivechain_parent_replay_store_rebuild_required) {
        DrivechainParentReplayTip stored_tip;
        std::string load_error;
        const DrivechainReplayStoreLoadStatus load_status =
            g_drivechain_parent_replay_store->Load(
                store_identity, stored_tip, &load_error);
        if (load_status == DrivechainReplayStoreLoadStatus::LOADED) {
            const bool contradicts_checkpoint =
                stored_tip.height >= consensus.drivechain_parent_state_height &&
                (stored_tip.state.active_proposal_hash.IsNull() ||
                 (stored_tip.state.required_proposal_activated &&
                  (stored_tip.state.active_proposal_hash != cache.proposal_hash ||
                   stored_tip.state.required_activation_block_hash.IsNull() ||
                   stored_tip.state.required_activation_height > stored_tip.height)) ||
                 !stored_tip.state.ctip ||
                 stored_tip.state.ctip_value <
                     consensus.drivechain_parent_state_ctip_value);
            if (!contradicts_checkpoint) {
                cache.height = stored_tip.height;
                cache.hash = stored_tip.hash;
                cache.state = std::move(stored_tip.state);
                return true;
            }
            LogPrintf("Discarding derived parent replay index whose tip contradicts the immutable launch checkpoint\n");
        }
        if (load_status == DrivechainReplayStoreLoadStatus::CORRUPT ||
            load_status == DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH) {
            LogPrintf("Discarding unusable derived parent replay index and rebuilding from authenticated genesis: %s\n",
                      load_error);
        }
    }

    Bitcoin::CBlock genesis_block;
    if (!ReadAuthenticatedRawMainchainBlock(active_genesis, genesis_block, error)) {
        cache = {};
        return false;
    }
    if (!genesis_block.hashPrevBlock.IsNull()) {
        cache = {};
        return SetError(error, "authenticated parent genesis unexpectedly has a predecessor");
    }
    DrivechainParentReplayState genesis_state;
    if (!ApplyDrivechainParentBlockState(
            genesis_block, 0, cache.slot, cache.proposal_hash,
            cache.unused_proposal_max_age, cache.unused_activation_threshold,
            cache.used_proposal_max_age, cache.used_activation_threshold,
            genesis_state, nullptr, error)) {
        cache = {};
        return false;
    }
    cache.height = 0;
    cache.hash = active_genesis;
    cache.state = std::move(genesis_state);
    if (!g_drivechain_parent_replay_store->Reset(
            store_identity,
            DrivechainParentReplayTip{cache.height, cache.hash, cache.state},
            error)) {
        cache = {};
        return false;
    }
    g_drivechain_parent_replay_store_rebuild_required = false;
    return true;
}

bool ReplayCacheMatchesConfiguredIdentity(const DrivechainParentReplayCache& cache,
                                          const Consensus::Params& consensus)
{
    return cache.initialized && consensus.drivechain_slot &&
           consensus.drivechain_proposal_hash &&
           cache.slot == *consensus.drivechain_slot &&
           cache.proposal_hash == *consensus.drivechain_proposal_hash &&
           cache.checkpoint_active_proposal_hash ==
               *consensus.drivechain_parent_state_active_proposal_hash &&
           cache.checkpoint_hash == consensus.drivechain_parent_state_hash &&
           cache.unused_proposal_max_age ==
               consensus.drivechain_unused_slot_proposal_max_age &&
           cache.unused_activation_threshold ==
               consensus.drivechain_unused_slot_activation_threshold &&
           cache.used_proposal_max_age ==
               consensus.drivechain_used_slot_proposal_max_age &&
           cache.used_activation_threshold ==
               consensus.drivechain_used_slot_activation_threshold &&
           cache.replay_version == consensus.drivechain_parent_state_replay_version;
}

bool RequireConfiguredElementsProposalActive(
    const DrivechainParentReplayCache& cache,
    const uint32_t target_height,
    std::string* error)
{
    if (!cache.state.required_proposal_activated ||
        cache.state.active_proposal_hash != cache.proposal_hash ||
        target_height < cache.state.required_activation_height) {
        return SetError(error, strprintf(
            "configured Elements slot proposal is not active at parent height %u",
            target_height));
    }
    return true;
}

bool EnsurePinnedDrivechainParentStateThroughLocked(const uint32_t target_height,
                                                    const uint256& target_hash,
                                                    const bool require_elements_active,
                                                    DrivechainParentReplayCache& cache,
                                                    std::string* error)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!HasPinnedDrivechainParentState(consensus)) return true;
    if (target_height < consensus.drivechain_parent_state_height) {
        return SetError(error, strprintf(
            "parent height %u predates native drivechain launch checkpoint %u",
            target_height, consensus.drivechain_parent_state_height));
    }

    // Never initialize or rebuild a potentially long replay while the caller
    // holds sidechain consensus locks. The background warmer owns that work;
    // locked validation fails closed and retries after the snapshot is ready.
    if (!ReplayCacheMatchesConfiguredIdentity(cache, consensus)) {
        if (DrivechainParentBudgetActive()) {
            return SetError(error, "authenticated parent replay cache is not warmed");
        }
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        cache = {};
        if (!InitializeDrivechainParentReplayCache(cache, error)) return false;
    }

    uint256 active_checkpoint;
    if (!ReadActiveMainchainHash(consensus.drivechain_parent_state_height,
                                 active_checkpoint, error)) {
        return false;
    }
    if (active_checkpoint != consensus.drivechain_parent_state_hash) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        return SetError(error, "active parent chain no longer contains the pinned drivechain launch checkpoint");
    }

    uint256 active_cache_hash;
    bool stale_cache = cache.height > target_height;
    if (!stale_cache) {
        if (!ReadActiveMainchainHash(cache.height, active_cache_hash, error)) return false;
        stale_cache = active_cache_hash != cache.hash;
    }
    if (stale_cache) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        if (DrivechainParentBudgetActive()) {
            return SetError(error, "authenticated parent replay cache is stale after a parent reorganization");
        }
        cache = {};
        // This LevelDB is only a derived cache. A reorg must never reload its
        // now-stale tip; rebuild it from authenticated parent genesis instead.
        if (!InitializeDrivechainParentReplayCache(
                cache, error, /*force_rebuild=*/true)) {
            return false;
        }
    }

    uint256 active_target;
    if (!ReadActiveMainchainHash(target_height, active_target, error)) return false;
    if (active_target != target_hash) {
        return SetError(error, "requested parent replay target is not active at its claimed height");
    }

    if (target_height > cache.height) {
        const uint32_t replay_steps = target_height - cache.height;
        if (!ConsumeDrivechainReplayBudget(replay_steps, error)) return false;
        for (uint32_t height = cache.height + 1; height <= target_height; ++height) {
            CheckDrivechainParentDeadline();
            uint256 block_hash;
            if (!ReadActiveMainchainHash(height, block_hash, error)) return false;
            Bitcoin::CBlock block;
            if (!ReadAuthenticatedRawMainchainBlock(block_hash, block, error)) return false;
            if (block.hashPrevBlock != cache.hash) {
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                return SetError(error, "authenticated parent-state replay is not a contiguous chain");
            }

            DrivechainParentReplayState next_state = cache.state;
            std::vector<DrivechainMintableDeposit> deposits;
            if (!ApplyDrivechainParentBlockState(
                    block, height, cache.slot, cache.proposal_hash,
                    consensus.drivechain_unused_slot_proposal_max_age,
                    consensus.drivechain_unused_slot_activation_threshold,
                    consensus.drivechain_used_slot_proposal_max_age,
                    consensus.drivechain_used_slot_activation_threshold,
                    next_state, &deposits, error)) {
                // The raw active parent block is authenticated, so a pure
                // state-transition rejection is a deterministic global halt
                // (including replacement of the required Elements proposal).
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                return false;
            }
            if (!CheckDrivechainParentReplayMilestone(
                    consensus, height, block, next_state, error)) {
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                return false;
            }
            CheckDrivechainParentDeadline();
            std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>> replayed_edge;
            if (height > consensus.drivechain_parent_state_height) {
                uint256 committed_sidechain_hash;
                const bool has_canonical_commitment =
                    ExtractCanonicalDrivechainBmmCommitmentInBlock(
                        block, cache.slot, committed_sidechain_hash,
                        nullptr, nullptr);
                replayed_edge.emplace(
                    cache.hash,
                    DrivechainReplayedBmmEdge{
                        block_hash, height - 1, height,
                        has_canonical_commitment,
                        committed_sidechain_hash});
            }

            // Commit the durable tip and all records in one synced batch. A
            // write failure must leave the in-memory replay at its old tip.
            if (!g_drivechain_parent_replay_store ||
                !g_drivechain_parent_replay_store->Append(
                    DrivechainParentReplayTip{
                        cache.height, cache.hash, cache.state},
                    DrivechainParentReplayTip{
                        height, block_hash, next_state},
                    deposits, replayed_edge, error)) {
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                return false;
            }
            cache.state = std::move(next_state);
            cache.height = height;
            cache.hash = block_hash;
        }
    }

    // Bracket every replay with active-chain reads.  If a reorg raced any raw
    // block request, the exact target or cached tip can no longer both match.
    if (!ReadActiveMainchainHash(consensus.drivechain_parent_state_height,
                                 active_checkpoint, error)) {
        return false;
    }
    if (active_checkpoint != consensus.drivechain_parent_state_hash) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        return SetError(error, "parent-chain reorg raced the pinned launch checkpoint check");
    }
    if (!ReadActiveMainchainHash(target_height, active_target, error)) {
        return false;
    }
    if (active_target != target_hash) {
        g_drivechain_parent_replay_published_epoch.store(
            0, std::memory_order_release);
        return SetError(error, "parent-chain reorg raced the replay target check");
    }
    uint256 final_active_cache_hash;
    if (!ReadActiveMainchainHash(cache.height, final_active_cache_hash, error)) {
        return false;
    }
    if (final_active_cache_hash != cache.hash) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        return SetError(error, "parent-chain reorg raced the replay cache tip check");
    }
    if (require_elements_active &&
        !RequireConfiguredElementsProposalActive(cache, target_height, error)) {
        return false;
    }
    CheckDrivechainParentDeadline();
    g_drivechain_parent_replay_published_epoch.store(
        cache.epoch, std::memory_order_release);
    return true;
}

bool EnsurePinnedDrivechainParentStateThrough(const uint32_t target_height,
                                              const uint256& target_hash,
                                              const bool require_elements_active,
                                              std::string* error)
{
    std::unique_lock<std::mutex> lock(g_drivechain_parent_replay_mutex, std::defer_lock);
    if (DrivechainParentBudgetActive()) {
        if (!lock.try_lock()) {
            return SetError(error, "authenticated parent replay cache is busy warming");
        }
    } else {
        lock.lock();
    }
    const bool authenticated = EnsurePinnedDrivechainParentStateThroughLocked(
        target_height, target_hash, require_elements_active,
        g_drivechain_parent_replay_cache, error);
    if (authenticated) {
        RecordDrivechainReplaySnapshot(
            target_height, target_hash,
            g_drivechain_parent_replay_cache.epoch,
            /*explicit_target=*/true);
    }
    return authenticated;
}

bool GetDrivechainParentContextForHash(const uint256& parent_hash,
                                       DrivechainParentBlockContext& context,
                                       std::string* error)
{
    context = {};
    Bitcoin::CBlock parent_block;
    VerifiedMainchainHeader parent;
    if (!ReadVerifiedMainchainBlock(parent_hash, 1, parent_block, parent, error)) return false;
    if (!EnsurePinnedDrivechainParentStateThrough(
            parent.height, parent_hash, /* require_elements_active= */ true, error)) {
        return false;
    }

    context.parent_hash = parent_hash;
    context.parent_chainwork = parent.chainwork;
    context.parent_height = parent.height;
    context.parent_median_time_past = parent.median_time_past;
    return true;
}

DrivechainBmmStatus SetBmmError(std::string* error,
                                const DrivechainBmmStatus status,
                                const std::string& message)
{
    if (error) *error = message;
    return status;
}

static constexpr size_t DRIVECHAIN_BMM_EDGE_CACHE_MAX{8};
static constexpr size_t DRIVECHAIN_BMM_NEGATIVE_PARENT_CACHE_MAX{64};
static constexpr auto DRIVECHAIN_BMM_NEGATIVE_PARENT_TTL{std::chrono::seconds{5}};

struct DrivechainBmmEdgeCacheEntry {
    uint64_t replay_epoch{0};
    uint256 parent_hash;
    uint256 successor_hash;
    uint8_t slot{0};
    DrivechainBmmBlockContext context;
    bool has_canonical_commitment{false};
    uint256 committed_sidechain_hash;
    std::string rejection_reason;
};

struct DrivechainBmmNegativeParentCacheEntry {
    uint64_t replay_epoch{0};
    uint256 parent_hash;
    uint8_t slot{0};
    std::string rejection_reason;
    std::chrono::steady_clock::time_point expires;
};

std::mutex g_drivechain_bmm_edge_cache_mutex;
std::deque<DrivechainBmmEdgeCacheEntry> g_drivechain_bmm_edge_cache;
std::deque<DrivechainBmmNegativeParentCacheEntry> g_drivechain_bmm_negative_parent_cache;

void PruneDrivechainBmmCachesForEpoch(const uint64_t replay_epoch)
{
    const auto now = std::chrono::steady_clock::now();
    const auto wrong_edge_epoch = [replay_epoch](const auto& entry) {
        return entry.replay_epoch != replay_epoch;
    };
    g_drivechain_bmm_edge_cache.erase(
        std::remove_if(g_drivechain_bmm_edge_cache.begin(),
                       g_drivechain_bmm_edge_cache.end(), wrong_edge_epoch),
        g_drivechain_bmm_edge_cache.end());
    g_drivechain_bmm_negative_parent_cache.erase(
        std::remove_if(g_drivechain_bmm_negative_parent_cache.begin(),
                       g_drivechain_bmm_negative_parent_cache.end(),
                       [replay_epoch, now](const auto& entry) {
                           return entry.replay_epoch != replay_epoch ||
                                  entry.expires <= now;
                       }),
        g_drivechain_bmm_negative_parent_cache.end());
}

void CacheRejectedDrivechainParent(const uint64_t replay_epoch,
                                   const uint256& parent_hash,
                                   const uint8_t slot,
                                   const std::string& reason)
{
    g_drivechain_bmm_negative_parent_cache.push_back(
        {replay_epoch, parent_hash, slot, reason,
         std::chrono::steady_clock::now() + DRIVECHAIN_BMM_NEGATIVE_PARENT_TTL});
    if (g_drivechain_bmm_negative_parent_cache.size() >
        DRIVECHAIN_BMM_NEGATIVE_PARENT_CACHE_MAX) {
        g_drivechain_bmm_negative_parent_cache.pop_front();
    }
}

enum class DrivechainParentProbeStatus {
    ACTIVE,
    REJECTED,
    UNAVAILABLE,
};

DrivechainParentProbeStatus ProbeActiveDrivechainParent(
    const uint256& parent_hash,
    uint32_t& parent_height,
    std::string* error)
{
    parent_height = 0;
    UniValue params(UniValue::VARR);
    params.push_back(parent_hash.GetHex());
    params.push_back(true);
    const UniValue reply = CallMainChainRPC("getblockheader", params);
    const UniValue& rpc_error = find_value(reply, "error");
    if (!rpc_error.isNull()) {
        if (rpc_error.isObject()) {
            const UniValue& code = find_value(rpc_error.get_obj(), "code");
            if (code.isNum() && code.get_int64() == -5) {
                if (error) *error = "committed parent hash is unknown to the authenticated parent node";
                return DrivechainParentProbeStatus::REJECTED;
            }
        }
        if (error) *error = strprintf("getblockheader returned error: %s", rpc_error.write());
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }

    const UniValue& result = find_value(reply, "result");
    if (!result.isObject()) {
        if (error) *error = "getblockheader returned no canonical metadata object";
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    uint256 returned_hash;
    const UniValue& height = find_value(result.get_obj(), "height");
    const UniValue& confirmations = find_value(result.get_obj(), "confirmations");
    if (!ParseCanonicalHash(find_value(result.get_obj(), "hash"), returned_hash) ||
        returned_hash != parent_hash || !height.isNum() || !confirmations.isNum()) {
        if (error) *error = "getblockheader returned noncanonical parent metadata";
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    const int64_t parsed_height = height.get_int64();
    const int64_t parsed_confirmations = confirmations.get_int64();
    if (parsed_height < 0 || parsed_height > std::numeric_limits<uint32_t>::max()) {
        if (error) *error = "committed parent height is outside the supported uint32 range";
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    parent_height = static_cast<uint32_t>(parsed_height);
    if (parsed_confirmations <= 0) {
        if (error) *error = "committed parent block is not on the active parent chain";
        return DrivechainParentProbeStatus::REJECTED;
    }
    uint256 active_hash;
    if (!ReadActiveMainchainHash(parent_height, active_hash, error)) {
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    if (active_hash != parent_hash) {
        if (error) *error = "committed parent block is not active at its declared height";
        return DrivechainParentProbeStatus::REJECTED;
    }
    return DrivechainParentProbeStatus::ACTIVE;
}

bool RecheckActiveBmmEdge(const uint256& parent_hash,
                          const uint32_t parent_height,
                          const uint256& successor_hash,
                          const uint32_t successor_height,
                          std::string* error)
{
    uint256 active_hash;
    if (!ReadActiveMainchainHash(parent_height, active_hash, error)) return false;
    if (active_hash != parent_hash) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        return SetError(error, "parent-chain reorg raced BIP301 validation at committed P");
    }
    if (!ReadActiveMainchainHash(successor_height, active_hash, error)) return false;
    if (active_hash != successor_hash) {
        g_drivechain_parent_replay_published_epoch.store(0, std::memory_order_release);
        return SetError(error, "parent-chain reorg raced BIP301 validation at successor Q");
    }
    return true;
}

DrivechainBmmStatus GetDrivechainBmmContextForHashesStatus(
    const uint256& sidechain_block_hash,
    const uint256& parent_hash,
    const int sidechain_slot,
    DrivechainBmmBlockContext& context,
    std::string* error)
{
    context = {};

    std::unique_lock<std::mutex> cache_lock(
        g_drivechain_bmm_edge_cache_mutex, std::defer_lock);
    if (DrivechainParentBudgetActive()) {
        if (!cache_lock.try_lock()) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "authenticated BMM edge cache is busy");
        }
    } else {
        cache_lock.lock();
    }

    const uint64_t replay_epoch = GetDrivechainParentReplayEpoch();
    if (replay_epoch == 0) {
        g_drivechain_bmm_edge_cache.clear();
        g_drivechain_bmm_negative_parent_cache.clear();
        return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                           "authenticated parent replay cache is not current");
    }
    PruneDrivechainBmmCachesForEpoch(replay_epoch);

    const uint8_t slot = static_cast<uint8_t>(sidechain_slot);
    for (auto it = g_drivechain_bmm_edge_cache.rbegin();
         it != g_drivechain_bmm_edge_cache.rend(); ++it) {
        if (it->parent_hash != parent_hash || it->slot != slot) continue;
        // Reject nonmatching candidate bytes entirely in memory. Rechecking
        // P/Q first would let arbitrary child hashes amplify two parent RPCs.
        // Because a background-observed reorg may have made this cached edge
        // stale, this cheap result is UNAVAILABLE and never peer blame.
        if (!it->has_canonical_commitment) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                "cached parent edge has no unique canonical M7; await a fresh authenticated edge");
        }
        if (it->committed_sidechain_hash != sidechain_block_hash) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                "candidate hash does not match the cached canonical M7; no parent RPC performed");
        }
        if (!RecheckActiveBmmEdge(
                it->parent_hash, it->context.parent_height,
                it->successor_hash, it->context.bmm_height, error)) {
            return DrivechainBmmStatus::UNAVAILABLE;
        }
        const uint64_t rechecked_epoch = GetDrivechainParentReplayEpoch();
        if (rechecked_epoch == 0 || rechecked_epoch != it->replay_epoch) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "parent replay epoch changed while rechecking cached BMM edge");
        }
        // Deposit validity for this child must be bounded by this exact Q,
        // never by a warmer replay tip. Mirror the cold path's explicit
        // snapshot so cache state cannot change consensus results.
        RecordDrivechainReplaySnapshot(
            it->context.bmm_height, it->successor_hash,
            rechecked_epoch, /*explicit_target=*/true);
        context = it->context;
        return DrivechainBmmStatus::VALID;
    }

    // Untrusted P2P cache misses may consult only the background-authenticated
    // genesis replay index. Unknown P values, edges without one canonical M7,
    // and wrong child hashes return without any parent RPC. Only the exact
    // indexed child commitment is allowed through to full live P/Q auth.
    if (DrivechainUntrustedParentAdmissionActive()) {
        std::unique_lock<std::mutex> replay_lock(
            g_drivechain_parent_replay_mutex, std::defer_lock);
        if (!replay_lock.try_lock()) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "authenticated parent replay index is busy warming");
        }
        const DrivechainParentReplayCache& replay_cache =
            g_drivechain_parent_replay_cache;
        if (!ReplayCacheMatchesConfiguredIdentity(
                replay_cache, Params().GetConsensus()) ||
            replay_cache.epoch != replay_epoch) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "authenticated parent replay index changed during admission");
        }
        if (!g_drivechain_parent_replay_store) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "persistent authenticated parent replay index is not open");
        }
        DrivechainReplayedBmmEdge indexed;
        const auto indexed_status =
            g_drivechain_parent_replay_store->ReadBmmEdge(
                parent_hash, indexed, error);
        if (indexed_status == DrivechainReplayStoreReadStatus::CORRUPT) {
            g_drivechain_parent_replay_published_epoch.store(
                0, std::memory_order_release);
            g_drivechain_parent_replay_cache = {};
            g_drivechain_parent_replay_store_rebuild_required = true;
            return DrivechainBmmStatus::UNAVAILABLE;
        }
        if (indexed_status == DrivechainReplayStoreReadStatus::NOT_FOUND) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "committed parent edge is not in the warmed authenticated replay index");
        }
        if (indexed.successor_height > replay_cache.height ||
            indexed.parent_height >= indexed.successor_height) {
            g_drivechain_parent_replay_published_epoch.store(
                0, std::memory_order_release);
            g_drivechain_parent_replay_cache = {};
            g_drivechain_parent_replay_store_rebuild_required = true;
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "persistent parent replay BMM edge lies beyond its durable tip");
        }
        if (!indexed.has_canonical_commitment ||
            indexed.committed_sidechain_hash != sidechain_block_hash) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                               "candidate does not match the warmed authenticated parent-edge M7 index");
        }
    }

    if (!DrivechainUntrustedParentAdmissionActive()) {
        for (const auto& rejected : g_drivechain_bmm_negative_parent_cache) {
            if (rejected.parent_hash == parent_hash && rejected.slot == slot) {
                return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                    rejected.rejection_reason + "; cached briefly without parent RPC");
            }
        }
    }
    uint32_t probed_parent_height{0};
    const DrivechainParentProbeStatus probe_status = ProbeActiveDrivechainParent(
        parent_hash, probed_parent_height, error);
    if (probe_status == DrivechainParentProbeStatus::UNAVAILABLE) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    if (probe_status == DrivechainParentProbeStatus::REJECTED) {
        const std::string reason = error ? *error :
            "committed parent hash is not on the active parent chain";
        CacheRejectedDrivechainParent(replay_epoch, parent_hash, slot, reason);
        return DrivechainBmmStatus::PARENT_REJECTED;
    }
    if (probed_parent_height <
        Params().GetConsensus().drivechain_parent_state_height) {
        const std::string reason = strprintf(
            "committed parent height %u predates the Elements launch checkpoint %u",
            probed_parent_height,
            Params().GetConsensus().drivechain_parent_state_height);
        CacheRejectedDrivechainParent(replay_epoch, parent_hash, slot, reason);
        return SetBmmError(error, DrivechainBmmStatus::PARENT_REJECTED, reason);
    }

    DrivechainParentBlockContext parent_context;
    if (!GetDrivechainParentContextForHash(parent_hash, parent_context, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    if (parent_context.parent_height == std::numeric_limits<uint32_t>::max()) {
        return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                           "committed parent height has no representable successor");
    }

    uint256 successor_hash;
    if (!ReadActiveMainchainHash(parent_context.parent_height + 1, successor_hash, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }

    Bitcoin::CBlock successor_block;
    VerifiedMainchainHeader successor;
    if (!ReadVerifiedMainchainBlock(successor_hash, 1, successor_block, successor, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    if (!EnsurePinnedDrivechainParentStateThrough(
            successor.height, successor_hash, /* require_elements_active= */ true, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    if (successor.height != parent_context.parent_height + 1 ||
        successor.header.hashPrevBlock != parent_hash) {
        return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                           strprintf("active parent block %s is not the exact successor of committed parent %s",
                                     successor_hash.GetHex(), parent_hash.GetHex()));
    }

    VerifiedMainchainHeader parent;
    // Chainwork continuity is authenticated again using the successor's raw
    // nBits.  The parent's full raw block and chainwork were verified above.
    parent.chainwork = parent_context.parent_chainwork;
    parent.height = parent_context.parent_height;
    if (!CheckParentChainworkStep(parent, successor, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }

    uint256 committed_sidechain_hash;
    std::string commitment_error;
    const bool has_canonical_commitment =
        ExtractCanonicalDrivechainBmmCommitmentInBlock(
            successor_block, sidechain_slot, committed_sidechain_hash,
            nullptr, &commitment_error);

    // The M7 result is deterministic only for this exact active P -> Q edge.
    // Recheck both heights after parsing Q so a racing reorg is never mistaken
    // for either success or a parent rejection.
    if (!RecheckActiveBmmEdge(parent_hash, parent_context.parent_height,
                              successor_hash, successor.height, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }

    static_cast<DrivechainParentBlockContext&>(context) = parent_context;
    context.bmm_block_hash = successor_hash;
    context.bmm_chainwork = successor.chainwork;
    context.bmm_height = successor.height;

    const uint64_t final_replay_epoch = GetDrivechainParentReplayEpoch();
    if (final_replay_epoch == 0 || final_replay_epoch != replay_epoch) {
        return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                           "authenticated parent replay epoch changed during BMM validation");
    }
    g_drivechain_bmm_edge_cache.push_back(DrivechainBmmEdgeCacheEntry{
        final_replay_epoch, parent_hash, successor_hash, slot, context,
        has_canonical_commitment, committed_sidechain_hash,
        commitment_error});
    if (g_drivechain_bmm_edge_cache.size() > DRIVECHAIN_BMM_EDGE_CACHE_MAX) {
        g_drivechain_bmm_edge_cache.pop_front();
    }

    if (!has_canonical_commitment) {
        return SetBmmError(error, DrivechainBmmStatus::PARENT_REJECTED,
                           commitment_error);
    }
    if (committed_sidechain_hash != sidechain_block_hash) {
        return SetBmmError(error, DrivechainBmmStatus::PARENT_REJECTED,
            strprintf("BMM successor commits to sidechain block %s, expected %s",
                      committed_sidechain_hash.GetHex(),
                      sidechain_block_hash.GetHex()));
    }
    return DrivechainBmmStatus::VALID;
}

DrivechainAnchorStatus SetAnchorError(std::string* error,
                                      const DrivechainAnchorStatus status,
                                      const std::string& message)
{
    if (error) *error = message;
    return status;
}

DrivechainDepositStatus SetDepositError(std::string* error,
                                        const DrivechainDepositStatus status,
                                        const std::string& message)
{
    if (error) *error = message;
    return status;
}

} // namespace

uint64_t GetDrivechainParentReplayEpoch()
{
    return g_drivechain_parent_replay_published_epoch.load(
        std::memory_order_acquire);
}

bool WarmDrivechainParentState(std::string* error)
{
    if (error) error->clear();
    if (!Params().GetConsensus().drivechain_slot.has_value()) return true;

    try {
        UniValue no_params(UniValue::VARR);
        const UniValue height_value = CallMainChainRPCChecked("getblockcount", no_params);
        if (!height_value.isNum()) {
            return SetError(error, "parent getblockcount returned a non-numeric height");
        }
        const int64_t height = height_value.get_int64();
        if (height < 0 || height > std::numeric_limits<uint32_t>::max()) {
            return SetError(error, "parent tip height is outside the supported uint32 range");
        }

        UniValue hash_params(UniValue::VARR);
        hash_params.push_back(height);
        const UniValue hash_value = CallMainChainRPCChecked("getblockhash", hash_params);
        uint256 tip_hash;
        if (!ParseCanonicalHash(hash_value, tip_hash)) {
            return SetError(error, "parent getblockhash returned a noncanonical hash");
        }
        return EnsurePinnedDrivechainParentStateThrough(
            static_cast<uint32_t>(height), tip_hash,
            /* require_elements_active= */ false, error);
    } catch (const std::exception& e) {
        return SetError(error, e.what());
    }
}

bool GetDrivechainParentBlockContext(const CBlock& block,
                                     const int sidechain_slot,
                                     DrivechainParentBlockContext& context,
                                     std::string* error)
{
    context = {};
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) return false;
    uint256 parent_hash;
    if (!ExtractDrivechainParentHashFromBlock(block, parent_hash, error)) return false;
    try {
        return GetDrivechainParentContextForHash(parent_hash, context, error);
    } catch (const std::exception& e) {
        return SetError(error, e.what());
    }
}

bool GetDrivechainParentBlockContext(const CBlock& block,
                                     const int sidechain_slot,
                                     DrivechainBmmBlockContext& context,
                                     std::string* error)
{
    context = {};
    DrivechainParentBlockContext parent_context;
    if (!GetDrivechainParentBlockContext(block, sidechain_slot, parent_context, error)) return false;
    static_cast<DrivechainParentBlockContext&>(context) = parent_context;
    return true;
}

bool GetDrivechainBmmBlockContext(const CBlock& block,
                                  const int sidechain_slot,
                                  DrivechainBmmBlockContext& context,
                                  std::string* error)
{
    const DrivechainBmmStatus status =
        GetDrivechainBmmBlockStatus(block, sidechain_slot, context, error);
    if (status != DrivechainBmmStatus::VALID) context = {};
    return status == DrivechainBmmStatus::VALID;
}

DrivechainBmmStatus GetDrivechainBmmBlockStatus(const CBlock& block,
                                                const int sidechain_slot,
                                                DrivechainBmmBlockContext& context,
                                                std::string* error)
{
    context = {};
    if (error) error->clear();
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    uint256 parent_hash;
    if (!ExtractDrivechainParentHashFromBlock(block, parent_hash, error)) {
        return DrivechainBmmStatus::INVALID;
    }
    try {
        return GetDrivechainBmmContextForHashesStatus(
            block.GetHash(), parent_hash, sidechain_slot, context, error);
    } catch (const std::exception& e) {
        return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE, e.what());
    }
}

DrivechainAnchorStatus IsDrivechainAnchorActive(const DrivechainAnchor& anchor,
                                                const int sidechain_slot,
                                                std::string* error)
{
    if (error) error->clear();
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) {
        return DrivechainAnchorStatus::UNAVAILABLE;
    }
    if (!anchor.IsSane()) {
        return SetAnchorError(error, DrivechainAnchorStatus::UNAVAILABLE,
                              "persisted drivechain anchor is malformed");
    }

    try {
        // These are the only observations allowed to classify an anchor as
        // orphaned.  Every other failure stalls reconciliation safely.
        uint256 active_parent_hash;
        if (!ReadActiveMainchainHash(anchor.parent_height, active_parent_hash, error)) {
            return DrivechainAnchorStatus::UNAVAILABLE;
        }
        if (active_parent_hash != anchor.parent_block_hash) {
            return SetAnchorError(error, DrivechainAnchorStatus::ORPHANED,
                strprintf("parent height %u now contains %s, persisted anchor contains %s",
                          anchor.parent_height, active_parent_hash.GetHex(), anchor.parent_block_hash.GetHex()));
        }

        uint256 active_successor_hash;
        if (!ReadActiveMainchainHash(anchor.bmm_height, active_successor_hash, error)) {
            return DrivechainAnchorStatus::UNAVAILABLE;
        }
        if (active_successor_hash != anchor.bmm_block_hash) {
            return SetAnchorError(error, DrivechainAnchorStatus::ORPHANED,
                strprintf("parent height %u now contains %s, persisted BMM anchor contains %s",
                          anchor.bmm_height, active_successor_hash.GetHex(), anchor.bmm_block_hash.GetHex()));
        }

        // Re-read and authenticate both raw blocks after the height checks.
        // A reorg racing these calls is UNAVAILABLE for this pass, never a
        // rollback signal.
        Bitcoin::CBlock parent_block;
        Bitcoin::CBlock successor_block;
        VerifiedMainchainHeader parent;
        VerifiedMainchainHeader successor;
        if (!ReadVerifiedMainchainBlock(anchor.parent_block_hash, 1, parent_block, parent, error) ||
            !ReadVerifiedMainchainBlock(anchor.bmm_block_hash, 1, successor_block, successor, error)) {
            return DrivechainAnchorStatus::UNAVAILABLE;
        }
        if (!EnsurePinnedDrivechainParentStateThrough(
                successor.height, anchor.bmm_block_hash,
                /* require_elements_active= */ true, error)) {
            return DrivechainAnchorStatus::UNAVAILABLE;
        }
        if (parent.height != anchor.parent_height || successor.height != anchor.bmm_height ||
            successor.header.hashPrevBlock != anchor.parent_block_hash ||
            parent.chainwork != anchor.parent_chainwork || successor.chainwork != anchor.bmm_chainwork ||
            parent.median_time_past != anchor.parent_median_time_past ||
            !CheckParentChainworkStep(parent, successor, error)) {
            if (error && error->empty()) *error = "persisted drivechain anchor context disagrees with authenticated parent blocks";
            return DrivechainAnchorStatus::UNAVAILABLE;
        }
        return DrivechainAnchorStatus::ACTIVE;
    } catch (const std::exception& e) {
        return SetAnchorError(error, DrivechainAnchorStatus::UNAVAILABLE, e.what());
    }
}

CScript CreateDrivechainParentCommitmentScript(const uint256& parent_hash)
{
    const auto& tag = ElementsDrivechainIdentity::PARENT_COMMITMENT_TAG;
    std::vector<unsigned char> payload(tag.begin(), tag.end());
    // The child block has historically serialized its committed Bitcoin hash
    // in uint256's internal byte order.  Freeze that order explicitly here.
    payload.insert(payload.end(), parent_hash.begin(), parent_hash.end());
    return CScript() << OP_RETURN << payload;
}

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error)
{
    parent_hash.SetNull();
    if (block.vtx.empty() || !block.vtx[0] || !block.vtx[0]->IsCoinBase()) {
        return SetError(error, "block has no coinbase transaction");
    }

    const auto& tag = ElementsDrivechainIdentity::PARENT_COMMITMENT_TAG;
    static constexpr uint8_t P_PAYLOAD_SIZE{
        ElementsDrivechainIdentity::PARENT_COMMITMENT_TAG.size() + uint256::size()};
    static constexpr size_t P_SCRIPT_SIZE{1 + 1 + P_PAYLOAD_SIZE};
    bool found = false;
    for (const CTxOut& txout : block.vtx[0]->vout) {
        const CScript& script = txout.scriptPubKey;
        CScript::const_iterator pc = script.begin();
        opcodetype opcode;
        std::vector<unsigned char> pushed;
        if (!script.GetOp(pc, opcode, pushed) || opcode != OP_RETURN ||
            !script.GetOp(pc, opcode, pushed) || pushed.size() < tag.size() ||
            !std::equal(tag.begin(), tag.end(), pushed.begin())) {
            continue;
        }

        // Once the reserved domain tag is present, there is exactly one
        // accepted encoding.  Do not ignore a second nonminimal or trailing
        // tagged form beside a canonical commitment: different parsers could
        // otherwise disagree about P.
        if (script.size() != P_SCRIPT_SIZE || script[0] != OP_RETURN ||
            script[1] != P_PAYLOAD_SIZE || pc != script.end()) {
            return SetError(error, "block coinbase contains a noncanonical ELMTP parent commitment");
        }

        if (found) {
            return SetError(error, "block coinbase contains multiple canonical drivechain parent commitments");
        }
        parent_hash = uint256(&script[2 + tag.size()], uint256::size());
        found = true;
    }

    if (!found && error) {
        *error = "block coinbase does not contain one canonical ELMTP drivechain parent commitment";
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
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) return false;
    try {
        DrivechainBmmBlockContext context;
        return GetDrivechainBmmContextForHashesStatus(
                   sidechain_block_hash, parent_hash, sidechain_slot,
                   context, error) == DrivechainBmmStatus::VALID;
    } catch (const std::exception& e) {
        return SetError(error, e.what());
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
