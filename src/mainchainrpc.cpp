#include <mainchainrpc.h>
#include <init.h>
#include <elements_drivechain_bootstrap.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <logging.h>
#include <chainparamsbase.h>
#include <consensus/merkle.h>
#include <drivechain_parent_replay.h>
#include <elements_drivechain_identity.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <script/script.h>
#include <signet.h>
#include <streams.h>
#include <util/signalinterrupt.h>
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
thread_local std::optional<std::chrono::steady_clock::time_point> g_drivechain_anchor_warm_deadline;
thread_local const util::SignalInterrupt* g_drivechain_anchor_warm_interrupt{nullptr};
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
    if (g_drivechain_anchor_warm_deadline.has_value()) {
        if (g_drivechain_anchor_warm_interrupt && *g_drivechain_anchor_warm_interrupt) {
            throw CConnectionFailed("drivechain anchor snapshot authentication interrupted");
        }
        if (std::chrono::steady_clock::now() >= *g_drivechain_anchor_warm_deadline) {
            throw CConnectionFailed("drivechain anchor snapshot authentication deadline exhausted");
        }
    }
    if (DrivechainParentBudgetActive() &&
        std::chrono::steady_clock::now() >= g_drivechain_parent_budget.deadline) {
        throw CConnectionFailed("drivechain parent validation work budget exhausted");
    }
}

std::string GetMainchainRPCCredentials()
{
    const bool private_file = gArgs.IsArgSet("-mainchainrpccredentialfile");
    if (private_file && (gArgs.IsArgSet("-mainchainrpccookiefile") ||
                         gArgs.IsArgSet("-mainchainrpcuser") ||
                         gArgs.IsArgSet("-mainchainrpcpassword"))) {
        throw std::runtime_error("select exactly one parent RPC authentication mechanism");
    }
    if (Params().GetConsensus().drivechain_slot.has_value() &&
        (gArgs.IsArgSet("-mainchainrpcuser") || gArgs.IsArgSet("-mainchainrpcpassword"))) {
        throw std::runtime_error("native parent RPC requires a rotating cookie or an explicit private credential file, not inline credentials");
    }
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
    std::string credential_error;
    if (private_file) {
        if (!IsMainchainRPCHostAllowed(gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT), true) ||
            !ReadMainchainRpcCredentialFile(
                fs::PathFromString(gArgs.GetArg("-mainchainrpccredentialfile", "")),
                loaded_cookie, &credential_error)) {
            throw std::runtime_error("cannot load private loopback parent RPC credentials: " + credential_error);
        }
    } else if (!GetMainchainAuthCookie(&loaded_cookie)) {
        throw std::runtime_error("cannot load the parent's private canonical rotating RPC cookie");
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
    int status{0};
    int error{-1};
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

    if (req == nullptr) {
        /* If req is nullptr, it means an error occurred while connecting: the
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
    } else if (g_drivechain_anchor_warm_deadline.has_value()) {
        auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            *g_drivechain_anchor_warm_deadline - std::chrono::steady_clock::now());
        if (remaining <= std::chrono::microseconds::zero()) {
            throw CConnectionFailed("drivechain anchor snapshot authentication deadline exhausted");
        }
        const int64_t configured = gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT);
        // Zero/negative means no configured timeout. The aggregate deadline
        // still applies, even when a caller configured an arbitrarily long RPC.
        if (configured > 0 && configured < std::chrono::ceil<std::chrono::seconds>(remaining).count()) {
            remaining = std::chrono::seconds{configured};
        }
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
        timeval timeout{};
        timeout.tv_sec = seconds.count();
        timeout.tv_usec = (remaining - seconds).count();
        evhttp_connection_set_timeout_tv(evcon.get(), &timeout);
    } else {
        evhttp_connection_set_timeout(
            evcon.get(), gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));
    }

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == nullptr)
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
        DataStream stream{ParseHex(raw.get_str())};
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
    if (!ParseCanonicalHash(metadata.get_obj()["hash"], returned_hash) || returned_hash != expected_hash) {
        return SetError(error, "getblockheader hash does not match requested parent block");
    }
    const UniValue& height = metadata.get_obj()["height"];
    const UniValue& confirmations = metadata.get_obj()["confirmations"];
    const UniValue& chainwork = metadata.get_obj()["chainwork"];
    uint256 parsed_chainwork;
    if (!height.isNum() || !confirmations.isNum() || !ParseCanonicalHash(chainwork, parsed_chainwork)) {
        return SetError(error, "getblockheader is missing canonical height, confirmations, or chainwork");
    }
    const int64_t parsed_height = height.getInt<int64_t>();
    const int64_t parsed_confirmations = confirmations.getInt<int64_t>();
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

    const UniValue& previous = metadata.get_obj()["previousblockhash"];
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
        const UniValue& previous_height = previous_metadata.get_obj()["height"];
        if (!ParseCanonicalHash(previous_metadata.get_obj()["hash"], returned_previous_hash) ||
            returned_previous_hash != previous_hash ||
            !ParseCanonicalHash(previous_metadata.get_obj()["chainwork"], previous_chainwork) ||
            !previous_height.isNum() || previous_height.getInt<int64_t>() != parsed_height - 1) {
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
        DataStream stream{ParseHex(raw.get_str())};
        stream >> TX_WITH_WITNESS(block);
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
    WITHDRAWAL_PROPOSAL,
    WITHDRAWAL_ACK,
    BMM_ACCEPT,
};

enum class DrivechainM4Encoding {
    NONE,
    REPEAT_PREVIOUS,
    EXPLICIT,
    LEADING_BY_50,
};

struct DrivechainParentMessage {
    DrivechainParentMessageType type{DrivechainParentMessageType::NONE};
    uint8_t slot{0};
    uint256 proposal_hash;
    DrivechainM4Encoding m4_encoding{DrivechainM4Encoding::NONE};
    std::vector<uint16_t> m4_votes;
};

struct DrivechainM8BmmRequest {
    uint8_t slot{0};
    uint256 sidechain_block_hash;
    uint256 previous_mainchain_block_hash;
};

/**
 * Parse exactly the M8 encoding recognized by the pinned enforcer's
 * M8BmmRequest::parse: the first transaction output is
 *
 *   OP_RETURN || PUSHBYTES_68 || 00bf00 || slot || h* || previous_parent
 *
 * Unlike coinbase-message parsing, the enforcer does not accept alternate push
 * opcodes for M8. A malformed lookalike is therefore an ordinary transaction,
 * not an invalid M8 request.
 */
bool ExtractDrivechainM8BmmRequest(const Bitcoin::CTransaction& transaction,
                                   DrivechainM8BmmRequest& request)
{
    static constexpr std::array<uint8_t, 3> M8_TAG{{0x00, 0xbf, 0x00}};
    static constexpr uint8_t M8_PAYLOAD_SIZE{
        M8_TAG.size() + 1 + uint256::size() + uint256::size()};
    static constexpr size_t M8_SCRIPT_SIZE{1 + 1 + M8_PAYLOAD_SIZE};

    if (transaction.vout.empty()) return false;
    const CScript& script = transaction.vout[0].scriptPubKey;
    if (script.size() != M8_SCRIPT_SIZE || script[0] != OP_RETURN ||
        script[1] != M8_PAYLOAD_SIZE ||
        !std::equal(M8_TAG.begin(), M8_TAG.end(), script.begin() + 2)) {
        return false;
    }

    request.slot = script[2 + M8_TAG.size()];
    auto sidechain_hash_begin = script.begin() + 2 + M8_TAG.size() + 1;
    // The enforcer's `critical_hash` gRPC field is ConsensusHex. Its opaque
    // BmmCommitment bytes are therefore the display-order hash supplied by
    // the sidechain, unlike the following Bitcoin BlockHash which is encoded
    // in rust-bitcoin's internal consensus byte order.
    std::reverse_copy(sidechain_hash_begin,
                      sidechain_hash_begin + uint256::size(),
                      request.sidechain_block_hash.begin());
    std::copy(sidechain_hash_begin + uint256::size(),
              script.end(),
              request.previous_mainchain_block_hash.begin());
    return true;
}

DrivechainParentMessage ParseDrivechainParentMessage(const CScript& script)
{
    static constexpr std::array<uint8_t, 4> M1_TAG{{0xd5, 0xe0, 0xc4, 0xaf}};
    static constexpr std::array<uint8_t, 4> M2_TAG{{0xd6, 0xe1, 0xc5, 0xdf}};
    static constexpr std::array<uint8_t, 4> M3_TAG{{0xd4, 0x5a, 0xa9, 0x43}};
    static constexpr std::array<uint8_t, 4> M4_TAG{{0xd7, 0x7d, 0x17, 0x76}};
    static constexpr std::array<uint8_t, 4> M7_TAG{{0xd1, 0x61, 0x73, 0x68}};

    std::vector<unsigned char> payload;
    if (!ExtractSingleOpReturnPush(script, payload) || payload.size() < 5) return {};
    if (std::equal(M1_TAG.begin(), M1_TAG.end(), payload.begin())) {
        const std::vector<unsigned char> description(payload.begin() + 5, payload.end());
        return {DrivechainParentMessageType::PROPOSAL, payload[4], Hash(description),
                DrivechainM4Encoding::NONE, {}};
    }
    if (payload.size() == M2_TAG.size() + 1 + uint256::size() &&
        std::equal(M2_TAG.begin(), M2_TAG.end(), payload.begin())) {
        uint256 proposal_hash;
        std::copy(payload.begin() + 5, payload.end(), proposal_hash.begin());
        return {DrivechainParentMessageType::ACK, payload[4], proposal_hash,
                DrivechainM4Encoding::NONE, {}};
    }
    if (payload.size() == M3_TAG.size() + 1 + uint256::size() &&
        std::equal(M3_TAG.begin(), M3_TAG.end(), payload.begin())) {
        uint256 m6id;
        std::copy(payload.begin() + 5, payload.end(), m6id.begin());
        return {DrivechainParentMessageType::WITHDRAWAL_PROPOSAL, payload[4], m6id,
                DrivechainM4Encoding::NONE, {}};
    }
    if (std::equal(M4_TAG.begin(), M4_TAG.end(), payload.begin())) {
        DrivechainParentMessage message;
        message.type = DrivechainParentMessageType::WITHDRAWAL_ACK;
        switch (payload[4]) {
        case 0:
            if (payload.size() != 5) return {};
            message.m4_encoding = DrivechainM4Encoding::REPEAT_PREVIOUS;
            return message;
        case 1:
            message.m4_encoding = DrivechainM4Encoding::EXPLICIT;
            for (size_t i = 5; i < payload.size(); ++i) {
                if (payload[i] == 0xff) {
                    message.m4_votes.push_back(0xffff);
                } else if (payload[i] == 0xfe) {
                    message.m4_votes.push_back(0xfffe);
                } else {
                    message.m4_votes.push_back(payload[i]);
                }
            }
            return message;
        case 2:
            if (((payload.size() - 5) & 1U) != 0) return {};
            message.m4_encoding = DrivechainM4Encoding::EXPLICIT;
            for (size_t i = 5; i < payload.size(); i += 2) {
                message.m4_votes.push_back(
                    static_cast<uint16_t>(payload[i]) |
                    (static_cast<uint16_t>(payload[i + 1]) << 8));
            }
            // Two-byte M4 is noncanonical and invalid unless at least one vote
            // requires more than the one-byte representation.
            if (std::all_of(message.m4_votes.begin(), message.m4_votes.end(),
                            [](uint16_t vote) { return vote <= 253; })) {
                message.m4_encoding = DrivechainM4Encoding::NONE;
            }
            return message;
        case 3:
            if (payload.size() != 5) return {};
            message.m4_encoding = DrivechainM4Encoding::LEADING_BY_50;
            return message;
        default:
            return {};
        }
    }
    if (payload.size() == M7_TAG.size() + 1 + uint256::size() &&
        std::equal(M7_TAG.begin(), M7_TAG.end(), payload.begin())) {
        uint256 commitment;
        // BmmCommitment is an opaque ConsensusHex byte array in the pinned
        // enforcer, so the M7 payload carries the sidechain's display-order
        // hash rather than a bitcoin::Hash internal byte array.
        std::reverse_copy(payload.begin() + 5, payload.end(), commitment.begin());
        return {DrivechainParentMessageType::BMM_ACCEPT, payload[4], commitment,
                DrivechainM4Encoding::NONE, {}};
    }
    return {};
}

DrivechainDepositStatus SetDepositError(std::string* error,
                                        DrivechainDepositStatus status,
                                        const std::string& message);

bool ReadActiveMainchainHash(uint32_t height, uint256& hash, std::string* error);
bool ReadActiveMainchainHeight(uint32_t& height, std::string* error);

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
    uint16_t withdrawal_bundle_max_age{0};
    uint16_t withdrawal_bundle_inclusion_threshold{0};
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

    // The pinned enforcer parses exactly OP_RETURN followed by one push, but
    // intentionally uses Script::instructions() rather than its minimal-push
    // variant. Match every push opcode it recognizes, not only PUSHBYTES_37.
    static constexpr std::array<uint8_t, 4> M7_TAG{{0xd1, 0x61, 0x73, 0x68}};
    static constexpr uint8_t M7_PAYLOAD_SIZE{M7_TAG.size() + 1 + uint256::size()};
    size_t matches{0};
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
        matched_index = static_cast<uint32_t>(i);
        // See ExtractDrivechainM8BmmRequest: M7 repeats the opaque
        // display-order BmmCommitment accepted through ConsensusHex.
        std::reverse_copy(payload.begin() + M7_TAG.size() + 1,
                          payload.end(), parsed_hash.begin());
    }

    if (matches == 0) {
        return SetError(error, strprintf(
            "BMM successor has no enforcer-recognized M7 for sidechain slot %d",
            sidechain_slot));
    }
    if (matches != 1) {
        return SetError(error, strprintf(
            "BMM successor has %u enforcer-recognized M7 outputs for sidechain slot %d",
            matches, sidechain_slot));
    }
    committed_sidechain_hash = parsed_hash;
    if (output_index) *output_index = matched_index;
    return true;
}

bool MatchDrivechainBmmCommitmentInBlock(const Bitcoin::CBlock& block,
                                         const int sidechain_slot,
                                         const uint256& expected_critical_hash,
                                         uint32_t* output_index,
                                         std::string* error)
{
    uint256 committed_hash;
    if (!ExtractCanonicalDrivechainBmmCommitmentInBlock(
            block, sidechain_slot, committed_hash, output_index, error)) {
        return false;
    }
    // ConsensusHex carries the opaque BmmCommitment in display order. The
    // parser normalizes those bytes into the node's internal uint256 order
    // before this comparison.
    if (committed_hash != expected_critical_hash) {
        return SetError(error, strprintf(
            "BMM successor commits to critical hash %s, expected %s",
            committed_hash.GetHex(), expected_critical_hash.GetHex()));
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

namespace {

DrivechainOtherSlotReplayState& OtherSlotState(DrivechainParentReplayState& state,
                                                const uint8_t slot,
                                                const uint8_t configured_slot)
{
    assert(slot != configured_slot);
    return state.other_slots[slot];
}

uint256& SlotActiveProposal(DrivechainParentReplayState& state,
                            const uint8_t slot,
                            const uint8_t configured_slot)
{
    return slot == configured_slot
        ? state.active_proposal_hash
        : OtherSlotState(state, slot, configured_slot).active_proposal_hash;
}

std::map<uint256, DrivechainPendingProposal>& SlotPendingProposals(
    DrivechainParentReplayState& state,
    const uint8_t slot,
    const uint8_t configured_slot)
{
    return slot == configured_slot
        ? state.pending_proposals
        : OtherSlotState(state, slot, configured_slot).pending_proposals;
}

std::vector<DrivechainPendingWithdrawal>& SlotPendingWithdrawals(
    DrivechainParentReplayState& state,
    const uint8_t slot,
    const uint8_t configured_slot)
{
    return slot == configured_slot
        ? state.pending_withdrawals
        : OtherSlotState(state, slot, configured_slot).pending_withdrawals;
}

std::optional<Bitcoin::COutPoint>& SlotCtip(DrivechainParentReplayState& state,
                                            const uint8_t slot,
                                            const uint8_t configured_slot)
{
    return slot == configured_slot
        ? state.ctip
        : OtherSlotState(state, slot, configured_slot).ctip;
}

CAmount& SlotCtipValue(DrivechainParentReplayState& state,
                       const uint8_t slot,
                       const uint8_t configured_slot)
{
    return slot == configured_slot
        ? state.ctip_value
        : OtherSlotState(state, slot, configured_slot).ctip_value;
}

std::vector<uint8_t> ActiveDrivechainSlots(const DrivechainParentReplayState& state,
                                           const uint8_t configured_slot)
{
    std::vector<uint8_t> active;
    if (!state.active_proposal_hash.IsNull()) active.push_back(configured_slot);
    for (const auto& [slot, slot_state] : state.other_slots) {
        if (!slot_state.active_proposal_hash.IsNull()) active.push_back(slot);
    }
    std::sort(active.begin(), active.end());
    return active;
}

bool ExtractDrivechainTreasurySlot(const CScript& script, uint8_t& slot)
{
    if (script.size() != 4 || script[0] != OP_NOP5 || script[1] != 0x01 ||
        script[3] != OP_TRUE) {
        return false;
    }
    slot = script[2];
    return true;
}

bool ApplyM4Upvote(std::vector<DrivechainPendingWithdrawal>& pending,
                   const uint256& m6id,
                   DrivechainM4Action& effective,
                   std::string* error)
{
    auto target = std::find_if(pending.begin(), pending.end(), [&](const auto& entry) {
        return entry.m6id == m6id;
    });
    if (target == pending.end()) {
        return SetError(error, strprintf(
            "M4 upvote references missing withdrawal bundle %s", m6id.GetHex()));
    }
    if (target->votes == std::numeric_limits<uint16_t>::max()) return true;
    ++target->votes;
    for (auto& entry : pending) {
        if (&entry != &*target && entry.votes > 0) --entry.votes;
    }
    effective = {DrivechainM4ActionType::UPVOTE, m6id};
    return true;
}

bool ApplyM4Alarm(std::vector<DrivechainPendingWithdrawal>& pending,
                  DrivechainM4Action& effective)
{
    bool changed{false};
    for (auto& entry : pending) {
        if (entry.votes > 0) {
            --entry.votes;
            changed = true;
        }
    }
    if (changed) effective = {DrivechainM4ActionType::ALARM, {}};
    return changed;
}

} // namespace

bool ComputeDrivechainM6Id(const Bitcoin::CTransaction& transaction,
                           const CAmount previous_treasury_value,
                           uint256& m6id,
                           uint8_t* sidechain_slot,
                           std::string* error)
{
    m6id.SetNull();
    if (transaction.vout.empty()) {
        return SetError(error, "BIP300 M6 has no replacement treasury output");
    }
    uint8_t parsed_slot{0};
    if (!ExtractDrivechainTreasurySlot(transaction.vout[0].scriptPubKey, parsed_slot)) {
        return SetError(error, "BIP300 M6 replacement treasury output is not vout 0");
    }
    if (transaction.vin.size() != 1) {
        return SetError(error, "BIP300 M6 must contain exactly one treasury input");
    }
    if (previous_treasury_value < 0 || !MoneyRange(previous_treasury_value) ||
        transaction.vout[0].nValue < 0 || !MoneyRange(transaction.vout[0].nValue)) {
        return SetError(error, "BIP300 M6 treasury amount is outside the money range");
    }

    CAmount payout{0};
    for (size_t i = 1; i < transaction.vout.size(); ++i) {
        const CAmount value = transaction.vout[i].nValue;
        if (value < 0 || !MoneyRange(value) || value > MAX_MONEY - payout) {
            return SetError(error, "BIP300 M6 payout total is outside the money range");
        }
        payout += value;
    }
    if (transaction.vout[0].nValue > previous_treasury_value ||
        payout > previous_treasury_value - transaction.vout[0].nValue) {
        return SetError(error, "BIP300 M6 spends more than the previous treasury value");
    }
    const CAmount fee = previous_treasury_value - transaction.vout[0].nValue - payout;
    const uint64_t fee_unsigned = static_cast<uint64_t>(fee);
    std::vector<unsigned char> fee_bytes(8);
    for (size_t i = 0; i < fee_bytes.size(); ++i) {
        fee_bytes[i] = static_cast<unsigned char>(fee_unsigned >> (8 * (7 - i)));
    }

    Bitcoin::CMutableTransaction blinded(transaction);
    blinded.vin.clear();
    blinded.vout[0] = Bitcoin::CTxOut(0, CScript() << OP_RETURN << fee_bytes);
    m6id = blinded.GetHash();
    if (sidechain_slot) *sidechain_slot = parsed_slot;
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
    const uint16_t withdrawal_bundle_max_age,
    const uint16_t withdrawal_bundle_inclusion_threshold,
    DrivechainParentReplayState& state,
    std::vector<DrivechainMintableDeposit>* deposits,
    std::string* error,
    std::vector<DrivechainSuccessfulWithdrawal>* successful_withdrawals,
    std::vector<DrivechainWithdrawalProposalIdentity>* withdrawal_proposals)
{
    CheckDrivechainParentDeadline();
    if (deposits) deposits->clear();
    if (successful_withdrawals) successful_withdrawals->clear();
    if (withdrawal_proposals) withdrawal_proposals->clear();
    std::vector<DrivechainSuccessfulWithdrawal> derived_withdrawals;
    std::vector<DrivechainWithdrawalProposalIdentity> derived_proposals;
    const uint8_t configured_slot = static_cast<uint8_t>(sidechain_slot);
    if (sidechain_slot < 0 || sidechain_slot > std::numeric_limits<uint8_t>::max() ||
        required_active_proposal.IsNull() ||
        unused_slot_proposal_max_age == 0 ||
        unused_slot_activation_threshold == 0 ||
        unused_slot_activation_threshold >= unused_slot_proposal_max_age ||
        used_slot_proposal_max_age == 0 || used_slot_activation_threshold == 0 ||
        used_slot_activation_threshold >= used_slot_proposal_max_age ||
        withdrawal_bundle_max_age == 0 ||
        withdrawal_bundle_inclusion_threshold == 0 ||
        withdrawal_bundle_inclusion_threshold >= withdrawal_bundle_max_age) {
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
    for (const auto& [slot, slot_state] : state.other_slots) {
        if (slot == configured_slot ||
            (slot_state.active_proposal_hash.IsNull() && slot_state.ctip) ||
            (slot_state.ctip &&
             (slot_state.ctip_value < 0 || !MoneyRange(slot_state.ctip_value))) ||
            (!slot_state.ctip && slot_state.ctip_value != 0)) {
            return SetError(error, "parent-state replay began with malformed global slot state");
        }
    }
    for (const auto& [slot, action] : state.previous_m4_actions) {
        if ((action.type != DrivechainM4ActionType::UPVOTE &&
             action.type != DrivechainM4ActionType::ALARM) ||
            (action.type == DrivechainM4ActionType::ALARM && !action.m6id.IsNull())) {
            return SetError(error, strprintf("parent-state replay has malformed prior M4 action for slot %u", slot));
        }
    }

    // Parse the complete ordered coinbase message stream first. The enforcer
    // rejects duplicate M1/M2/M4/M7 messages globally, even for slots this
    // Elements chain does not use directly.
    std::vector<DrivechainParentMessage> messages;
    std::set<std::pair<uint8_t, uint256>> m1_messages;
    std::set<uint8_t> m2_slots;
    std::set<uint8_t> m7_slots;
    std::map<uint8_t, uint256> accepted_bmm_requests;
    bool saw_m4{false};
    for (size_t output_index = 0; output_index < block.vtx[0]->vout.size(); ++output_index) {
        if ((output_index & 0xffU) == 0) CheckDrivechainParentDeadline();
        DrivechainParentMessage message =
            ParseDrivechainParentMessage(block.vtx[0]->vout[output_index].scriptPubKey);
        if (message.type == DrivechainParentMessageType::NONE) continue;
        if (message.type == DrivechainParentMessageType::PROPOSAL &&
            !m1_messages.emplace(message.slot, message.proposal_hash).second) {
            return SetError(error, "parent block contains a duplicate M1 proposal message");
        }
        if (message.type == DrivechainParentMessageType::ACK &&
            !m2_slots.insert(message.slot).second) {
            return SetError(error, "parent block contains multiple M2 ACK messages for one slot");
        }
        if (message.type == DrivechainParentMessageType::WITHDRAWAL_ACK && saw_m4) {
            return SetError(error, "parent block contains multiple M4 withdrawal ACK messages");
        }
        if (message.type == DrivechainParentMessageType::WITHDRAWAL_ACK) saw_m4 = true;
        if (message.type == DrivechainParentMessageType::BMM_ACCEPT &&
            !m7_slots.insert(message.slot).second) {
            return SetError(error, "parent block contains multiple M7 commitments for one slot");
        }
        if (message.type == DrivechainParentMessageType::BMM_ACCEPT) {
            accepted_bmm_requests.emplace(message.slot, message.proposal_hash);
        }
        messages.push_back(std::move(message));
    }

    // The enforcer validates every recognized M8 after constructing the M7 map
    // for this exact block. Do this before mutating replay state so a rejected
    // block cannot leave a partially applied state in callers or tests.
    for (size_t transaction_index = 1; transaction_index < block.vtx.size(); ++transaction_index) {
        CheckDrivechainParentDeadline();
        DrivechainM8BmmRequest request;
        if (!ExtractDrivechainM8BmmRequest(*block.vtx[transaction_index], request)) continue;
        const auto accepted = accepted_bmm_requests.find(request.slot);
        if (accepted == accepted_bmm_requests.end() ||
            accepted->second != request.sidechain_block_hash) {
            return SetError(error, strprintf(
                "BIP301 M8 for slot %u was not accepted by this block's M7",
                request.slot));
        }
        if (request.previous_mainchain_block_hash != block.hashPrevBlock) {
            return SetError(error, strprintf(
                "BIP301 M8 for slot %u references an expired parent block",
                request.slot));
        }
    }

    std::map<uint8_t, DrivechainM4Action> effective_m4_actions;
    for (const DrivechainParentMessage& message : messages) {
        CheckDrivechainParentDeadline();
        if (message.type == DrivechainParentMessageType::BMM_ACCEPT) continue;

        if (message.type == DrivechainParentMessageType::PROPOSAL) {
            auto& pending = SlotPendingProposals(state, message.slot, configured_slot);
            if (pending.count(message.proposal_hash) == 0) {
                pending.emplace(message.proposal_hash, DrivechainPendingProposal{height, 0});
            }
            continue;
        }

        if (message.type == DrivechainParentMessageType::ACK) {
            auto& pending = SlotPendingProposals(state, message.slot, configured_slot);
            auto proposal = pending.find(message.proposal_hash);
            if (proposal == pending.end() || proposal->second.proposal_height == height) {
                // Unknown ACKs and ACKs in the proposal's own block are ignored.
                continue;
            }
            if (proposal->second.proposal_height > height) {
                return SetError(error, "M2 proposal height is ahead of replay height");
            }
            ++proposal->second.votes;
            uint256& active = SlotActiveProposal(state, message.slot, configured_slot);
            const bool used = !active.IsNull();
            const uint16_t max_age = used
                ? used_slot_proposal_max_age
                : unused_slot_proposal_max_age;
            const uint16_t threshold = used
                ? used_slot_activation_threshold
                : unused_slot_activation_threshold;
            const uint32_t age = height - proposal->second.proposal_height;
            if (proposal->second.votes > threshold && age <= max_age) {
                active = message.proposal_hash;
                pending.erase(proposal);
                if (message.slot == configured_slot) {
                    if (state.required_proposal_activated && active != required_active_proposal) {
                        return SetError(error, strprintf(
                            "parent slot %d was replaced by proposal %s",
                            sidechain_slot, active.GetHex()));
                    }
                    if (!state.required_proposal_activated && active == required_active_proposal) {
                        state.required_proposal_activated = true;
                        state.required_activation_height = height;
                        state.required_activation_block_hash = block.GetHash();
                    }
                }
            }
            continue;
        }

        if (message.type == DrivechainParentMessageType::WITHDRAWAL_PROPOSAL) {
            if (SlotActiveProposal(state, message.slot, configured_slot).IsNull()) {
                return SetError(error, strprintf(
                    "M3 proposes a withdrawal for inactive sidechain slot %u", message.slot));
            }
            auto& pending = SlotPendingWithdrawals(state, message.slot, configured_slot);
            if (std::any_of(pending.begin(), pending.end(), [&](const auto& entry) {
                    return entry.m6id == message.proposal_hash;
                })) {
                return SetError(error, strprintf(
                    "M3 withdrawal bundle %s is already pending for slot %u",
                    message.proposal_hash.GetHex(), message.slot));
            }
            derived_proposals.push_back(
                DrivechainWithdrawalProposalIdentity{
                    message.slot, message.proposal_hash});
            pending.push_back(DrivechainPendingWithdrawal{
                message.proposal_hash, height, 1});
            continue;
        }

        if (message.type != DrivechainParentMessageType::WITHDRAWAL_ACK) {
            return SetError(error, "unhandled BIP300 parent coinbase message");
        }
        if (message.m4_encoding == DrivechainM4Encoding::NONE) {
            return SetError(error, "two-byte M4 contains no value requiring two-byte encoding");
        }

        const std::vector<uint8_t> active_slots =
            ActiveDrivechainSlots(state, configured_slot);
        if (message.m4_encoding == DrivechainM4Encoding::EXPLICIT) {
            if (message.m4_votes.size() != active_slots.size()) {
                return SetError(error, strprintf(
                    "M4 vote vector has %u entries for %u active sidechains",
                    message.m4_votes.size(), active_slots.size()));
            }
            for (size_t i = 0; i < active_slots.size(); ++i) {
                const uint8_t slot = active_slots[i];
                const uint16_t vote = message.m4_votes[i];
                if (vote == 0xffff) continue;
                auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
                DrivechainM4Action action;
                bool effective{false};
                if (vote == 0xfffe) {
                    effective = ApplyM4Alarm(pending, action);
                } else {
                    if (vote >= pending.size()) {
                        return SetError(error, strprintf(
                            "M4 vote index %u is absent for sidechain slot %u", vote, slot));
                    }
                    if (!ApplyM4Upvote(pending, pending[vote].m6id, action, error)) return false;
                    effective = action.type == DrivechainM4ActionType::UPVOTE;
                }
                if (effective) effective_m4_actions.emplace(slot, action);
            }
        } else if (message.m4_encoding == DrivechainM4Encoding::LEADING_BY_50) {
            for (const uint8_t slot : active_slots) {
                auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
                if (pending.empty()) continue;
                size_t leader{0};
                uint16_t second{0};
                for (size_t i = 1; i < pending.size(); ++i) {
                    if (pending[i].votes > pending[leader].votes) {
                        second = std::max(second, pending[leader].votes);
                        leader = i;
                    } else {
                        second = std::max(second, pending[i].votes);
                    }
                }
                const uint16_t lead = pending[leader].votes;
                if (lead >= second && static_cast<uint16_t>(lead - second) >= 50 &&
                    lead < std::numeric_limits<uint16_t>::max()) {
                    const uint256 m6id = pending[leader].m6id;
                    DrivechainM4Action action;
                    if (!ApplyM4Upvote(pending, m6id, action, error)) return false;
                    effective_m4_actions.emplace(slot, action);
                }
            }
        } else {
            // Repeat only the prior block's effective actions, rebuilding the
            // downvote/alarm set against current pending state.
            for (const auto& [slot, previous] : state.previous_m4_actions) {
                if (SlotActiveProposal(state, slot, configured_slot).IsNull()) {
                    return SetError(error, strprintf(
                        "RepeatPrevious references inactive sidechain slot %u", slot));
                }
                auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
                DrivechainM4Action action;
                bool effective{false};
                if (previous.type == DrivechainM4ActionType::UPVOTE) {
                    if (!ApplyM4Upvote(pending, previous.m6id, action, error)) return false;
                    effective = action.type == DrivechainM4ActionType::UPVOTE;
                } else {
                    effective = ApplyM4Alarm(pending, action);
                }
                if (effective) effective_m4_actions.emplace(slot, action);
            }
        }
    }
    // No M4 means the next RepeatPrevious repeats an empty effective action.
    state.previous_m4_actions = std::move(effective_m4_actions);

    const auto expire_proposals = [&](const uint8_t slot,
                                      std::map<uint256, DrivechainPendingProposal>& pending,
                                      const bool used) -> bool {
        const uint16_t max_age = used
            ? used_slot_proposal_max_age
            : unused_slot_proposal_max_age;
        const uint16_t threshold = used
            ? used_slot_activation_threshold
            : unused_slot_activation_threshold;
        for (auto proposal = pending.begin(); proposal != pending.end();) {
            if (height < proposal->second.proposal_height) {
                return SetError(error, strprintf(
                    "parent proposal height is ahead of replay height for slot %u", slot));
            }
            const uint32_t age = height - proposal->second.proposal_height;
            if (proposal->second.votes > age) {
                return SetError(error, strprintf(
                    "parent proposal has more votes than elapsed blocks for slot %u", slot));
            }
            const uint32_t misses = age - proposal->second.votes;
            const uint32_t max_fails = max_age - threshold;
            if (age > max_age || (age > max_fails && misses >= max_fails)) {
                proposal = pending.erase(proposal);
            } else {
                ++proposal;
            }
        }
        return true;
    };
    if (!expire_proposals(configured_slot, state.pending_proposals,
                          !state.active_proposal_hash.IsNull())) {
        return false;
    }
    for (auto& [slot, slot_state] : state.other_slots) {
        if (!expire_proposals(slot, slot_state.pending_proposals,
                              !slot_state.active_proposal_hash.IsNull())) {
            return false;
        }
    }

    // M6 proposals fail only after their maximum age, following M4 processing.
    for (const uint8_t slot : ActiveDrivechainSlots(state, configured_slot)) {
        auto& pending = SlotPendingWithdrawals(state, slot, configured_slot);
        for (auto withdrawal = pending.begin(); withdrawal != pending.end();) {
            if (height < withdrawal->proposal_height) {
                return SetError(error, "M3 proposal height is ahead of replay height");
            }
            if (height - withdrawal->proposal_height > withdrawal_bundle_max_age) {
                withdrawal = pending.erase(withdrawal);
            } else {
                ++withdrawal;
            }
        }
    }

    const bool required_proposal_active_for_transactions =
        state.required_proposal_activated &&
        state.active_proposal_hash == required_active_proposal;

    struct CtipChange {
        uint8_t slot;
        uint32_t output_index;
        CAmount old_value;
        CAmount new_value;
    };

    bool configured_slot_m6_applied{false};
    for (size_t transaction_index = 1; transaction_index < block.vtx.size(); ++transaction_index) {
        CheckDrivechainParentDeadline();
        const Bitcoin::CTransaction& transaction = *block.vtx[transaction_index];
        const std::vector<uint8_t> active_slots =
            ActiveDrivechainSlots(state, configured_slot);
        std::set<uint8_t> active_set(active_slots.begin(), active_slots.end());
        std::map<Bitcoin::COutPoint, uint8_t> ctip_owner;
        for (const uint8_t slot : active_slots) {
            auto& ctip = SlotCtip(state, slot, configured_slot);
            CAmount& value = SlotCtipValue(state, slot, configured_slot);
            if ((ctip && (value < 0 || !MoneyRange(value))) || (!ctip && value != 0)) {
                return SetError(error, strprintf("malformed CTIP state for slot %u", slot));
            }
            if (ctip && !ctip_owner.emplace(*ctip, slot).second) {
                return SetError(error, "two drivechain slots share one canonical CTIP");
            }
        }

        std::map<uint8_t, size_t> ctip_spends;
        for (size_t input_index = 0; input_index < transaction.vin.size(); ++input_index) {
            if ((input_index & 0xffU) == 0) CheckDrivechainParentDeadline();
            const auto owner = ctip_owner.find(transaction.vin[input_index].prevout);
            if (owner != ctip_owner.end() && ++ctip_spends[owner->second] > 1) {
                return SetError(error, strprintf(
                    "parent transaction spends slot %u CTIP more than once", owner->second));
            }
        }

        std::map<uint8_t, uint32_t> new_ctips;
        for (uint32_t output_index = 0; output_index < transaction.vout.size(); ++output_index) {
            if ((output_index & 0xffU) == 0) CheckDrivechainParentDeadline();
            uint8_t slot{0};
            if (!ExtractDrivechainTreasurySlot(transaction.vout[output_index].scriptPubKey, slot) ||
                active_set.count(slot) == 0) {
                continue;
            }
            if (transaction.vout[output_index].nValue < 0 ||
                !MoneyRange(transaction.vout[output_index].nValue)) {
                return SetError(error, strprintf("invalid treasury value for slot %u", slot));
            }
            if (!new_ctips.emplace(slot, output_index).second) {
                return SetError(error, strprintf(
                    "parent transaction creates multiple treasury outputs for slot %u", slot));
            }
        }

        for (const auto& [outpoint, slot] : ctip_owner) {
            if (ctip_spends[slot] != 0 && new_ctips.count(slot) == 0) {
                return SetError(error, strprintf(
                    "parent transaction spends slot %u CTIP without replacement", slot));
            }
        }

        std::vector<CtipChange> changes;
        size_t decreases{0};
        for (const auto& [slot, output_index] : new_ctips) {
            auto& old_ctip = SlotCtip(state, slot, configured_slot);
            if (old_ctip && ctip_spends[slot] == 0) {
                return SetError(error, strprintf(
                    "parent transaction creates a parallel treasury output for slot %u", slot));
            }
            const CAmount old_value = old_ctip
                ? SlotCtipValue(state, slot, configured_slot)
                : 0;
            const CAmount new_value = transaction.vout[output_index].nValue;
            if (new_value == old_value) {
                return SetError(error, strprintf(
                    "slot %u CTIP replacement has zero value delta", slot));
            }
            if (new_value < old_value) ++decreases;
            changes.push_back({slot, output_index, old_value, new_value});
        }
        if (changes.empty()) continue;

        if (decreases != 0) {
            // The enforcer permits one M6 or one-or-more M5 deposits per tx,
            // never a mixed or multi-withdrawal transition.
            if (decreases != 1 || changes.size() != 1) {
                return SetError(error, "parent transaction ambiguously mixes M5 and M6 transitions");
            }
            const CtipChange& change = changes.front();
            if (transaction.vin.size() != 1 || change.output_index != 0) {
                return SetError(error, "BIP300 M6 must have one input and treasury vout 0");
            }
            uint256 m6id;
            uint8_t m6_slot{0};
            if (!ComputeDrivechainM6Id(transaction, change.old_value,
                                       m6id, &m6_slot, error)) {
                return false;
            }
            if (m6_slot != change.slot) {
                return SetError(error, "BIP300 M6 slot changed while deriving its blinded id");
            }
            auto& pending = SlotPendingWithdrawals(state, change.slot, configured_slot);
            auto approved = std::find_if(pending.begin(), pending.end(), [&](const auto& entry) {
                return entry.m6id == m6id;
            });
            if (approved == pending.end()) {
                return SetError(error, strprintf(
                    "BIP300 M6 %s was never proposed for slot %u", m6id.GetHex(), change.slot));
            }
            if (approved->votes <= withdrawal_bundle_inclusion_threshold) {
                return SetError(error, strprintf(
                    "BIP300 M6 %s has %u votes, requiring more than %u",
                    m6id.GetHex(), approved->votes,
                    withdrawal_bundle_inclusion_threshold));
            }
            if (change.slot == configured_slot && configured_slot_m6_applied) {
                return SetError(error, strprintf(
                    "parent block contains multiple successful M6 withdrawals for configured slot %u",
                    configured_slot));
            }
            if (change.slot == configured_slot) configured_slot_m6_applied = true;
            derived_withdrawals.push_back(DrivechainSuccessfulWithdrawal{
                change.slot, m6id, height, block.GetHash()});
            pending.erase(approved);
            SlotCtip(state, change.slot, configured_slot) =
                Bitcoin::COutPoint(transaction.GetHash(), change.output_index);
            SlotCtipValue(state, change.slot, configured_slot) = change.new_value;
            continue;
        }

        for (const CtipChange& change : changes) {
            std::vector<unsigned char> address;
            if (change.output_index + 1 >= transaction.vout.size() ||
                !ExtractSingleOpReturnPush(
                    transaction.vout[change.output_index + 1].scriptPubKey, address)) {
                return SetError(error, strprintf(
                    "positive CTIP replacement for slot %u has no following address", change.slot));
            }
            const CAmount delta = change.new_value - change.old_value;
            if (delta <= 0 || !MoneyRange(delta)) {
                return SetError(error, "parent CTIP increase is outside the money range");
            }
            SlotCtip(state, change.slot, configured_slot) =
                Bitcoin::COutPoint(transaction.GetHash(), change.output_index);
            SlotCtipValue(state, change.slot, configured_slot) = change.new_value;
            if (deposits && change.slot == configured_slot &&
                required_proposal_active_for_transactions &&
                !address.empty() && address.size() <= 128) {
                deposits->push_back(DrivechainMintableDeposit{
                    *state.ctip, block.GetHash(), height, delta, std::move(address)});
            }
        }
    }

    for (auto slot = state.other_slots.begin(); slot != state.other_slots.end();) {
        const auto& slot_state = slot->second;
        if (slot_state.active_proposal_hash.IsNull() &&
            slot_state.pending_proposals.empty() &&
            slot_state.pending_withdrawals.empty() && !slot_state.ctip &&
            slot_state.ctip_value == 0 &&
            state.previous_m4_actions.count(slot->first) == 0) {
            slot = state.other_slots.erase(slot);
        } else {
            ++slot;
        }
    }

    if (state.required_proposal_activated &&
        state.active_proposal_hash != required_active_proposal) {
        return SetError(error, "parent slot no longer has the required active proposal");
    }
    if (successful_withdrawals) {
        *successful_withdrawals = std::move(derived_withdrawals);
    }
    if (withdrawal_proposals) {
        *withdrawal_proposals = std::move(derived_proposals);
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
        !IsCanonicalDrivechainParentCheckpointIdentity(
            consensus.drivechain_parent_state_active_proposal_description,
            consensus.drivechain_parent_state_active_proposal_hash,
            consensus.drivechain_parent_state_proposal_height,
            consensus.drivechain_parent_state_proposal_block_hash,
            consensus.drivechain_parent_state_activation_height,
            consensus.drivechain_parent_state_activation_block_hash,
            consensus.drivechain_parent_state_height,
            consensus.drivechain_parent_state_ctip_txid,
            consensus.drivechain_parent_state_ctip_vout,
            consensus.drivechain_parent_state_ctip_value) ||
        consensus.drivechain_unused_slot_proposal_max_age == 0 ||
        consensus.drivechain_unused_slot_activation_threshold == 0 ||
        consensus.drivechain_used_slot_proposal_max_age == 0 ||
        consensus.drivechain_used_slot_activation_threshold == 0 ||
        consensus.drivechain_withdrawal_bundle_max_age == 0 ||
        consensus.drivechain_withdrawal_bundle_inclusion_threshold == 0 ||
        !consensus.DrivechainWithdrawalValidationEnabled() ||
        consensus.drivechain_parent_state_replay_version !=
            ElementsDrivechainIdentity::PARENT_REPLAY_VERSION) {
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

    const UniValue& hash = header.get_obj()["hash"];
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
    const UniValue& mtp = header.get_obj()["mediantime"];
    if (!mtp.isNum()) {
        if (error) *error = "getblockheader result has no numeric mediantime";
        return false;
    }
    try {
        const int64_t parsed = mtp.getInt<int64_t>();
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

bool IsCanonicalDrivechainParentCheckpointIdentity(
    const std::vector<unsigned char>& active_proposal_description,
    const std::optional<uint256>& active_proposal_hash,
    const uint32_t proposal_height,
    const uint256& proposal_block_hash,
    const uint32_t activation_height,
    const uint256& activation_block_hash,
    const uint32_t checkpoint_height,
    const uint256& ctip_txid,
    const uint32_t ctip_vout,
    const CAmount ctip_value)
{
    if (!IsCanonicalDrivechainParentCheckpointCtip(
            ctip_txid, ctip_vout, ctip_value)) {
        return false;
    }
    const bool proposal_absent = active_proposal_description.empty() &&
        (!active_proposal_hash || active_proposal_hash->IsNull()) &&
        proposal_height == 0 && proposal_block_hash.IsNull() &&
        activation_height == 0 && activation_block_hash.IsNull();
    if (proposal_absent) {
        return ctip_txid.IsNull();
    }
    const bool proposal_present = !active_proposal_description.empty() &&
        active_proposal_hash && !active_proposal_hash->IsNull() &&
        Hash(active_proposal_description) == *active_proposal_hash &&
        !proposal_block_hash.IsNull() && !activation_block_hash.IsNull() &&
        proposal_height < activation_height && activation_height <= checkpoint_height;
    return proposal_present;
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

bool ReadActiveMainchainHeight(uint32_t& height, std::string* error)
{
    UniValue params(UniValue::VARR);
    const UniValue result = CallMainChainRPCChecked("getblockcount", params);
    if (!result.isNum()) {
        return SetError(error, "parent getblockcount returned a non-numeric height");
    }
    try {
        const int64_t parsed = result.getInt<int64_t>();
        if (parsed < 0 || parsed > std::numeric_limits<uint32_t>::max()) {
            return SetError(error, "parent tip height is outside the supported uint32 range");
        }
        height = static_cast<uint32_t>(parsed);
        return true;
    } catch (const std::exception&) {
        return SetError(error, "parent getblockcount returned a noncanonical height");
    }
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
    const bool post_activation =
        !consensus.drivechain_parent_state_active_proposal_description.empty();
    const auto require_block_hash = [&](const uint256& expected) {
        return block.GetHash() == expected || SetError(error, strprintf(
            "authenticated parent milestone height %u hashes to %s, expected %s",
            height, block.GetHash().GetHex(), expected.GetHex()));
    };

    if (post_activation && height == consensus.drivechain_parent_state_proposal_height) {
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

    if (post_activation && height == consensus.drivechain_parent_state_activation_height) {
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
        const bool expects_ctip = !consensus.drivechain_parent_state_ctip_txid.IsNull();
        const bool checkpoint_ctip_matches = expects_ctip
            ? state.ctip &&
                state.ctip->hash == consensus.drivechain_parent_state_ctip_txid &&
                state.ctip->n == consensus.drivechain_parent_state_ctip_vout &&
                state.ctip_value == consensus.drivechain_parent_state_ctip_value
            : !state.ctip && state.ctip_value == 0;
        const bool checkpoint_proposal_matches = post_activation
            ? state.active_proposal_hash ==
                *consensus.drivechain_parent_state_active_proposal_hash
            : state.active_proposal_hash.IsNull();
        if (!checkpoint_proposal_matches ||
            !checkpoint_ctip_matches) {
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
    HashWriter writer;
    writer << std::string{"ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V4"}
           << std::string{ElementsDrivechainIdentity::BIP300301_ENFORCER_REVISION}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN}
           << std::string{ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_ID}
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
           << consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{})
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
           << uint256S(ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT)
           << consensus.drivechain_unused_slot_proposal_max_age
           << consensus.drivechain_unused_slot_activation_threshold
           << consensus.drivechain_used_slot_proposal_max_age
           << consensus.drivechain_used_slot_activation_threshold
           << consensus.drivechain_withdrawal_bundle_max_age
           << consensus.drivechain_withdrawal_bundle_inclusion_threshold
           << consensus.drivechain_m6_withdrawal_validation
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
        consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{});
    cache.checkpoint_hash = consensus.drivechain_parent_state_hash;
    cache.unused_proposal_max_age = consensus.drivechain_unused_slot_proposal_max_age;
    cache.unused_activation_threshold = consensus.drivechain_unused_slot_activation_threshold;
    cache.used_proposal_max_age = consensus.drivechain_used_slot_proposal_max_age;
    cache.used_activation_threshold = consensus.drivechain_used_slot_activation_threshold;
    cache.withdrawal_bundle_max_age = consensus.drivechain_withdrawal_bundle_max_age;
    cache.withdrawal_bundle_inclusion_threshold =
        consensus.drivechain_withdrawal_bundle_inclusion_threshold;
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
        !IsCanonicalDrivechainParentCheckpointIdentity(
            consensus.drivechain_parent_state_active_proposal_description,
            consensus.drivechain_parent_state_active_proposal_hash,
            consensus.drivechain_parent_state_proposal_height,
            consensus.drivechain_parent_state_proposal_block_hash,
            consensus.drivechain_parent_state_activation_height,
            consensus.drivechain_parent_state_activation_block_hash,
            consensus.drivechain_parent_state_height,
            consensus.drivechain_parent_state_ctip_txid,
            consensus.drivechain_parent_state_ctip_vout,
            consensus.drivechain_parent_state_ctip_value) ||
        consensus.drivechain_parent_state_chainwork.IsNull() ||
        consensus.drivechain_unused_slot_proposal_max_age == 0 ||
        consensus.drivechain_unused_slot_activation_threshold == 0 ||
        consensus.drivechain_unused_slot_activation_threshold >=
            consensus.drivechain_unused_slot_proposal_max_age ||
        consensus.drivechain_used_slot_proposal_max_age == 0 ||
        consensus.drivechain_used_slot_activation_threshold == 0 ||
        consensus.drivechain_used_slot_activation_threshold >=
            consensus.drivechain_used_slot_proposal_max_age ||
        consensus.drivechain_withdrawal_bundle_max_age == 0 ||
        consensus.drivechain_withdrawal_bundle_inclusion_threshold == 0 ||
        consensus.drivechain_withdrawal_bundle_inclusion_threshold >=
            consensus.drivechain_withdrawal_bundle_max_age ||
        !consensus.DrivechainWithdrawalValidationEnabled() ||
        consensus.drivechain_parent_state_replay_version !=
            ElementsDrivechainIdentity::PARENT_REPLAY_VERSION) {
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
            const bool checkpoint_requires_active =
                !consensus.drivechain_parent_state_active_proposal_description.empty();
            const bool checkpoint_requires_ctip =
                !consensus.drivechain_parent_state_ctip_txid.IsNull();
            const bool contradicts_checkpoint =
                stored_tip.height >= consensus.drivechain_parent_state_height &&
                ((checkpoint_requires_active && stored_tip.state.active_proposal_hash.IsNull()) ||
                 (stored_tip.state.required_proposal_activated &&
                  (stored_tip.state.active_proposal_hash != cache.proposal_hash ||
                   stored_tip.state.required_activation_block_hash.IsNull() ||
                   stored_tip.state.required_activation_height > stored_tip.height)) ||
                 (checkpoint_requires_ctip && !stored_tip.state.ctip));
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

    if (ElementsDrivechainBootstrap::ENABLED) {
        const uint256 expected_bootstrap_commitment = uint256S(
            ElementsDrivechainIdentity::PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT);
        HashWriter bootstrap_writer;
        bootstrap_writer
            << std::string{"ELEMENTS_ALPHANET_PARENT_REPLAY_BOOTSTRAP_V1"}
            << consensus.drivechain_parent_state_height
            << consensus.drivechain_parent_state_hash
            << consensus.drivechain_parent_state_chainwork
            << static_cast<uint32_t>(ElementsDrivechainBootstrap::SLOTS.size());
        for (const auto& slot : ElementsDrivechainBootstrap::SLOTS) {
            const uint256 active = uint256S(slot.active);
            const uint256 ctip_hash = uint256S(slot.ctip_txid);
            const bool has_ctip = !ctip_hash.IsNull();
            bootstrap_writer << slot.slot << active << has_ctip;
            if (has_ctip) {
                bootstrap_writer << ctip_hash << slot.ctip_vout << slot.ctip_value;
            }
        }
        if (expected_bootstrap_commitment.IsNull() ||
            bootstrap_writer.GetHash() != expected_bootstrap_commitment) {
            cache = {};
            return SetError(error, "parent replay bootstrap state does not match its identity commitment");
        }
        DrivechainParentReplayState bootstrap_state;
        for (const auto& slot : ElementsDrivechainBootstrap::SLOTS) {
            if (slot.slot == cache.slot || slot.active == nullptr || slot.ctip_txid == nullptr) {
                cache = {};
                return SetError(error, "parent replay bootstrap contains an invalid global slot");
            }
            DrivechainOtherSlotReplayState other;
            other.active_proposal_hash = uint256S(slot.active);
            if (other.active_proposal_hash.IsNull()) {
                cache = {};
                return SetError(error, "parent replay bootstrap contains a null active proposal");
            }
            const uint256 ctip_hash = uint256S(slot.ctip_txid);
            if (!ctip_hash.IsNull()) {
                other.ctip = Sidechain::Bitcoin::COutPoint(ctip_hash, slot.ctip_vout);
                other.ctip_value = slot.ctip_value;
            } else if (slot.ctip_vout != Sidechain::Bitcoin::COutPoint::NULL_INDEX ||
                       slot.ctip_value != 0) {
                cache = {};
                return SetError(error, "parent replay bootstrap has a malformed absent CTIP");
            }
            if (!bootstrap_state.other_slots.emplace(slot.slot, std::move(other)).second) {
                cache = {};
                return SetError(error, "parent replay bootstrap repeats a global slot");
            }
        }
        cache.height = consensus.drivechain_parent_state_height;
        cache.hash = consensus.drivechain_parent_state_hash;
        cache.state = std::move(bootstrap_state);
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
            cache.withdrawal_bundle_max_age,
            cache.withdrawal_bundle_inclusion_threshold,
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
               consensus.drivechain_parent_state_active_proposal_hash.value_or(uint256{}) &&
           cache.checkpoint_hash == consensus.drivechain_parent_state_hash &&
           cache.unused_proposal_max_age ==
               consensus.drivechain_unused_slot_proposal_max_age &&
           cache.unused_activation_threshold ==
               consensus.drivechain_unused_slot_activation_threshold &&
           cache.used_proposal_max_age ==
               consensus.drivechain_used_slot_proposal_max_age &&
           cache.used_activation_threshold ==
               consensus.drivechain_used_slot_activation_threshold &&
           cache.withdrawal_bundle_max_age ==
               consensus.drivechain_withdrawal_bundle_max_age &&
           cache.withdrawal_bundle_inclusion_threshold ==
               consensus.drivechain_withdrawal_bundle_inclusion_threshold &&
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
    bool stale_cache{false};
    if (cache.height > target_height) {
        // Historical child blocks legitimately authenticate an older parent
        // boundary after the replay cache has advanced beyond it. Distinguish
        // that case from a parent reorg whose new tip is actually below the
        // cached height before deciding that the derived cache is stale.
        uint32_t active_tip_height{0};
        if (!ReadActiveMainchainHeight(active_tip_height, error)) return false;
        stale_cache = cache.height > active_tip_height;
    }
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
            std::vector<DrivechainSuccessfulWithdrawal> successful_withdrawals;
            std::vector<DrivechainWithdrawalProposalIdentity> withdrawal_proposals;
            if (!ApplyDrivechainParentBlockState(
                    block, height, cache.slot, cache.proposal_hash,
                    consensus.drivechain_unused_slot_proposal_max_age,
                    consensus.drivechain_unused_slot_activation_threshold,
                    consensus.drivechain_used_slot_proposal_max_age,
                    consensus.drivechain_used_slot_activation_threshold,
                    consensus.drivechain_withdrawal_bundle_max_age,
                    consensus.drivechain_withdrawal_bundle_inclusion_threshold,
                    next_state, &deposits, error, &successful_withdrawals,
                    &withdrawal_proposals)) {
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
                    deposits, replayed_edge, successful_withdrawals,
                    withdrawal_proposals, error)) {
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
    const UniValue& rpc_error = reply["error"];
    if (!rpc_error.isNull()) {
        if (rpc_error.isObject()) {
            const UniValue& code = rpc_error.get_obj()["code"];
            if (code.isNum() && code.getInt<int64_t>() == -5) {
                if (error) *error = "committed parent hash is unknown to the authenticated parent node";
                return DrivechainParentProbeStatus::REJECTED;
            }
        }
        if (error) *error = strprintf("getblockheader returned error: %s", rpc_error.write());
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }

    const UniValue& result = reply["result"];
    if (!result.isObject()) {
        if (error) *error = "getblockheader returned no canonical metadata object";
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    uint256 returned_hash;
    const UniValue& height = result.get_obj()["height"];
    const UniValue& confirmations = result.get_obj()["confirmations"];
    if (!ParseCanonicalHash(result.get_obj()["hash"], returned_hash) ||
        returned_hash != parent_hash || !height.isNum() || !confirmations.isNum()) {
        if (error) *error = "getblockheader returned noncanonical parent metadata";
        return DrivechainParentProbeStatus::UNAVAILABLE;
    }
    const int64_t parsed_height = height.getInt<int64_t>();
    const int64_t parsed_confirmations = confirmations.getInt<int64_t>();
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
    const uint256& expected_critical_hash,
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
        // Reject nonmatching critical hashes entirely in memory. Rechecking
        // P/Q first would let arbitrary values amplify two parent RPCs.
        // Because a background-observed reorg may have made this cached edge
        // stale, this cheap result is UNAVAILABLE and never peer blame.
        if (!it->has_canonical_commitment) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                "cached parent edge has no unique enforcer-recognized M7; await a fresh authenticated edge");
        }
        if (it->committed_sidechain_hash != expected_critical_hash) {
            return SetBmmError(error, DrivechainBmmStatus::UNAVAILABLE,
                "expected critical hash does not match the cached enforcer-recognized M7; no parent RPC performed");
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
    // genesis replay index. Unknown P values, edges without one unique
    // enforcer-recognized M7,
    // and wrong critical hashes return without any parent RPC. Only the exact
    // indexed commitment is allowed through to full live P/Q authentication.
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
            indexed.committed_sidechain_hash != expected_critical_hash) {
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
    // Cache the M7 value observed in Q, not the caller's candidate. Otherwise
    // a first lookup with a nonmatching candidate could poison the shared edge
    // context and make a later exact candidate fail its final recomputation.
    context.critical_hash = has_canonical_commitment
        ? committed_sidechain_hash
        : uint256{};
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
    if (committed_sidechain_hash != expected_critical_hash) {
        return SetBmmError(error, DrivechainBmmStatus::PARENT_REJECTED,
            strprintf("BMM successor commits to critical hash %s, expected %s",
                      committed_sidechain_hash.GetHex(),
                      expected_critical_hash.GetHex()));
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

bool IsDefinitiveDrivechainBmmWaitError(const std::string& error)
{
    return error.find("BMM successor") != std::string::npos ||
           error.find("not the exact successor of committed parent") != std::string::npos ||
           error.find("not the active-chain block at its declared height") != std::string::npos ||
           error.find("cached parent edge has no unique enforcer-recognized M7") != std::string::npos ||
           error.find("expected critical hash does not match the cached enforcer-recognized M7") != std::string::npos;
}

uint64_t GetDrivechainParentReplayEpoch()
{
    return g_drivechain_parent_replay_published_epoch.load(
        std::memory_order_acquire);
}

bool GetDrivechainSuccessfulWithdrawal(
    const int sidechain_slot,
    const uint256& m6id,
    std::optional<DrivechainSuccessfulWithdrawal>& result,
    std::string* error)
{
    result.reset();
    if (error) error->clear();
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) return false;

    try {
        uint32_t target_height{0};
        if (!ReadActiveMainchainHeight(target_height, error)) return false;
        uint256 target_hash;
        if (!ReadActiveMainchainHash(target_height, target_hash, error)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(g_drivechain_parent_replay_mutex);
        DrivechainParentReplayCache& cache =
            g_drivechain_parent_replay_cache;
        if (!EnsurePinnedDrivechainParentStateThroughLocked(
                target_height, target_hash,
                /*require_elements_active=*/true, cache, error)) {
            return false;
        }
        if (!g_drivechain_parent_replay_store) {
            return SetError(
                error,
                "persistent authenticated parent replay index is not open");
        }

        DrivechainSuccessfulWithdrawal withdrawal;
        const DrivechainReplayStoreReadStatus status =
            g_drivechain_parent_replay_store->ReadSuccessfulWithdrawal(
                static_cast<uint8_t>(sidechain_slot), m6id,
                withdrawal, error);
        if (status == DrivechainReplayStoreReadStatus::CORRUPT ||
            (status == DrivechainReplayStoreReadStatus::FOUND &&
             withdrawal.block_height > cache.height)) {
            g_drivechain_parent_replay_published_epoch.store(
                0, std::memory_order_release);
            cache = {};
            g_drivechain_parent_replay_store_rebuild_required = true;
            if (error && error->empty()) {
                *error = "persistent authenticated parent replay successful-withdrawal index is inconsistent";
            }
            return false;
        }
        if (status == DrivechainReplayStoreReadStatus::FOUND) {
            uint256 active_withdrawal_hash;
            if (!ReadActiveMainchainHash(
                    withdrawal.block_height, active_withdrawal_hash, error)) {
                return false;
            }
            if (active_withdrawal_hash != withdrawal.block_hash) {
                g_drivechain_parent_replay_published_epoch.store(
                    0, std::memory_order_release);
                cache = {};
                g_drivechain_parent_replay_store_rebuild_required = true;
                return SetError(
                    error,
                    "persistent successful-withdrawal record is not on the active parent chain");
            }
        }

        // The query and durable record read are bracketed by the same active
        // tip check as replay. If a parent reorg raced this call, invalidate
        // the complete derived index so the next call rebuilds from genesis.
        uint256 active_cache_hash;
        if (!ReadActiveMainchainHash(cache.height, active_cache_hash, error)) {
            return false;
        }
        if (active_cache_hash != cache.hash) {
            g_drivechain_parent_replay_published_epoch.store(
                0, std::memory_order_release);
            cache = {};
            g_drivechain_parent_replay_store_rebuild_required = true;
            return SetError(
                error,
                "parent-chain reorganization raced successful-withdrawal lookup");
        }

        if (status == DrivechainReplayStoreReadStatus::FOUND) {
            result = std::move(withdrawal);
        }
        return true;
    } catch (const std::exception& e) {
        return SetError(error, e.what());
    }
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
        const int64_t height = height_value.getInt<int64_t>();
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
                                  const uint256& expected_critical_hash,
                                  const int sidechain_slot,
                                  DrivechainBmmBlockContext& context,
                                  std::string* error)
{
    const DrivechainBmmStatus status =
        GetDrivechainBmmBlockStatus(
            block, expected_critical_hash, sidechain_slot, context, error);
    if (status != DrivechainBmmStatus::VALID) context = {};
    return status == DrivechainBmmStatus::VALID;
}

DrivechainBmmStatus GetDrivechainBmmBlockStatus(const CBlock& block,
                                                const uint256& expected_critical_hash,
                                                const int sidechain_slot,
                                                DrivechainBmmBlockContext& context,
                                                std::string* error)
{
    context = {};
    if (error) error->clear();
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) {
        return DrivechainBmmStatus::UNAVAILABLE;
    }
    if (expected_critical_hash.IsNull()) {
        return SetBmmError(
            error, DrivechainBmmStatus::INVALID,
            "BIP301 expected critical hash is null");
    }
    uint256 parent_hash;
    if (!ExtractDrivechainParentHashFromBlock(block, parent_hash, error)) {
        return DrivechainBmmStatus::INVALID;
    }
    try {
        return GetDrivechainBmmContextForHashesStatus(
            expected_critical_hash, parent_hash, sidechain_slot, context, error);
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

bool DrivechainAnchorSnapshot::Matches(const int slot, const uint256& parent_tip,
                                       const uint64_t epoch) const
{
    return !m_parent_tip.IsNull() && m_parent_tip == parent_tip && EpochMatches(slot, epoch);
}

bool DrivechainAnchorSnapshot::EpochMatches(const int slot, const uint64_t epoch) const
{
    return m_slot >= 0 && m_slot <= 255 && m_slot == slot && m_epoch != 0 && m_epoch == epoch;
}

bool DrivechainAnchorSnapshot::Add(const DrivechainAnchor& anchor,
                                   const DrivechainAnchorStatus status)
{
    if (status != DrivechainAnchorStatus::ACTIVE || !anchor.IsSane() ||
        m_parent_tip.IsNull() || !EpochMatches(m_slot, m_epoch)) return false;
    std::vector<unsigned char> encoded;
    VectorWriter{encoded, 0} << anchor;
    const auto [it, inserted] = m_active_anchors.emplace((HashWriter{} << anchor).GetHash(), encoded);
    return inserted || it->second == encoded;
}

bool DrivechainAnchorSnapshot::Contains(const DrivechainAnchor& anchor,
                                        const int slot, const uint64_t epoch) const
{
    if (!EpochMatches(slot, epoch) || !anchor.IsSane()) return false;
    const auto found = m_active_anchors.find((HashWriter{} << anchor).GetHash());
    if (found == m_active_anchors.end()) return false;
    std::vector<unsigned char> encoded;
    VectorWriter{encoded, 0} << anchor;
    return found->second == encoded;
}

namespace {
bool ReadDrivechainAnchorSnapshotTip(uint256& tip, std::string* error)
{
    const UniValue result = CallMainChainRPCChecked("getbestblockhash", UniValue(UniValue::VARR));
    if (!ParseCanonicalHash(result, tip) || tip.IsNull()) {
        return SetError(error, "parent getbestblockhash returned a noncanonical tip");
    }
    return true;
}
} // namespace

bool CheckDrivechainAnchorSnapshotEpoch(const DrivechainAnchorSnapshot& snapshot,
                                        const int sidechain_slot, std::string* error)
{
    try {
        CheckDrivechainParentDeadline();
        if (!snapshot.EpochMatches(sidechain_slot, GetDrivechainParentReplayEpoch())) {
            return SetError(error, "authenticated parent generation changed during anchor snapshot use");
        }
        return true;
    } catch (const std::exception& e) {
        return SetError(error, e.what());
    }
}

bool CheckDrivechainAnchorSnapshot(const DrivechainAnchorSnapshot& snapshot,
                                   const int sidechain_slot, std::string* error)
{
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error) ||
        !CheckDrivechainAnchorSnapshotEpoch(snapshot, sidechain_slot, error)) return false;
    try {
        uint256 tip;
        if (!ReadDrivechainAnchorSnapshotTip(tip, error)) return false;
        // Epoch alone is insufficient: the warmer may not yet have observed
        // a reorg. Even benign extension requires a freshly authenticated set.
        if (!snapshot.Matches(sidechain_slot, tip, GetDrivechainParentReplayEpoch())) {
            return SetError(error, "active parent tip changed during anchor snapshot use");
        }
        return CheckDrivechainAnchorSnapshotEpoch(snapshot, sidechain_slot, error);
    } catch (const std::exception& e) {
        return SetError(error, e.what());
    }
}

bool WarmDrivechainAnchorSnapshot(
    const std::vector<DrivechainAnchor>& anchors, const int sidechain_slot,
    const util::SignalInterrupt& interrupt,
    std::shared_ptr<const DrivechainAnchorSnapshot>& result, std::string* error)
{
    result.reset();
    if (error) error->clear();
    if (DrivechainParentBudgetActive() || g_drivechain_anchor_warm_deadline.has_value()) {
        return SetError(error, "bulk anchor authentication cannot run inside a parent validation budget");
    }
    if (interrupt) return SetError(error, "drivechain anchor snapshot authentication interrupted");
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) return false;
    struct DeadlineScope {
        explicit DeadlineScope(const util::SignalInterrupt& interrupt) {
            g_drivechain_anchor_warm_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{120};
            g_drivechain_anchor_warm_interrupt = &interrupt;
        }
        ~DeadlineScope() {
            g_drivechain_anchor_warm_deadline.reset();
            g_drivechain_anchor_warm_interrupt = nullptr;
        }
    } deadline_scope{interrupt};
    try {
        CheckDrivechainParentDeadline();
        const uint64_t epoch = GetDrivechainParentReplayEpoch();
        if (epoch == 0) return SetError(error, "anchor snapshot requires authenticated parent replay");
        uint256 tip;
        if (!ReadDrivechainAnchorSnapshotTip(tip, error)) return false;
        auto snapshot = std::make_shared<DrivechainAnchorSnapshot>(sidechain_slot, tip, epoch);
        for (const DrivechainAnchor& anchor : anchors) {
            CheckDrivechainParentDeadline();
            if (!snapshot->EpochMatches(sidechain_slot, GetDrivechainParentReplayEpoch())) {
                return SetError(error, "parent replay changed while authenticating anchor snapshot");
            }
            if (snapshot->Contains(anchor, sidechain_slot, epoch)) continue;
            std::string anchor_error;
            const DrivechainAnchorStatus status = IsDrivechainAnchorActive(anchor, sidechain_slot, &anchor_error);
            if (status == DrivechainAnchorStatus::UNAVAILABLE) {
                return SetError(error, "cannot authenticate complete anchor snapshot: " + anchor_error);
            }
            if (status == DrivechainAnchorStatus::ACTIVE && !snapshot->Add(anchor, status)) {
                return SetError(error, "authenticated anchor snapshot contains malformed identity");
            }
            // Never retain ORPHANED as a rollback authority: reconciliation
            // must freshly establish those active-height mismatches itself.
        }
        if (!CheckDrivechainAnchorSnapshot(*snapshot, sidechain_slot, error)) return false;
        result = std::move(snapshot);
        return true;
    } catch (const std::exception& e) {
        return SetError(error, e.what());
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

bool IsDrivechainBmmCommitmentMined(const uint256& critical_hash, const uint256& parent_hash, const int sidechain_slot, std::string* error)
{
    if (!CheckConfiguredDrivechainSlot(sidechain_slot, error)) return false;
    if (critical_hash.IsNull()) {
        return SetError(error, "BIP301 expected critical hash is null");
    }
    try {
        DrivechainBmmBlockContext context;
        return GetDrivechainBmmContextForHashesStatus(
                   critical_hash, parent_hash, sidechain_slot,
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
        const UniValue& errval = reply.find_value("error");
        if (!errval.isNull()) {
            LogPrintf("WARNING: Got error reply from bitcoind getblockheader: %s\n", errval.write());
            return false;
        }
        const UniValue& result = reply.find_value("result");
        if (!result.isObject()) {
            LogPrintf("ERROR: bitcoind getblockheader result was malformed (not object): %s\n", result.write());
            return false;
        }

        UniValue confirmations = result.get_obj().find_value("confirmations");
        if (!confirmations.isNum() || confirmations.getInt<int64_t>() < nMinConfirmationDepth) {
            LogPrintf("Insufficient confirmations (got %s, need at least %d).\n", confirmations.write(), nMinConfirmationDepth);
            return false;
        }

        // Only perform extra test if nbTxs has been provided (non-zero).
        if (nbTxs != 0) {
            UniValue nTx = result.get_obj().find_value("nTx");
            if (!nTx.isNum() || nTx.getInt<int64_t>() != nbTxs) {
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
