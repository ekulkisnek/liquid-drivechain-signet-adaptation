// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/request.h>

#include <chainparamsbase.h>
#include <fs.h>

#include <random.h>
#include <rpc/protocol.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 *
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("method", strMethod);
    request.pushKV("params", params);
    request.pushKV("id", id);
    return request;
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ);
    if (!error.isNull())
        reply.pushKV("result", NullUniValue);
    else
        reply.pushKV("result", result);
    reply.pushKV("error", error);
    reply.pushKV("id", id);
    return reply;
}

std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id);
    return reply.write() + "\n";
}

UniValue JSONRPCError(int code, const std::string& message)
{
    UniValue error(UniValue::VOBJ);
    error.pushKV("code", code);
    error.pushKV("message", message);
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const std::string COOKIEAUTH_FILE = ".cookie";

/** Get name of RPC authentication cookie file */
static fs::path GetAuthCookieFile(bool temp=false)
{
    std::string arg = gArgs.GetArg("-rpccookiefile", COOKIEAUTH_FILE);
    if (temp) {
        arg += ".tmp";
    }
    return AbsPathForConfigVal(fs::PathFromString(arg));
}

static bool g_generated_cookie = false;

bool GenerateAuthCookie(std::string *cookie_out)
{
    const size_t COOKIE_SIZE = 32;
    unsigned char rand_pwd[COOKIE_SIZE];
    GetRandBytes(rand_pwd, COOKIE_SIZE);
    std::string cookie = COOKIEAUTH_USER + ":" + HexStr(rand_pwd);

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */
    std::ofstream file;
    fs::path filepath_tmp = GetAuthCookieFile(true);
    file.open(filepath_tmp);
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", fs::PathToString(filepath_tmp));
        return false;
    }
    file << cookie;
    file.close();

    fs::path filepath = GetAuthCookieFile(false);
    if (!RenameOver(filepath_tmp, filepath)) {
        LogPrintf("Unable to rename cookie authentication file %s to %s\n", fs::PathToString(filepath_tmp), fs::PathToString(filepath));
        return false;
    }
    g_generated_cookie = true;
    LogPrintf("Generated RPC authentication cookie %s\n", fs::PathToString(filepath));

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    fs::path filepath = GetAuthCookieFile();
    file.open(filepath);
    if (!file.is_open())
        return false;
    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

//
// ELEMENTS:

std::string GetDefaultMainchainAuthCookieFile(const std::string& chain)
{
    // The sole production Elements chain is anchored to Bitcoin Signet.
    if (chain == CBaseChainParams::ELEMENTS) return "signet/.cookie";

    // These paths exist only for inherited unit/functional-test contexts.
    if (chain == CBaseChainParams::LIQUID1) return ".cookie";
    return "regtest/.cookie";
}

/** Get name mainchain RPC authentication cookie file */
fs::path GetMainchainAuthCookieFile()
{
    const std::string cookie_file =
        GetDefaultMainchainAuthCookieFile(gArgs.GetChainName());
    fs::path cookie_path = fs::PathFromString(gArgs.GetArg("-mainchainrpccookiefile", cookie_file));
    if (cookie_path.is_absolute())
        return cookie_path;
    return fsbridge::AbsPathJoin(GetMainchainDefaultDataDir(), cookie_path);
}

bool ReadPrivateRpcAuthFile(
    const fs::path& path,
    std::string& cookie,
    std::string* error)
{
    cookie.clear();
    if (error) error->clear();
    const std::string native_path = fs::PathToString(path);
    if (!path.is_absolute()) {
        if (error) *error = "RPC authentication file path must be absolute";
        return false;
    }

#ifndef WIN32
    const int descriptor = open(
        native_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (error) {
            *error = strprintf(
                "cannot securely open mainchain RPC cookie %s: %s",
                native_path, std::strerror(errno));
        }
        return false;
    }

    struct stat metadata {};
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        if (error) *error = "mainchain RPC cookie is not a regular file: " + native_path;
        close(descriptor);
        return false;
    }
    if (metadata.st_uid != geteuid()) {
        if (error) {
            *error = "mainchain RPC cookie must be owned by the Elements process user: " +
                native_path;
        }
        close(descriptor);
        return false;
    }
    if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (error) {
            *error = "mainchain RPC cookie permissions must deny all group and other access: " +
                native_path;
        }
        close(descriptor);
        return false;
    }

    static constexpr size_t MAX_COOKIE_FILE_SIZE{4096};
    std::array<char, MAX_COOKIE_FILE_SIZE + 1> contents{};
    size_t used{0};
    while (used < contents.size()) {
        const ssize_t count = read(
            descriptor, contents.data() + used, contents.size() - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        if (error) {
            *error = strprintf(
                "cannot read mainchain RPC cookie %s: %s",
                native_path, std::strerror(errno));
        }
        close(descriptor);
        return false;
    }
    close(descriptor);
    if (used == contents.size()) {
        if (error) *error = "mainchain RPC cookie file is unexpectedly large";
        return false;
    }
    cookie.assign(contents.data(), used);
#else
    if (fs::is_symlink(path) || !fs::exists(path) || !fs::is_regular_file(path)) {
        if (error) *error = "mainchain RPC cookie is not a regular file: " + native_path;
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) {
        if (error) *error = "cannot read mainchain RPC cookie: " + native_path;
        return false;
    }
    std::array<char, 4097> contents{};
    input.read(contents.data(), contents.size());
    cookie.assign(contents.data(), input.gcount());
    if (input.bad() || cookie.size() > 4096) {
        cookie.clear();
        if (error) *error = "mainchain RPC cookie file is unexpectedly large";
        return false;
    }
#endif

    if (!cookie.empty() && cookie.back() == '\n') cookie.pop_back();
    if (!cookie.empty() && cookie.back() == '\r') cookie.pop_back();
    return true;
}

bool ReadMainchainAuthCookieFile(
    const fs::path& path, std::string& cookie, std::string* error)
{
    if (!ReadPrivateRpcAuthFile(path, cookie, error)) return false;
    static constexpr const char* COOKIE_PREFIX{"__cookie__:"};
    static constexpr size_t COOKIE_PREFIX_SIZE{11};
    if (cookie.rfind(COOKIE_PREFIX, 0) != 0 ||
        cookie.size() != COOKIE_PREFIX_SIZE + 64 ||
        !IsHex(cookie.substr(COOKIE_PREFIX_SIZE))) {
        cookie.clear();
        if (error) {
            *error = "mainchain RPC cookie is not a canonical rotating Bitcoin Core cookie";
        }
        return false;
    }
    return true;
}

bool ReadNativeDrivechainCookieFile(
    const fs::path& path, std::string& cookie, std::string* error)
{
    return ReadMainchainAuthCookieFile(path, cookie, error);
}

bool ReadMainchainRpcCredentialFile(
    const fs::path& path, std::string& credentials, std::string* error)
{
    credentials.clear();
#ifdef WIN32
    // This opt-in path promises POSIX ownership/mode enforcement. Do not
    // silently downgrade it to the Windows cookie compatibility path.
    if (error) *error = "private static parent credential files require POSIX file permissions";
    return false;
#else
    if (!ReadPrivateRpcAuthFile(path, credentials, error)) return false;
    const auto separator = credentials.find(':');
    if (credentials.size() > 1024 || separator == std::string::npos ||
        separator == 0 || separator + 1 == credentials.size() ||
        credentials.find(':', separator + 1) != std::string::npos ||
        credentials.compare(0, separator, "__cookie__") == 0 ||
        !std::all_of(credentials.begin(), credentials.end(),
                     [](unsigned char c) { return c >= 33 && c <= 126; })) {
        credentials.clear();
        if (error) *error = "parent credential file must contain one bounded username:password record";
        return false;
    }
    return true;
#endif
}

bool GetMainchainAuthCookie(std::string *cookie_out)
{
    std::string cookie;
    std::string error;
    if (!ReadMainchainAuthCookieFile(
            GetMainchainAuthCookieFile(), cookie, &error)) {
        LogPrintf("Unable to read mainchain RPC authentication cookie: %s\n", error);
        return false;
    }

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

// END ELEMENTS
//

void DeleteAuthCookie()
{
    try {
        if (g_generated_cookie) {
            // Delete the cookie file if it was generated by this process
            fs::remove(GetAuthCookieFile());
        }
    } catch (const fs::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, fsbridge::get_filesystem_error_message(e));
    }
}

std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue& in)
{
    if (!in.isArray()) {
        throw std::runtime_error("Batch must be an array");
    }
    const size_t num {in.size()};
    std::vector<UniValue> batch(num);
    for (const UniValue& rec : in.getValues()) {
        if (!rec.isObject()) {
            throw std::runtime_error("Batch member must be an object");
        }
        size_t id = rec["id"].get_int();
        if (id >= num) {
            throw std::runtime_error("Batch member id is larger than batch size");
        }
        batch[id] = rec;
    }
    return batch;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (fLogIPs)
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s peeraddr=%s\n", SanitizeString(strMethod),
            this->authUser, this->peerAddr);
    else
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s\n", SanitizeString(strMethod), this->authUser);

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray() || valParams.isObject())
        params = valParams;
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
}
