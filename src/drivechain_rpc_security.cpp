// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <init.h>
#include <chainparamsbase.h>
#include <mainchainrpc.h>
#include <netbase.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <algorithm>
#include <fstream>
#include <limits>
#include <set>
#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static std::string ResolveDrivechainBmmGrpcurlPath(const ArgsManager& args)
{
    const std::string configured_path = args.GetArg("-drivechainbmmgrpcurl", "");
    if (!configured_path.empty()) {
        return configured_path;
    }

    const std::vector<fs::path> candidates{
        args.GetDataDirBase().parent_path() / "assets" / "bin" / "grpcurl",
        args.GetDataDirBase().parent_path() / "bin" / "grpcurl",
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

namespace {

struct DrivechainGrpcTLSConfig {
    std::string address;
    fs::path ca_certificate;
    fs::path client_certificate;
    fs::path client_key;
    std::string authority;
};

fs::path ResolveDrivechainGrpcCredentialPath(const ArgsManager& args,
                                             const std::string& argument,
                                             const std::string& fallback)
{
    fs::path path = fs::PathFromString(args.GetArg(argument, fallback));
    if (path.is_absolute()) return path;
    return fsbridge::AbsPathJoin(args.GetDataDirNet(), path);
}

DrivechainGrpcTLSConfig GetDrivechainGrpcTLSConfig(const ArgsManager& args)
{
    return {
        args.GetArg("-drivechainbmmgrpcaddr", "127.0.0.1:55051"),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpcca", "enforcer-tls/ca.pem"),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpccert", "enforcer-tls/elements-client.pem"),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpckey", "enforcer-tls/elements-client-key.pem"),
        args.GetArg("-drivechainbmmgrpcauthority", ""),
    };
}

bool ValidateReadableRegularFile(const fs::path& path,
                                 const bool private_key,
                                 std::string* error)
{
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        if (error) {
            *error = strprintf("required %s is not a regular file: %s",
                               private_key ? "mTLS client key" : "mTLS certificate",
                               fs::PathToString(path));
        }
        return false;
    }

#ifndef WIN32
    struct stat metadata {};
    const std::string native_path = fs::PathToString(path);
    if (lstat(native_path.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode)) {
        if (error) {
            *error = strprintf("mTLS credential must be a non-symlink regular file: %s",
                               native_path);
        }
        return false;
    }
    if (metadata.st_uid != geteuid()) {
        if (error) {
            *error = strprintf("mTLS credential must be owned by the Elements process user: %s",
                               native_path);
        }
        return false;
    }
    const fs::path parent_path = path.parent_path();
    struct stat parent_metadata {};
    const std::string native_parent = fs::PathToString(parent_path);
    if (parent_path.empty() ||
        lstat(native_parent.c_str(), &parent_metadata) != 0 ||
        !S_ISDIR(parent_metadata.st_mode) ||
        parent_metadata.st_uid != geteuid() ||
        (parent_metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (error) {
            *error = strprintf(
                "mTLS credential directory must be owned by the Elements process user and deny group/other write access: %s",
                native_parent);
        }
        return false;
    }
    const mode_t forbidden = private_key
        ? (S_IRWXG | S_IRWXO)
        : (S_IWGRP | S_IWOTH);
    if ((metadata.st_mode & forbidden) != 0) {
        if (error) {
            *error = strprintf(
                private_key
                    ? "mTLS client key must deny all group and other access: %s"
                    : "mTLS certificate must deny group and other write access: %s",
                native_path);
        }
        return false;
    }
    // Opening after path-only checks must not follow a replacement symlink or
    // block on a replacement FIFO. Validate the opened file as well, before
    // letting grpcurl use a credential in this protected directory.
    const int descriptor = open(
        native_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat opened_metadata {};
    const bool valid_open = descriptor >= 0 &&
        fstat(descriptor, &opened_metadata) == 0 &&
        S_ISREG(opened_metadata.st_mode) &&
        opened_metadata.st_uid == geteuid() &&
        (opened_metadata.st_mode & forbidden) == 0 &&
        opened_metadata.st_dev == metadata.st_dev &&
        opened_metadata.st_ino == metadata.st_ino;
    if (descriptor >= 0) close(descriptor);
    if (!valid_open) {
        if (error) *error = "mTLS credential could not be securely opened: " + native_path;
        return false;
    }
#else
    if (fs::is_symlink(path)) {
        if (error) *error = "mTLS credential must be a non-symlink regular file";
        return false;
    }
    std::ifstream input(path);
    if (!input.good()) {
        if (error) *error = "required mTLS credential is not readable: " + fs::PathToString(path);
        return false;
    }
#endif
    return true;
}

} // namespace

bool ValidateDrivechainGrpcTLSConfig(const ArgsManager& args, std::string* error)
{
    if (error) error->clear();
    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    if (config.address.empty() || config.address.find("://") != std::string::npos) {
        if (error) *error = "-drivechainbmmgrpcaddr must be a host:port endpoint without a URL scheme";
        return false;
    }
    if (config.address.size() > 512 ||
        std::any_of(config.address.begin(), config.address.end(),
                    [](const unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        if (error) *error = "-drivechainbmmgrpcaddr contains whitespace, control characters, or excessive data";
        return false;
    }
    uint16_t port{0};
    std::string host;
    SplitHostPort(config.address, port, host);
    if (host.empty() || host.front() == '-' || port == 0) {
        if (error) *error = "-drivechainbmmgrpcaddr must contain a non-empty host and nonzero port";
        return false;
    }
    // The former peg-out endpoint is a compatibility assertion, not a second
    // transport. BMM bids and withdrawals must use the same authenticated
    // enforcer; silently ignoring a conflicting endpoint would misroute funds.
    if (args.IsArgSet("-drivechainpegoutenforcer") &&
        args.GetArg("-drivechainpegoutenforcer", "") != config.address) {
        if (error) *error = "-drivechainpegoutenforcer and -drivechainbmmgrpcaddr must select the same authenticated endpoint";
        return false;
    }
    if (!config.authority.empty() &&
        std::any_of(config.authority.begin(), config.authority.end(),
                    [](const unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        if (error) *error = "-drivechainbmmgrpcauthority contains whitespace or control characters";
        return false;
    }
    return ValidateReadableRegularFile(config.ca_certificate, false, error) &&
           ValidateReadableRegularFile(config.client_certificate, false, error) &&
           ValidateReadableRegularFile(config.client_key, true, error);
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    BoundedCommandResult failure;
    static const std::set<std::string> ALLOWED_METHODS{
        "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
    };
    if (ALLOWED_METHODS.count(method) == 0) {
        failure.error = "refusing an unrecognized enforcer gRPC method";
        return failure;
    }
    if (json_payload.empty() || json_payload.size() > (1U << 20)) {
        failure.error = "enforcer gRPC payload must contain 1..1048576 bytes";
        return failure;
    }

    std::string config_error;
    UniValue parsed_payload;
    if (!parsed_payload.read(json_payload) || !parsed_payload.isObject()) {
        failure.error = "enforcer gRPC payload must be one JSON object";
        return failure;
    }
    if (!ValidateDrivechainGrpcTLSConfig(args, &config_error)) {
        failure.error = config_error;
        return failure;
    }
    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    std::vector<std::string> argv{
        ResolveDrivechainBmmGrpcurlPath(args),
        "-cacert", fs::PathToString(config.ca_certificate),
        "-cert", fs::PathToString(config.client_certificate),
        "-key", fs::PathToString(config.client_key),
    };
    if (!config.authority.empty()) {
        argv.push_back("-authority");
        argv.push_back(config.authority);
    }
    argv.insert(argv.end(), {
        "-d", json_payload, config.address, method,
    });
    return RunBoundedCommand(argv, timeout, max_output, should_cancel);
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    return RunAuthenticatedDrivechainGrpc(
        gArgs, method, json_payload, timeout, max_output, should_cancel);
}


std::string GetDrivechainGrpcAddress(const ArgsManager& args)
{
    return GetDrivechainGrpcTLSConfig(args).address;
}

bool ValidateNativeDrivechainRpcServerConfig(const ArgsManager& args,
                                             std::string* error)
{
    if (error) error->clear();
    const int64_t configured_port = args.GetIntArg(
        "-rpcport", BaseParams().RPCPort());
    if (configured_port <= 0 ||
        configured_port > std::numeric_limits<uint16_t>::max()) {
        if (error) *error = "-rpcport must be between 1 and 65535";
        return false;
    }

    for (const std::string& binding : args.GetArgs("-rpcbind")) {
        uint16_t port = static_cast<uint16_t>(configured_port);
        std::string host;
        SplitHostPort(binding, port, host);
        if (port == 0 || host.empty() ||
            !IsMainchainRPCHostAllowed(host, /*native_drivechain=*/true)) {
            if (error) {
                *error = strprintf(
                    "native drivechain JSON-RPC requires a numeric IPv4 127/8 or IPv6 ::1 binding, not %s",
                    binding);
            }
            return false;
        }
    }
    return true;
}
