// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_REQUEST_H
#define BITCOIN_RPC_REQUEST_H

#include <any>
#include <string>

#include <fs.h>
#include <univalue.h>

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id);
UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id);
std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id);
UniValue JSONRPCError(int code, const std::string& message);

/** Generate a new RPC authentication cookie and write it to disk */
bool GenerateAuthCookie(std::string *cookie_out);
/** Read the RPC authentication cookie from disk */
bool GetAuthCookie(std::string *cookie_out);
/** Delete RPC authentication cookie from disk */
void DeleteAuthCookie();
/** Parse JSON-RPC batch reply into a vector */
std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue& in);

class JSONRPCRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;
    enum Mode { EXECUTE, GET_HELP, GET_ARGS } mode = EXECUTE;
    std::string URI;
    std::string authUser;
    std::string peerAddr;
    std::any context;

    void parse(const UniValue& valRequest);
};

// ELEMENTS:
/** Return the resolved parent-node cookie path. */
fs::path GetMainchainAuthCookieFile();
/** Read one private, canonical Bitcoin Core rotating cookie. */
bool ReadMainchainAuthCookieFile(
    const fs::path& path,
    std::string& cookie,
    std::string* error = nullptr);
/** Compatibility name for the same strict, rotating-cookie reader. */
bool ReadNativeDrivechainCookieFile(
    const fs::path& path, std::string& cookie, std::string* error = nullptr);
/** Read a private, owner-only regular file without following symlinks. */
bool ReadPrivateRpcAuthFile(
    const fs::path& path, std::string& contents, std::string* error = nullptr);
/** Explicit static credentials for a loopback parent; not a cookie fallback. */
bool ReadMainchainRpcCredentialFile(
    const fs::path& path, std::string& credentials, std::string* error = nullptr);
/** Return the parent-node cookie path relative to Bitcoin's data directory. */
std::string GetDefaultMainchainAuthCookieFile(const std::string& chain);
/** Needs to know cookiedir path info -cli doesn't require */
bool GetMainchainAuthCookie(std::string *cookie_out);

#endif // BITCOIN_RPC_REQUEST_H
