// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAINCHAINRPC_H
#define BITCOIN_MAINCHAINRPC_H

#include <rpc/client.h>
#include <rpc/protocol.h>
#include <uint256.h>

#include <string>
#include <stdexcept>
#include <chrono>
#include <cstddef>
#include <functional>
#include <vector>

#include <univalue.h>

class CBlock;
class CTransaction;
class ArgsManager;
struct DrivechainDepositEvidence;
namespace drivechain {
struct AuthenticatedDeposit;
struct BmmL1State;
struct BmmProof;
}

static const bool DEFAULT_NAMED=false;
static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Result of running one direct-argv child with bounded time and output. */
struct BoundedCommandResult {
    bool started{false};
    bool exited{false};
    bool timed_out{false};
    bool cancelled{false};
    bool output_truncated{false};
    int exit_code{-1};
    std::string output;
    std::string error;
};

/** Execute argv directly, never through a shell, and always reap the child. */
BoundedCommandResult RunBoundedCommand(
    const std::vector<std::string>& argv,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});

/** Validate the mandatory CA, client certificate, and client key. */
bool ValidateDrivechainGrpcTLSConfig(
    const ArgsManager& args,
    std::string* error = nullptr);

/** Call an allowlisted enforcer method using mutual TLS and direct argv. */
BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});
BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});

std::string GetDrivechainGrpcAddress(const ArgsManager& args);

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params);
/**
 * Call a unary CUSF Connect RPC over bounded in-process HTTP/JSON.
 *
 * The endpoint is a host[:port] authority (no URL scheme) and method is the
 * fully-qualified service/method path without a leading slash. This function
 * never invokes a shell or external executable.
 */
bool CallDrivechainConnectJSON(
    const std::string& endpoint,
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error = nullptr);
/**
 * Submit a BIP301 M8 bid through the BitWindow/CUSF enforcer wallet.
 *
 * The bid is paid on the parent chain. The committed critical hash identifies
 * the Elements candidate whose policy-asset fees are collected by its
 * coinbase destination.
 */
bool SubmitDrivechainBmmBid(
    int sidechain_slot,
    uint64_t bid_sats,
    uint32_t parent_height,
    const uint256& critical_hash,
    const uint256& previous_parent_hash,
    uint256& request_txid,
    std::string* error = nullptr);
bool GetDrivechainTwoWayPegData(int sidechain_slot, UniValue& response, std::string* error = nullptr);
bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated = nullptr,
    std::string* error = nullptr);
/** Build committed v2 SPV/CTIP evidence outside consensus validation. */
bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error = nullptr);
/** Build and self-verify deterministic successor/BMM proof outside consensus. */
bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error = nullptr);

// Verify if the block with given hash has at least the specified minimum number
// of confirmations.
// For validating merkle blocks, you can provide the nbTxs parameter to verify if
// it equals the number of transactions in the block.
bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs);

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error = nullptr);

#endif // BITCOIN_MAINCHAINRPC_H
