// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <consensus/amount.h>

#include <any>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

//! Default value for -daemon option
static constexpr bool DEFAULT_DAEMON = false;
//! Default value for -daemonwait option
static constexpr bool DEFAULT_DAEMONWAIT = false;
//! Default liveness-only BIP301 bid submitted to the local enforcer wallet.
static constexpr CAmount DEFAULT_DRIVECHAIN_BMM_BID{1000};

class ArgsManager;
namespace interfaces {
struct BlockAndHeaderTipInfo;
}
namespace node {
struct NodeContext;
} // namespace node

/** Interrupt threads */
void Interrupt(node::NodeContext& node);
void Shutdown(node::NodeContext& node);
//!Initialize the logging infrastructure
void InitLogging(const ArgsManager& args);
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction(ArgsManager& args);

/** Native drivechains forbid DNS on synchronous consensus RPC paths. */
bool IsMainchainRPCHostAllowed(const std::string& host, bool native_drivechain);

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

/**
 * Execute argv directly (never through a shell), combining stdout/stderr.
 * The child process group is terminated and reaped on timeout, cancellation,
 * output truncation, or read failure.
 */
BoundedCommandResult RunBoundedCommand(
    const std::vector<std::string>& argv,
    std::chrono::milliseconds timeout,
    size_t max_output,
    const std::function<bool()>& should_cancel = {});

/** Validate and select max(configured bid, candidate transaction fees). */
bool ComputeDrivechainBmmBid(CAmount configured_bid,
                             CAmount sidechain_fees,
                             CAmount& selected_bid,
                             std::string* error = nullptr);

/** Strictly parse a positive, MoneyRange-safe BIP301 bid. */
bool ParseDrivechainBmmBid(const std::string& value,
                           CAmount& bid,
                           std::string* error = nullptr);

/** Initialize bitcoin core: Basic context setup.
 *  @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInitBasicSetup(const ArgsManager& args);
/**
 * Initialization: parameter interaction.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitBasicSetup should have been called.
 */
bool AppInitParameterInteraction(ArgsManager& args);
/**
 * Initialization sanity checks: ecc init, sanity checks, dir lock.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitParameterInteraction should have been called.
 */
bool AppInitSanityChecks();
/**
 * Lock bitcoin core data directory.
 * @note This should only be done after daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitSanityChecks should have been called.
 */
bool AppInitLockDataDirectory();
/**
 * Initialize node and wallet interface pointers. Has no prerequisites or side effects besides allocating memory.
 */
bool AppInitInterfaces(node::NodeContext& node);
/**
 * Bitcoin core main initialization.
 * @note This should only be done after daemonization. Call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitLockDataDirectory should have been called.
 */
bool AppInitMain(node::NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info = nullptr);

/**
 * Register all arguments with the ArgsManager
 */
void SetupServerArgs(ArgsManager& argsman);

#endif // BITCOIN_INIT_H
