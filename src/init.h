// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <addresstype.h>

#include <asset.h>
#include <consensus/amount.h>
#include <mainchainrpc.h>

#include <any>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <atomic>

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
namespace kernel {
struct Context;
}
namespace node {
struct NodeContext;
} // namespace node

/**
 * Build the automatic bidder's reward script from a locally spendable,
 * unconfidential P2PKH/P2WPKH address on the selected network. This is mining
 * policy, not a restriction on other miners' consensus-valid destinations.
 * The ownership callback must exclude watch-only/private-key-disabled wallets.
 * On failure, clear the output script; never fall back to OP_TRUE.
 */
bool BuildDrivechainRewardScript(
    const std::string& address,
    const std::function<bool(const CTxDestination&)>& is_spendable,
    CScript& script,
    std::string* error = nullptr);

/** Initialize node context shutdown and args variables. */
void InitContext(node::NodeContext& node);
/** Return whether node shutdown was requested. */
bool ShutdownRequested(node::NodeContext& node);

/** Interrupt threads */
void Interrupt(node::NodeContext& node);
void Shutdown(node::NodeContext& node);
//!Initialize the logging infrastructure
void InitLogging(const ArgsManager& args);
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction(ArgsManager& args);

/** Native drivechains forbid DNS on synchronous consensus RPC paths. */
bool IsMainchainRPCHostAllowed(const std::string& host, bool native_drivechain);

/** Forbid non-loopback JSON-RPC listeners on the native chain. */
bool ValidateNativeDrivechainRpcServerConfig(
    const ArgsManager& args, std::string* error = nullptr);

/** Validate and select max(configured bid, candidate transaction fees). */
bool ComputeDrivechainBmmBid(CAmount configured_bid,
                             CAmount sidechain_fees,
                             CAmount& selected_bid,
                             std::string* error = nullptr);

/** Strictly parse a positive, MoneyRange-safe BIP301 bid. */
bool ParseDrivechainBmmBid(const std::string& value,
                           CAmount& bid,
                           std::string* error = nullptr);

/**
 * Submit one already-validated blinded BIP300 M6 to the configured enforcer.
 *
 * This is a liveness-only transport helper. Callers must first authenticate
 * the corresponding, confirmed Elements burn; an enforcer response is never
 * consensus evidence.
 */
bool SubmitDrivechainWithdrawalBundle(node::NodeContext& node,
                                      int sidechain_slot,
                                      const std::vector<unsigned char>& bundle,
                                      std::string* response = nullptr,
                                      std::string* error = nullptr);

/** Resolve -feeasset, optionally enforcing the immutable production asset. */
bool ResolveElementsFeeAsset(const std::optional<std::string>& configured,
                             const CAsset& pegged_asset,
                             bool enforce_canonical,
                             CAsset& resolved,
                             std::string* error = nullptr);

/** Initialize bitcoin core: Basic context setup.
 *  @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInitBasicSetup(const ArgsManager& args, std::atomic<int>& exit_status);
/**
 * Initialization: parameter interaction.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitBasicSetup should have been called.
 */
bool AppInitParameterInteraction(ArgsManager& args);
/**
 * Initialization sanity checks.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitParameterInteraction should have been called.
 */
bool AppInitSanityChecks(const kernel::Context& kernel);
/**
 * Lock bitcoin core critical directories.
 * @note This should only be done after daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitSanityChecks should have been called.
 */
bool AppInitLockDirectories();
/**
 * Initialize node and wallet interface pointers. Has no prerequisites or side effects besides allocating memory.
 */
bool AppInitInterfaces(node::NodeContext& node);
/**
 * Bitcoin core main initialization.
 * @note This should only be done after daemonization. Call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitLockDirectories should have been called.
 */
bool AppInitMain(node::NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info = nullptr);

/**
 * Register all arguments with the ArgsManager
 */
void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc=false);

/** Validates requirements to run the indexes and spawns each index initial sync thread */
bool StartIndexBackgroundSync(node::NodeContext& node);

#endif // BITCOIN_INIT_H
