// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_SETTINGS_H
#define BITCOIN_DRIVECHAIN_SETTINGS_H

#include <consensus/amount.h>

#include <cstdint>

/**
 * Defaults for the drivechain peg settings.
 *
 * These live in one header so that the argument registration in init.cpp and
 * the readers in the wallet RPC cannot drift apart. They were previously
 * environment variables read at each call site with independently written
 * fallbacks, which is how ELEMENTS_DRIVECHAIN_PEGOUT_REQUIRE_L1_EVENT came to
 * exist as an undocumented way to disable a custody check.
 */

//! BIP300 sidechain slot this node is bound to.
static constexpr int64_t DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT{24};

//! Address of the mutually authenticated BIP300 enforcer gRPC endpoint.
inline constexpr const char* DEFAULT_DRIVECHAIN_GRPC_ENDPOINT{"127.0.0.1:55051"};

//! Satoshi reserved out of a withdrawal to pay for the M6 bundle on L1.
//!
//! Must be positive: a bundle carrying no mainchain fee gives miners no reason
//! to include it, so the withdrawal can be accepted on the sidechain and then
//! never pay out.
static constexpr CAmount DEFAULT_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS{10'000};

#endif // BITCOIN_DRIVECHAIN_SETTINGS_H
