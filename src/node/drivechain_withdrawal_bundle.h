// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_BUNDLE_H
#define BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_BUNDLE_H

#include <uint256.h>

namespace node {

uint256 GetCurrentDrivechainWithdrawalBundleHash();
void SetCurrentDrivechainWithdrawalBundleHash(const uint256& bundle_hash);

} // namespace node

#endif // BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_BUNDLE_H
