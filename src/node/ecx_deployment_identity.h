// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#ifndef BITCOIN_NODE_ECX_DEPLOYMENT_IDENTITY_H
#define BITCOIN_NODE_ECX_DEPLOYMENT_IDENTITY_H

#include <string>

class ChainstateManager;

namespace node {

/**
 * Validate an already-bound runtime ECX/private-BMM configuration before any
 * block-index or chainstate replay is attempted. A missing record is handled
 * by BindEcxDeploymentIdentityIfNeeded after the coins databases are opened.
 */
bool CheckEcxDeploymentIdentity(std::string& error);

/** Reject any reset that could erase the evidence needed for first binding. */
bool CheckEcxDeploymentResetAllowed(
    bool reset_requested,
    bool databases_in_memory,
    std::string& error);

/**
 * First-bind a runtime deployment only while every persisted coins best/head
 * block is strictly below its earliest activation height.
 */
bool BindEcxDeploymentIdentityIfNeeded(
    ChainstateManager& chainman,
    bool databases_in_memory,
    std::string& error);

} // namespace node

#endif // BITCOIN_NODE_ECX_DEPLOYMENT_IDENTITY_H
