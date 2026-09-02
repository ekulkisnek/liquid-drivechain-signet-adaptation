// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H
#define BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <elements_drivechain_identity.h>
#include <script/usdd_sp1_verifier_ffi.h>

#include <algorithm>
#include <array>
#include <string>

/**
 * Enforce the verifier identity required by the immutable production network.
 *
 * Keeping this check at startup prevents build-dependent consensus after the
 * proof gate is activated: a node cannot run the sole production network with
 * no verifier, an old ABI, or different verifier semantics. Until activation
 * is configured, every annex remains rejected by the separate consensus gate
 * and omission of the archive is safe.
 */
inline bool CheckUsddSp1VerifierStartupIdentity(
    const bool activation_configured,
    const std::array<uint8_t, 32>& expected_identity,
    std::string* error)
{
    if (error) error->clear();
    if (!activation_configured) return true;

    if (std::all_of(expected_identity.begin(), expected_identity.end(),
                    [](const uint8_t byte) { return byte == 0; })) {
        if (error) *error = "USDD SP1 activation has no frozen verifier semantic identity";
        return false;
    }

#if defined(HAVE_USDD_SP1_VERIFIER)
    if (usdd_sp1_verifier_abi_version() !=
        ElementsDrivechainIdentity::REQUIRED_USDD_SP1_VERIFIER_ABI_VERSION) {
        if (error) *error = "linked USDD SP1 verifier ABI does not match the production identity";
        return false;
    }
    if (usdd_sp1_verifier_semantic_identity_version() !=
        ElementsDrivechainIdentity::REQUIRED_USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_VERSION) {
        if (error) *error = "linked USDD SP1 verifier semantic-identity format does not match the production identity";
        return false;
    }
    std::array<uint8_t, USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_SIZE> actual_identity{};
    const uint32_t status = usdd_sp1_verifier_semantic_identity(
        actual_identity.data(), actual_identity.size());
    if (status != USDD_SP1_VERIFIER_ACCEPTED) {
        if (error) *error = "linked USDD SP1 verifier could not export its semantic identity";
        return false;
    }
    if (!std::equal(actual_identity.begin(), actual_identity.end(), expected_identity.begin())) {
        if (error) *error = "linked USDD SP1 verifier semantics do not match the production identity";
        return false;
    }
    return true;
#else
    (void)expected_identity;
    if (error) *error = "USDD SP1 activation requires the pinned verifier, but this binary was built without it";
    return false;
#endif
}

inline bool CheckCanonicalUsddSp1VerifierStartupIdentity(std::string* error)
{
    return CheckUsddSp1VerifierStartupIdentity(
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED,
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY,
        error);
}

#endif // BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H
