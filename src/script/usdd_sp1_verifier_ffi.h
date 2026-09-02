// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_USDD_SP1_VERIFIER_FFI_H
#define BITCOIN_SCRIPT_USDD_SP1_VERIFIER_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USDD_SP1_VERIFIER_ABI_VERSION 1U
#define USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_VERSION 1U
#define USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_SIZE 32U

typedef enum usdd_sp1_verifier_status_t {
    USDD_SP1_VERIFIER_ACCEPTED = 0,
    USDD_SP1_VERIFIER_REJECTED = 1,
    USDD_SP1_VERIFIER_INVALID_ARGUMENT = 2,
    USDD_SP1_VERIFIER_ABI_MISMATCH = 3,
    USDD_SP1_VERIFIER_PANICKED = 4,
} usdd_sp1_verifier_status;

uint32_t usdd_sp1_verifier_abi_version(void);

/** Return the version of the platform-independent semantic identity format. */
uint32_t usdd_sp1_verifier_semantic_identity_version(void);

/**
 * Copy the 32-byte platform-independent verifier semantic identity to output.
 *
 * This identity commits to the FFI contract, pinned SP1 recursion verifier,
 * proof codec/hash mode, and normalized Cargo.lock/local source closure. It is
 * deliberately not a native static-archive hash. Returns ACCEPTED on success.
 */
uint32_t usdd_sp1_verifier_semantic_identity(
    uint8_t* output,
    size_t output_len);

/**
 * Verify one complete canonical USDD SP1 annex.
 *
 * `expected_public_values_sha256` is SHA256 of the exact canonical public
 * values consumed by the Simplicity controller. The statement-kind codec
 * determines whether those bytes are a typed journal or the incompatible V11
 * raw strong-execution hash. Only ACCEPTED authorizes the verifier jet to
 * return true; every other or unknown status is false.
 */
uint32_t usdd_sp1_verify_annex(
    uint32_t abi_version,
    const uint8_t* annex,
    size_t annex_len,
    const uint8_t* expected_program_id,
    size_t expected_program_id_len,
    const uint8_t* expected_public_values_sha256,
    size_t expected_public_values_sha256_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_SCRIPT_USDD_SP1_VERIFIER_FFI_H
