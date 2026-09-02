// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#ifndef BITCOIN_TEST_ECX_SIMPLICITY_TEST_SHIM_H
#define BITCOIN_TEST_ECX_SIMPLICITY_TEST_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <simplicity/elements/env.h>

/* Test-only C boundary: exercise the real jet frame adapter without exposing
 * private Simplicity C structures to Bitcoin's C++ headers. Returns whether
 * evaluation succeeded; the proof acceptance bit is written to valid. */
bool ecx_test_successor_jet_frame(
    const unsigned char* annex,
    size_t annex_len,
    const unsigned char program[32],
    const unsigned char public_values_digest[32],
    ecx_sp1_groth16_verify_fn verifier,
    void* verifier_context,
    bool* valid);

#ifdef __cplusplus
}
#endif

#endif
