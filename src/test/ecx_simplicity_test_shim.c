// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include "ecx_simplicity_test_shim.h"

#include <simplicity/elements/elementsJets.h>
#include <simplicity/elements/txEnv.h>
#include <simplicity/frame.h>

bool ecx_test_successor_jet_frame(
    const unsigned char* annex,
    size_t annex_len,
    const unsigned char program[32],
    const unsigned char public_values_digest[32],
    ecx_sp1_groth16_verify_fn verifier,
    void* verifier_context,
    bool* valid)
{
    if (!valid) return false;
    *valid = false;
    if ((!annex && annex_len) || !program || !public_values_digest || annex_len > UINT_FAST32_MAX) return false;

    UWORD source[ROUND_UWORD(512)] = {0};
    UWORD output[ROUND_UWORD(1)] = {0};
    frameItem writer = initWriteFrame(512, source + ROUND_UWORD(512));
    write8s(&writer, program, 32);
    write8s(&writer, public_values_digest, 32);

    sigInput input = {0};
    input.annex = annex;
    input.annexLen = (uint_fast32_t)annex_len;
    elementsTransaction transaction = {0};
    transaction.input = &input;
    transaction.numInputs = 1;
    txEnv env = {0};
    env.tx = &transaction;
    env.verifySp1Groth16 = verifier;
    env.verifySp1Groth16Context = verifier_context;

    frameItem dst = initWriteFrame(1, output + ROUND_UWORD(1));
    if (!simplicity_verify_sp1_groth16_v6_incremental_successor_sha256(
            &dst, initReadFrame(512, source), &env)) return false;
    frameItem result = initReadFrame(1, output);
    *valid = readBit(&result);
    return true;
}
