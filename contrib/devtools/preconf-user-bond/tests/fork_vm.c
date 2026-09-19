/* Isolated test driver for the unmodified, pinned node's Simplicity C runtime.
 * This does NOT replace full node UTXO, Taproot, finality, or mempool checks.
 * Input is a bounded test-fixture binary stream emitted by check-fork.mjs.
 * No RPC, private keys, external verifier stubs, or consensus-rule modifications.
 */
#include <simplicity/elements/env.h>
#include <simplicity/elements/exec.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BLOB 1048576U
#define MAX_IO 8U
static unsigned char *allocations[100];
static unsigned allocation_count;
static void cleanup(void) {
    for (unsigned i = 0; i < allocation_count; ++i) free(allocations[i]);
}
static void fail(const char *message) {
    fprintf(stderr, "fixture error: %s\n", message);
    exit(2);
}
static uint32_t read32(void) {
    unsigned char p[4];
    if (fread(p, 1, 4, stdin) != 4) fail("truncated integer");
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static rawElementsBuffer blob(void) {
    uint32_t len = read32();
    if (len > MAX_BLOB || allocation_count >= 100) fail("size limit");
    unsigned char *p = malloc(len ? len : 1);
    if (!p) fail("allocation failed");
    allocations[allocation_count++] = p;
    if (fread(p, 1, len, stdin) != len) fail("truncated blob");
    return (rawElementsBuffer){.buf = p, .len = len};
}
static const unsigned char *fixed(uint32_t size) {
    rawElementsBuffer b = blob();
    if (b.len != size) fail("wrong fixed field size");
    return b.buf;
}
static uint32_t compact_size(uint32_t n) { return n < 253 ? 1 : n <= 65535 ? 3 : 5; }

int main(void) {
    if (atexit(cleanup) != 0) fail("atexit failed");
    rawElementsBuffer program = blob(), witness = blob();
    const unsigned char *cmr = fixed(32), *control = fixed(33), *genesis = fixed(32), *txid = fixed(32);
    uint32_t version = read32(), locktime = read32();
    uint32_t ni = read32();
    if (!ni || ni > MAX_IO) fail("input count");
    rawElementsInput inputs[MAX_IO] = {0};
    rawElementsOutput outputs[MAX_IO] = {0};
    for (uint32_t i = 0; i < ni; ++i) {
        inputs[i].prevTxid = fixed(32);
        inputs[i].prevIx = read32();
        inputs[i].sequence = read32();
        inputs[i].txo.asset = fixed(33);
        inputs[i].txo.value = fixed(9);
        if (inputs[i].txo.asset[0] != 1 || inputs[i].txo.value[0] != 1) fail("explicit input required");
        inputs[i].txo.scriptPubKey = blob();
    }
    uint32_t no = read32();
    if (no > MAX_IO) fail("output count");
    for (uint32_t i = 0; i < no; ++i) {
        outputs[i].asset = fixed(33);
        outputs[i].value = fixed(9);
        if (outputs[i].asset[0] != 1 || outputs[i].value[0] != 1) fail("explicit output required");
        outputs[i].scriptPubKey = blob();
    }
    if (fgetc(stdin) != EOF) fail("trailing data");
    rawElementsTransaction raw = {.txid = txid, .input = inputs, .output = outputs,
        .numInputs = ni, .numOutputs = no, .version = version, .lockTime = locktime};
    rawElementsTapEnv raw_tap = {.controlBlock = control, .scriptCMR = cmr, .pathLen = 0};
    elementsTransaction *tx = simplicity_elements_mallocTransaction(&raw);
    elementsTapEnv *tap = simplicity_elements_mallocTapEnv(&raw_tap);
    if (!tx || !tap) fail("environment allocation failed");
    /* Same stack-serialization + 50 budget used by the node, NOT unlimited. */
    int64_t budget = 50 + 1 + compact_size(program.len) + program.len +
        compact_size(witness.len) + witness.len + 1 + 32 + 1 + 33;
    simplicity_err error;
    const ecx_prior_active_root_env ecx_root = {0};
    const rawElementsBlockEnv block_env = {0};
    const bool executed = simplicity_elements_execSimplicityWithBlockEnv(&error, NULL,
        tx, 0, tap, genesis, &ecx_root, &block_env, 0, budget, NULL,
        program.buf, program.len, witness.buf, witness.len);
    simplicity_elements_freeTapEnv(tap);
    simplicity_elements_freeTransaction(tx);
    if (!executed) fail("interpreter allocation failure");
    printf("{\"error\":%d,\"budget\":%lld}\n", (int)error, (long long)budget);
    return 0;
}
