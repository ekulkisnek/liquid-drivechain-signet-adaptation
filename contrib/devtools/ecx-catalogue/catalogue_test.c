/* Copyright (c) 2026 The Elements Core developers
 * Distributed under the MIT software license.
 * Offline catalogue/frame tests, not cryptographic proof qualification.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elements/elementsJets.h"
#include "elements/primitive.h"
#include "elements/txEnv.h"
#include "eval.h"

static size_t checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
  fprintf(stderr, "FAIL at %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

typedef struct vector {
  const char* name;
  const char* bits;
  bool (*jet)(frameItem*, frameItem, const txEnv*);
  ubounded cost;
  size_t source_bits, target_bits;
  sha256_midstate cmr, imr, amr, source_tmr, target_tmr;
} vector;

static const vector vectors[] = {
#include "catalogue_vectors.inc"
};

/* Right alignment makes every prefix test end at an exact bit boundary. */
static simplicity_err decode(dag_node* node, const char* bits, size_t length) {
  unsigned char bytes[32] = {0};
  const unsigned char offset = (unsigned char)((8 - length % 8) % 8);
  CHECK(length <= 8 * sizeof(bytes) - offset);
  for (size_t i = 0; i < length; ++i) {
    CHECK(bits[i] == '0' || bits[i] == '1');
    if (bits[i] == '1') bytes[(i + offset) / 8] |= (unsigned char)(1u << (7 - (i + offset) % 8));
  }
  bitstream stream = {bytes, (length + offset) / 8, offset};
  const simplicity_err result = simplicity_elements_decodeJet(node, &stream);
  if (result == SIMPLICITY_NO_ERROR) CHECK(stream.len == 0 && stream.offset == 0);
  return result;
}

static size_t natural(char* out, uint32_t n) {
  CHECK(n > 0);
  if (n == 1) { out[0] = '0'; return 1; }
  uint32_t tail = n;
  unsigned int count = 0;
  while (tail >>= 1) ++count;
  out[0] = '1';
  size_t used = 1 + natural(out + 1, count);
  for (unsigned int i = count; i > 0; --i) out[used++] = (n >> (i - 1)) & 1u ? '1' : '0';
  return used;
}

static simplicity_err decode_path(dag_node* node, uint32_t branch, uint32_t index) {
  char bits[128] = {'1'};
  size_t used = 1 + natural(bits + 1, branch);
  used += natural(bits + used, index);
  return decode(node, bits, used);
}

static bool hash_eq(const sha256_midstate* a, const sha256_midstate* b) {
  return memcmp(a->s, b->s, sizeof(a->s)) == 0;
}

static void test_decoder(void) {
  CHECK(sizeof(vectors) / sizeof(*vectors) == 24);
  for (size_t i = 0; i < 24; ++i) {
    const vector* v = &vectors[i];
    dag_node node = {0};
#ifdef ECX_SIMPLICITY_CATALOGUE_FROZEN
    CHECK(decode(&node, v->bits, strlen(v->bits)) == SIMPLICITY_NO_ERROR);
    CHECK(node.tag == JET && node.jet == v->jet && node.cost == v->cost);
    CHECK(hash_eq(&node.cmr, &v->cmr));
    type* types = NULL;
    const combinator_counters census = {0};
    CHECK(simplicity_mallocTypeInference(&types, simplicity_elements_mallocBoundVars, &node, 1, &census)
          == SIMPLICITY_NO_ERROR);
    CHECK(types != NULL);
    CHECK(types[node.sourceType].bitSize == v->source_bits);
    CHECK(types[node.targetType].bitSize == v->target_bits);
    CHECK(hash_eq(&types[node.sourceType].typeMerkleRoot, &v->source_tmr));
    CHECK(hash_eq(&types[node.targetType].typeMerkleRoot, &v->target_tmr));
    sha256_midstate imr;
    CHECK(simplicity_verifyNoDuplicateIdentityHashes(&imr, &node, types, 1) == SIMPLICITY_NO_ERROR);
    CHECK(hash_eq(&imr, &v->imr));
    analyses amr;
    simplicity_computeAnnotatedMerkleRoot(&amr, &node, types, 1);
    CHECK(hash_eq(&amr.annotatedMerkleRoot, &v->amr));
    ubounded cells, words, frames, cost;
    CHECK(simplicity_analyseBounds(&cells, &words, &frames, &cost,
          UBOUNDED_MAX, 0, UBOUNDED_MAX, &node, types, 1) == SIMPLICITY_NO_ERROR);
    CHECK(cost > v->cost); /* Includes the evaluator's node overhead. */
    const ubounded exact_cost = cost;
    CHECK(simplicity_analyseBounds(&cells, &words, &frames, &cost,
          UBOUNDED_MAX, 0, exact_cost, &node, types, 1) == SIMPLICITY_NO_ERROR);
    CHECK(simplicity_analyseBounds(&cells, &words, &frames, &cost,
          UBOUNDED_MAX, 0, exact_cost - 1, &node, types, 1) == SIMPLICITY_ERR_EXEC_BUDGET);
    free(types);
    for (size_t cut = 0; cut < strlen(v->bits); ++cut)
      CHECK(decode(&node, v->bits, cut) == SIMPLICITY_ERR_BITSTREAM_EOF);
#else
    CHECK(decode(&node, v->bits, strlen(v->bits)) == SIMPLICITY_ERR_DATA_OUT_OF_RANGE);
#endif
  }
  for (uint32_t index = 25; index <= 256; ++index) {
    dag_node node;
    CHECK(decode_path(&node, 5, index) == SIMPLICITY_ERR_DATA_OUT_OF_RANGE);
  }
  dag_node node;
  CHECK(decode_path(&node, 5, 2147483647) == SIMPLICITY_ERR_DATA_OUT_OF_RANGE);
  /* Native Alpha identities remain distinct from the additive branch. */
  CHECK(decode_path(&node, 4, 53) == SIMPLICITY_NO_ERROR);
  CHECK(node.jet == simplicity_native_current_bmm_parent_mtp_required);
  CHECK(!hash_eq(&node.cmr, &vectors[7].cmr));
  CHECK(decode_path(&node, 4, 52) == SIMPLICITY_NO_ERROR);
  CHECK(node.jet == simplicity_verify_sp1_compressed_sha256);
  CHECK(node.cost == 900007720);
  CHECK(decode_path(&node, 4, 57) == SIMPLICITY_NO_ERROR);
  CHECK(node.jet == simplicity_prior_active_bmm_parent_checkpoint_required);
}

static sha256_midstate small_hash(uint32_t value) {
  const sha256_midstate hash = {{0, 0, 0, 0, 0, 0, 0, value}};
  return hash;
}

static bool role(const vector* v, uint32_t index, const txEnv* env) {
  UWORD input[ROUND_UWORD(32)] = {0}, output[1] = {0};
  frameItem writer = initWriteFrame(32, input + ROUND_UWORD(32));
  simplicity_write32(&writer, index);
  frameItem dst = initWriteFrame(0, output);
  return v->jet(&dst, initReadFrame(32, input), env);
}

static void test_runtime(void) {
  sigInput inputs[4] = {0};
  elementsTransaction tx = {.input = inputs, .numInputs = 4};
  const txEnv absent = {.tx = &tx, .ix = 3};
  txEnv env = absent;
  env.priorActiveExchangeStateRoot = small_hash(1);
  env.priorActiveExchangeStateRootPresent = true;
  env.priorActiveForcedInboxRoot = small_hash(2);
  env.priorActiveForcedInboxRootPresent = true;
  env.priorActiveDepositInboxRoot = small_hash(3);
  env.priorActiveDepositInboxRootPresent = true;
  env.priorActiveDepositProcessedCursor = 9;
  env.currentBmmParentBlockHash = small_hash(1);
  env.currentBmmParentHeight = 77;
  env.currentBmmParentMtp = 88;
  env.currentBmmParentPresent = true;
  env.bondV2ConfigurationHash = small_hash(2);
  env.bondV2AssetId = small_hash(3);
  env.bondV2DeploymentCommitment = small_hash(4);
  env.bondV2TransitionCmr = small_hash(5);
  env.bondV2IdentityPresent = true;
  env.bondV2IncrementalActivationCmr = small_hash(6);
  env.incrementalSuccessorTransitionCmr = small_hash(1);
  env.bondV2IncrementalActivationIdentityPresent = true;
  env.priorActiveBondInboxRoot = small_hash(6);
  env.currentSidechainHeight = 77;
  env.bondV2ProjectionPresent = true;
  env.bondV2InsuranceReserveScriptSha256 = small_hash(11);
  env.bondV2CollateralVaultScriptSha256 = small_hash(12);
  /* These values also appear in the typed Haskell semantics tests. */
  const uint32_t expected[] = {1, 2, 3, 0, 9, 1, 77, 88, 2, 3, 4, 5,
                             0, 0, 0, 6, 0, 77, 0, 0, 6, 1, 0, 0};
  for (size_t i = 0; i < 24; ++i) {
    const vector* v = &vectors[i];
    UWORD source[ROUND_UWORD(512)] = {0}, output[ROUND_UWORD(256)] = {0};
    frameItem dst = initWriteFrame(v->target_bits, output + ROUND_UWORD(v->target_bits));
    frameItem src = initReadFrame(v->source_bits, source);
    const bool absent_result = v->jet(&dst, src, &absent);
    if (v->target_bits == 1) {
      CHECK(absent_result);
      frameItem result = initReadFrame(1, output);
      CHECK(!readBit(&result));
    } else {
      CHECK(!absent_result);
    }
    if (v->source_bits == 32) {
      inputs[3].txo.scriptPubKey = small_hash(i == 18 ? 11 : 12);
      CHECK(role(v, 3, &env));
      CHECK(!role(v, 2, &env));
      CHECK(!role(v, 4, &env));
      CHECK(!role(v, 3, NULL));
      inputs[3].isPegin = true;
      CHECK(!role(v, 3, &env));
      inputs[3].isPegin = false;
      inputs[3].issuance.type = NEW_ISSUANCE;
      CHECK(!role(v, 3, &env));
      inputs[3].issuance.type = NO_ISSUANCE;
      inputs[3].txo.scriptPubKey = small_hash(99);
      CHECK(!role(v, 3, &env));
      continue;
    }
    dst = initWriteFrame(v->target_bits, output + ROUND_UWORD(v->target_bits));
    CHECK(v->jet(&dst, src, &env));
    frameItem result = initReadFrame(v->target_bits, output);
    if (v->target_bits == 256) {
      for (size_t word = 0; word < 7; ++word) CHECK(simplicity_read32(&result) == 0);
      CHECK(simplicity_read32(&result) == expected[i]);
    } else if (v->target_bits == 64) {
      CHECK(simplicity_read64(&result) == expected[i]);
    } else {
      CHECK(!readBit(&result)); /* No annex/backend, including the successor jet. */
    }
  }
  /* The two activation identities are absent unless both presence gates hold. */
  for (size_t i = 20; i <= 21; ++i) {
    UWORD source[1] = {0}, output[ROUND_UWORD(256)] = {0};
    frameItem dst = initWriteFrame(256, output + ROUND_UWORD(256));
    txEnv incomplete = env;
    incomplete.bondV2IdentityPresent = false;
    CHECK(!vectors[i].jet(&dst, initReadFrame(0, source), &incomplete));
    incomplete = env;
    incomplete.bondV2IncrementalActivationIdentityPresent = false;
    CHECK(!vectors[i].jet(&dst, initReadFrame(0, source), &incomplete));
  }
}

int main(void) {
  test_decoder();
  test_runtime();
#ifdef ECX_SIMPLICITY_CATALOGUE_FROZEN
  printf("PASS: %zu C checks; all 24 catalogue identities/types/costs/encodings, truncations, runtime frames and fail-closed cases\n", checks);
#else
  printf("PASS: %zu C checks; default decoder rejects all 24 ECX encodings; native/runtime checks preserved\n", checks);
#endif
  return 0;
}
