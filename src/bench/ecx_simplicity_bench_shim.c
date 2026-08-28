#include "ecx_simplicity_bench_shim.h"

#include <simplicity/elements/elementsJets.h>
#include <simplicity/elements/txEnv.h>
#include <simplicity/eval.h>
#include <simplicity/frame.h>
#include <simplicity/jets.h>
#include <simplicity/precomputed.h>
#include <simplicity/sha256.h>

#include "../simplicity/bitstream.h"
#include "../simplicity/deserialize.h"
#include "../simplicity/limitations.h"
#include "../simplicity/simplicity_alloc.h"
#include "../simplicity/typeInference.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LEGACY_WIRE_ANNEX_LEN 436
#define LEGACY_PAYLOAD_ANNEX_LEN 435
#define PV4_WIRE_ANNEX_LEN 1045
#define PV4_PAYLOAD_ANNEX_LEN 1044
#define PV5_WIRE_ANNEX_LEN 1286
#define PV5_PAYLOAD_ANNEX_LEN 1285
#define PUBLIC_VALUES_PROOF_MUTATION_OFFSET 280
#define ACTIVATION_V5_WIRE_ANNEX_LEN 800
#define ACTIVATION_V5_PAYLOAD_ANNEX_LEN 799
#define ACTIVATION_V5_PROOF_MUTATION_OFFSET 280

enum {
  TYPE_ONE = 0,
  TYPE_BIT = 1,
  TYPE_WORD_2 = 2,
  TYPE_WORD_4 = 3,
  TYPE_WORD_8 = 4,
  TYPE_WORD_16 = 5,
  TYPE_WORD_32 = 6,
  TYPE_WORD_64 = 7,
  TYPE_WORD_128 = 8,
  TYPE_WORD_256 = 9,
  TYPE_WORD_512 = 10,
  TYPE_WORD_1024 = 11,
  TYPE_WORD_1280 = 12,
  TYPE_COUNT = 13
};

extern bool ecx_sp1_6_3_1_verify_groth16_sha256(
  void* context,
  const unsigned char* proof,
  size_t proof_len,
  const uint32_t* program_id_words,
  const unsigned char* public_values_sha256);

typedef struct {
  unsigned char valid_annex[PV5_WIRE_ANNEX_LEN];
  unsigned char tampered_annex[PV5_WIRE_ANNEX_LEN];
  size_t wire_len;
  size_t payload_len;
  sigInput inputs[3];
  elementsTransaction transaction;
  txEnv env;
  UWORD source[ROUND_UWORD(512)];
} public_values_fixture;

struct ecx_simplicity_bench_context {
  type type_dag[TYPE_COUNT];
  txEnv projection_env;
  sigInput role_inputs[3];
  elementsTransaction role_transaction;
  UWORD role_source[ROUND_UWORD(32)];

  UWORD checksig_source[ROUND_UWORD(1280)];

  unsigned char valid_annex[LEGACY_WIRE_ANNEX_LEN];
  unsigned char tampered_annex[LEGACY_WIRE_ANNEX_LEN];
  sigInput groth_inputs[3];
  elementsTransaction groth_transaction;
  txEnv groth_env;
  UWORD groth_source[ROUND_UWORD(512)];

  public_values_fixture pv4;
  public_values_fixture pv5;

  unsigned char valid_activation_annex[ACTIVATION_V5_WIRE_ANNEX_LEN];
  unsigned char tampered_activation_annex[ACTIVATION_V5_WIRE_ANNEX_LEN];
  sigInput activation_inputs[3];
  elementsTransaction activation_transaction;
  txEnv activation_env;
  UWORD activation_source[ROUND_UWORD(512)];

  UWORD output[ROUND_UWORD(256)];
};

static char error_buffer[160];

enum candidate_type_name {
  CANDIDATE_TYPE_ONE = 0,
  CANDIDATE_TYPE_BIT,
  CANDIDATE_TYPE_WORD_2,
  CANDIDATE_TYPE_WORD_4,
  CANDIDATE_TYPE_WORD_8,
  CANDIDATE_TYPE_WORD_16,
  CANDIDATE_TYPE_WORD_32,
  CANDIDATE_TYPE_WORD_64,
  CANDIDATE_TYPE_WORD_128,
  CANDIDATE_TYPE_WORD_256,
  CANDIDATE_TYPE_WORD_512,
  CANDIDATE_TYPE_COUNT
};

static const char* const candidate_jet_bits[23] = {
  "111100010",
  "11110001100",
  "11110001101",
  "11110001110000",
  "11110001110001",
  "11110001110010",
  "11110001110011",
  "111100011101000",
  "111100011101001",
  "111100011101010",
  "111100011101011",
  "111100011101100",
  "111100011101101",
  "111100011101110",
  "111100011101111",
  "1111000111100000000",
  "1111000111100000001",
  "1111000111100000010",
  "1111000111100000011",
  "1111000111100000100",
  "1111000111100000101",
  "1111000111100000110",
  "1111000111100000111"
};

static const jet_ptr candidate_jets[23] = {
  simplicity_prior_active_exchange_state_root_required,
  simplicity_prior_active_forced_inbox_root_required,
  simplicity_prior_active_deposit_inbox_root_required,
  simplicity_prior_active_forced_processed_cursor_required,
  simplicity_prior_active_deposit_processed_cursor_required,
  simplicity_current_bmm_parent_block_hash_required,
  simplicity_current_bmm_parent_height_required,
  simplicity_current_bmm_parent_mtp_required,
  simplicity_bond_v2_configuration_hash_required,
  simplicity_bond_v2_asset_id_required,
  simplicity_bond_v2_deployment_commitment_required,
  simplicity_bond_v2_transition_cmr_required,
  simplicity_verify_sp1_groth16_sha256,
  simplicity_verify_sp1_groth16_v3_public_values_v4_sha256,
  simplicity_verify_sp1_groth16_v4_public_values_v5_sha256,
  simplicity_prior_active_bond_inbox_root_required,
  simplicity_prior_active_bond_inbox_count_required,
  simplicity_current_sidechain_height_required,
  simplicity_bond_v2_insurance_reserve_input_required,
  simplicity_bond_v2_collateral_vault_input_required,
  simplicity_bond_v2_incremental_activation_cmr_required,
  simplicity_incremental_successor_transition_cmr_required,
  simplicity_verify_sp1_groth16_v5_incremental_activation_sha256
};

static const size_t candidate_source_types[23] = {
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_WORD_512, CANDIDATE_TYPE_WORD_512, CANDIDATE_TYPE_WORD_512,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_WORD_32, CANDIDATE_TYPE_WORD_32,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_WORD_512
};

static const size_t candidate_target_types[23] = {
  CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_256,
  CANDIDATE_TYPE_WORD_64, CANDIDATE_TYPE_WORD_64, CANDIDATE_TYPE_WORD_256,
  CANDIDATE_TYPE_WORD_64, CANDIDATE_TYPE_WORD_64, CANDIDATE_TYPE_WORD_256,
  CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_256,
  CANDIDATE_TYPE_BIT, CANDIDATE_TYPE_BIT, CANDIDATE_TYPE_BIT,
  CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_64, CANDIDATE_TYPE_WORD_64,
  CANDIDATE_TYPE_ONE, CANDIDATE_TYPE_ONE,
  CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_WORD_256, CANDIDATE_TYPE_BIT
};

static size_t candidate_malloc_bound_vars(
  unification_var** bound_var,
  size_t* word256_ix,
  size_t* extra_var_start,
  size_t extra_var_len
) {
  size_t i;
  if (NULL == bound_var || NULL == word256_ix || NULL == extra_var_start ||
      extra_var_len > 6 * DAG_LEN_MAX ||
      CANDIDATE_TYPE_COUNT + extra_var_len > SIZE_MAX / sizeof(unification_var)) {
    return 0;
  }
  *bound_var = simplicity_calloc(
    CANDIDATE_TYPE_COUNT + extra_var_len, sizeof(unification_var));
  if (NULL == *bound_var) return 0;
  (*bound_var)[CANDIDATE_TYPE_ONE] = (unification_var){
    .isBound = true, .bound = {.kind = ONE}};
  (*bound_var)[CANDIDATE_TYPE_BIT] = (unification_var){
    .isBound = true,
    .bound = {.kind = SUM,
              .arg = {&(*bound_var)[CANDIDATE_TYPE_ONE],
                      &(*bound_var)[CANDIDATE_TYPE_ONE]}}};
  for (i = CANDIDATE_TYPE_WORD_2; i <= CANDIDATE_TYPE_WORD_512; ++i) {
    (*bound_var)[i] = (unification_var){
      .isBound = true,
      .bound = {.kind = PRODUCT,
                .arg = {&(*bound_var)[i - 1], &(*bound_var)[i - 1]}}};
  }
  *word256_ix = CANDIDATE_TYPE_WORD_256;
  *extra_var_start = CANDIDATE_TYPE_COUNT;
  return CANDIDATE_TYPE_COUNT - 1;
}

static simplicity_err candidate_decode_jet(dag_node* node, bitstream* stream) {
  int32_t elements;
  int32_t shelf;
  int32_t code;
  if (NULL == node || NULL == stream) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;
  elements = read1Bit(stream);
  if (elements < 0) return (simplicity_err)elements;
  if (1 != elements) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;
  shelf = simplicity_decodeUptoMaxInt(stream);
  if (shelf < 0) return (simplicity_err)shelf;
  if (5 != shelf) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;
  code = simplicity_decodeUptoMaxInt(stream);
  if (code < 0) return (simplicity_err)code;
  if (code < 1 || 23 < code) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;
  *node = (dag_node){
    .jet = candidate_jets[code - 1],
    .sourceIx = candidate_source_types[code - 1],
    .targetIx = candidate_target_types[code - 1],
    .cost = 1000,
    .tag = JET
  };
  /* The benchmark callback deliberately has no release CMRs or release costs. */
  return SIMPLICITY_NO_ERROR;
}

static bool candidate_program(unsigned int jet_index, unsigned char program[4], size_t* length) {
  const char* encoded;
  size_t bit_count;
  size_t i;
  if (jet_index >= 23 || NULL == program || NULL == length) return false;
  memset(program, 0, 4);
  encoded = candidate_jet_bits[jet_index];
  bit_count = 2 + strlen(encoded);
  if (32 < bit_count) return false;
  /* putPositive(1), the Jet node tag, then the authoritative putJetBit bits. */
  for (i = 0; i < strlen(encoded); ++i) {
    if ('1' == encoded[i]) {
      const size_t position = i + 2;
      program[position / 8] |= (unsigned char)(1U << (7 - position % 8));
    } else if ('0' != encoded[i]) {
      return false;
    }
  }
  program[0] |= 1U << 6;
  *length = (bit_count + 7) / 8;
  return true;
}

static bool decode_candidate_program(
  unsigned int jet_index,
  dag_node** dag,
  type** type_dag,
  combinator_counters* census
) {
  unsigned char program[4];
  size_t program_len;
  bitstream stream;
  int_fast32_t dag_len;
  simplicity_err error;
  *dag = NULL;
  *type_dag = NULL;
  memset(census, 0, sizeof(*census));
  if (!candidate_program(jet_index, program, &program_len)) return false;
  stream = initializeBitstream(program, program_len);
  dag_len = simplicity_decodeMallocDag(dag, candidate_decode_jet, census, &stream);
  if (1 != dag_len || NULL == *dag ||
      SIMPLICITY_NO_ERROR != simplicity_closeBitstream(&stream)) {
    simplicity_free(*dag);
    *dag = NULL;
    return false;
  }
  error = simplicity_mallocTypeInference(
    type_dag, candidate_malloc_bound_vars, *dag, 1, census);
  if (SIMPLICITY_NO_ERROR != error || NULL == *type_dag) {
    simplicity_free(*dag);
    simplicity_free(*type_dag);
    *dag = NULL;
    *type_dag = NULL;
    return false;
  }
  return true;
}

static bool raw_candidate_program_accepts(const unsigned char* program, size_t program_len) {
  bitstream stream = initializeBitstream(program, program_len);
  combinator_counters census = {0};
  dag_node* dag = NULL;
  type* type_dag = NULL;
  int_fast32_t dag_len = simplicity_decodeMallocDag(
    &dag, candidate_decode_jet, &census, &stream);
  simplicity_err error = 1 == dag_len
    ? simplicity_closeBitstream(&stream)
    : (simplicity_err)dag_len;
  if (SIMPLICITY_NO_ERROR == error) {
    error = simplicity_mallocTypeInference(
      &type_dag, candidate_malloc_bound_vars, dag, 1, &census);
  }
  simplicity_free(type_dag);
  simplicity_free(dag);
  return SIMPLICITY_NO_ERROR == error;
}

static bool candidate_serialization_mutations_reject(void) {
  unsigned char program[4];
  unsigned char mutated[4];
  size_t program_len;
  if (!candidate_program(19, program, &program_len) || program_len < 2 ||
      !raw_candidate_program_accepts(program, program_len)) {
    return false;
  }
  memcpy(mutated, program, sizeof(mutated));
  mutated[0] ^= 1U << 5; /* Elements-vs-core leaf discriminator. */
  if (raw_candidate_program_accepts(mutated, program_len)) return false;
  if (raw_candidate_program_accepts(program, program_len - 1)) return false;
  memcpy(mutated, program, sizeof(mutated));
  mutated[program_len - 1] |= 1U; /* Non-zero trailing padding. */
  return !raw_candidate_program_accepts(mutated, program_len);
}

static void set_error(const char* error) {
  snprintf(error_buffer, sizeof(error_buffer), "%s", error);
}

const char* ecx_simplicity_bench_error(void) {
  return error_buffer;
}

static bool read_exact_file(const char* path, unsigned char* output, size_t expected_len) {
  FILE* file;
  size_t read_len;
  int trailing;
  if (NULL == path || '\0' == path[0]) {
    set_error("valid V1 annex path is required");
    return false;
  }
  file = fopen(path, "rb");
  if (NULL == file) {
    set_error("cannot open valid V1 annex");
    return false;
  }
  read_len = fread(output, 1, expected_len, file);
  trailing = fgetc(file);
  fclose(file);
  if (read_len != expected_len || trailing != EOF) {
    set_error("valid V1 annex has wrong length");
    return false;
  }
  return true;
}

static bool verify_sp1(
  void* context,
  const unsigned char* proof,
  size_t proof_len,
  const uint32_t* program_id_words,
  const unsigned char* public_values_sha256
) {
  if (NULL != context) return false;
  return ecx_sp1_6_3_1_verify_groth16_sha256(
    NULL, proof, proof_len, program_id_words, public_values_sha256);
}

static void fill_projection_env(txEnv* env) {
  size_t i;
  memset(env, 0, sizeof(*env));
  for (i = 0; i < 8; ++i) {
    const uint32_t word = (uint32_t)(i + 1);
    env->priorActiveExchangeStateRoot.s[i] = word;
    env->priorActiveForcedInboxRoot.s[i] = word + 8;
    env->priorActiveDepositInboxRoot.s[i] = word + 16;
    env->currentBmmParentBlockHash.s[i] = word + 24;
    env->bondV2ConfigurationHash.s[i] = word + 32;
    env->bondV2AssetId.s[i] = word + 40;
    env->bondV2DeploymentCommitment.s[i] = word + 48;
    env->bondV2TransitionCmr.s[i] = word + 56;
    env->priorActiveBondInboxRoot.s[i] = word + 64;
    env->bondV2IncrementalActivationCmr.s[i] = word + 72;
    env->incrementalSuccessorTransitionCmr.s[i] = word + 80;
  }
  env->priorActiveExchangeStateRootPresent = true;
  env->priorActiveForcedInboxRootPresent = true;
  env->priorActiveDepositInboxRootPresent = true;
  env->priorActiveForcedProcessedCursor = 17;
  env->priorActiveDepositProcessedCursor = 19;
  env->currentBmmParentHeight = 23;
  env->currentBmmParentMtp = 29;
  env->currentBmmParentPresent = true;
  env->bondV2IdentityPresent = true;
  env->priorActiveBondInboxCount = 31;
  env->currentSidechainHeight = 37;
  env->bondV2ProjectionPresent = true;
  env->bondV2IncrementalActivationIdentityPresent = true;
}

static void initialize_type_dag(type type_dag[TYPE_COUNT]) {
  size_t i;
  memset(type_dag, 0, sizeof(type) * TYPE_COUNT);
  type_dag[TYPE_ONE].kind = ONE;
  type_dag[TYPE_BIT].kind = SUM;
  type_dag[TYPE_BIT].typeArg[0] = TYPE_ONE;
  type_dag[TYPE_BIT].typeArg[1] = TYPE_ONE;
  for (i = TYPE_WORD_2; i <= TYPE_WORD_1024; ++i) {
    type_dag[i].kind = PRODUCT;
    type_dag[i].typeArg[0] = i - 1;
    type_dag[i].typeArg[1] = i - 1;
  }
  type_dag[TYPE_WORD_1280].kind = PRODUCT;
  type_dag[TYPE_WORD_1280].typeArg[0] = TYPE_WORD_256;
  type_dag[TYPE_WORD_1280].typeArg[1] = TYPE_WORD_1024;
  simplicity_computeTypeAnalyses(type_dag, TYPE_COUNT);
}

static bool evaluate_jet(
  ecx_simplicity_bench_context* context,
  jet_ptr jet,
  size_t source_type,
  size_t target_type,
  const UWORD* input,
  UWORD* output,
  const txEnv* env
) {
  dag_node node;
  simplicity_err error;
  memset(&node, 0, sizeof(node));
  node.tag = JET;
  node.jet = jet;
  node.sourceType = source_type;
  node.targetType = target_type;
  /* Candidate-only analysis cost. Release costs remain deliberately unfrozen. */
  node.cost = 1000;
  error = simplicity_evalTCOExpression(
    CHECK_ALL, output, input, &node, context->type_dag, 1, 0, NULL, env);
  return SIMPLICITY_NO_ERROR == error;
}

static bool build_checksig_fixture(ecx_simplicity_bench_context* context) {
  unsigned char secret[32] = {0};
  unsigned char aux[32] = {0};
  unsigned char digest[32];
  unsigned char signature[64];
  unsigned char message[64];
  unsigned char public_key_bytes[32];
  sha256_midstate output_hash;
  sha256_context hash_context = sha256_tagged_init(output_hash.s, &signatureIV);
  secp256k1_context* secp_context;
  secp256k1_keypair keypair;
  secp256k1_xonly_pubkey public_key;
  frameItem writer;
  frameItem reader;
  frameItem output;

  secret[31] = 1;
  memset(message, 0x42, sizeof(message));
  sha256_uchars(&hash_context, message, sizeof(message));
  sha256_finalize(&hash_context);
  sha256_fromMidstate(digest, output_hash.s);

  secp_context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (NULL == secp_context ||
      !secp256k1_keypair_create(secp_context, &keypair, secret) ||
      !secp256k1_keypair_xonly_pub(secp_context, &public_key, NULL, &keypair) ||
      !secp256k1_xonly_pubkey_serialize(secp_context, public_key_bytes, &public_key) ||
      !secp256k1_schnorrsig_sign32(secp_context, signature, digest, &keypair, aux)) {
    if (NULL != secp_context) secp256k1_context_destroy(secp_context);
    set_error("cannot create CheckSigVerify fixture");
    return false;
  }
  secp256k1_context_destroy(secp_context);

  memset(context->checksig_source, 0, sizeof(context->checksig_source));
  writer = initWriteFrame(1280, context->checksig_source + ROUND_UWORD(1280));
  write8s(&writer, public_key_bytes, sizeof(public_key_bytes));
  write8s(&writer, message, sizeof(message));
  write8s(&writer, signature, sizeof(signature));
  reader = initReadFrame(1280, context->checksig_source);
  output = initWriteFrame(0, context->output);
  if (!simplicity_check_sig_verify(&output, reader, NULL)) {
    set_error("CheckSigVerify fixture did not verify");
    return false;
  }
  return true;
}

static bool build_role_fixture(ecx_simplicity_bench_context* context) {
  size_t i;
  frameItem writer;
  memset(context->role_inputs, 0, sizeof(context->role_inputs));
  memset(&context->role_transaction, 0, sizeof(context->role_transaction));
  context->role_transaction.input = context->role_inputs;
  context->role_transaction.numInputs = 3;
  context->projection_env.tx = &context->role_transaction;
  context->projection_env.ix = 2;
  context->role_inputs[2].issuance.type = NO_ISSUANCE;
  for (i = 0; i < 8; ++i) {
    const uint32_t word = (uint32_t)(100 + i);
    context->projection_env.bondV2InsuranceReserveScriptSha256.s[i] = word;
    context->projection_env.bondV2CollateralVaultScriptSha256.s[i] = word;
    context->role_inputs[2].txo.scriptPubKey.s[i] = word;
  }
  memset(context->role_source, 0, sizeof(context->role_source));
  writer = initWriteFrame(32, context->role_source + ROUND_UWORD(32));
  simplicity_write32(&writer, 2);
  return true;
}

static bool build_groth_fixture(ecx_simplicity_bench_context* context, const char* path) {
  static const unsigned char expected_prefix[12] = {
    0x50, 'E', 'C', 'X', 'S', 'P', '1', 0x00, 0x02, 0x02, 0x01, 0x00};
  frameItem writer;
  frameItem reader;
  frameItem output;
  bool jet_ok;
  bool proof_ok;

  if (NULL == path) return true;
  if (!read_exact_file(path, context->valid_annex, sizeof(context->valid_annex)) ||
      0 != memcmp(context->valid_annex, expected_prefix, sizeof(expected_prefix))) {
    set_error("V1 annex header is not canonical");
    return false;
  }
  memcpy(context->tampered_annex, context->valid_annex, sizeof(context->valid_annex));
  context->tampered_annex[LEGACY_WIRE_ANNEX_LEN - 1] ^= 1;

  memset(context->groth_inputs, 0, sizeof(context->groth_inputs));
  memset(&context->groth_transaction, 0, sizeof(context->groth_transaction));
  memset(&context->groth_env, 0, sizeof(context->groth_env));
  context->groth_transaction.input = context->groth_inputs;
  context->groth_transaction.numInputs = 3;
  context->groth_inputs[2].annex = context->valid_annex + 1;
  context->groth_inputs[2].annexLen = LEGACY_PAYLOAD_ANNEX_LEN;
  context->groth_inputs[2].hasAnnex = true;
  context->groth_env.tx = &context->groth_transaction;
  context->groth_env.ix = 2;
  context->groth_env.verifySp1Groth16 = verify_sp1;

  memset(context->groth_source, 0, sizeof(context->groth_source));
  writer = initWriteFrame(512, context->groth_source + ROUND_UWORD(512));
  write8s(&writer, context->valid_annex + 12, 32);
  write8s(&writer, context->valid_annex + 44, 32);
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->groth_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  jet_ok = simplicity_verify_sp1_groth16_sha256(&output, reader, &context->groth_env);
  reader = initReadFrame(1, context->output);
  proof_ok = readBit(&reader);
  if (!jet_ok || !proof_ok) {
    set_error("V1 Groth16 fixture did not verify through the Simplicity jet");
    return false;
  }
  context->groth_inputs[2].annex = context->tampered_annex + 1;
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->groth_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  jet_ok = simplicity_verify_sp1_groth16_sha256(&output, reader, &context->groth_env);
  reader = initReadFrame(1, context->output);
  proof_ok = readBit(&reader);
  context->groth_inputs[2].annex = context->valid_annex + 1;
  if (!jet_ok || proof_ok) {
    set_error("tampered V1 Groth16 fixture was not rejected through the Simplicity jet");
    return false;
  }
  return true;
}

static bool build_activation_v5_fixture(
  ecx_simplicity_bench_context* context,
  const char* path
) {
  static const unsigned char expected_prefix[12] = {
    0x50, 'E', 'C', 'X', 'S', 'P', '1', 0x00, 0x05, 0x02, 0x01, 0x00};
  frameItem writer;
  frameItem reader;
  frameItem output;
  bool jet_ok;
  bool proof_ok;

  if (NULL == path) return true;
  if (!read_exact_file(path, context->valid_activation_annex,
                       sizeof(context->valid_activation_annex)) ||
      0 != memcmp(context->valid_activation_annex, expected_prefix,
                  sizeof(expected_prefix))) {
    set_error("activation V5 annex is not canonical");
    return false;
  }
  memcpy(context->tampered_activation_annex, context->valid_activation_annex,
         sizeof(context->valid_activation_annex));
  context->tampered_activation_annex[ACTIVATION_V5_PROOF_MUTATION_OFFSET] ^= 1;

  memset(context->activation_inputs, 0, sizeof(context->activation_inputs));
  memset(&context->activation_transaction, 0, sizeof(context->activation_transaction));
  fill_projection_env(&context->activation_env);
  context->activation_transaction.input = context->activation_inputs;
  context->activation_transaction.numInputs = 3;
  context->activation_inputs[2].annex = context->valid_activation_annex + 1;
  context->activation_inputs[2].annexLen = ACTIVATION_V5_PAYLOAD_ANNEX_LEN;
  context->activation_inputs[2].hasAnnex = true;
  context->activation_env.tx = &context->activation_transaction;
  context->activation_env.ix = 2;
  context->activation_env.verifySp1Groth16 = verify_sp1;

  memset(context->activation_source, 0, sizeof(context->activation_source));
  writer = initWriteFrame(512, context->activation_source + ROUND_UWORD(512));
  write8s(&writer, context->valid_activation_annex + 12, 32);
  write8s(&writer, context->valid_activation_annex + 44, 32);
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->activation_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  jet_ok = simplicity_verify_sp1_groth16_v5_incremental_activation_sha256(
    &output, reader, &context->activation_env);
  reader = initReadFrame(1, context->output);
  proof_ok = readBit(&reader);
  if (!jet_ok || !proof_ok) {
    set_error("activation V5 Groth16 fixture did not verify through the Simplicity jet");
    return false;
  }
  context->activation_inputs[2].annex = context->tampered_activation_annex + 1;
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->activation_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  jet_ok = simplicity_verify_sp1_groth16_v5_incremental_activation_sha256(
    &output, reader, &context->activation_env);
  reader = initReadFrame(1, context->output);
  proof_ok = readBit(&reader);
  context->activation_inputs[2].annex = context->valid_activation_annex + 1;
  if (!jet_ok || proof_ok) {
    set_error("tampered activation V5 Groth16 fixture was not rejected through the Simplicity jet");
    return false;
  }
  return true;
}

static bool run_public_values_fixture(
  ecx_simplicity_bench_context* context,
  public_values_fixture* fixture,
  jet_ptr jet,
  bool tampered
) {
  frameItem reader;
  frameItem output;
  bool jet_ok;
  bool proof_ok;
  if (NULL == context || NULL == fixture || NULL == jet || NULL == fixture->env.tx) {
    return false;
  }
  fixture->inputs[2].annex =
    (tampered ? fixture->tampered_annex : fixture->valid_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, fixture->source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  jet_ok = jet(&output, reader, &fixture->env);
  reader = initReadFrame(1, context->output);
  proof_ok = readBit(&reader);
  return jet_ok && proof_ok;
}

static bool build_public_values_fixture(
  ecx_simplicity_bench_context* context,
  public_values_fixture* fixture,
  const char* path,
  unsigned char version,
  size_t wire_len,
  jet_ptr jet
) {
  unsigned char expected_prefix[12] = {
    0x50, 'E', 'C', 'X', 'S', 'P', '1', 0x00, 0x00, 0x02, 0x01, 0x00};
  frameItem writer;
  if (NULL == path) return true;
  if (NULL == context || NULL == fixture || NULL == jet ||
      (wire_len != PV4_WIRE_ANNEX_LEN && wire_len != PV5_WIRE_ANNEX_LEN)) {
    set_error("invalid public-values fixture arguments");
    return false;
  }
  expected_prefix[8] = version;
  fixture->wire_len = wire_len;
  fixture->payload_len = wire_len - 1;
  if (!read_exact_file(path, fixture->valid_annex, wire_len) ||
      0 != memcmp(fixture->valid_annex, expected_prefix, sizeof(expected_prefix))) {
    set_error("public-values annex header is not canonical");
    return false;
  }
  memcpy(fixture->tampered_annex, fixture->valid_annex, wire_len);
  fixture->tampered_annex[PUBLIC_VALUES_PROOF_MUTATION_OFFSET] ^= 1;
  memset(fixture->inputs, 0, sizeof(fixture->inputs));
  memset(&fixture->transaction, 0, sizeof(fixture->transaction));
  fill_projection_env(&fixture->env);
  fixture->transaction.input = fixture->inputs;
  fixture->transaction.numInputs = 3;
  fixture->inputs[2].annex = fixture->valid_annex + 1;
  fixture->inputs[2].annexLen = fixture->payload_len;
  fixture->inputs[2].hasAnnex = true;
  fixture->env.tx = &fixture->transaction;
  fixture->env.ix = 2;
  fixture->env.verifySp1Groth16 = verify_sp1;
  memset(fixture->source, 0, sizeof(fixture->source));
  writer = initWriteFrame(512, fixture->source + ROUND_UWORD(512));
  write8s(&writer, fixture->valid_annex + 12, 32);
  write8s(&writer, fixture->valid_annex + 44, 32);
  if (!run_public_values_fixture(context, fixture, jet, false) ||
      run_public_values_fixture(context, fixture, jet, true)) {
    set_error("public-values Groth16 fixture did not enforce valid/tampered paths");
    return false;
  }
  fixture->inputs[2].annex = fixture->valid_annex + 1;
  return true;
}

static bool validate_evaluator_fixture(
  ecx_simplicity_bench_context* context,
  bool has_groth_fixture,
  bool has_pv4_fixture,
  bool has_pv5_fixture,
  bool has_activation_v5_fixture
) {
  unsigned int i;
  if (!candidate_serialization_mutations_reject()) {
    set_error("candidate serialized jet mutation checks failed");
    return false;
  }
  for (i = 0; i < 17; ++i) {
    if (!ecx_simplicity_bench_eval_nullary(context, i)) {
      set_error("projection fixture failed through Simplicity evaluator");
      return false;
    }
  }
  if (!ecx_simplicity_bench_eval_role(context, true) ||
      !ecx_simplicity_bench_eval_role(context, false)) {
    set_error("role fixture failed through Simplicity evaluator");
    return false;
  }
  if (!ecx_simplicity_bench_eval_check_sig_verify(context)) {
    set_error("CheckSigVerify fixture failed through Simplicity evaluator");
    return false;
  }
  if (has_groth_fixture &&
      (!ecx_simplicity_bench_eval_groth16(context, false) ||
       ecx_simplicity_bench_eval_groth16(context, true))) {
    set_error("V1 Groth16 fixture did not enforce valid/tampered evaluator paths");
    return false;
  }
  if (has_pv4_fixture &&
      (!ecx_simplicity_bench_decode_eval_jet(context, 13, false) ||
       !ecx_simplicity_bench_decode_eval_jet(context, 13, true))) {
    set_error("serialized PV4 Groth16 jet did not enforce valid/tampered paths");
    return false;
  }
  if (has_pv5_fixture &&
      (!ecx_simplicity_bench_decode_eval_jet(context, 14, false) ||
       !ecx_simplicity_bench_decode_eval_jet(context, 14, true))) {
    set_error("serialized PV5 Groth16 jet did not enforce valid/tampered paths");
    return false;
  }
  if (has_activation_v5_fixture &&
      (!ecx_simplicity_bench_eval_activation_v5_groth16(context, false) ||
       ecx_simplicity_bench_eval_activation_v5_groth16(context, true))) {
    set_error("activation V5 Groth16 fixture did not enforce valid/tampered evaluator paths");
    return false;
  }
  for (i = 0; i < 23; ++i) {
    if (!ecx_simplicity_bench_decode_jet(context, i)) {
      set_error("candidate serialized jet did not decode and type-infer");
      return false;
    }
    if (i != 12 && i != 13 && i != 14 && i != 22 &&
        !ecx_simplicity_bench_decode_eval_jet(context, i, false)) {
      set_error("candidate serialized jet did not evaluate");
      return false;
    }
  }
  if (has_groth_fixture &&
      (!ecx_simplicity_bench_decode_eval_jet(context, 12, false) ||
       !ecx_simplicity_bench_decode_eval_jet(context, 12, true))) {
    set_error("serialized V1 Groth16 jet did not enforce valid/tampered paths");
    return false;
  }
  if (has_activation_v5_fixture &&
      (!ecx_simplicity_bench_decode_eval_jet(context, 22, false) ||
       !ecx_simplicity_bench_decode_eval_jet(context, 22, true))) {
    set_error("serialized activation V5 Groth16 jet did not enforce valid/tampered paths");
    return false;
  }
  return true;
}

ecx_simplicity_bench_context* ecx_simplicity_bench_context_create(
  const char* valid_v1_annex_path,
  const char* valid_pv4_annex_path,
  const char* valid_pv5_annex_path,
  const char* valid_activation_v5_annex_path
) {
  ecx_simplicity_bench_context* context = calloc(1, sizeof(*context));
  error_buffer[0] = '\0';
  if (NULL == context) {
    set_error("cannot allocate benchmark context");
    return NULL;
  }
  fill_projection_env(&context->projection_env);
  initialize_type_dag(context->type_dag);
  if (!build_role_fixture(context) ||
      !build_checksig_fixture(context) ||
      !build_groth_fixture(context, valid_v1_annex_path) ||
      !build_public_values_fixture(
        context, &context->pv4, valid_pv4_annex_path, 3,
        PV4_WIRE_ANNEX_LEN,
        simplicity_verify_sp1_groth16_v3_public_values_v4_sha256) ||
      !build_public_values_fixture(
        context, &context->pv5, valid_pv5_annex_path, 4,
        PV5_WIRE_ANNEX_LEN,
        simplicity_verify_sp1_groth16_v4_public_values_v5_sha256) ||
      !build_activation_v5_fixture(context, valid_activation_v5_annex_path) ||
      !validate_evaluator_fixture(context, NULL != valid_v1_annex_path,
                                  NULL != valid_pv4_annex_path,
                                  NULL != valid_pv5_annex_path,
                                  NULL != valid_activation_v5_annex_path)) {
    free(context);
    return NULL;
  }
  return context;
}

void ecx_simplicity_bench_context_destroy(ecx_simplicity_bench_context* context) {
  if (NULL != context) {
    memset(context, 0, sizeof(*context));
    free(context);
  }
}

bool ecx_simplicity_bench_nullary(ecx_simplicity_bench_context* context, unsigned int jet_index) {
  static const jet_ptr jets[17] = {
    simplicity_prior_active_exchange_state_root_required,
    simplicity_prior_active_forced_inbox_root_required,
    simplicity_prior_active_deposit_inbox_root_required,
    simplicity_prior_active_forced_processed_cursor_required,
    simplicity_prior_active_deposit_processed_cursor_required,
    simplicity_current_bmm_parent_block_hash_required,
    simplicity_current_bmm_parent_height_required,
    simplicity_current_bmm_parent_mtp_required,
    simplicity_bond_v2_configuration_hash_required,
    simplicity_bond_v2_asset_id_required,
    simplicity_bond_v2_deployment_commitment_required,
    simplicity_bond_v2_transition_cmr_required,
    simplicity_prior_active_bond_inbox_root_required,
    simplicity_prior_active_bond_inbox_count_required,
    simplicity_current_sidechain_height_required,
    simplicity_bond_v2_incremental_activation_cmr_required,
    simplicity_incremental_successor_transition_cmr_required
  };
  static const size_t output_bits[17] = {
    256, 256, 256, 64, 64, 256, 64, 64, 256, 256, 256, 256, 256, 64, 64,
    256, 256};
  UWORD source[1] = {0};
  frameItem reader;
  frameItem output;
  if (NULL == context || jet_index >= 17) return false;
  reader = initReadFrame(0, source);
  output = initWriteFrame(output_bits[jet_index],
                          context->output + ROUND_UWORD(output_bits[jet_index]));
  return jets[jet_index](&output, reader, &context->projection_env);
}

bool ecx_simplicity_bench_role(ecx_simplicity_bench_context* context, bool insurance_reserve) {
  frameItem reader;
  frameItem output;
  if (NULL == context) return false;
  reader = initReadFrame(32, context->role_source);
  output = initWriteFrame(0, context->output);
  return (insurance_reserve ? simplicity_bond_v2_insurance_reserve_input_required
                            : simplicity_bond_v2_collateral_vault_input_required)(
    &output, reader, &context->projection_env);
}

bool ecx_simplicity_bench_check_sig_verify(ecx_simplicity_bench_context* context) {
  frameItem reader;
  frameItem output;
  if (NULL == context) return false;
  reader = initReadFrame(1280, context->checksig_source);
  output = initWriteFrame(0, context->output);
  return simplicity_check_sig_verify(&output, reader, NULL);
}

bool ecx_simplicity_bench_groth16(ecx_simplicity_bench_context* context, bool tampered) {
  frameItem reader;
  frameItem output;
  if (NULL == context || context->groth_env.tx == NULL) return false;
  context->groth_inputs[2].annex = (tampered ? context->tampered_annex : context->valid_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->groth_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  if (!simplicity_verify_sp1_groth16_sha256(&output, reader, &context->groth_env)) return false;
  reader = initReadFrame(1, context->output);
  return readBit(&reader);
}

bool ecx_simplicity_bench_activation_v5_groth16(
  ecx_simplicity_bench_context* context,
  bool tampered
) {
  frameItem reader;
  frameItem output;
  if (NULL == context || context->activation_env.tx == NULL) return false;
  context->activation_inputs[2].annex =
    (tampered ? context->tampered_activation_annex : context->valid_activation_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  reader = initReadFrame(512, context->activation_source);
  output = initWriteFrame(1, context->output + ROUND_UWORD(1));
  if (!simplicity_verify_sp1_groth16_v5_incremental_activation_sha256(
        &output, reader, &context->activation_env)) return false;
  reader = initReadFrame(1, context->output);
  return readBit(&reader);
}

bool ecx_simplicity_bench_eval_nullary(ecx_simplicity_bench_context* context, unsigned int jet_index) {
  static const jet_ptr jets[17] = {
    simplicity_prior_active_exchange_state_root_required,
    simplicity_prior_active_forced_inbox_root_required,
    simplicity_prior_active_deposit_inbox_root_required,
    simplicity_prior_active_forced_processed_cursor_required,
    simplicity_prior_active_deposit_processed_cursor_required,
    simplicity_current_bmm_parent_block_hash_required,
    simplicity_current_bmm_parent_height_required,
    simplicity_current_bmm_parent_mtp_required,
    simplicity_bond_v2_configuration_hash_required,
    simplicity_bond_v2_asset_id_required,
    simplicity_bond_v2_deployment_commitment_required,
    simplicity_bond_v2_transition_cmr_required,
    simplicity_prior_active_bond_inbox_root_required,
    simplicity_prior_active_bond_inbox_count_required,
    simplicity_current_sidechain_height_required,
    simplicity_bond_v2_incremental_activation_cmr_required,
    simplicity_incremental_successor_transition_cmr_required
  };
  static const size_t output_types[17] = {
    TYPE_WORD_256, TYPE_WORD_256, TYPE_WORD_256, TYPE_WORD_64, TYPE_WORD_64,
    TYPE_WORD_256, TYPE_WORD_64, TYPE_WORD_64, TYPE_WORD_256, TYPE_WORD_256,
    TYPE_WORD_256, TYPE_WORD_256, TYPE_WORD_256, TYPE_WORD_64, TYPE_WORD_64,
    TYPE_WORD_256, TYPE_WORD_256};
  UWORD source[1] = {0};
  if (NULL == context || jet_index >= 17) return false;
  memset(context->output, 0, sizeof(context->output));
  return evaluate_jet(context, jets[jet_index], TYPE_ONE, output_types[jet_index],
                      source, context->output, &context->projection_env);
}

bool ecx_simplicity_bench_eval_role(ecx_simplicity_bench_context* context, bool insurance_reserve) {
  if (NULL == context) return false;
  return evaluate_jet(
    context,
    insurance_reserve ? simplicity_bond_v2_insurance_reserve_input_required
                      : simplicity_bond_v2_collateral_vault_input_required,
    TYPE_WORD_32, TYPE_ONE, context->role_source, NULL, &context->projection_env);
}

bool ecx_simplicity_bench_eval_check_sig_verify(ecx_simplicity_bench_context* context) {
  if (NULL == context) return false;
  return evaluate_jet(context, simplicity_check_sig_verify, TYPE_WORD_1280, TYPE_ONE,
                      context->checksig_source, NULL, &context->projection_env);
}

bool ecx_simplicity_bench_eval_groth16(ecx_simplicity_bench_context* context, bool tampered) {
  frameItem reader;
  if (NULL == context || context->groth_env.tx == NULL) return false;
  context->groth_inputs[2].annex = (tampered ? context->tampered_annex : context->valid_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  if (!evaluate_jet(context, simplicity_verify_sp1_groth16_sha256,
                    TYPE_WORD_512, TYPE_BIT, context->groth_source,
                    context->output, &context->groth_env)) {
    return false;
  }
  reader = initReadFrame(1, context->output);
  return readBit(&reader);
}

bool ecx_simplicity_bench_eval_public_values_groth16(
  ecx_simplicity_bench_context* context,
  unsigned int public_values_version,
  bool tampered
) {
  public_values_fixture* fixture;
  jet_ptr jet;
  frameItem reader;
  if (NULL == context || (4 != public_values_version && 5 != public_values_version)) {
    return false;
  }
  fixture = 4 == public_values_version ? &context->pv4 : &context->pv5;
  jet = 4 == public_values_version
          ? simplicity_verify_sp1_groth16_v3_public_values_v4_sha256
          : simplicity_verify_sp1_groth16_v4_public_values_v5_sha256;
  if (NULL == fixture->env.tx) return false;
  fixture->inputs[2].annex =
    (tampered ? fixture->tampered_annex : fixture->valid_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  if (!evaluate_jet(context, jet, TYPE_WORD_512, TYPE_BIT,
                    fixture->source, context->output, &fixture->env)) {
    return false;
  }
  reader = initReadFrame(1, context->output);
  return readBit(&reader);
}

bool ecx_simplicity_bench_eval_activation_v5_groth16(
  ecx_simplicity_bench_context* context,
  bool tampered
) {
  frameItem reader;
  if (NULL == context || context->activation_env.tx == NULL) return false;
  context->activation_inputs[2].annex =
    (tampered ? context->tampered_activation_annex : context->valid_activation_annex) + 1;
  memset(context->output, 0, sizeof(context->output));
  if (!evaluate_jet(context,
                    simplicity_verify_sp1_groth16_v5_incremental_activation_sha256,
                    TYPE_WORD_512, TYPE_BIT, context->activation_source,
                    context->output, &context->activation_env)) {
    return false;
  }
  reader = initReadFrame(1, context->output);
  return readBit(&reader);
}

bool ecx_simplicity_bench_decode_jet(
  ecx_simplicity_bench_context* context,
  unsigned int jet_index
) {
  dag_node* dag = NULL;
  type* type_dag = NULL;
  combinator_counters census;
  bool ok;
  if (NULL == context || jet_index >= 23) return false;
  ok = decode_candidate_program(jet_index, &dag, &type_dag, &census) &&
       JET == dag[0].tag &&
       candidate_jets[jet_index] == dag[0].jet &&
       type_dag[dag[0].sourceType].bitSize ==
         context->type_dag[candidate_source_types[jet_index]].bitSize &&
       type_dag[dag[0].targetType].bitSize ==
         context->type_dag[candidate_target_types[jet_index]].bitSize;
  simplicity_free(type_dag);
  simplicity_free(dag);
  return ok;
}

bool ecx_simplicity_bench_decode_eval_jet(
  ecx_simplicity_bench_context* context,
  unsigned int jet_index,
  bool tampered
) {
  UWORD unit_source[1] = {0};
  const UWORD* source = unit_source;
  UWORD* output = context ? context->output : NULL;
  const txEnv* env = context ? &context->projection_env : NULL;
  dag_node* dag = NULL;
  type* type_dag = NULL;
  combinator_counters census;
  simplicity_err error;
  frameItem reader;
  bool actual;
  if (NULL == context || jet_index >= 23) {
    return false;
  }
  if (!decode_candidate_program(jet_index, &dag, &type_dag, &census)) return false;
  if (12 == jet_index) {
    if (NULL == context->groth_env.tx) {
      simplicity_free(type_dag);
      simplicity_free(dag);
      return false;
    }
    context->groth_inputs[2].annex =
      (tampered ? context->tampered_annex : context->valid_annex) + 1;
    source = context->groth_source;
    env = &context->groth_env;
  } else if (13 == jet_index || 14 == jet_index) {
    public_values_fixture* fixture = 13 == jet_index ? &context->pv4 : &context->pv5;
    if (NULL == fixture->env.tx) {
      simplicity_free(type_dag);
      simplicity_free(dag);
      return false;
    }
    fixture->inputs[2].annex =
      (tampered ? fixture->tampered_annex : fixture->valid_annex) + 1;
    source = fixture->source;
    env = &fixture->env;
  } else if (22 == jet_index) {
    if (NULL == context->activation_env.tx) {
      simplicity_free(type_dag);
      simplicity_free(dag);
      return false;
    }
    context->activation_inputs[2].annex =
      (tampered ? context->tampered_activation_annex : context->valid_activation_annex) + 1;
    source = context->activation_source;
    env = &context->activation_env;
  } else if (18 <= jet_index && jet_index <= 19) {
    source = context->role_source;
    output = NULL;
  }
  memset(context->output, 0, sizeof(context->output));
  error = simplicity_evalTCOExpression(
    CHECK_ALL, output, source, dag, type_dag, 1, 0, NULL, env);
  if (SIMPLICITY_NO_ERROR != error) {
    simplicity_free(type_dag);
    simplicity_free(dag);
    return false;
  }
  if (12 == jet_index || 13 == jet_index || 14 == jet_index || 22 == jet_index) {
    reader = initReadFrame(1, context->output);
    actual = readBit(&reader);
    if (actual == tampered) {
      simplicity_free(type_dag);
      simplicity_free(dag);
      return false;
    }
  }
  simplicity_free(type_dag);
  simplicity_free(dag);
  return true;
}
