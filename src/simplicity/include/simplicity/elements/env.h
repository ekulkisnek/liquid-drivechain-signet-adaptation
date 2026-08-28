#ifndef SIMPLICITY_ELEMENTS_ENV_H
#define SIMPLICITY_ELEMENTS_ENV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* This section builds the 'rawElementsTransaction' structure which is the transaction data needed to build an Elements 'txEnv' environment
 * for evaluating Simplicity expressions within.
 * The 'rawElementsTransaction' is copied into an opaque 'elementsTransaction' structure that can be reused within evaluating Simplicity on multiple
 * inputs within the same transaction.
 */

/* A type for an unparsed buffer
 *
 * Invariant: if 0 < len then unsigned char buf[len]
 */
typedef struct rawElementsBuffer {
  const unsigned char* buf;
  uint32_t len;
} rawElementsBuffer;

#define ECX_SP1_GROTH16_PROOF_LEN ((size_t)356)
/* Historical V2 pre-release statement.  It remains decodeable only for
 * regression tests and is never an accepted bond-V2 transition statement. */
#define ECX_SP1_PUBLIC_VALUES_V4_LEN ((size_t)609)
/* Frozen bond-V2 statement carried only by annex transport version 4. */
#define ECX_SP1_PUBLIC_VALUES_V5_LEN ((size_t)850)
/* One-shot pristine V18 -> incremental successor activation statement. */
#define ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN ((size_t)364)
/* Incremental successor outer proof statement. */
#define ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN ((size_t)1627)

typedef bool (*ecx_sp1_groth16_verify_fn)(
  void* context,
  const unsigned char proof[ECX_SP1_GROTH16_PROOF_LEN],
  size_t proof_len,
  const uint32_t program_id_words[8],
  const unsigned char public_values_sha256[32]);

/**
 * Validate and dispatch one stripped ECX Taproot annex payload.  The leading
 * BIP341 0x50 byte is not part of this buffer.  Version 2 is the frozen V1
 * proof-only codec; version 3 is the disjoint V2 codec carrying the exact
 * canonical 609-byte PublicValuesV4 after the proof.
 *
 * `require_public_values_v4` makes version 2 fail even though the generic
 * Simplicity jet remains backwards compatible.  The V2 singleton transition
 * path uses this flag before projecting authenticated capital state.
 */
extern bool simplicity_elements_verify_sp1_groth16_annex_sha256(
  const unsigned char* annex,
  size_t annex_len,
  const unsigned char expected_program_id[32],
  const unsigned char expected_public_values_sha256[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verify_context,
  bool require_public_values_v4);

/** Strictly decode the disjoint version-3 V2 annex without dispatching the
 * pairing verifier.  Callers may use the projection only after the enclosing
 * Simplicity input has already succeeded. */
extern bool simplicity_elements_parse_sp1_groth16_v2_annex(
  const unsigned char* annex,
  size_t annex_len,
  unsigned char program_id[32],
  unsigned char public_values_sha256[32],
  unsigned char public_values_v4[ECX_SP1_PUBLIC_VALUES_V4_LEN]);

/** Strictly decode the bond-V2 version-4 transport containing the exact
 * canonical 850-byte PublicValuesV5.  This parser does not dispatch the
 * pairing verifier; callers may project fields only after script success. */
extern bool simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
  const unsigned char* annex,
  size_t annex_len,
  unsigned char program_id[32],
  unsigned char public_values_sha256[32],
  unsigned char public_values_v5[ECX_SP1_PUBLIC_VALUES_V5_LEN]);

/** Dedicated bond-V2 verifier.  It accepts exactly transport version 4 and
 * PublicValuesV5; neither the legacy version-2 form nor historical
 * version-3/PublicValuesV4 is an alias. */
extern bool simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
  const unsigned char* annex,
  size_t annex_len,
  const unsigned char expected_program_id[32],
  const unsigned char expected_public_values_sha256[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verify_context);

/** Strictly decode the disjoint version-5 activation transport containing
 * exactly the 364-byte IncrementalActivationPublicValuesV2 statement. */
extern bool simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
  const unsigned char* annex,
  size_t annex_len,
  unsigned char program_id[32],
  unsigned char public_values_sha256[32],
  unsigned char public_values[ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN]);

/** Dedicated one-shot activation verifier.  Normal version-4/PublicValuesV5
 * transition annexes and every historical transport version are rejected. */
extern bool simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
  const unsigned char* annex,
  size_t annex_len,
  const unsigned char expected_program_id[32],
  const unsigned char expected_public_values_sha256[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verify_context);

/** Strictly decode the disjoint version-6 incremental successor transport. */
extern bool simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
  const unsigned char* annex,
  size_t annex_len,
  unsigned char program_id[32],
  unsigned char public_values_sha256[32],
  unsigned char public_values[ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN]);

/** Dedicated incremental successor verifier. Every finite/activation/historical
 * annex version is rejected. */
extern bool simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
  const unsigned char* annex,
  size_t annex_len,
  const unsigned char expected_program_id[32],
  const unsigned char expected_public_values_sha256[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verify_context);

/* A structure representing data for one output from an Elements transaction.
 *
 * Invariant: unsigned char asset[33] or asset == NULL;
 *            unsigned char value[value[0] == 1 ? 9 : 33] or value == NULL;
 *            unsigned char nonce[33] or nonce == NULL;
 */
typedef struct rawElementsOutput {
  const unsigned char* asset;
  const unsigned char* value;
  const unsigned char* nonce;
  rawElementsBuffer scriptPubKey;
  rawElementsBuffer surjectionProof;
  rawElementsBuffer rangeProof;
} rawElementsOutput;

/* A structure representing data for one input from an Elements transaction, including its taproot annex,
 * plus the TXO data of the output being redeemed.
 *
 * Invariant: unsigned char prevTxid[32];
 *            unsigned char pegin[32] or pegin == NULL;
 *            unsigned char issuance.blindingNonce[32] or (issuance.amount == NULL and issuance.inflationKeys == NULL);
 *            unsigned char issuance.assetEntropy[32] or (issuance.amount == NULL and issuance.inflationKeys == NULL);
 *            unsigned char issuance.amount[issuance.amount[0] == 1 ? 9 : 33] or issuance.amount == NULL;
 *            unsigned char issuance.inflationKeys[issuance.inflaitonKeys[0] == 1 ? 9 : 33] or issuance.inflationKeys == NULL;
 *            unsigned char txo.asset[33] or txo.asset == NULL;
 *            unsigned char txo.value[txo.value[0] == 1 ? 9 : 33] or txo.value == NULL;
 */
typedef struct rawElementsInput {
  const rawElementsBuffer* annex;
  const unsigned char* prevTxid;
  const unsigned char* pegin;
  struct {
    const unsigned char* blindingNonce;
    const unsigned char* assetEntropy;
    const unsigned char* amount;
    const unsigned char* inflationKeys;
    rawElementsBuffer amountRangePrf;
    rawElementsBuffer inflationKeysRangePrf;
  } issuance;
  struct {
    const unsigned char* asset;
    const unsigned char* value;
    rawElementsBuffer scriptPubKey;
  } txo;
  rawElementsBuffer scriptSig;
  uint32_t prevIx;
  uint32_t sequence;
} rawElementsInput;

/* A structure representing data for an Elements transaction, including the TXO data of each output being redeemed.
 *
 * Invariant: unsigned char txid[32];
 *            rawElementsInput input[numInputs];
 *            rawElementsOutput output[numOutputs];
 */
typedef struct rawElementsTransaction {
  const unsigned char* txid; /* While in theory we could recompute the txid ourselves, it is easier and safer for it to be provided. */
  const rawElementsInput* input;
  const rawElementsOutput* output;
  uint32_t numInputs;
  uint32_t numOutputs;
  uint32_t version;
  uint32_t lockTime;
} rawElementsTransaction;

/* A forward declaration for the structure containing a copy (and digest) of the rawElementsTransaction data */
typedef struct elementsTransaction elementsTransaction;

/* Allocate and initialize a 'elementsTransaction' from a 'rawElementsTransaction', copying or hashing the data as needed.
 * Returns NULL if malloc fails (or if malloc cannot be called because we require an allocation larger than SIZE_MAX).
 *
 * Precondition: NULL != rawTx
 */
extern elementsTransaction* simplicity_elements_mallocTransaction(const rawElementsTransaction* rawTx);

/* Free a pointer to 'elementsTransaction'.
 */
extern void simplicity_elements_freeTransaction(elementsTransaction* tx);

/* A structure representing taproot spending data for an Elements transaction.
 *
 * Invariant: pathLen <= 128;
 *            unsigned char controlBlock[33+pathLen*32];
 *            unsigned char scriptCMR[32];
 */
typedef struct rawElementsTapEnv {
  const unsigned char* controlBlock;
  const unsigned char* scriptCMR;
  unsigned char pathLen;
} rawElementsTapEnv;

/*
 * Consensus environment supplied by Elements for ECX-aware Simplicity
 * execution. This native structure is never serialized. Presence flags must
 * be exactly zero or one; absent roots and parent clock values must be zero.
 */
typedef struct ecx_prior_active_root_env {
  uint8_t present;
  uint8_t root_wire[32];
  uint8_t forced_inbox_present;
  uint8_t forced_inbox_root_wire[32];
  uint8_t deposit_inbox_present;
  uint8_t deposit_inbox_root_wire[32];
  uint64_t forced_processed_cursor;
  uint64_t deposit_processed_cursor;
  uint8_t current_bmm_parent_present;
  uint8_t current_bmm_parent_block_hash_wire[32];
  uint64_t current_bmm_parent_height;
  uint64_t current_bmm_parent_mtp;
  uint8_t bond_v2_identity_present;
  uint8_t bond_v2_configuration_hash_wire[32];
  uint8_t bond_v2_asset_id_wire[32];
  uint8_t bond_v2_deployment_commitment_wire[32];
  uint8_t bond_v2_transition_cmr_wire[32];
  uint8_t bond_v2_collateral_vault_script_sha256_wire[32];
  uint8_t bond_v2_collateral_vault_cmr_wire[32];
  uint8_t bond_v2_insurance_reserve_script_sha256_wire[32];
  uint8_t bond_v2_insurance_reserve_cmr_wire[32];
  /* Preauthorized migration identities are deliberately separate from the
   * ordinary V18 identity.  Until both genuine catalogue CMRs are frozen,
   * this presence flag remains zero and activation jets fail closed. */
  uint8_t bond_v2_incremental_activation_identity_present;
  uint8_t bond_v2_incremental_activation_cmr_wire[32];
  uint8_t incremental_successor_transition_cmr_wire[32];
  uint8_t bond_v2_projection_present;
  uint8_t prior_active_bond_inbox_root_wire[32];
  uint64_t prior_active_bond_inbox_count;
  uint64_t current_sidechain_height;
  ecx_sp1_groth16_verify_fn verify_sp1_groth16;
  void* verify_sp1_groth16_context;
} ecx_prior_active_root_env;

/* A forward declaration for the structure containing a copy (and digest) of the rawElementsTapEnv data */
typedef struct elementsTapEnv elementsTapEnv;

/* Allocate and initialize a 'elementsTapEnv' from a 'rawElementsTapEnv', copying or hashing the data as needed.
 * Returns NULL if malloc fails (or if malloc cannot be called because we require an allocation larger than SIZE_MAX).
 *
 * Precondition: *rawEnv is well-formed (i.e. rawEnv->pathLen <= 128.)
 */
extern elementsTapEnv* simplicity_elements_mallocTapEnv(const rawElementsTapEnv* rawEnv);

/* Free a pointer to 'elementsTapEnv'.
 */
extern void simplicity_elements_freeTapEnv(elementsTapEnv* env);
#endif
