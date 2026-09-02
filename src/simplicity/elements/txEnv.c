#include "txEnv.h"

#include <string.h>

static bool all_zero(const unsigned char* bytes, size_t len) {
  unsigned char aggregate = 0;
  for (size_t i = 0; i < len; ++i) aggregate |= bytes[i];
  return aggregate == 0;
}

static bool valid_prior_active_bmm_parent_checkpoint(
    bool present, const unsigned char endpoint[80]) {
  if (!endpoint) return !present;
  if (!present) return all_zero(endpoint, 80);
  return !all_zero(endpoint, 32)
      && !all_zero(endpoint + 40, 8)
      && !all_zero(endpoint + 48, 32);
}

/* Construct a txEnv structure from its components.
 * This function will precompute any cached values.
 *
 * Precondition: NULL != tx
 *               NULL != taproot
 *               NULL != genesisHash
 *               ix < tx->numInputs
 */
txEnv simplicity_elements_build_txEnv(const elementsTransaction* tx, const elementsTapEnv* taproot,
                                      const sha256_midstate* genesisHash, const ecx_prior_active_root_env* ecxRoot, uint_fast32_t ix,
                                      bool bmmParentMtpPresent, uint_fast64_t bmmParentMtp,
                                      bool priorActiveBmmParentCheckpointPresent,
                                      const unsigned char priorActiveBmmParentCheckpoint[80]) {
  txEnv result = { .tx = tx
                 , .taproot = taproot
                 , .genesisHash = *genesisHash
                 , .priorActiveExchangeStateRootPresent = 0 != ecxRoot->present
                 , .priorActiveForcedInboxRootPresent = 0 != ecxRoot->forced_inbox_present
                 , .priorActiveDepositInboxRootPresent = 0 != ecxRoot->deposit_inbox_present
                 , .priorActiveForcedProcessedCursor = ecxRoot->forced_processed_cursor
                 , .priorActiveDepositProcessedCursor = ecxRoot->deposit_processed_cursor
                 , .currentBmmParentHeight = ecxRoot->current_bmm_parent_height
                 , .currentBmmParentMtp = ecxRoot->current_bmm_parent_mtp
                 , .currentBmmParentPresent = 0 != ecxRoot->current_bmm_parent_present
                 , .bondV2IdentityPresent = 0 != ecxRoot->bond_v2_identity_present
                 , .bondV2IncrementalActivationIdentityPresent =
                     0 != ecxRoot->bond_v2_incremental_activation_identity_present
                 , .priorActiveBondInboxCount = ecxRoot->prior_active_bond_inbox_count
                 , .currentSidechainHeight = ecxRoot->current_sidechain_height
                 , .bondV2ProjectionPresent = 0 != ecxRoot->bond_v2_projection_present
                 , .verifySp1Groth16 = ecxRoot->verify_sp1_groth16
                 , .verifySp1Groth16Context = ecxRoot->verify_sp1_groth16_context
                 , .ix = ix
                 , .bmmParentMtp = bmmParentMtp
                 , .bmmParentMtpPresent = bmmParentMtpPresent
                 , .priorActiveBmmParentCheckpointPresent =
                     priorActiveBmmParentCheckpointPresent
                 , .priorActiveBmmParentCheckpointValid =
                     valid_prior_active_bmm_parent_checkpoint(
                         priorActiveBmmParentCheckpointPresent,
                         priorActiveBmmParentCheckpoint)
                 };
  sha256_toMidstate(result.priorActiveExchangeStateRoot.s, ecxRoot->root_wire);
  sha256_toMidstate(result.priorActiveForcedInboxRoot.s, ecxRoot->forced_inbox_root_wire);
  sha256_toMidstate(result.priorActiveDepositInboxRoot.s, ecxRoot->deposit_inbox_root_wire);
  sha256_toMidstate(result.currentBmmParentBlockHash.s, ecxRoot->current_bmm_parent_block_hash_wire);
  sha256_toMidstate(result.bondV2ConfigurationHash.s, ecxRoot->bond_v2_configuration_hash_wire);
  sha256_toMidstate(result.bondV2AssetId.s, ecxRoot->bond_v2_asset_id_wire);
  sha256_toMidstate(result.bondV2DeploymentCommitment.s, ecxRoot->bond_v2_deployment_commitment_wire);
  sha256_toMidstate(result.bondV2TransitionCmr.s, ecxRoot->bond_v2_transition_cmr_wire);
  sha256_toMidstate(result.bondV2CollateralVaultScriptSha256.s,
                    ecxRoot->bond_v2_collateral_vault_script_sha256_wire);
  sha256_toMidstate(result.bondV2CollateralVaultCmr.s,
                    ecxRoot->bond_v2_collateral_vault_cmr_wire);
  sha256_toMidstate(result.bondV2InsuranceReserveScriptSha256.s,
                    ecxRoot->bond_v2_insurance_reserve_script_sha256_wire);
  sha256_toMidstate(result.bondV2InsuranceReserveCmr.s,
                    ecxRoot->bond_v2_insurance_reserve_cmr_wire);
  sha256_toMidstate(result.bondV2IncrementalActivationCmr.s,
                    ecxRoot->bond_v2_incremental_activation_cmr_wire);
  sha256_toMidstate(result.incrementalSuccessorTransitionCmr.s,
                    ecxRoot->incremental_successor_transition_cmr_wire);
  sha256_toMidstate(result.priorActiveBondInboxRoot.s,
                    ecxRoot->prior_active_bond_inbox_root_wire);
  if (priorActiveBmmParentCheckpoint) {
    memcpy(result.priorActiveBmmParentCheckpoint,
           priorActiveBmmParentCheckpoint, 80);
  }
  sha256_context ctx = sha256_init(result.sigAllHash.s);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, &tx->txHash);
  sha256_hash(&ctx, &taproot->tapEnvHash);
  sha256_u32be(&ctx, ix);
  sha256_finalize(&ctx);

  return result;
}
