#include "txEnv.h"

/* Construct a txEnv structure from its components.
 * This function will precompute any cached values.
 *
 * Precondition: NULL != tx
 *               NULL != taproot
 *               NULL != genesisHash
 *               ix < tx->numInputs
 */
txEnv simplicity_elements_build_txEnv(const elementsTransaction* tx, const elementsTapEnv* taproot, const sha256_midstate* genesisHash, const ecx_prior_active_root_env* ecxRoot, uint_fast32_t ix) {
  txEnv result = { .tx = tx
                 , .taproot = taproot
                 , .genesisHash = *genesisHash
                 , .priorActiveExchangeStateRootPresent = 0 != ecxRoot->present
                 , .priorActiveForcedInboxRootPresent = 0 != ecxRoot->forced_inbox_present
                 , .priorActiveDepositInboxRootPresent = 0 != ecxRoot->deposit_inbox_present
                 , .currentBmmParentHeight = ecxRoot->current_bmm_parent_height
                 , .currentBmmParentMtp = ecxRoot->current_bmm_parent_mtp
                 , .currentBmmParentPresent = 0 != ecxRoot->current_bmm_parent_present
                 , .ix = ix
                 };
  sha256_toMidstate(result.priorActiveExchangeStateRoot.s, ecxRoot->root_wire);
  sha256_toMidstate(result.priorActiveForcedInboxRoot.s, ecxRoot->forced_inbox_root_wire);
  sha256_toMidstate(result.priorActiveDepositInboxRoot.s, ecxRoot->deposit_inbox_root_wire);
  sha256_toMidstate(result.currentBmmParentBlockHash.s, ecxRoot->current_bmm_parent_block_hash_wire);
  sha256_context ctx = sha256_init(result.sigAllHash.s);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, &tx->txHash);
  sha256_hash(&ctx, &taproot->tapEnvHash);
  sha256_u32be(&ctx, ix);
  sha256_finalize(&ctx);

  return result;
}
