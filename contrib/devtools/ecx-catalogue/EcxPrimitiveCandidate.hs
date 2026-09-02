{-# LANGUAGE GADTs #-}

-- | Typed, source-only candidate for the ECX Elements primitive environment.
--
-- This module is deliberately not imported by the authoritative Elements jet
-- catalogue.  It fixes the types and pure semantics that a reviewed overlay
-- must preserve, but it does not assign a primitive tag, derive a CMR, choose a
-- cost, or make the catalogue generatable.
module Simplicity.Elements.EcxPrimitiveCandidate
  ( EcxPrim(..)
  , EcxEnv(..)
  , EcxBondIdentity(..)
  , EcxBondProjection(..)
  , EcxBmmParent(..)
  , EcxInputRole(..)
  , EcxSp1Variant(..)
  , emptyEcxEnv
  , ecxPrimName
  , ecxPrimSem
  ) where

import Simplicity.Ty.Bit (Bit, toBit)
import Simplicity.Ty.Word (Word32, Word64, Word256, fromWord64, fromWord256)


-- | The exact two node-owned input classifications consumed by the V18
-- reserve and collateral covenants.
data EcxInputRole
  = InsuranceReserveInput
  | CollateralVaultInput
  deriving (Eq, Show)


-- | Historical verifier shapes remain typed for V1 regression.  V2 selects
-- normal transitions select 'Groth16V4PublicValuesV5Sha256'; the one-shot
-- pristine migration selects the distinct activation-v5 variant.
data EcxSp1Variant
  = Groth16V2Sha256
  | Groth16V3PublicValuesV4Sha256
  | Groth16V4PublicValuesV5Sha256
  | Groth16V5IncrementalActivationSha256
  | Groth16V6IncrementalSuccessorSha256
  deriving (Eq, Show)


data EcxBondIdentity = EcxBondIdentity
  { bondConfigurationHash :: Word256
  , bondAssetId :: Word256
  , bondDeploymentCommitment :: Word256
  , bondTransitionCmr :: Word256
  , bondIncrementalActivationCmr :: Word256
  , incrementalSuccessorTransitionCmr :: Word256
  } deriving (Eq, Show)


-- | These values must be populated atomically from one authenticated prior
-- block-index projection.  A zero inbox count is canonical and valid.
data EcxBondProjection = EcxBondProjection
  { priorBondInboxRoot :: Word256
  , priorBondInboxCount :: Word64
  , currentSidechainHeight :: Word64
  } deriving (Eq, Show)


-- | The hash, height and MTP form one authenticated BMM parent context.
data EcxBmmParent = EcxBmmParent
  { bmmParentBlockHash :: Word256
  , bmmParentHeight :: Word64
  , bmmParentMtp :: Word64
  } deriving (Eq, Show)


-- | Pure Haskell view of the node-owned ECX evaluation context.
--
-- The two functions represent consensus callbacks.  The role callback must
-- classify the requested input exhaustively.  The SP1 callback must implement
-- the exact annex parser and frozen cryptographic verifier for its version;
-- this candidate intentionally does not claim that implementation exists in
-- the authoritative Haskell tree.
data EcxEnv = EcxEnv
  { exchangeFeatureActive :: Bool
  , priorActiveExchangeStateRoot :: Maybe Word256
  , priorActiveForcedInboxRoot :: Maybe Word256
  , priorActiveDepositInboxRoot :: Maybe Word256
  , priorActiveForcedProcessedCursor :: Maybe Word64
  , priorActiveDepositProcessedCursor :: Maybe Word64
  , authenticatedBmmParent :: Maybe EcxBmmParent
  , activatedBondIdentity :: Maybe EcxBondIdentity
  , authenticatedBondProjection :: Maybe EcxBondProjection
  , classifyBondInput :: Word32 -> EcxInputRole -> Bool
  , verifySp1Groth16Sha256 :: EcxSp1Variant -> Word256 -> Word256 -> Bool
  }


instance Show EcxEnv where
  showsPrec d env = showParen (d > 10)
                  $ showString "EcxEnv "
                  . showsPrec 11 (exchangeFeatureActive env)
                  . showString " <authenticated-context>"


emptyEcxEnv :: EcxEnv
emptyEcxEnv = EcxEnv
  { exchangeFeatureActive = False
  , priorActiveExchangeStateRoot = Nothing
  , priorActiveForcedInboxRoot = Nothing
  , priorActiveDepositInboxRoot = Nothing
  , priorActiveForcedProcessedCursor = Nothing
  , priorActiveDepositProcessedCursor = Nothing
  , authenticatedBmmParent = Nothing
  , activatedBondIdentity = Nothing
  , authenticatedBondProjection = Nothing
  , classifyBondInput = \_ _ -> False
  , verifySp1Groth16Sha256 = \_ _ _ -> False
  }


-- | Typed primitive tokens in exact registry order.
data EcxPrim a b where
  PriorActiveExchangeStateRootRequired :: EcxPrim () Word256
  PriorActiveForcedInboxRootRequired :: EcxPrim () Word256
  PriorActiveDepositInboxRootRequired :: EcxPrim () Word256
  PriorActiveForcedProcessedCursorRequired :: EcxPrim () Word64
  PriorActiveDepositProcessedCursorRequired :: EcxPrim () Word64
  CurrentBmmParentBlockHashRequired :: EcxPrim () Word256
  CurrentBmmParentHeightRequired :: EcxPrim () Word64
  CurrentBmmParentMtpRequired :: EcxPrim () Word64
  BondV2ConfigurationHashRequired :: EcxPrim () Word256
  BondV2AssetIdRequired :: EcxPrim () Word256
  BondV2DeploymentCommitmentRequired :: EcxPrim () Word256
  BondV2TransitionCmrRequired :: EcxPrim () Word256
  VerifySp1Groth16Sha256 :: EcxPrim (Word256, Word256) Bit
  VerifySp1Groth16V3PublicValuesV4Sha256 :: EcxPrim (Word256, Word256) Bit
  VerifySp1Groth16V4PublicValuesV5Sha256 :: EcxPrim (Word256, Word256) Bit
  PriorActiveBondInboxRootRequired :: EcxPrim () Word256
  PriorActiveBondInboxCountRequired :: EcxPrim () Word64
  CurrentSidechainHeightRequired :: EcxPrim () Word64
  BondV2InsuranceReserveInputRequired :: EcxPrim Word32 ()
  BondV2CollateralVaultInputRequired :: EcxPrim Word32 ()
  BondV2IncrementalActivationCmrRequired :: EcxPrim () Word256
  IncrementalSuccessorTransitionCmrRequired :: EcxPrim () Word256
  VerifySp1Groth16V5IncrementalActivationSha256 :: EcxPrim (Word256, Word256) Bit
  VerifySp1Groth16V6IncrementalSuccessorSha256 :: EcxPrim (Word256, Word256) Bit


instance Eq (EcxPrim a b) where
  PriorActiveExchangeStateRootRequired == PriorActiveExchangeStateRootRequired = True
  PriorActiveForcedInboxRootRequired == PriorActiveForcedInboxRootRequired = True
  PriorActiveDepositInboxRootRequired == PriorActiveDepositInboxRootRequired = True
  PriorActiveForcedProcessedCursorRequired == PriorActiveForcedProcessedCursorRequired = True
  PriorActiveDepositProcessedCursorRequired == PriorActiveDepositProcessedCursorRequired = True
  CurrentBmmParentBlockHashRequired == CurrentBmmParentBlockHashRequired = True
  CurrentBmmParentHeightRequired == CurrentBmmParentHeightRequired = True
  CurrentBmmParentMtpRequired == CurrentBmmParentMtpRequired = True
  BondV2ConfigurationHashRequired == BondV2ConfigurationHashRequired = True
  BondV2AssetIdRequired == BondV2AssetIdRequired = True
  BondV2DeploymentCommitmentRequired == BondV2DeploymentCommitmentRequired = True
  BondV2TransitionCmrRequired == BondV2TransitionCmrRequired = True
  VerifySp1Groth16Sha256 == VerifySp1Groth16Sha256 = True
  VerifySp1Groth16V3PublicValuesV4Sha256 == VerifySp1Groth16V3PublicValuesV4Sha256 = True
  VerifySp1Groth16V4PublicValuesV5Sha256 == VerifySp1Groth16V4PublicValuesV5Sha256 = True
  PriorActiveBondInboxRootRequired == PriorActiveBondInboxRootRequired = True
  PriorActiveBondInboxCountRequired == PriorActiveBondInboxCountRequired = True
  CurrentSidechainHeightRequired == CurrentSidechainHeightRequired = True
  BondV2InsuranceReserveInputRequired == BondV2InsuranceReserveInputRequired = True
  BondV2CollateralVaultInputRequired == BondV2CollateralVaultInputRequired = True
  BondV2IncrementalActivationCmrRequired == BondV2IncrementalActivationCmrRequired = True
  IncrementalSuccessorTransitionCmrRequired == IncrementalSuccessorTransitionCmrRequired = True
  VerifySp1Groth16V5IncrementalActivationSha256 == VerifySp1Groth16V5IncrementalActivationSha256 = True
  VerifySp1Groth16V6IncrementalSuccessorSha256 == VerifySp1Groth16V6IncrementalSuccessorSha256 = True
  _ == _ = False


instance Show (EcxPrim a b) where
  showsPrec _ = showString . ecxPrimName


ecxPrimName :: EcxPrim a b -> String
ecxPrimName PriorActiveExchangeStateRootRequired = "prior_active_exchange_state_root_required"
ecxPrimName PriorActiveForcedInboxRootRequired = "prior_active_forced_inbox_root_required"
ecxPrimName PriorActiveDepositInboxRootRequired = "prior_active_deposit_inbox_root_required"
ecxPrimName PriorActiveForcedProcessedCursorRequired = "prior_active_forced_processed_cursor_required"
ecxPrimName PriorActiveDepositProcessedCursorRequired = "prior_active_deposit_processed_cursor_required"
ecxPrimName CurrentBmmParentBlockHashRequired = "current_bmm_parent_block_hash_required"
ecxPrimName CurrentBmmParentHeightRequired = "current_bmm_parent_height_required"
ecxPrimName CurrentBmmParentMtpRequired = "current_bmm_parent_mtp_required"
ecxPrimName BondV2ConfigurationHashRequired = "bond_v2_configuration_hash_required"
ecxPrimName BondV2AssetIdRequired = "bond_v2_asset_id_required"
ecxPrimName BondV2DeploymentCommitmentRequired = "bond_v2_deployment_commitment_required"
ecxPrimName BondV2TransitionCmrRequired = "bond_v2_transition_cmr_required"
ecxPrimName VerifySp1Groth16Sha256 = "verify_sp1_groth16_sha256"
ecxPrimName VerifySp1Groth16V3PublicValuesV4Sha256 = "verify_sp1_groth16_v3_public_values_v4_sha256"
ecxPrimName VerifySp1Groth16V4PublicValuesV5Sha256 = "verify_sp1_groth16_v4_public_values_v5_sha256"
ecxPrimName PriorActiveBondInboxRootRequired = "prior_active_bond_inbox_root_required"
ecxPrimName PriorActiveBondInboxCountRequired = "prior_active_bond_inbox_count_required"
ecxPrimName CurrentSidechainHeightRequired = "current_sidechain_height_required"
ecxPrimName BondV2InsuranceReserveInputRequired = "bond_v2_insurance_reserve_input_required"
ecxPrimName BondV2CollateralVaultInputRequired = "bond_v2_collateral_vault_input_required"
ecxPrimName BondV2IncrementalActivationCmrRequired = "bond_v2_incremental_activation_cmr_required"
ecxPrimName IncrementalSuccessorTransitionCmrRequired = "incremental_successor_transition_cmr_required"
ecxPrimName VerifySp1Groth16V5IncrementalActivationSha256 = "verify_sp1_groth16_v5_incremental_activation_sha256"
ecxPrimName VerifySp1Groth16V6IncrementalSuccessorSha256 = "verify_sp1_groth16_v6_incremental_successor_sha256"


nonzero256 :: Word256 -> Bool
nonzero256 value = fromWord256 value /= 0


nonzero64 :: Word64 -> Bool
nonzero64 value = fromWord64 value /= 0


requiredHash :: EcxEnv -> Maybe Word256 -> Maybe Word256
requiredHash env value
  | exchangeFeatureActive env = value >>= \x -> if nonzero256 x then Just x else Nothing
  | otherwise = Nothing


requiredCursor :: EcxEnv -> Maybe Word64 -> Maybe Word64
requiredCursor env value
  | exchangeFeatureActive env = value
  | otherwise = Nothing


requiredIdentity :: EcxEnv -> (EcxBondIdentity -> Word256) -> Maybe Word256
requiredIdentity env field = requiredHash env (field <$> activatedBondIdentity env)


-- | Pure candidate semantics matching the standalone C reference boundary.
-- Projection and role primitives fail closed through 'Nothing'.  Verifier
-- primitives are total boolean jets: unavailable or invalid proof context
-- yields @Just false@, matching the Elements frame adapter.
ecxPrimSem :: EcxPrim a b -> a -> EcxEnv -> Maybe b
ecxPrimSem PriorActiveExchangeStateRootRequired () env =
  requiredHash env (priorActiveExchangeStateRoot env)
ecxPrimSem PriorActiveForcedInboxRootRequired () env =
  requiredHash env (priorActiveForcedInboxRoot env)
ecxPrimSem PriorActiveDepositInboxRootRequired () env =
  requiredHash env (priorActiveDepositInboxRoot env)
ecxPrimSem PriorActiveForcedProcessedCursorRequired () env =
  requiredCursor env (priorActiveForcedProcessedCursor env)
ecxPrimSem PriorActiveDepositProcessedCursorRequired () env =
  requiredCursor env (priorActiveDepositProcessedCursor env)
ecxPrimSem CurrentBmmParentBlockHashRequired () env = do
  parent <- if exchangeFeatureActive env then authenticatedBmmParent env else Nothing
  let value = bmmParentBlockHash parent
  if nonzero256 value then Just value else Nothing
ecxPrimSem CurrentBmmParentHeightRequired () env = do
  parent <- if exchangeFeatureActive env then authenticatedBmmParent env else Nothing
  let value = bmmParentHeight parent
  if nonzero64 value then Just value else Nothing
ecxPrimSem CurrentBmmParentMtpRequired () env = do
  parent <- if exchangeFeatureActive env then authenticatedBmmParent env else Nothing
  let value = bmmParentMtp parent
  if nonzero64 value then Just value else Nothing
ecxPrimSem BondV2ConfigurationHashRequired () env =
  requiredIdentity env bondConfigurationHash
ecxPrimSem BondV2AssetIdRequired () env =
  requiredIdentity env bondAssetId
ecxPrimSem BondV2DeploymentCommitmentRequired () env =
  requiredIdentity env bondDeploymentCommitment
ecxPrimSem BondV2TransitionCmrRequired () env =
  requiredIdentity env bondTransitionCmr
ecxPrimSem VerifySp1Groth16Sha256 (programId, publicValuesHash) env =
  Just . toBit $ verifySp1Groth16Sha256 env Groth16V2Sha256 programId publicValuesHash
ecxPrimSem VerifySp1Groth16V3PublicValuesV4Sha256 (programId, publicValuesHash) env =
  Just . toBit $ verifySp1Groth16Sha256 env Groth16V3PublicValuesV4Sha256 programId publicValuesHash
ecxPrimSem VerifySp1Groth16V4PublicValuesV5Sha256 (programId, publicValuesHash) env =
  Just . toBit $ verifySp1Groth16Sha256 env Groth16V4PublicValuesV5Sha256 programId publicValuesHash
ecxPrimSem PriorActiveBondInboxRootRequired () env = do
  projection <- if exchangeFeatureActive env then authenticatedBondProjection env else Nothing
  let value = priorBondInboxRoot projection
  if nonzero256 value then Just value else Nothing
ecxPrimSem PriorActiveBondInboxCountRequired () env = do
  projection <- if exchangeFeatureActive env then authenticatedBondProjection env else Nothing
  Just (priorBondInboxCount projection)
ecxPrimSem CurrentSidechainHeightRequired () env = do
  projection <- if exchangeFeatureActive env then authenticatedBondProjection env else Nothing
  let value = currentSidechainHeight projection
  if nonzero64 value then Just value else Nothing
ecxPrimSem BondV2InsuranceReserveInputRequired index env
  | exchangeFeatureActive env
  , Just _ <- activatedBondIdentity env
  , classifyBondInput env index InsuranceReserveInput = Just ()
  | otherwise = Nothing
ecxPrimSem BondV2CollateralVaultInputRequired index env
  | exchangeFeatureActive env
  , Just _ <- activatedBondIdentity env
  , classifyBondInput env index CollateralVaultInput = Just ()
  | otherwise = Nothing
ecxPrimSem BondV2IncrementalActivationCmrRequired () env =
  requiredIdentity env bondIncrementalActivationCmr
ecxPrimSem IncrementalSuccessorTransitionCmrRequired () env =
  requiredIdentity env incrementalSuccessorTransitionCmr
ecxPrimSem VerifySp1Groth16V5IncrementalActivationSha256 (programId, publicValuesHash) env =
  Just . toBit $ verifySp1Groth16Sha256 env Groth16V5IncrementalActivationSha256 programId publicValuesHash
ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (programId, publicValuesHash) env =
  Just . toBit $ verifySp1Groth16Sha256 env Groth16V6IncrementalSuccessorSha256 programId publicValuesHash
