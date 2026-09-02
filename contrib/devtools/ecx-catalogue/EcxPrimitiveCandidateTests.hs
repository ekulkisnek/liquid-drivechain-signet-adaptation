module Main (main) where

import Control.Monad (unless)
import Simplicity.Elements.EcxPrimitiveCandidate
import Simplicity.Ty.Bit (toBit)
import Simplicity.Ty.Word (toWord32, toWord64, toWord256)


expect :: String -> Bool -> IO ()
expect label condition = unless condition (fail label)


main :: IO ()
main = do
  let one = toWord256 1
      two = toWord256 2
      three = toWord256 3
      four = toWord256 4
      five = toWord256 5
      six = toWord256 6
      height = toWord64 77
      mtp = toWord64 88
      index = toWord32 3
      identity = EcxBondIdentity two three four five six one
      projection = EcxBondProjection six (toWord64 0) height
      parent = EcxBmmParent one height mtp
      env = emptyEcxEnv
        { exchangeFeatureActive = True
        , priorActiveExchangeStateRoot = Just one
        , priorActiveForcedInboxRoot = Just two
        , priorActiveDepositInboxRoot = Just three
        , priorActiveForcedProcessedCursor = Just (toWord64 0)
        , priorActiveDepositProcessedCursor = Just (toWord64 9)
        , authenticatedBmmParent = Just parent
        , activatedBondIdentity = Just identity
        , authenticatedBondProjection = Just projection
        , classifyBondInput = \candidate role -> candidate == index && role == InsuranceReserveInput
        , verifySp1Groth16Sha256 = \variant programId publicValuesHash ->
            variant `elem` [Groth16V4PublicValuesV5Sha256, Groth16V5IncrementalActivationSha256,
                           Groth16V6IncrementalSuccessorSha256]
              && programId == one && publicValuesHash == two
        }

  expect "inactive root must fail" $
    ecxPrimSem PriorActiveExchangeStateRootRequired () emptyEcxEnv == Nothing
  expect "root projection mismatch" $
    ecxPrimSem PriorActiveExchangeStateRootRequired () env == Just one
  expect "forced root projection mismatch" $
    ecxPrimSem PriorActiveForcedInboxRootRequired () env == Just two
  expect "deposit root projection mismatch" $
    ecxPrimSem PriorActiveDepositInboxRootRequired () env == Just three
  expect "zero forced cursor must remain valid" $
    ecxPrimSem PriorActiveForcedProcessedCursorRequired () env == Just (toWord64 0)
  expect "deposit cursor projection mismatch" $
    ecxPrimSem PriorActiveDepositProcessedCursorRequired () env == Just (toWord64 9)
  expect "BMM block hash projection mismatch" $
    ecxPrimSem CurrentBmmParentBlockHashRequired () env == Just one
  expect "BMM height projection mismatch" $
    ecxPrimSem CurrentBmmParentHeightRequired () env == Just height
  expect "BMM MTP projection mismatch" $
    ecxPrimSem CurrentBmmParentMtpRequired () env == Just mtp
  expect "configuration identity mismatch" $
    ecxPrimSem BondV2ConfigurationHashRequired () env == Just two
  expect "asset identity mismatch" $
    ecxPrimSem BondV2AssetIdRequired () env == Just three
  expect "deployment identity mismatch" $
    ecxPrimSem BondV2DeploymentCommitmentRequired () env == Just four
  expect "transition CMR identity mismatch" $
    ecxPrimSem BondV2TransitionCmrRequired () env == Just five
  expect "bond inbox root mismatch" $
    ecxPrimSem PriorActiveBondInboxRootRequired () env == Just six
  expect "zero bond inbox count must remain valid" $
    ecxPrimSem PriorActiveBondInboxCountRequired () env == Just (toWord64 0)
  expect "sidechain height mismatch" $
    ecxPrimSem CurrentSidechainHeightRequired () env == Just height
  expect "reserve role assertion mismatch" $
    ecxPrimSem BondV2InsuranceReserveInputRequired index env == Just ()
  expect "collateral role must fail for reserve-only index" $
    ecxPrimSem BondV2CollateralVaultInputRequired index env == Nothing
  expect "activation CMR identity mismatch" $
    ecxPrimSem BondV2IncrementalActivationCmrRequired () env == Just six
  expect "successor CMR identity mismatch" $
    ecxPrimSem IncrementalSuccessorTransitionCmrRequired () env == Just one
  expect "wrong input index must fail" $
    ecxPrimSem BondV2InsuranceReserveInputRequired (toWord32 4) env == Nothing
  expect "V5 verifier callback mismatch" $
    ecxPrimSem VerifySp1Groth16V4PublicValuesV5Sha256 (one, two) env == Just (toBit True)
  expect "historical verifier must remain version-separated" $
    ecxPrimSem VerifySp1Groth16V3PublicValuesV4Sha256 (one, two) env == Just (toBit False)
  expect "activation verifier callback mismatch" $
    ecxPrimSem VerifySp1Groth16V5IncrementalActivationSha256 (one, two) env == Just (toBit True)
  expect "successor verifier callback mismatch" $
    ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (one, two) env == Just (toBit True)
  expect "successor verifier requires the exact program" $
    ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (three, two) env == Just (toBit False)
  expect "successor verifier requires the exact public values digest" $
    ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (one, three) env == Just (toBit False)
  expect "successor verifier cannot reuse an activation-only backend" $
    ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (one, two)
      (env { verifySp1Groth16Sha256 = \variant _ _ -> variant == Groth16V5IncrementalActivationSha256 })
        == Just (toBit False)
  expect "successor verifier is false when unavailable" $
    ecxPrimSem VerifySp1Groth16V6IncrementalSuccessorSha256 (one, two) emptyEcxEnv == Just (toBit False)
  expect "unavailable verifier is a false bit, not evaluator failure" $
    ecxPrimSem VerifySp1Groth16Sha256 (one, two) emptyEcxEnv == Just (toBit False)

  let zeroHashEnv = env { priorActiveExchangeStateRoot = Just (toWord256 0) }
      zeroParentEnv = env { authenticatedBmmParent = Just (EcxBmmParent one (toWord64 0) mtp) }
      zeroIdentityEnv = env { activatedBondIdentity = Just (EcxBondIdentity (toWord256 0) three four five six one) }
      zeroProjectionEnv = env { authenticatedBondProjection = Just (EcxBondProjection (toWord256 0) (toWord64 0) height) }
      zeroHeightProjectionEnv = env { authenticatedBondProjection = Just (EcxBondProjection six (toWord64 0) (toWord64 0)) }
  expect "zero required root must fail" $
    ecxPrimSem PriorActiveExchangeStateRootRequired () zeroHashEnv == Nothing
  expect "zero required parent height must fail" $
    ecxPrimSem CurrentBmmParentHeightRequired () zeroParentEnv == Nothing
  expect "zero activated identity field must fail" $
    ecxPrimSem BondV2ConfigurationHashRequired () zeroIdentityEnv == Nothing
  expect "zero bond projection root must fail" $
    ecxPrimSem PriorActiveBondInboxRootRequired () zeroProjectionEnv == Nothing
  expect "zero current sidechain height must fail" $
    ecxPrimSem CurrentSidechainHeightRequired () zeroHeightProjectionEnv == Nothing
  expect "role assertion requires activated identity" $
    ecxPrimSem BondV2InsuranceReserveInputRequired index
      (env { activatedBondIdentity = Nothing }) == Nothing

  expect "registry name 0 mismatch" $
    ecxPrimName PriorActiveExchangeStateRootRequired == "prior_active_exchange_state_root_required"
  expect "registry name 12 mismatch" $
    ecxPrimName VerifySp1Groth16Sha256 == "verify_sp1_groth16_sha256"
  expect "registry name 14 mismatch" $
    ecxPrimName VerifySp1Groth16V4PublicValuesV5Sha256 ==
      "verify_sp1_groth16_v4_public_values_v5_sha256"
  expect "registry name 19 mismatch" $
    ecxPrimName BondV2CollateralVaultInputRequired ==
      "bond_v2_collateral_vault_input_required"
  expect "registry name 20 mismatch" $
    ecxPrimName BondV2IncrementalActivationCmrRequired ==
      "bond_v2_incremental_activation_cmr_required"
  expect "registry name 21 mismatch" $
    ecxPrimName IncrementalSuccessorTransitionCmrRequired ==
      "incremental_successor_transition_cmr_required"
  expect "registry name 22 mismatch" $
    ecxPrimName VerifySp1Groth16V5IncrementalActivationSha256 ==
      "verify_sp1_groth16_v5_incremental_activation_sha256"
  expect "registry name 23 mismatch" $
    ecxPrimName VerifySp1Groth16V6IncrementalSuccessorSha256 ==
      "verify_sp1_groth16_v6_incremental_successor_sha256"

  putStrLn "ECX typed Haskell primitive candidate: 44 checks PASS"
