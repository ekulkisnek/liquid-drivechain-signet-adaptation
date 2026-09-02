{-# LANGUAGE GADTs, RankNTypes #-}
module Main (main) where

import Control.Monad (forM_, unless)
import Data.Either (isLeft)
import Data.List (intercalate, isPrefixOf, nub)
import Numeric (showHex)
import System.IO (hPutStrLn, stderr)

import Simplicity.Digest (Hash256, integerHash256)
import qualified Simplicity.Elements.EcxPrimitiveCandidate as Ecx
import qualified Simplicity.Elements.Jets as E
import qualified Simplicity.Elements.Term as Term
import Simplicity.MerkleRoot
  ( annotatedRoot, commitmentRoot, identityHash, typeRootR )
import Simplicity.Serialization (Error, evalStreamWithError, putPositive)
import Simplicity.Ty (SomeArrow(..), reifyArrow)
import Simplicity.Weight (milli, milliWeight)

-- These are actual jet identities, not specification-only fingerprints.
-- asJet commits the configured milliweight and the typed specification.
-- Derivation does not turn a policy cost into a measured benchmark result.
namedJets :: [(String, SomeArrow E.JetType)]
namedJets =
  [ ("prior_active_exchange_state_root_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveExchangeStateRootRequired)))
  , ("prior_active_forced_inbox_root_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveForcedInboxRootRequired)))
  , ("prior_active_deposit_inbox_root_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveDepositInboxRootRequired)))
  , ("prior_active_forced_processed_cursor_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveForcedProcessedCursorRequired)))
  , ("prior_active_deposit_processed_cursor_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveDepositProcessedCursorRequired)))
  , ("current_bmm_parent_block_hash_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.CurrentBmmParentBlockHashRequired)))
  , ("current_bmm_parent_height_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.CurrentBmmParentHeightRequired)))
  , ("current_bmm_parent_mtp_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.CurrentBmmParentMtpRequired)))
  , ("bond_v2_configuration_hash_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2ConfigurationHashRequired)))
  , ("bond_v2_asset_id_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2AssetIdRequired)))
  , ("bond_v2_deployment_commitment_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2DeploymentCommitmentRequired)))
  , ("bond_v2_transition_cmr_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2TransitionCmrRequired)))
  , ("verify_sp1_groth16_sha256", SomeArrow (E.ElementsJet (E.EcxJet Ecx.VerifySp1Groth16Sha256)))
  , ("verify_sp1_groth16_v3_public_values_v4_sha256", SomeArrow (E.ElementsJet (E.EcxJet Ecx.VerifySp1Groth16V3PublicValuesV4Sha256)))
  , ("verify_sp1_groth16_v4_public_values_v5_sha256", SomeArrow (E.ElementsJet (E.EcxJet Ecx.VerifySp1Groth16V4PublicValuesV5Sha256)))
  , ("prior_active_bond_inbox_root_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveBondInboxRootRequired)))
  , ("prior_active_bond_inbox_count_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.PriorActiveBondInboxCountRequired)))
  , ("current_sidechain_height_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.CurrentSidechainHeightRequired)))
  , ("bond_v2_insurance_reserve_input_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2InsuranceReserveInputRequired)))
  , ("bond_v2_collateral_vault_input_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2CollateralVaultInputRequired)))
  , ("bond_v2_incremental_activation_cmr_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.BondV2IncrementalActivationCmrRequired)))
  , ("incremental_successor_transition_cmr_required", SomeArrow (E.ElementsJet (E.EcxJet Ecx.IncrementalSuccessorTransitionCmrRequired)))
  , ("verify_sp1_groth16_v5_incremental_activation_sha256", SomeArrow (E.ElementsJet (E.EcxJet Ecx.VerifySp1Groth16V5IncrementalActivationSha256)))
  , ("verify_sp1_groth16_v6_incremental_successor_sha256", SomeArrow (E.ElementsJet (E.EcxJet Ecx.VerifySp1Groth16V6IncrementalSuccessorSha256)))
  ]

-- Full Haskell jet encodings: the first bit selects a jet rather than a
-- constant word. The C/Rust jet decoder is given the remaining bits.
expectedBits :: [String]
expectedBits =
  [ "111100010", "11110001100", "11110001101"
  , "11110001110000", "11110001110001", "11110001110010", "11110001110011"
  , "111100011101000", "111100011101001", "111100011101010", "111100011101011"
  , "111100011101100", "111100011101101", "111100011101110", "111100011101111"
  , "1111000111100000000", "1111000111100000001", "1111000111100000010"
  , "1111000111100000011", "1111000111100000100", "1111000111100000101"
  , "1111000111100000110", "1111000111100000111", "1111000111100001000"
  ]

expect :: String -> Bool -> IO ()
expect label condition = unless condition (fail label)

showBits :: [Bool] -> String
showBits = map (\bit -> if bit then '1' else '0')

hex256 :: Hash256 -> String
hex256 value = replicate (64 - length rendered) '0' ++ rendered
 where
  rendered = showHex (integerHash256 value) ""

encoded :: (String, SomeArrow E.JetType) -> String
encoded (_, SomeArrow jet) = showBits (E.putJetBit jet [])

jetCmr :: (String, SomeArrow E.JetType) -> Hash256
jetCmr (_, SomeArrow jet) = commitmentRoot (E.asJet jet)

checkJet :: (Int, (String, SomeArrow E.JetType)) -> IO ()
checkJet (index, (name, wrapped@(SomeArrow jet))) = do
  let bits = E.putJetBit jet []
      cost = milliWeight (E.jetCost jet)
      cmr = commitmentRoot (E.asJet jet)
      imr = identityHash (E.asJet jet)
      amr = annotatedRoot (E.asJet jet)
      changedCmr = commitmentRoot (Term.jet (milli (cost + 1)) (E.specification jet))
      changedImr = identityHash (Term.jet (milli (cost + 1)) (E.specification jet))
  expect (name ++ ": published path encoding") (showBits bits == expectedBits !! (index - 1))
  expect (name ++ ": typed decoder round trip")
    (evalStreamWithError E.getJetBit bits == Right wrapped)
  expect (name ++ ": finite positive consensus cost") (0 < cost && cost <= 2147483647)
  expect (name ++ ": jet CMR must differ from specification CMR")
    (cmr /= commitmentRoot (E.specification jet))
  expect (name ++ ": leaf AMR must equal jet CMR") (amr == cmr)
  expect (name ++ ": typed identity hash must differ from CMR") (imr /= cmr)
  expect (name ++ ": cost must affect CMR") (changedCmr /= cmr)
  expect (name ++ ": cost must affect typed identity hash") (changedImr /= imr)
  forM_ [0 .. length bits - 1] $ \size ->
    expect (name ++ ": truncated encoding accepted at " ++ show size)
      (isLeft (evalStreamWithError E.getJetBit (take size bits) :: Either Error (SomeArrow E.JetType)))

renderJet :: (Int, (String, SomeArrow E.JetType)) -> String
renderJet (index, (name, SomeArrow jet)) = intercalate "\t"
  [ show index, name, showBits bits, showBits (tail bits)
  , show (milliWeight (E.jetCost jet))
  , hex256 (commitmentRoot (E.asJet jet))
  , hex256 (identityHash (E.asJet jet))
  , hex256 (annotatedRoot (E.asJet jet))
  , hex256 (typeRootR source), hex256 (typeRootR target)
  , hex256 (commitmentRoot (E.specification jet))
  , hex256 (identityHash (E.specification jet))
  ]
 where
  bits = E.putJetBit jet []
  (source, target) = reifyArrow jet

main :: IO ()
main = do
  expect "exactly 24 ECX interfaces required" (length namedJets == 24)
  expect "jet names must be unique" (length (nub (map fst namedJets)) == 24)
  expect "jet CMRs must be unique" (length (nub (map jetCmr namedJets)) == 24)
  let encodings = map encoded namedJets
  expect "jet encodings must be unique" (length (nub encodings) == 24)
  expect "jet encodings must be prefix-free" $
    and [not (a `isPrefixOf` b) | a <- encodings, b <- encodings, a /= b]
  mapM_ checkJet (zip [1..] namedJets)
  forM_ [(5, 25), (5, 31), (5, 2147483647), (6, 1)] $ \(shelf, index) -> do
    let bits = [True, True] ++ putPositive shelf (putPositive index [])
    expect ("unassigned decoder path accepted: " ++ show (shelf, index))
      (isLeft (evalStreamWithError E.getJetBit bits :: Either Error (SomeArrow E.JetType)))
  putStrLn $ intercalate "\t"
    [ "index", "name", "haskell_bits", "encoding_bits", "cost_milliweight"
    , "cmr", "imr", "amr", "source_tmr", "target_tmr", "specification_cmr", "specification_imr"
    ]
  mapM_ (putStrLn . renderJet) (zip [1..] namedJets)
  hPutStrLn stderr "PASS: 24 actual jet identities, typed decoder round trips, all truncated encodings, unassigned paths, unique/prefix-free encodings, and cost-sensitive identities."
