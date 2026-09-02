#!/usr/bin/env python3
"""Apply the pinned 24-interface Alpha catalogue overlay with POLICY costs.

The 1,000 / 1,000,000,000 milliweight values are configured policy values,
not measurements. This derives candidate identities without certifying
benchmark provenance, production review, or activation readiness.

Based on the source-workflow overlay with SHA-256:
3f32e3cb7e02c6375c6d49b0135f014f7be155208237100c682df92ca5796b3a.
Its old 23-interface source pin/catalogue/encoder were stale; this version
pins and includes the actual 24-interface typed source.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


UPSTREAM_COMMIT = "e3b670103101108faa238df012676ff5d8b77cf9"
PREIMAGES = {
    "Haskell/Elements/Simplicity/Elements/Primitive.hs":
        "ff0930b42d423579690856add4a35afafca56e10c17a534bdade4f359c491ddb",
    "Haskell/Simplicity/Elements/Jets.hs":
        "a65af128f8fdae6a09aa5adf7827d8c4452b8087b5fa8bac615ca27259753df0",
    "Simplicity.cabal":
        "93ee38c472beefcde66b364d2ffa1c6673d9eaad71815eadffac3fb210e4cb87",
}
CANDIDATE_SHA256 = "c92269809eb58fc035652fbe2907354fc97e7c4c329209b5d18659bb8b1e6460"
CONTEXT_POLICY_MILLIWEIGHT = 1_000
PROOF_POLICY_MILLIWEIGHT = 1_000_000_000
PROOF_CONSTRUCTORS = (
    "VerifySp1Groth16Sha256",
    "VerifySp1Groth16V3PublicValuesV4Sha256",
    "VerifySp1Groth16V4PublicValuesV5Sha256",
    "VerifySp1Groth16V5IncrementalActivationSha256",
    "VerifySp1Groth16V6IncrementalSuccessorSha256",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one preimage occurrence, found {count}")
    return text.replace(old, new, 1)


def apply(upstream: Path, candidate_source: Path) -> dict[str, str]:
    head = subprocess.check_output(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != UPSTREAM_COMMIT:
        raise ValueError(f"upstream HEAD must be {UPSTREAM_COMMIT}")
    if subprocess.check_output(
        ["git", "-C", str(upstream), "status", "--porcelain"], text=True
    ).strip():
        raise ValueError("upstream checkout must be clean")
    for relative, expected in PREIMAGES.items():
        path = upstream / relative
        if sha256(path) != expected:
            raise ValueError(f"upstream preimage mismatch: {relative}")
    if sha256(candidate_source) != CANDIDATE_SHA256:
        raise ValueError("typed Haskell primitive candidate source mismatch")

    destination = (
        upstream / "Haskell/Elements/Simplicity/Elements/EcxPrimitiveCandidate.hs"
    )
    if destination.exists():
        raise ValueError("ECX candidate module destination already exists")
    primitive_path = upstream / "Haskell/Elements/Simplicity/Elements/Primitive.hs"
    primitive = primitive_path.read_text(encoding="utf-8")
    primitive = replace_once(
        primitive,
        "  , PrimEnv, primEnv, envTx, envIx, envTap, envGenesisBlock\n",
        "  , PrimEnv, primEnv, primEnvWithEcx, envTx, envIx, envTap, envGenesisBlock, envEcx\n",
        "Primitive exports",
    )
    primitive = replace_once(
        primitive,
        "import Simplicity.Elements.DataTypes\n",
        "import Simplicity.Elements.DataTypes\n"
        "import qualified Simplicity.Elements.EcxPrimitiveCandidate as Ecx\n",
        "Primitive ECX import",
    )
    primitive = replace_once(
        primitive,
        "  TransactionId :: Prim () Word256\n",
        "  TransactionId :: Prim () Word256\n"
        "  EcxPrim :: Ecx.EcxPrim a b -> Prim a b\n",
        "Primitive constructor",
    )
    primitive = replace_once(
        primitive,
        "  TransactionId == TransactionId = True\n  _ == _ = False\n",
        "  TransactionId == TransactionId = True\n"
        "  EcxPrim left == EcxPrim right = left == right\n"
        "  _ == _ = False\n",
        "Primitive equality",
    )
    primitive = replace_once(
        primitive,
        'primName TransactionId = "transactionId"\n',
        'primName TransactionId = "transactionId"\n'
        "primName (EcxPrim primitive) = Ecx.ecxPrimName primitive\n",
        "Primitive name",
    )
    primitive = replace_once(
        primitive,
        "                       , envGenesisBlock :: Hash256\n"
        "                       }\n",
        "                       , envGenesisBlock :: Hash256\n"
        "                       , envEcx :: Ecx.EcxEnv\n"
        "                       }\n",
        "Primitive environment field",
    )
    primitive = replace_once(
        primitive,
        "                                              , envTap = tap\n"
        "                                              , envGenesisBlock = gen\n"
        "                                              }\n",
        "                                              , envTap = tap\n"
        "                                              , envGenesisBlock = gen\n"
        "                                              , envEcx = Ecx.emptyEcxEnv\n"
        "                                              }\n",
        "Primitive default environment",
    )
    primitive = replace_once(
        primitive,
        "  cond = fromIntegral ix < Vector.length (sigTxIn tx)\n\n"
        "-- | A hash of\n",
        "  cond = fromIntegral ix < Vector.length (sigTxIn tx)\n\n"
        "primEnvWithEcx :: SigTx -> Data.Word.Word32 -> TapEnv -> Hash256 -> Ecx.EcxEnv -> Maybe PrimEnv\n"
        "primEnvWithEcx tx ix tap gen ecx = (\\env -> env { envEcx = ecx }) <$> primEnv tx ix tap gen\n\n"
        "-- | A hash of\n",
        "Primitive ECX constructor",
    )
    primitive = replace_once(
        primitive,
        "  interpret TransactionId = element . return . encodeHash . txid $ tx\n",
        "  interpret TransactionId = element . return . encodeHash . txid $ tx\n"
        "  interpret (EcxPrim primitive) = \\input -> Ecx.ecxPrimSem primitive input (envEcx env)\n",
        "Primitive semantics",
    )
    jets_path = upstream / "Haskell/Simplicity/Elements/Jets.hs"
    jets = jets_path.read_text(encoding="utf-8")
    jets = replace_once(
        jets,
        "import Simplicity.Elements.DataTypes\n",
        "import Simplicity.Elements.DataTypes\n"
        "import qualified Simplicity.Elements.EcxPrimitiveCandidate as Ecx\n",
        "Jets ECX import",
    )
    jets = replace_once(
        jets,
        "  TransactionJet :: TransactionJet a b -> ElementsJet a b\n",
        "  TransactionJet :: TransactionJet a b -> ElementsJet a b\n"
        "  EcxJet :: (TyC a, TyC b) => Ecx.EcxPrim a b -> ElementsJet a b\n",
        "Jets constructor",
    )
    jets = replace_once(
        jets,
        "specificationElements (TransactionJet x) = specificationTransaction x\n",
        "specificationElements (TransactionJet x) = specificationTransaction x\n"
        "specificationElements (EcxJet x) = primitive (Prim.EcxPrim x)\n",
        "Jets specification",
    )
    jets = replace_once(
        jets,
        "implementationElements (TransactionJet x) = implementationTransaction x\n",
        "implementationElements (TransactionJet x) = implementationTransaction x\n"
        "implementationElements (EcxJet x) = \\env input -> Ecx.ecxPrimSem x input (Prim.envEcx env)\n",
        "Jets implementation",
    )
    jets = replace_once(
        jets,
        " , someArrowMap TransactionJet <$> transactionCatalogue\n"
        " ]\n"
        "sigHashCatalogue = book\n",
        " , someArrowMap TransactionJet <$> transactionCatalogue\n"
        " , someArrowMap EcxJet <$> ecxCatalogue\n"
        " ]\n"
        "ecxCatalogue = book\n"
        "  [ SomeArrow Ecx.PriorActiveExchangeStateRootRequired\n"
        "  , SomeArrow Ecx.PriorActiveForcedInboxRootRequired\n"
        "  , SomeArrow Ecx.PriorActiveDepositInboxRootRequired\n"
        "  , SomeArrow Ecx.PriorActiveForcedProcessedCursorRequired\n"
        "  , SomeArrow Ecx.PriorActiveDepositProcessedCursorRequired\n"
        "  , SomeArrow Ecx.CurrentBmmParentBlockHashRequired\n"
        "  , SomeArrow Ecx.CurrentBmmParentHeightRequired\n"
        "  , SomeArrow Ecx.CurrentBmmParentMtpRequired\n"
        "  , SomeArrow Ecx.BondV2ConfigurationHashRequired\n"
        "  , SomeArrow Ecx.BondV2AssetIdRequired\n"
        "  , SomeArrow Ecx.BondV2DeploymentCommitmentRequired\n"
        "  , SomeArrow Ecx.BondV2TransitionCmrRequired\n"
        "  , SomeArrow Ecx.VerifySp1Groth16Sha256\n"
        "  , SomeArrow Ecx.VerifySp1Groth16V3PublicValuesV4Sha256\n"
        "  , SomeArrow Ecx.VerifySp1Groth16V4PublicValuesV5Sha256\n"
        "  , SomeArrow Ecx.PriorActiveBondInboxRootRequired\n"
        "  , SomeArrow Ecx.PriorActiveBondInboxCountRequired\n"
        "  , SomeArrow Ecx.CurrentSidechainHeightRequired\n"
        "  , SomeArrow Ecx.BondV2InsuranceReserveInputRequired\n"
        "  , SomeArrow Ecx.BondV2CollateralVaultInputRequired\n"
        "  , SomeArrow Ecx.BondV2IncrementalActivationCmrRequired\n"
        "  , SomeArrow Ecx.IncrementalSuccessorTransitionCmrRequired\n"
        "  , SomeArrow Ecx.VerifySp1Groth16V5IncrementalActivationSha256\n"
        "  , SomeArrow Ecx.VerifySp1Groth16V6IncrementalSuccessorSha256\n"
        "  ]\n"
        "sigHashCatalogue = book\n",
        "Jets catalogue",
    )
    jets = replace_once(
        jets,
        "jetCostElements (TransactionJet x) = jetCostTransaction x\n",
        "jetCostElements (TransactionJet x) = jetCostTransaction x\n"
        "-- ECX costs below are POLICY choices, not claimed benchmark measurements.\n"
        + "".join(
            f"jetCostElements (EcxJet Ecx.{name}) = milli {PROOF_POLICY_MILLIWEIGHT}\n"
            for name in PROOF_CONSTRUCTORS
        )
        + f"jetCostElements (EcxJet _) = milli {CONTEXT_POLICY_MILLIWEIGHT}\n",
        "Jets unmeasured policy costs",
    )
    jets = replace_once(
        jets,
        "putJetBitElements (TransactionJet x) = putPositive 4 . putJetBitTransaction x\n\n"
        "putJetBitSigHash :: SigHashJet a b -> DList Bool\n",
        "putJetBitElements (TransactionJet x) = putPositive 4 . putJetBitTransaction x\n"
        "putJetBitElements (EcxJet x)         = putPositive 5 . putJetBitEcx x\n\n"
        "putJetBitEcx :: Ecx.EcxPrim a b -> DList Bool\n"
        "putJetBitEcx Ecx.PriorActiveExchangeStateRootRequired = putPositive 1\n"
        "putJetBitEcx Ecx.PriorActiveForcedInboxRootRequired = putPositive 2\n"
        "putJetBitEcx Ecx.PriorActiveDepositInboxRootRequired = putPositive 3\n"
        "putJetBitEcx Ecx.PriorActiveForcedProcessedCursorRequired = putPositive 4\n"
        "putJetBitEcx Ecx.PriorActiveDepositProcessedCursorRequired = putPositive 5\n"
        "putJetBitEcx Ecx.CurrentBmmParentBlockHashRequired = putPositive 6\n"
        "putJetBitEcx Ecx.CurrentBmmParentHeightRequired = putPositive 7\n"
        "putJetBitEcx Ecx.CurrentBmmParentMtpRequired = putPositive 8\n"
        "putJetBitEcx Ecx.BondV2ConfigurationHashRequired = putPositive 9\n"
        "putJetBitEcx Ecx.BondV2AssetIdRequired = putPositive 10\n"
        "putJetBitEcx Ecx.BondV2DeploymentCommitmentRequired = putPositive 11\n"
        "putJetBitEcx Ecx.BondV2TransitionCmrRequired = putPositive 12\n"
        "putJetBitEcx Ecx.VerifySp1Groth16Sha256 = putPositive 13\n"
        "putJetBitEcx Ecx.VerifySp1Groth16V3PublicValuesV4Sha256 = putPositive 14\n"
        "putJetBitEcx Ecx.VerifySp1Groth16V4PublicValuesV5Sha256 = putPositive 15\n"
        "putJetBitEcx Ecx.PriorActiveBondInboxRootRequired = putPositive 16\n"
        "putJetBitEcx Ecx.PriorActiveBondInboxCountRequired = putPositive 17\n"
        "putJetBitEcx Ecx.CurrentSidechainHeightRequired = putPositive 18\n"
        "putJetBitEcx Ecx.BondV2InsuranceReserveInputRequired = putPositive 19\n"
        "putJetBitEcx Ecx.BondV2CollateralVaultInputRequired = putPositive 20\n"
        "putJetBitEcx Ecx.BondV2IncrementalActivationCmrRequired = putPositive 21\n"
        "putJetBitEcx Ecx.IncrementalSuccessorTransitionCmrRequired = putPositive 22\n"
        "putJetBitEcx Ecx.VerifySp1Groth16V5IncrementalActivationSha256 = putPositive 23\n"
        "putJetBitEcx Ecx.VerifySp1Groth16V6IncrementalSuccessorSha256 = putPositive 24\n\n"
        "putJetBitSigHash :: SigHashJet a b -> DList Bool\n",
        "Jets encoder",
    )
    cabal_path = upstream / "Simplicity.cabal"
    cabal = cabal_path.read_text(encoding="utf-8")
    cabal = replace_once(
        cabal,
        "  exposed-modules:     Simplicity.Elements.Primitive, Simplicity.Elements.DataTypes\n",
        "  exposed-modules:     Simplicity.Elements.Primitive, Simplicity.Elements.DataTypes,\n"
        "                       Simplicity.Elements.EcxPrimitiveCandidate\n",
        "Cabal exposed module",
    )
    # Do not modify the checkout until every preimage and textual integration
    # point has been validated.  This makes a rejected overlay retryable and
    # prevents a late mismatch from leaving a misleading half-applied tree.
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate_source, destination)
    primitive_path.write_bytes(primitive.encode("utf-8"))
    jets_path.write_bytes(jets.encode("utf-8"))
    cabal_path.write_bytes(cabal.encode("utf-8"))

    outputs = {
        relative: sha256(upstream / relative)
        for relative in PREIMAGES
    }
    outputs["Haskell/Elements/Simplicity/Elements/EcxPrimitiveCandidate.hs"] = sha256(destination)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("upstream", type=Path)
    parser.add_argument(
        "--candidate-source",
        type=Path,
        required=True,
    )
    args = parser.parse_args()
    try:
        outputs = apply(args.upstream.resolve(), args.candidate_source.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}")
        return 1
    for path, digest in sorted(outputs.items()):
        print(f"{digest}  {path}")
    print("ECX 24-interface Haskell overlay: APPLIED; POLICY COSTS, NOT MEASUREMENTS; UNFROZEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
