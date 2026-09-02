#!/bin/sh
# Rebuild the typed reference in a fresh checkout; check, never rewrite, this repo.
set -eu
ecx_tool_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ecx_cabal=${ECX_CABAL:-cabal}
ecx_ghc=ghc-9.6.7
if [ "$("$ecx_ghc" --numeric-version)" != 9.6.7 ]; then
  printf '%s\n' 'Expected ghc-9.6.7 on PATH.' >&2
  exit 1
fi
ecx_work=$(mktemp -d "${TMPDIR:-/tmp}/ecx-catalogue-reproduce.XXXXXX")
printf 'Reproduction artifacts: %s\n' "$ecx_work"
ecx_cabal_cmd() {
  if [ -n "${ECX_CABAL_CONFIG:-}" ]; then
    "$ecx_cabal" --config-file="$ECX_CABAL_CONFIG" "$@"
  else
    "$ecx_cabal" "$@"
  fi
}
ecx_project_cmd() {
  ecx_command=$1
  shift
  ecx_cabal_cmd "$ecx_command" --project-dir="$ecx_work" \
    --project-file=catalogue.project --builddir="$ecx_work/build" "$@"
}

git clone --no-checkout --filter=blob:none https://github.com/BlockstreamResearch/simplicity.git \
  "$ecx_work/catalogue-upstream"
git -C "$ecx_work/catalogue-upstream" checkout --detach e3b670103101108faa238df012676ff5d8b77cf9
python3 "$ecx_tool_dir/apply_overlay.py" "$ecx_work/catalogue-upstream" \
  --candidate-source "$ecx_tool_dir/EcxPrimitiveCandidate.hs"
cp "$ecx_tool_dir/catalogue.project" "$ecx_tool_dir/catalogue.project.freeze" "$ecx_work/"
ecx_project_cmd build exe:GenPrimitive exe:GenDecodeJet exe:GenRustJets
ecx_primitive=$(ecx_project_cmd list-bin exe:GenPrimitive)
ecx_decode=$(ecx_project_cmd list-bin exe:GenDecodeJet)
ecx_rust=$(ecx_project_cmd list-bin exe:GenRustJets)
mkdir -p "$ecx_work/derived/identity-objects" "$ecx_work/derived/semantics-objects"
cd "$ecx_work/derived"
"$ecx_primitive"
"$ecx_decode"
"$ecx_rust"

# Explicit package databases avoid a GHC 9.6.7 panic when cabal exec exposes
# multiple in-place Simplicity sublibraries through a package environment.
# Ask Cabal for its store location instead of assuming a user's home directory.
ecx_store=$(ecx_cabal_cmd path --with-compiler="$ecx_ghc" --output-format=json |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["store-dir"])')
ecx_compile() {
  ecx_name=$1
  ecx_source=$2
  "$ecx_ghc" -O0 -Wall -Werror -package-env - -no-user-package-db -hide-all-packages \
    -package base -package-db "$ecx_store/ghc-9.6.7/package.db" \
    -package-db "$ecx_work/build/packagedb/ghc-9.6.7" \
    -package-id Simplicity-0.0.0-inplace \
    -package-id Simplicity-0.0.0-inplace-Simplicity-Elements \
    -odir "$ecx_work/derived/$ecx_name-objects" -hidir "$ecx_work/derived/$ecx_name-objects" \
    -o "$ecx_work/derived/$ecx_name" "$ecx_tool_dir/$ecx_source"
}
# These probes are correctness checks, not benchmarks. -O0 also avoids GHC's
# simplifier limit when specializing the deeply nested Word256 test fixtures.
ecx_compile identity DeriveEcxCatalogue.hs
ecx_compile semantics EcxPrimitiveCandidateTests.hs
./identity > jet-identities.tsv
./semantics
cmp jet-identities.tsv "$ecx_tool_dir/jet-identities.tsv"
python3 "$ecx_tool_dir/generate.py" --upstream-generated "$ecx_work/derived"
printf '%s\n' 'PASS: fresh pinned Haskell build reproduces all 24 published identities and C/Rust bindings.'
