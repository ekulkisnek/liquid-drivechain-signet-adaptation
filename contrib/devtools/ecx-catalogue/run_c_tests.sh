#!/bin/sh
# Offline tests. Builds only in a fresh temporary directory; no node is started.
set -eu
ecx_tool_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ecx_src_dir=$(CDPATH= cd -- "$ecx_tool_dir/../../../src/simplicity" && pwd)
ecx_build_dir=$(mktemp -d "${TMPDIR:-/tmp}/ecx-catalogue-c.XXXXXX")
printf 'Build/test artifacts: %s\n' "$ecx_build_dir"
cd "$ecx_build_dir"
ecx_compiler=${CC:-cc}
ecx_objects=
for ecx_unit in bitstream cmr dag deserialize eval frame jets jets-secp256k1 rsort sha256 type typeInference \
  elements/env elements/exec elements/ops elements/elementsJets elements/cmr elements/txEnv; do
  ecx_object=$(printf '%s' "$ecx_unit" | tr / _).o
  "$ecx_compiler" -std=c11 -O2 -DPRODUCTION -Wall -Wextra -Werror ${CFLAGS:-} \
    -I"$ecx_src_dir/include" -I"$ecx_src_dir" -c "$ecx_src_dir/$ecx_unit.c" -o "$ecx_object"
  ecx_objects="$ecx_objects $ecx_object"
done
for ecx_mode in default frozen; do
  ecx_define=
  if [ "$ecx_mode" = frozen ]; then ecx_define=-DECX_SIMPLICITY_CATALOGUE_FROZEN; fi
  "$ecx_compiler" -std=c11 -O2 -DPRODUCTION -Wall -Wextra -Werror ${CFLAGS:-} $ecx_define \
    -I"$ecx_src_dir/include" -I"$ecx_src_dir" -c "$ecx_src_dir/elements/primitive.c" -o "primitive-$ecx_mode.o"
  "$ecx_compiler" -std=c11 -O2 -DPRODUCTION -Wall -Wextra -Werror ${CFLAGS:-} $ecx_define \
    -I"$ecx_src_dir/include" -I"$ecx_src_dir" -I"$ecx_tool_dir" \
    "$ecx_tool_dir/catalogue_test.c" $ecx_objects "primitive-$ecx_mode.o" ${LDFLAGS:-} -o "catalogue-$ecx_mode"
  "./catalogue-$ecx_mode"
done
# Run all existing C regression vectors against the opt-in decoder as well.
ecx_test_objects=
for ecx_unit in test ctx8Pruned ctx8Unpruned hashBlock regression4 schnorr0 schnorr6 typeSkipTest elements/checkSigHashAllTx1; do
  ecx_object=$(printf '%s' "$ecx_unit" | tr / _).o
  "$ecx_compiler" -std=c11 -O2 -DPRODUCTION -Wall -Wextra -Werror ${CFLAGS:-} -DECX_SIMPLICITY_CATALOGUE_FROZEN \
    -I"$ecx_src_dir/include" -I"$ecx_src_dir" -c "$ecx_src_dir/$ecx_unit.c" -o "$ecx_object"
  ecx_test_objects="$ecx_test_objects $ecx_object"
done
"$ecx_compiler" $ecx_objects $ecx_test_objects primitive-frozen.o ${CFLAGS:-} ${LDFLAGS:-} -o native-regression
./native-regression
