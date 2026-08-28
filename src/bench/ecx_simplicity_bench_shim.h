#ifndef BITCOIN_BENCH_ECX_SIMPLICITY_BENCH_SHIM_H
#define BITCOIN_BENCH_ECX_SIMPLICITY_BENCH_SHIM_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecx_simplicity_bench_context ecx_simplicity_bench_context;

ecx_simplicity_bench_context* ecx_simplicity_bench_context_create(
  const char* valid_v1_annex_path,
  const char* valid_pv4_annex_path,
  const char* valid_pv5_annex_path,
  const char* valid_activation_v5_annex_path);
void ecx_simplicity_bench_context_destroy(ecx_simplicity_bench_context* context);
const char* ecx_simplicity_bench_error(void);

bool ecx_simplicity_bench_nullary(ecx_simplicity_bench_context* context, unsigned int jet_index);
bool ecx_simplicity_bench_role(ecx_simplicity_bench_context* context, bool insurance_reserve);
bool ecx_simplicity_bench_check_sig_verify(ecx_simplicity_bench_context* context);
bool ecx_simplicity_bench_groth16(ecx_simplicity_bench_context* context, bool tampered);
bool ecx_simplicity_bench_activation_v5_groth16(
  ecx_simplicity_bench_context* context,
  bool tampered);
bool ecx_simplicity_bench_eval_nullary(ecx_simplicity_bench_context* context, unsigned int jet_index);
bool ecx_simplicity_bench_eval_role(ecx_simplicity_bench_context* context, bool insurance_reserve);
bool ecx_simplicity_bench_eval_check_sig_verify(ecx_simplicity_bench_context* context);
bool ecx_simplicity_bench_eval_groth16(ecx_simplicity_bench_context* context, bool tampered);
bool ecx_simplicity_bench_eval_public_values_groth16(
  ecx_simplicity_bench_context* context,
  unsigned int public_values_version,
  bool tampered);
bool ecx_simplicity_bench_eval_activation_v5_groth16(
  ecx_simplicity_bench_context* context,
  bool tampered);
bool ecx_simplicity_bench_decode_jet(ecx_simplicity_bench_context* context, unsigned int jet_index);
bool ecx_simplicity_bench_decode_eval_jet(
  ecx_simplicity_bench_context* context,
  unsigned int jet_index,
  bool tampered);

#ifdef __cplusplus
}
#endif

#endif
