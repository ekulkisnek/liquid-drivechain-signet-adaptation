// Copyright (c) 2026 The ECX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <bench/ecx_simplicity_bench_shim.h>

#include <cstdlib>
#include <memory>
#include <stdexcept>

namespace {

struct ContextDeleter {
    void operator()(ecx_simplicity_bench_context* context) const
    {
        ecx_simplicity_bench_context_destroy(context);
    }
};

using Context = std::unique_ptr<ecx_simplicity_bench_context, ContextDeleter>;

Context MakeContext(
    const char* v1_annex_path = nullptr,
    const char* pv4_annex_path = nullptr,
    const char* pv5_annex_path = nullptr,
    const char* activation_v5_annex_path = nullptr)
{
    Context context{ecx_simplicity_bench_context_create(
        v1_annex_path, pv4_annex_path, pv5_annex_path, activation_v5_annex_path)};
    if (!context) throw std::runtime_error{ecx_simplicity_bench_error()};
    return context;
}

void BenchmarkNullary(benchmark::Bench& bench, unsigned int jet_index)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_nullary(context.get(), jet_index);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

#define ECX_NULLARY_BENCHMARK(name, index)                    \
    static void Bench_##name(benchmark::Bench& bench)         \
    {                                                          \
        BenchmarkNullary(bench, index);                        \
    }                                                          \
    BENCHMARK(Bench_##name)

ECX_NULLARY_BENCHMARK(prior_active_exchange_state_root_required, 0);
ECX_NULLARY_BENCHMARK(prior_active_forced_inbox_root_required, 1);
ECX_NULLARY_BENCHMARK(prior_active_deposit_inbox_root_required, 2);
ECX_NULLARY_BENCHMARK(prior_active_forced_processed_cursor_required, 3);
ECX_NULLARY_BENCHMARK(prior_active_deposit_processed_cursor_required, 4);
ECX_NULLARY_BENCHMARK(current_bmm_parent_block_hash_required, 5);
ECX_NULLARY_BENCHMARK(current_bmm_parent_height_required, 6);
ECX_NULLARY_BENCHMARK(current_bmm_parent_mtp_required, 7);
ECX_NULLARY_BENCHMARK(bond_v2_configuration_hash_required, 8);
ECX_NULLARY_BENCHMARK(bond_v2_asset_id_required, 9);
ECX_NULLARY_BENCHMARK(bond_v2_deployment_commitment_required, 10);
ECX_NULLARY_BENCHMARK(bond_v2_transition_cmr_required, 11);
ECX_NULLARY_BENCHMARK(prior_active_bond_inbox_root_required, 12);
ECX_NULLARY_BENCHMARK(prior_active_bond_inbox_count_required, 13);
ECX_NULLARY_BENCHMARK(current_sidechain_height_required, 14);
ECX_NULLARY_BENCHMARK(bond_v2_incremental_activation_cmr_required, 15);
ECX_NULLARY_BENCHMARK(incremental_successor_transition_cmr_required, 16);

void BenchmarkEvalNullary(benchmark::Bench& bench, unsigned int jet_index)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_eval_nullary(context.get(), jet_index);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

#define ECX_EVAL_NULLARY_BENCHMARK(name, index)               \
    static void Bench_eval_##name(benchmark::Bench& bench)    \
    {                                                          \
        BenchmarkEvalNullary(bench, index);                    \
    }                                                          \
    BENCHMARK(Bench_eval_##name)

ECX_EVAL_NULLARY_BENCHMARK(prior_active_exchange_state_root_required, 0);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_forced_inbox_root_required, 1);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_deposit_inbox_root_required, 2);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_forced_processed_cursor_required, 3);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_deposit_processed_cursor_required, 4);
ECX_EVAL_NULLARY_BENCHMARK(current_bmm_parent_block_hash_required, 5);
ECX_EVAL_NULLARY_BENCHMARK(current_bmm_parent_height_required, 6);
ECX_EVAL_NULLARY_BENCHMARK(current_bmm_parent_mtp_required, 7);
ECX_EVAL_NULLARY_BENCHMARK(bond_v2_configuration_hash_required, 8);
ECX_EVAL_NULLARY_BENCHMARK(bond_v2_asset_id_required, 9);
ECX_EVAL_NULLARY_BENCHMARK(bond_v2_deployment_commitment_required, 10);
ECX_EVAL_NULLARY_BENCHMARK(bond_v2_transition_cmr_required, 11);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_bond_inbox_root_required, 12);
ECX_EVAL_NULLARY_BENCHMARK(prior_active_bond_inbox_count_required, 13);
ECX_EVAL_NULLARY_BENCHMARK(current_sidechain_height_required, 14);
ECX_EVAL_NULLARY_BENCHMARK(bond_v2_incremental_activation_cmr_required, 15);
ECX_EVAL_NULLARY_BENCHMARK(incremental_successor_transition_cmr_required, 16);

void BenchmarkDecode(benchmark::Bench& bench, unsigned int jet_index)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_decode_jet(context.get(), jet_index);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

#define ECX_DECODE_BENCHMARK(name, index)                     \
    static void Bench_decode_##name(benchmark::Bench& bench)  \
    {                                                          \
        BenchmarkDecode(bench, index);                         \
    }                                                          \
    BENCHMARK(Bench_decode_##name)

ECX_DECODE_BENCHMARK(prior_active_exchange_state_root_required, 0);
ECX_DECODE_BENCHMARK(prior_active_forced_inbox_root_required, 1);
ECX_DECODE_BENCHMARK(prior_active_deposit_inbox_root_required, 2);
ECX_DECODE_BENCHMARK(prior_active_forced_processed_cursor_required, 3);
ECX_DECODE_BENCHMARK(prior_active_deposit_processed_cursor_required, 4);
ECX_DECODE_BENCHMARK(current_bmm_parent_block_hash_required, 5);
ECX_DECODE_BENCHMARK(current_bmm_parent_height_required, 6);
ECX_DECODE_BENCHMARK(current_bmm_parent_mtp_required, 7);
ECX_DECODE_BENCHMARK(bond_v2_configuration_hash_required, 8);
ECX_DECODE_BENCHMARK(bond_v2_asset_id_required, 9);
ECX_DECODE_BENCHMARK(bond_v2_deployment_commitment_required, 10);
ECX_DECODE_BENCHMARK(bond_v2_transition_cmr_required, 11);
ECX_DECODE_BENCHMARK(verify_sp1_groth16_sha256, 12);
ECX_DECODE_BENCHMARK(verify_sp1_groth16_v3_public_values_v4_sha256, 13);
ECX_DECODE_BENCHMARK(verify_sp1_groth16_v4_public_values_v5_sha256, 14);
ECX_DECODE_BENCHMARK(prior_active_bond_inbox_root_required, 15);
ECX_DECODE_BENCHMARK(prior_active_bond_inbox_count_required, 16);
ECX_DECODE_BENCHMARK(current_sidechain_height_required, 17);
ECX_DECODE_BENCHMARK(bond_v2_insurance_reserve_input_required, 18);
ECX_DECODE_BENCHMARK(bond_v2_collateral_vault_input_required, 19);
ECX_DECODE_BENCHMARK(bond_v2_incremental_activation_cmr_required, 20);
ECX_DECODE_BENCHMARK(incremental_successor_transition_cmr_required, 21);
ECX_DECODE_BENCHMARK(verify_sp1_groth16_v5_incremental_activation_sha256, 22);

void BenchmarkDecodeEval(benchmark::Bench& bench, unsigned int jet_index, bool tampered = false)
{
    const char* v1_path = jet_index == 12 ? std::getenv("ECX_BENCH_VALID_V1_ANNEX") : nullptr;
    const char* pv4_path = jet_index == 13 ? std::getenv("ECX_BENCH_VALID_PV4_ANNEX") : nullptr;
    const char* pv5_path = jet_index == 14 ? std::getenv("ECX_BENCH_VALID_PV5_ANNEX") : nullptr;
    const char* activation_path =
        jet_index == 22 ? std::getenv("ECX_BENCH_VALID_ACTIVATION_V5_ANNEX") : nullptr;
    if (jet_index == 12 && (v1_path == nullptr || v1_path[0] == '\0')) {
        throw std::runtime_error{"ECX_BENCH_VALID_V1_ANNEX is required"};
    }
    if (jet_index == 22 && (activation_path == nullptr || activation_path[0] == '\0')) {
        throw std::runtime_error{"ECX_BENCH_VALID_ACTIVATION_V5_ANNEX is required"};
    }
    if (jet_index == 13 && (pv4_path == nullptr || pv4_path[0] == '\0')) {
        throw std::runtime_error{"ECX_BENCH_VALID_PV4_ANNEX is required"};
    }
    if (jet_index == 14 && (pv5_path == nullptr || pv5_path[0] == '\0')) {
        throw std::runtime_error{"ECX_BENCH_VALID_PV5_ANNEX is required"};
    }
    Context context = MakeContext(v1_path, pv4_path, pv5_path, activation_path);
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_decode_eval_jet(context.get(), jet_index, tampered);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void Bench_decode_eval_prior_active_exchange_state_root_required(benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 0);
}
BENCHMARK(Bench_decode_eval_prior_active_exchange_state_root_required)

static void Bench_decode_eval_bond_v2_insurance_reserve_input_required(benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 18);
}
BENCHMARK(Bench_decode_eval_bond_v2_insurance_reserve_input_required)

static void Bench_decode_eval_verify_sp1_groth16_sha256_valid(benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 12, false);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_sha256_valid)

static void Bench_decode_eval_verify_sp1_groth16_sha256_tampered(benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 12, true);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_sha256_tampered)

static void Bench_decode_eval_verify_sp1_groth16_v3_public_values_v4_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 13, false);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v3_public_values_v4_sha256_valid)

static void Bench_decode_eval_verify_sp1_groth16_v3_public_values_v4_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 13, true);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v3_public_values_v4_sha256_tampered)

static void Bench_decode_eval_verify_sp1_groth16_v4_public_values_v5_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 14, false);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v4_public_values_v5_sha256_valid)

static void Bench_decode_eval_verify_sp1_groth16_v4_public_values_v5_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 14, true);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v4_public_values_v5_sha256_tampered)

static void Bench_decode_eval_verify_sp1_groth16_v5_incremental_activation_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 22, false);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v5_incremental_activation_sha256_valid)

static void Bench_decode_eval_verify_sp1_groth16_v5_incremental_activation_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkDecodeEval(bench, 22, true);
}
BENCHMARK(Bench_decode_eval_verify_sp1_groth16_v5_incremental_activation_sha256_tampered)

static void Bench_bond_v2_insurance_reserve_input_required(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_role(context.get(), true);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_bond_v2_insurance_reserve_input_required)

static void Bench_bond_v2_collateral_vault_input_required(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_role(context.get(), false);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_bond_v2_collateral_vault_input_required)

static void Bench_eval_bond_v2_insurance_reserve_input_required(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_eval_role(context.get(), true);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_eval_bond_v2_insurance_reserve_input_required)

static void Bench_eval_bond_v2_collateral_vault_input_required(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_eval_role(context.get(), false);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_eval_bond_v2_collateral_vault_input_required)

static void Bench_CheckSigVerify(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_check_sig_verify(context.get());
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_CheckSigVerify)

static void Bench_eval_CheckSigVerify(benchmark::Bench& bench)
{
    Context context = MakeContext();
    bench.run([&] {
        const bool ok = ecx_simplicity_bench_eval_check_sig_verify(context.get());
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}
BENCHMARK(Bench_eval_CheckSigVerify)

void BenchmarkGroth16(benchmark::Bench& bench, bool tampered)
{
    const char* path = std::getenv("ECX_BENCH_VALID_V1_ANNEX");
    if (path == nullptr || path[0] == '\0') {
        throw std::runtime_error{"ECX_BENCH_VALID_V1_ANNEX is required"};
    }
    Context context = MakeContext(path);
    bench.run([&] {
        const bool valid = ecx_simplicity_bench_groth16(context.get(), tampered);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void Bench_verify_sp1_groth16_sha256_valid(benchmark::Bench& bench)
{
    BenchmarkGroth16(bench, false);
}
BENCHMARK(Bench_verify_sp1_groth16_sha256_valid)

static void Bench_verify_sp1_groth16_sha256_tampered(benchmark::Bench& bench)
{
    BenchmarkGroth16(bench, true);
}
BENCHMARK(Bench_verify_sp1_groth16_sha256_tampered)

void BenchmarkActivationV5Groth16(benchmark::Bench& bench, bool tampered)
{
    const char* path = std::getenv("ECX_BENCH_VALID_ACTIVATION_V5_ANNEX");
    if (path == nullptr || path[0] == '\0') {
        throw std::runtime_error{"ECX_BENCH_VALID_ACTIVATION_V5_ANNEX is required"};
    }
    Context context = MakeContext(nullptr, path);
    bench.run([&] {
        const bool valid = ecx_simplicity_bench_activation_v5_groth16(context.get(), tampered);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void Bench_verify_sp1_groth16_v5_incremental_activation_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkActivationV5Groth16(bench, false);
}
BENCHMARK(Bench_verify_sp1_groth16_v5_incremental_activation_sha256_valid)

static void Bench_verify_sp1_groth16_v5_incremental_activation_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkActivationV5Groth16(bench, true);
}
BENCHMARK(Bench_verify_sp1_groth16_v5_incremental_activation_sha256_tampered)

void BenchmarkEvalGroth16(benchmark::Bench& bench, bool tampered)
{
    const char* path = std::getenv("ECX_BENCH_VALID_V1_ANNEX");
    if (path == nullptr || path[0] == '\0') {
        throw std::runtime_error{"ECX_BENCH_VALID_V1_ANNEX is required"};
    }
    Context context = MakeContext(path);
    bench.run([&] {
        const bool valid = ecx_simplicity_bench_eval_groth16(context.get(), tampered);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void Bench_eval_verify_sp1_groth16_sha256_valid(benchmark::Bench& bench)
{
    BenchmarkEvalGroth16(bench, false);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_sha256_valid)

static void Bench_eval_verify_sp1_groth16_sha256_tampered(benchmark::Bench& bench)
{
    BenchmarkEvalGroth16(bench, true);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_sha256_tampered)

void BenchmarkEvalPublicValuesGroth16(
    benchmark::Bench& bench, unsigned int version, bool tampered)
{
    const char* path = std::getenv(
        version == 4 ? "ECX_BENCH_VALID_PV4_ANNEX" : "ECX_BENCH_VALID_PV5_ANNEX");
    if (path == nullptr || path[0] == '\0') {
        throw std::runtime_error{
            version == 4 ? "ECX_BENCH_VALID_PV4_ANNEX is required"
                         : "ECX_BENCH_VALID_PV5_ANNEX is required"};
    }
    Context context = version == 4 ? MakeContext(nullptr, path, nullptr, nullptr)
                                   : MakeContext(nullptr, nullptr, path, nullptr);
    bench.run([&] {
        const bool valid =
            ecx_simplicity_bench_eval_public_values_groth16(context.get(), version, tampered);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void Bench_eval_verify_sp1_groth16_v3_public_values_v4_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkEvalPublicValuesGroth16(bench, 4, false);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v3_public_values_v4_sha256_valid)

static void Bench_eval_verify_sp1_groth16_v3_public_values_v4_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkEvalPublicValuesGroth16(bench, 4, true);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v3_public_values_v4_sha256_tampered)

static void Bench_eval_verify_sp1_groth16_v4_public_values_v5_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkEvalPublicValuesGroth16(bench, 5, false);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v4_public_values_v5_sha256_valid)

static void Bench_eval_verify_sp1_groth16_v4_public_values_v5_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkEvalPublicValuesGroth16(bench, 5, true);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v4_public_values_v5_sha256_tampered)

void BenchmarkEvalActivationV5Groth16(benchmark::Bench& bench, bool tampered)
{
    const char* path = std::getenv("ECX_BENCH_VALID_ACTIVATION_V5_ANNEX");
    if (path == nullptr || path[0] == '\0') {
        throw std::runtime_error{"ECX_BENCH_VALID_ACTIVATION_V5_ANNEX is required"};
    }
    Context context = MakeContext(nullptr, path);
    bench.run([&] {
        const bool valid =
            ecx_simplicity_bench_eval_activation_v5_groth16(context.get(), tampered);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void Bench_eval_verify_sp1_groth16_v5_incremental_activation_sha256_valid(
    benchmark::Bench& bench)
{
    BenchmarkEvalActivationV5Groth16(bench, false);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v5_incremental_activation_sha256_valid)

static void Bench_eval_verify_sp1_groth16_v5_incremental_activation_sha256_tampered(
    benchmark::Bench& bench)
{
    BenchmarkEvalActivationV5Groth16(bench, true);
}
BENCHMARK(Bench_eval_verify_sp1_groth16_v5_incremental_activation_sha256_tampered)

} // namespace
