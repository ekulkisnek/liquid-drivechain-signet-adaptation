#ifndef BITCOIN_SCRIPT_ECX_ACTIVATION_ANNEX_H
#define BITCOIN_SCRIPT_ECX_ACTIVATION_ANNEX_H

#include <script/script.h>
#include <uint256.h>
#include <algorithm>
#include <array>
#include <cstdint>
extern "C" {
#include <simplicity/elements/env.h>
}

namespace ecx {
// Static simplicity_analyseBounds result for the exact CMR below with the
// unchanged frozen catalogue: 1,002,635,231 milliWU, rounded up to WU.
// This is a consensus allowance, not a measured runtime. No other program gets
// this credit, even if a different activation CMR is configured later.
static constexpr int64_t ACTIVATION_EXECUTION_BUDGET_WU{1'002'636};
static constexpr std::array<unsigned char, 32> ACTIVATION_BUDGET_CMR{
    0xd9,0xef,0x88,0xa9,0x38,0x9f,0x87,0x11,0x4f,0x62,0x53,0x9d,0x7e,0x0e,0x2d,0x07,
    0x0f,0xed,0x1a,0x4e,0xa9,0x0f,0xda,0xa7,0xc2,0x06,0xac,0x14,0x0e,0xcf,0x2e,0x87};

inline bool ParseActivationAnnex(const std::vector<std::vector<unsigned char>>& stack,
    std::array<unsigned char, 32>& program, std::array<unsigned char, 364>& values)
{
    if (stack.size() != 5 || stack[2].size() != 32 || stack[4].size() != 800 ||
        stack[4][0] != 0x50 || stack[3].size() < 33 || stack[3].size() > 4129 ||
        (stack[3].size() - 33) % 32 || (stack[3][0] & 0xfe) != 0xbe) return false;
    std::array<unsigned char, 32> digest{};
    return simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        stack[4].data() + 1, stack[4].size() - 1,
        program.data(), digest.data(), values.data());
}

inline int64_t ActivationExecutionBudget(int64_t ordinary, unsigned int input,
    const std::vector<std::vector<unsigned char>>& stack, const uint256* frozen_cmr,
    const uint256* frozen_program)
{
    if (ordinary < 0 || ordinary > ACTIVATION_EXECUTION_BUDGET_WU || input != 0 ||
        frozen_cmr == nullptr || frozen_program == nullptr || frozen_program->IsNull() ||
        !std::equal(ACTIVATION_BUDGET_CMR.begin(), ACTIVATION_BUDGET_CMR.end(), frozen_cmr->begin())) return ordinary;
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 364> values{};
    if (!ParseActivationAnnex(stack, program, values) ||
        !std::equal(stack[2].begin(), stack[2].end(), frozen_cmr->begin()) ||
        !std::equal(program.begin(), program.end(), frozen_program->begin())) return ordinary;
    // The interpreter already verified the Taproot leaf commitment. The leaf's
    // unchanged CMR commits to the full program and its proof/identity checks.
    return ACTIVATION_EXECUTION_BUDGET_WU;
}
} // namespace ecx
#endif
