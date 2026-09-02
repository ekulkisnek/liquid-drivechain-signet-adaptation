// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_USDD_SP1_RESOURCES_H
#define BITCOIN_USDD_SP1_RESOURCES_H

#include <primitives/transaction.h>
#include <script/usdd_sp1_annex.h>
#include <simplicity/elements/env.h>

#include <cstddef>
#include <cstdint>

namespace usdd {

static_assert(SP1_ANNEX_MAX_SIZE ==
                  SIMPLICITY_ELEMENTS_MAX_OWNED_ANNEX_SIZE,
              "SP1 consensus and Simplicity owned-annex limits must match");

/** One deterministic proof-verification lane is available in each block. */
static constexpr std::size_t SP1_ANNEXES_PER_BLOCK{
    ElementsDrivechainIdentity::USDD_SP1_ANNEXES_PER_BLOCK};
/** Consensus and policy ceiling for the transaction occupying that lane. */
static constexpr uint64_t SP1_PROOF_TX_MAX_WEIGHT{
    ElementsDrivechainIdentity::USDD_SP1_PROOF_TX_MAX_WEIGHT};
static_assert(SP1_PROOF_TX_MAX_WEIGHT * 4U <=
              ElementsDrivechainIdentity::CONSENSUS_MAX_BLOCK_WEIGHT,
              "one proof transaction must consume at most 25% of a block");
static_assert(
    ElementsDrivechainIdentity::USDD_SP1_MAX_ANNEX_WEIGHT <
        SP1_PROOF_TX_MAX_WEIGHT,
    "maximum annex must leave deterministic transaction headroom");

struct Sp1AnnexResourceUsage {
    std::size_t namespace_annexes{0};
    bool oversized{false};
    bool malformed{false};
    bool wrong_spend_shape{false};
    bool wrong_controller_cmr{false};
    bool wrong_guest_program_id{false};
    bool malformed_public_values{false};
    bool deployment_unconfigured{false};
    bool wrong_inbound_mint_domain{false};
};

static constexpr std::size_t SP1_TAPSIMPLICITY_WITNESS_ITEMS{5};
static constexpr std::size_t SP1_TAPROOT_CONTROL_BASE_SIZE{33};
static constexpr std::size_t SP1_TAPROOT_CONTROL_NODE_SIZE{32};
static constexpr std::size_t SP1_TAPROOT_CONTROL_MAX_SIZE{
    SP1_TAPROOT_CONTROL_BASE_SIZE + 128 * SP1_TAPROOT_CONTROL_NODE_SIZE};
static constexpr unsigned char SP1_TAPROOT_LEAF_MASK{0xfe};
static constexpr unsigned char SP1_TAPSIMPLICITY_LEAF_VERSION{0xbe};

inline bool ExceedsUsddSp1AnnexLane(const std::size_t current,
                                    const std::size_t additional)
{
    return current > SP1_ANNEXES_PER_BLOCK ||
           additional > SP1_ANNEXES_PER_BLOCK - current;
}

/**
 * Count BIP341-shaped annexes in the reserved 0x50 || "USDD" namespace.
 *
 * Count the raw namespace before parsing it, so malformed members consume the
 * same deterministic lane and cannot evade the cap. V11 performs only
 * structural/resource admission here. Authorization belongs exclusively to
 * successful execution of the configuration-bound Simplicity leaf and its
 * verifier jet. Historical profiles retain their frozen-pair prefilter.
 */
inline Sp1AnnexResourceUsage GetUsddSp1AnnexResourceUsage(const CTransaction& tx)
{
    Sp1AnnexResourceUsage usage;
    for (const auto& input_witness : tx.witness.vtxinwit) {
        const auto& stack = input_witness.scriptWitness.stack;
        if (stack.size() < 2 ||
            !IsUsddSp1ProofAnnex(stack.back())) {
            continue;
        }
        ++usage.namespace_annexes;
        usage.oversized |= stack.back().size() > SP1_ANNEX_MAX_SIZE;

        Sp1ProofAnnexView parsed;
        const Sp1AnnexError parse_error =
            ParseUsddSp1ProofAnnex(stack.back(), parsed);
        switch (parse_error) {
        case Sp1AnnexError::OK:
            break;
        case Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE:
            // Preserve rejection while reporting the precise bounded-field
            // violation. All other parser failures remain malformed-envelope
            // errors, including V11 zero or wrong-width public values.
            usage.malformed_public_values = true;
            continue;
        case Sp1AnnexError::NOT_USDD:
        case Sp1AnnexError::TOO_LARGE:
        case Sp1AnnexError::TRUNCATED:
        case Sp1AnnexError::BAD_MAGIC:
        case Sp1AnnexError::BAD_VERSION:
        case Sp1AnnexError::BAD_PROOF_SYSTEM:
        case Sp1AnnexError::BAD_STATEMENT_KIND:
        case Sp1AnnexError::BAD_DIGEST_MODE:
        case Sp1AnnexError::BAD_FLAGS:
        case Sp1AnnexError::EMPTY_PUBLIC_VALUES:
        case Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES:
        case Sp1AnnexError::EMPTY_PROOF:
        case Sp1AnnexError::ZERO_GUEST_PROGRAM_ID:
        case Sp1AnnexError::LENGTH_MISMATCH:
            usage.malformed = true;
            continue;
        }

        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            if (parsed.statement_kind !=
                Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
                usage.malformed = true;
                continue;
            }
        }

        // A reserved proof annex is valid only on the exact structural form
        // of a Tapsimplicity script-path spend:
        //
        //   witness, program, script CMR, control block, annex
        //
        // UTXO commitment and program/CMR equality remain script-consensus
        // checks. This context-free rule also compares the carried CMR and
        // annex guest ID to the frozen pair, preventing any other key path,
        // Tapscript, or Tapsimplicity program from occupying the proof lane.
        if (stack.size() != SP1_TAPSIMPLICITY_WITNESS_ITEMS ||
            stack[2].size() != 32) {
            usage.wrong_spend_shape = true;
            continue;
        }
        const auto& control = stack[3];
        const bool wrong_spend_shape =
            control.size() < SP1_TAPROOT_CONTROL_BASE_SIZE ||
            control.size() > SP1_TAPROOT_CONTROL_MAX_SIZE ||
            (control.size() - SP1_TAPROOT_CONTROL_BASE_SIZE) %
                    SP1_TAPROOT_CONTROL_NODE_SIZE !=
                0 ||
            (control[0] & SP1_TAPROOT_LEAF_MASK) !=
                SP1_TAPSIMPLICITY_LEAF_VERSION;
        usage.wrong_spend_shape |= wrong_spend_shape;
        if (wrong_spend_shape) continue;

        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            continue;
        }

        switch (CheckUsddSp1ProofIdentity(
            stack[2], parsed.guest_program_id, parsed.public_values)) {
        case Sp1ProofIdentityResult::MATCH:
            break;
        case Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR:
            usage.wrong_controller_cmr = true;
            break;
        case Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID:
            usage.wrong_guest_program_id = true;
            break;
        case Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES:
            usage.malformed_public_values = true;
            break;
        case Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED:
            usage.deployment_unconfigured = true;
            break;
        case Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN:
            usage.wrong_inbound_mint_domain = true;
            break;
        }
    }
    return usage;
}

} // namespace usdd

#endif // BITCOIN_USDD_SP1_RESOURCES_H
