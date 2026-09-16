// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>
#include <script/ecx_activation_annex.h>

#include <coins.h>
#include <ecx_exchange_state.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/pak.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pegins.h>
#include <script/usdd_sp1_annex.h>
#include <usdd_sp1_resources.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <chainparams.h> // Peg-out enforcement
#include <chainparamsbase.h>

#include <limits>

// ELEMENTS:
CAsset policyAsset;

#include <algorithm>
#include <cstddef>
#include <vector>

namespace {

bool IsFrozenActivationAnnex(const CTransaction& tx, size_t input,
    const ecx::ExchangeConsensus* consensus)
{
    if (!consensus || input != 0 || tx.witness.vtxinwit.empty() ||
        !consensus->bond_v2.activation_enabled || !consensus->bond_v2.identities_frozen) return false;
    const auto& stack = tx.witness.vtxinwit[input].scriptWitness.stack;
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 364> values{};
    const auto& frozen = consensus->bond_v2;
    return ecx::ParseActivationAnnex(stack, program, values) &&
        !frozen.incremental_activation_cmr.IsNull() &&
        std::equal(stack[2].begin(), stack[2].end(), frozen.incremental_activation_cmr.begin()) &&
        std::equal(program.begin(), program.end(), frozen.incremental_activation_program_id.begin()) &&
        std::equal(values.begin() + 4, values.begin() + 36, frozen.incremental_activation_configuration_hash.begin()) &&
        std::equal(values.begin() + 36, values.begin() + 68, frozen.configuration_hash.begin()) &&
        std::equal(values.begin() + 100, values.begin() + 132, frozen.incremental_successor_configuration_hash.begin()) &&
        std::equal(values.begin() + 164, values.begin() + 196, tx.GetHash().begin(),
            [](unsigned char a, std::byte b) { return a == std::to_integer<unsigned char>(b); }) &&
        std::equal(values.begin() + 228, values.begin() + 260, consensus->chain_id.begin());
}

bool UsddSp1AnnexPolicyEnabled()
{
    const CChainParams& params = Params();
    return params.NetworkIDString() == CBaseChainParams::ELEMENTS &&
           params.GetConsensus().drivechain_slot.has_value() &&
           params.GetConsensus().enable_usdd_sp1_annex;
}

/**
 * Classify BIP341-shaped annex items before UTXO lookup and return the exact
 * witness weight attributable to one canonical USDD proof annex. The caller
 * can subtract only this amount from total transaction weight; all other
 * witness bytes remain subject to the ordinary standardness cap.
 */
bool GetUsddSp1AnnexPolicyWeight(const CTransaction& tx,
                                 uint64_t& annex_weight,
                                 std::string& reason,
                                 const ecx::ExchangeConsensus* consensus)
{
    annex_weight = 0;
    const usdd::Sp1AnnexResourceUsage resource_usage =
        usdd::GetUsddSp1AnnexResourceUsage(tx);
    if (resource_usage.oversized || resource_usage.malformed) {
        reason = "usdd-sp1-annex";
        return false;
    }
    if (resource_usage.wrong_spend_shape) {
        reason = "usdd-sp1-annex-shape";
        return false;
    }
    if (resource_usage.wrong_controller_cmr) {
        reason = "usdd-sp1-annex-controller-cmr";
        return false;
    }
    if (resource_usage.wrong_guest_program_id) {
        reason = "usdd-sp1-annex-guest-program-id";
        return false;
    }
    if (resource_usage.malformed_public_values) {
        reason = "usdd-sp1-annex-public-values";
        return false;
    }
    if (resource_usage.deployment_unconfigured) {
        reason = "usdd-sp1-deployment-unconfigured";
        return false;
    }
    if (resource_usage.wrong_inbound_mint_domain) {
        reason = "usdd-sp1-annex-inbound-domain";
        return false;
    }

    bool found{false};
    for (size_t input = 0; input < tx.witness.vtxinwit.size(); ++input) {
        const auto& input_witness = tx.witness.vtxinwit[input];
        const auto& stack = input_witness.scriptWitness.stack;
        if (stack.size() < 2 || stack.back().empty() ||
            stack.back()[0] != usdd::SP1_ANNEX_TAG) {
            continue;
        }
        // ECX activation is a disjoint, frozen lane. It receives no USDD
        // transaction-weight discount and remains fully script-validated.
        if (IsFrozenActivationAnnex(tx, input, consensus)) continue;
        if (!UsddSp1AnnexPolicyEnabled()) {
            reason = "usdd-sp1-annex";
            return false;
        }
        usdd::Sp1ProofAnnexView parsed;
        if (usdd::ParseUsddSp1ProofAnnex(stack.back(), parsed) !=
            usdd::Sp1AnnexError::OK) {
            reason = "usdd-sp1-annex";
            return false;
        }
        if (found) {
            reason = "usdd-sp1-annex-multiple";
            return false;
        }
        if (stack.size() != usdd::SP1_TAPSIMPLICITY_WITNESS_ITEMS ||
            stack[2].size() != 32) {
            reason = "usdd-sp1-annex-shape";
            return false;
        }
        const auto& control = stack[3];
        if (control.size() < usdd::SP1_TAPROOT_CONTROL_BASE_SIZE ||
            control.size() > usdd::SP1_TAPROOT_CONTROL_MAX_SIZE ||
            (control.size() - usdd::SP1_TAPROOT_CONTROL_BASE_SIZE) %
                    usdd::SP1_TAPROOT_CONTROL_NODE_SIZE !=
                0 ||
            (control[0] & usdd::SP1_TAPROOT_LEAF_MASK) !=
                usdd::SP1_TAPSIMPLICITY_LEAF_VERSION) {
            reason = "usdd-sp1-annex-shape";
            return false;
        }
        if constexpr (!ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            if (usdd::CheckUsddSp1ProofIdentity(
                    stack[2], parsed.guest_program_id, parsed.public_values) !=
                usdd::Sp1ProofIdentityResult::MATCH) {
                // Historical profiles retain their frozen CMR/program lane.
                reason = "usdd-sp1-annex-identity";
                return false;
            }
        }
        found = true;

        // Witness bytes have weight one. Removing an annex deletes its compact
        // byte length and payload, and can also shrink the stack-item-count
        // CompactSize at an encoding boundary.
        annex_weight = GetSizeOfCompactSize(stack.back().size()) +
                       stack.back().size() +
                       GetSizeOfCompactSize(stack.size()) -
                       GetSizeOfCompactSize(stack.size() - 1);
    }
    return true;
}

} // namespace

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kvB.
    // A typical spendable segwit P2WPKH txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kvB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Note this computation is for spending a Segwit v0 P2WPKH output (a 33 bytes
    // public key + an ECDSA signature). For Segwit v1 Taproot outputs the minimum
    // satisfaction is lower (a single BIP340 signature) but this computation was
    // kept to not further reduce the dust level.
    // See discussion in https://github.com/bitcoin/bitcoin/pull/22779 for details.
    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // sum the sizes of the parts of a transaction input
        // with 75% segwit discount applied to the script size.
        nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    if (!txout.nValue.IsExplicit())
        return false; // FIXME
    if (!txout.nAsset.IsExplicit())
        return false;
    if (txout.IsFee())
        return false;
    return (txout.nValue.GetAmount() < GetDustThreshold(txout, dustRelayFeeIn));
}

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        // ELEMENTS: check explicitly
        const auto& output = tx.vout[i];
        if (output.nAsset.IsExplicit() && output.nAsset.GetAsset() != ::policyAsset) continue;
        if (IsDust(output, dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

bool IsStandard(const CScript& scriptPubKey, const std::optional<unsigned>& max_datacarrier_bytes, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    const CChainParams& params = Params();
    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    } else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    } else if (whichType == TxoutType::NULL_DATA && params.GetEnforcePak() &&
            scriptPubKey.IsPegoutScript(Params().ParentGenesisBlockHash()) ) {
        // If we're enforcing pak let through larger peg-out scripts
        return true;
    } else if (whichType == TxoutType::NULL_DATA) {
        if (!max_datacarrier_bytes || scriptPubKey.size() > *max_datacarrier_bytes) {
            return false;
        }
    }

    return true;
}

bool IsStandardTx(
    const CTransaction& tx,
    const std::optional<unsigned>& max_datacarrier_bytes,
    bool permit_bare_multisig,
    const CFeeRate& dust_relay_fee,
    std::string& reason,
    const ecx::ExchangeConsensus* ecx_consensus)
{
    if (tx.version > TX_MAX_STANDARD_VERSION || tx.version < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    std::string bond_inbox_error;
    const bool maybe_bond_inbox_source = ecx_consensus != nullptr &&
        std::any_of(tx.vout.begin(), tx.vout.end(), [](const CTxOut& output) {
            static constexpr std::array<unsigned char, 4> magic{{'E','C','X','B'}};
            return output.scriptPubKey.size() >= 8 && output.scriptPubKey[0] == OP_RETURN &&
                std::search(
                    output.scriptPubKey.begin() + 1, output.scriptPubKey.end(),
                    magic.begin(), magic.end()) != output.scriptPubKey.end();
        });
    const bool canonical_bond_inbox_source = maybe_bond_inbox_source &&
        ecx::IsCanonicalBondInboxSourceTransaction(
            tx, bond_inbox_error, *ecx_consensus);
    const uint64_t total_weight = GetTransactionWeight(tx);
    uint64_t usdd_annex_weight{0};
    if (Params().GetConsensus().drivechain_slot.has_value() &&
        !GetUsddSp1AnnexPolicyWeight(tx, usdd_annex_weight, reason, ecx_consensus)) {
        return false;
    }
    // Exceptions are independently bounded and cannot be combined to bypass
    // either application's cap. Ordinary non-annex bytes retain their limit.
    if (usdd_annex_weight > total_weight ||
        (canonical_bond_inbox_source && usdd_annex_weight != 0) ||
        (total_weight - usdd_annex_weight > MAX_STANDARD_TX_WEIGHT &&
         !canonical_bond_inbox_source) ||
        (usdd_annex_weight != 0 && total_weight > usdd::SP1_PROOF_TX_MAX_WEIGHT)) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH
        // multisig with compressed keys (remember the MAX_SCRIPT_ELEMENT_SIZE byte limit on
        // redeemScript size). That works out to a (15*(33+1))+3=513 byte
        // redeemScript, 513+1+15*(73+1)+3=1627 bytes of scriptSig, which
        // we round off to 1650(MAX_STANDARD_SCRIPTSIG_SIZE) bytes for
        // some minor future-proofing. That's also enough to spend a
        // 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey
        // is not considered standard.
        if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    const CChainParams& params = Params();
    unsigned int nDataOut = 0;
    TxoutType whichType;
    for (size_t output_index = 0; output_index < tx.vout.size(); ++output_index) {
        const CTxOut& txout = tx.vout[output_index];
        if (!::IsStandard(txout.scriptPubKey, max_datacarrier_bytes, whichType)) {
            std::string ecx_error;
            const bool drivechain_pegout = ecx_consensus != nullptr &&
                txout.scriptPubKey.IsPegoutScript(Params().ParentGenesisBlockHash());
            const bool forced_action = ecx_consensus != nullptr &&
                ecx::IsCanonicalForcedActionOutput(
                    tx, output_index, ecx_error, *ecx_consensus);
            const bool bond_inbox_marker = canonical_bond_inbox_source &&
                txout.scriptPubKey.size() == 507 &&
                txout.scriptPubKey[0] == OP_RETURN &&
                txout.scriptPubKey[1] == OP_PUSHDATA2;
            if (!drivechain_pegout && !forced_action && !bond_inbox_marker) {
                reason = "scriptpubkey";
                return false;
            }
            whichType = TxoutType::NULL_DATA;
        }

        if (whichType == TxoutType::NULL_DATA) {
            nDataOut++;
        } else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
            reason = "bare-multisig";
            return false;
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    // only one OP_RETURN txout is permitted
    if (!params.GetMultiDataPermitted() && nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

/**
 * Check transaction inputs to mitigate two
 * potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them,
 *    not consumed by scriptPubKey (or P2SH script)
 * 2. P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 *
 * Note that only the non-witness portion of the transaction is checked here.
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (tx.vin[i].m_is_pegin) {
            // This deals with p2sh in general only
            continue;
        }

        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD || whichType == TxoutType::WITNESS_UNKNOWN) {
            // WITNESS_UNKNOWN failures are typically also caught with a policy
            // flag in the script interpreter, but it can be helpful to catch
            // this type of NONSTANDARD transaction earlier in transaction
            // validation.
            return false;
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(
    const CTransaction& tx,
    const CCoinsViewCache& mapInputs,
    const ecx::ExchangeConsensus* ecx_consensus)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    std::string bond_inbox_error;
    const bool canonical_bond_inbox_source = ecx_consensus != nullptr &&
        ecx::IsCanonicalBondInboxSourceTransaction(
            tx, bond_inbox_error, *ecx_consensus);

    const usdd::Sp1AnnexResourceUsage resource_usage =
        usdd::GetUsddSp1AnnexResourceUsage(tx);
    if (resource_usage.oversized || resource_usage.malformed ||
        resource_usage.wrong_spend_shape ||
        resource_usage.wrong_controller_cmr ||
        resource_usage.wrong_guest_program_id ||
        resource_usage.malformed_public_values ||
        resource_usage.deployment_unconfigured ||
        resource_usage.wrong_inbound_mint_domain ||
        resource_usage.namespace_annexes > usdd::SP1_ANNEXES_PER_BLOCK) {
        return false;
    }

    bool found_usdd_sp1_annex{false};
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.witness.vtxinwit.size() <= i || tx.witness.vtxinwit[i].scriptWitness.IsNull()) {
            continue;
        }

        const CTxOut &prev = tx.vin[i].m_is_pegin ? GetPeginOutputFromWitness(tx.witness.vtxinwit[i].m_pegin_witness) : mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            return false;
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        Span stack{tx.witness.vtxinwit[i].scriptWitness.stack};
        const bool has_annex = stack.size() >= 2 && !stack.back().empty() &&
                               stack.back()[0] == usdd::SP1_ANNEX_TAG;
        const bool is_native_taproot = witnessversion == 1 &&
            witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh;
        if (has_annex && is_native_taproot && IsFrozenActivationAnnex(tx, i, ecx_consensus)) {
            SpanPopBack(stack);
        } else if (has_annex && Params().GetConsensus().drivechain_slot.has_value()) {
            if (!is_native_taproot || !UsddSp1AnnexPolicyEnabled() ||
                found_usdd_sp1_annex) {
                return false;
            }
            if (stack.size() != usdd::SP1_TAPSIMPLICITY_WITNESS_ITEMS ||
                stack[2].size() != 32) {
                return false;
            }
            const auto& proof_control = stack[3];
            if (proof_control.size() < usdd::SP1_TAPROOT_CONTROL_BASE_SIZE ||
                proof_control.size() > usdd::SP1_TAPROOT_CONTROL_MAX_SIZE ||
                (proof_control.size() - usdd::SP1_TAPROOT_CONTROL_BASE_SIZE) %
                        usdd::SP1_TAPROOT_CONTROL_NODE_SIZE !=
                    0 ||
                (proof_control[0] & usdd::SP1_TAPROOT_LEAF_MASK) !=
                    usdd::SP1_TAPSIMPLICITY_LEAF_VERSION) {
                return false;
            }
            usdd::Sp1ProofAnnexView parsed;
            if (usdd::ParseUsddSp1ProofAnnex(stack.back(), parsed) !=
                usdd::Sp1AnnexError::OK) {
                return false;
            }
            if constexpr (!ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
                if (usdd::CheckUsddSp1ProofIdentity(
                        stack[2], parsed.guest_program_id,
                        parsed.public_values) !=
                    usdd::Sp1ProofIdentityResult::MATCH) {
                    return false;
                }
            }
            found_usdd_sp1_annex = true;
            SpanPopBack(stack);
        } else if (has_annex) {
            SpanPopBack(stack);
        }

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            const CScriptWitness& scriptWitness = tx.witness.vtxinwit[i].scriptWitness;
            if (scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - At most one canonical USDD SP1 annex on the sole Elements network;
        //   every other annex is nonstandard
        if (is_native_taproot) {
            // Missing witness; invalid by consensus rules
            if (i >= tx.witness.vtxinwit.size()) {
                return false;
            }
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const auto& control_block = SpanPopBack(stack);
                const auto& script = SpanPopBack(stack);
                if (control_block.empty()) return false; // Empty control block is invalid
                const uint8_t leaf_version = control_block[0] & TAPROOT_LEAF_MASK;
                if (leaf_version == TAPROOT_LEAF_TAPSCRIPT) {
                    // Annexes remain nonstandard for Tapscript.
                    if (has_annex) return false;
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)
                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                    }
                } else if (leaf_version == TAPROOT_LEAF_TAPSIMPLICITY) {
                    // A TapSimplicity annex has application-defined semantics and is
                    // committed to by the transaction.  Only admit the exact witness
                    // shape consumed by the consensus interpreter: witness, program,
                    // 32-byte CMR, control block, and an optional annex.
                    if (stack.size() != 2 || script.size() != 32) return false;
                } else if (has_annex) {
                    // Annexes for key-path and unknown leaf-version spends retain the
                    // existing nonstandard policy.
                    return false;
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // The sole annex exception is input zero of an already fully
                // validated canonical bond-inbox source.  Its exact
                // [64-byte SIGHASH_DEFAULT signature, ECXBIN2 annex] shape,
                // marker, custody receipts, byte caps, and absence of every
                // other annex are rechecked by that classifier.  No generic
                // Taproot-annex policy relaxation is introduced.
                if (has_annex && !(canonical_bond_inbox_source && i == 0)) {
                    return false;
                }
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                return false;
            }
        }
    }
    return true;
}

bool IsIssuanceInMoneyRange(const CTransaction& tx)
{
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CAssetIssuance& issuance = tx.vin[i].assetIssuance;
        if (issuance.IsNull()) {
            continue;
        }
        if (issuance.nAmount.IsExplicit() && !MoneyRange(issuance.nAmount.GetAmount())) {
            return false;
        }
        // check the reissuance token is in range
        if (!issuance.nInflationKeys.IsNull() && issuance.nInflationKeys.IsExplicit() && !MoneyRange(issuance.nInflationKeys.GetAmount())) {
            return false;
        }
    }
    return true;
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (std::max(nWeight, nSigOpCost * bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

uint64_t GetSimplicityValidationMilliweight(const CTransaction& tx)
{
    uint64_t total{0};
    for (const CTxInWitness& witness : tx.witness.vtxinwit) {
        if (witness.scriptWitness.stack.size() < 4) continue;
        const auto& stack = witness.scriptWitness.stack;
        size_t control_index{stack.size() - 1};
        // Taproot annex, when present, is the final stack item.
        if (!stack[control_index].empty() && stack[control_index][0] == ANNEX_TAG) {
            if (control_index == 0) continue;
            --control_index;
        }
        if (control_index < 1) continue;
        const auto& control = stack[control_index];
        const auto& script_cmr = stack[control_index - 1];
        if (control.empty() ||
            (control[0] & TAPROOT_LEAF_MASK) != TAPROOT_LEAF_TAPSIMPLICITY ||
            script_cmr.size() != 32) {
            continue;
        }
        const uint64_t budget_wu{
            static_cast<uint64_t>(::GetSerializeSize(stack)) +
            static_cast<uint64_t>(VALIDATION_WEIGHT_OFFSET)};
        if (budget_wu > std::numeric_limits<uint64_t>::max() / 1000 ||
            total > std::numeric_limits<uint64_t>::max() - budget_wu * 1000) {
            return std::numeric_limits<uint64_t>::max();
        }
        total += budget_wu * 1000;
    }
    return total;
}

bool CalculateBmmWorkFeeQuote(
    const CAmount collected_fees,
    const uint64_t simplicity_milliweight,
    const CAmount work_sats_per_kwu,
    const CAmount producer_reserve,
    BmmWorkFeeQuote& quote)
{
    quote = {};
    if (collected_fees < 0 || work_sats_per_kwu < 0 || producer_reserve < 0 ||
        !MoneyRange(collected_fees) || !MoneyRange(work_sats_per_kwu) ||
        !MoneyRange(producer_reserve)) {
        return false;
    }
    static constexpr uint64_t MILLIWEIGHT_PER_KWU{1'000'000};
    const uint64_t rate{static_cast<uint64_t>(work_sats_per_kwu)};
    if (rate != 0 && simplicity_milliweight >
            (std::numeric_limits<uint64_t>::max() - (MILLIWEIGHT_PER_KWU - 1)) / rate) {
        return false;
    }
    const uint64_t priced_work{
        (simplicity_milliweight * rate + MILLIWEIGHT_PER_KWU - 1) /
        MILLIWEIGHT_PER_KWU};
    if (priced_work > static_cast<uint64_t>(MAX_MONEY)) return false;
    quote.verification_fee = static_cast<CAmount>(priced_work);
    quote.producer_reserve = producer_reserve;
    if (quote.verification_fee > collected_fees ||
        producer_reserve > collected_fees - quote.verification_fee) {
        return false;
    }
    quote.bid = collected_fees - quote.verification_fee - producer_reserve;
    return MoneyRange(quote.bid);
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTransaction& tx, const size_t nIn, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(tx, nIn), nSigOpCost, bytes_per_sigop);
}
