// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_PARENT_RULES_H
#define BITCOIN_DRIVECHAIN_PARENT_RULES_H

#include <drivechain_treasury.h>
#include <elements_drivechain_identity.h>

#include <cstdint>
#include <optional>
#include <string_view>

enum class DrivechainM6ReplayRule {
    SINGLE_CONFIGURED_SLOT_M6,
    SEQUENTIAL_M6,
};

enum class DrivechainWithdrawalHistoryRule {
    UNIQUE_M6ID,
    ALLOW_REPROPOSAL,
};

namespace drivechain {

static_assert(!ElementsDrivechainIdentity::BETANET_EXISTING_ELEMENTS_TEST_PROFILE ||
    (ElementsDrivechainIdentity::PARENT_REPLAY_VERSION == 5 &&
     ElementsDrivechainIdentity::SIDECHAIN_SLOT == 24),
    "Elements test profile requires Betanet replay and slot 24");

struct ParentRules {
    TreasuryOpcode treasury_opcode;
    DrivechainM6ReplayRule m6;
    DrivechainWithdrawalHistoryRule history;
    std::string_view bootstrap_domain;
    std::string_view local_rule_domain;
    std::string_view proposal_text;
};

// Replay versions are committed by the frozen protocol manifest. Never infer
// compatibility with a future version or select these rules from runtime flags.
constexpr std::optional<ParentRules> ParentRulesForVersion(uint32_t version)
{
    switch (version) {
    case 4:
        return ParentRules{TreasuryOpcode::NOP5,
            DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6,
            DrivechainWithdrawalHistoryRule::UNIQUE_M6ID,
            "ELEMENTS_ALPHANET_PARENT_REPLAY_BOOTSTRAP_V1",
            "ELEMENTS_SLOT24_SINGLE_M6_PER_PARENT_BLOCK_V1",
            "Elements Drivechain v11; parameterized controller profile; replay v4; annex v2; one M6 per parent block; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24"};
    case 5:
        return ParentRules{TreasuryOpcode::NOP8,
            DrivechainM6ReplayRule::SEQUENTIAL_M6,
            DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL,
            "ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1",
            "ELEMENTS_SLOT24_SEQUENTIAL_M6_REPROPOSAL_V1",
            "Elements Drivechain Betanet v1; parameterized controller profile; replay v5; annex v2; sequential M6; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24"};
    default:
        return std::nullopt;
    }
}

static_assert(ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION).has_value(),
    "Frozen identity selects unsupported parent replay rules");
inline constexpr ParentRules FROZEN_PARENT_RULES =
    *ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION);
static_assert(FROZEN_PARENT_RULES.local_rule_domain == ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN,
    "Frozen identity local rule domain disagrees with replay version");
static_assert(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION != 5 ||
    ElementsDrivechainIdentity::SIDECHAIN_SLOT == 24,
    "Betanet frozen identity must select sidechain slot 24");

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_PARENT_RULES_H
