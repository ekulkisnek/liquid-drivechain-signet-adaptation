// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_treasury.h>
#include <drivechain_parent_rules.h>
#include <elements_drivechain_bootstrap.h>
#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_AUTO_TEST_SUITE(drivechain_treasury_tests)

BOOST_AUTO_TEST_CASE(bootstrap_slots_do_not_cross_networks)
{
    const auto legacy = ElementsDrivechainBootstrap::SlotsForReplayVersion(4);
    const auto beta = ElementsDrivechainBootstrap::SlotsForReplayVersion(5);
    BOOST_REQUIRE(legacy);
    BOOST_REQUIRE(beta);
    BOOST_CHECK_EQUAL(legacy->size(), 7);
    BOOST_CHECK(beta->empty());
    for (const auto& slot : *legacy) BOOST_CHECK(slot.slot != 24);
    for (const uint32_t version : {0U, 3U, 6U, 0xffffffffU}) {
        BOOST_CHECK(!ElementsDrivechainBootstrap::SlotsForReplayVersion(version));
    }
}

BOOST_AUTO_TEST_CASE(parent_rules_are_versioned_and_fail_closed)
{
    const auto legacy = drivechain::ParentRulesForVersion(4);
    const auto beta = drivechain::ParentRulesForVersion(5);
    BOOST_REQUIRE(legacy);
    BOOST_REQUIRE(beta);
    BOOST_CHECK(legacy->treasury_opcode == drivechain::TreasuryOpcode::NOP5);
    BOOST_CHECK(legacy->m6 == DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6);
    BOOST_CHECK(legacy->history == DrivechainWithdrawalHistoryRule::UNIQUE_M6ID);
    BOOST_CHECK(beta->treasury_opcode == drivechain::TreasuryOpcode::NOP8);
    BOOST_CHECK(beta->m6 == DrivechainM6ReplayRule::SEQUENTIAL_M6);
    BOOST_CHECK(beta->history == DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL);
    BOOST_CHECK(legacy->bootstrap_domain == "ELEMENTS_ALPHANET_PARENT_REPLAY_BOOTSTRAP_V1");
    BOOST_CHECK(beta->bootstrap_domain == "ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1");
    BOOST_CHECK(legacy->local_rule_domain == "ELEMENTS_SLOT24_SINGLE_M6_PER_PARENT_BLOCK_V1");
    BOOST_CHECK(beta->local_rule_domain == "ELEMENTS_SLOT130_SEQUENTIAL_M6_REPROPOSAL_V1");
    BOOST_CHECK(legacy->proposal_text.find("replay v4;") != std::string_view::npos);
    BOOST_CHECK(beta->proposal_text.find("replay v5;") != std::string_view::npos);
    BOOST_CHECK(beta->proposal_text.find("slot 130") != std::string_view::npos);
    BOOST_CHECK(beta->proposal_text.find("one M6") == std::string_view::npos);
    for (const uint32_t version : {0U, 1U, 2U, 3U, 6U, 255U, 0xffffffffU}) {
        BOOST_CHECK(!drivechain::ParentRulesForVersion(version));
    }
    const auto frozen = drivechain::ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION);
    BOOST_REQUIRE(frozen);
    BOOST_CHECK(frozen->treasury_opcode == drivechain::FROZEN_PARENT_RULES.treasury_opcode);
    BOOST_CHECK(frozen->m6 == drivechain::FROZEN_PARENT_RULES.m6);
    BOOST_CHECK(frozen->history == drivechain::FROZEN_PARENT_RULES.history);
}

BOOST_AUTO_TEST_CASE(parent_opcode_and_all_slots)
{
    for (const auto opcode : {drivechain::TreasuryOpcode::NOP5, drivechain::TreasuryOpcode::NOP8}) {
        for (int n = 0; n < 256; ++n) {
            const std::vector<unsigned char> script{static_cast<uint8_t>(opcode), 1, static_cast<uint8_t>(n), 0x51};
            uint8_t slot{0};
            BOOST_CHECK(drivechain::ExtractTreasurySlot(script, opcode, slot));
            BOOST_CHECK_EQUAL(slot, n);
            BOOST_CHECK(drivechain::IsTreasuryScript(script, opcode, n));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, (n + 1) % 256));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, -1));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, 256));
            const auto other = opcode == drivechain::TreasuryOpcode::NOP5
                ? drivechain::TreasuryOpcode::NOP8 : drivechain::TreasuryOpcode::NOP5;
            BOOST_CHECK(!drivechain::ExtractTreasurySlot(script, other, slot));
        }
    }
}

BOOST_AUTO_TEST_CASE(noncanonical_and_truncated_scripts)
{
    for (const auto opcode : {drivechain::TreasuryOpcode::NOP5, drivechain::TreasuryOpcode::NOP8}) {
        const auto byte = static_cast<uint8_t>(opcode);
        const std::vector<std::vector<unsigned char>> invalid{
            {}, {byte}, {byte, 1}, {byte, 1, 24},
            {byte, 1, 24, 0x51, 0}, {byte, 1, 24, 0},
            {byte, 0x4c, 1, 24, 0x51}, {byte, 0x4d, 1, 0, 24, 0x51},
            {byte, 0x4e, 1, 0, 0, 0, 24, 0x51}, {byte, 0x51, 0x51},
        };
        for (const auto& script : invalid) {
            uint8_t slot{99};
            BOOST_CHECK(!drivechain::ExtractTreasurySlot(script, opcode, slot));
            BOOST_CHECK_EQUAL(slot, 99);
        }
    }
}

BOOST_AUTO_TEST_CASE(unknown_parent_opcode)
{
    for (int n = 0; n < 256; ++n) {
        if (n == 0xb4 || n == 0xb7) continue;
        const std::vector<unsigned char> script{static_cast<uint8_t>(n), 1, 24, 0x51};
        uint8_t slot{99};
        BOOST_CHECK(!drivechain::ExtractTreasurySlot(
            script, static_cast<drivechain::TreasuryOpcode>(n), slot));
        BOOST_CHECK_EQUAL(slot, 99);
    }
}

BOOST_AUTO_TEST_SUITE_END()
