// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_TREASURY_H
#define BITCOIN_DRIVECHAIN_TREASURY_H

#include <span.h>

#include <cstdint>

namespace drivechain {

// Parent-network rules, not interchangeable script aliases.
enum class TreasuryOpcode : uint8_t { NOP5 = 0xb4, NOP8 = 0xb7 };

inline bool ExtractTreasurySlot(Span<const unsigned char> script,
                               TreasuryOpcode opcode, uint8_t& slot)
{
    // Match the enforcer's exact four-byte encoding, including the direct push.
    if ((opcode != TreasuryOpcode::NOP5 && opcode != TreasuryOpcode::NOP8) ||
        script.size() != 4 || script[0] != static_cast<uint8_t>(opcode) ||
        script[1] != 0x01 || script[3] != 0x51) {
        return false;
    }
    slot = script[2];
    return true;
}

inline bool IsTreasuryScript(Span<const unsigned char> script,
                             TreasuryOpcode opcode, int expected_slot)
{
    uint8_t slot;
    return expected_slot >= 0 && expected_slot <= 255 &&
           ExtractTreasurySlot(script, opcode, slot) && slot == expected_slot;
}

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_TREASURY_H
