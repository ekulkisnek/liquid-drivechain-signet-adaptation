// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_JOURNAL_H
#define BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_JOURNAL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace node {

/**
 * Durable record of an in-flight drivechain withdrawal.
 *
 * Before this existed, the only record that a withdrawal bundle was active
 * lived in a process-global uint256 and in the sidechain block header once a
 * block had been mined. A withdrawal that had been broadcast on the sidechain
 * but whose bundle had not yet reached a block was therefore invisible across a
 * restart: the funds were spent, no bundle was tracked, and nothing would ever
 * retry. A second withdrawal could then create a competing bundle.
 *
 * The sidechain spend and its destination metadata are persisted by the wallet.
 * Once that spend confirms, the exact height-bound M6 is written and flushed to
 * this journal *before* it is submitted to the enforcer. Recovery therefore
 * resubmits identical bytes instead of rebuilding a different bundle from a
 * chain tip that may have moved.
 */

enum class WithdrawalJournalState : uint8_t {
    //! Confirmed sidechain spend and exact M6 are durable; enforcer submission
    //! has not completed yet.
    RESERVED = 0,
    //! Legacy transition state retained for journal format compatibility. It
    //! is treated like RESERVED and is never emitted by the current workflow.
    SIDECHAIN_BROADCAST = 1,
    //! The enforcer accepted the bundle. It is now awaiting its ACK window.
    BUNDLE_SUBMITTED = 2,
    //! L1 reported the bundle as succeeded. This terminal tombstone remains
    //! durable until a later withdrawal replaces it, preventing a stale bundle
    //! hash in the sidechain tip from being resurrected after restart.
    SETTLED = 3,
    //! L1 rejected or expired this proposal. The exact M6 is retained for an
    //! explicit retry; a failed bundle must never be mistaken for a completed
    //! payout or silently discarded.
    FAILED = 4,
};

enum class WithdrawalJournalReadResult {
    MISSING,
    OK,
    CORRUPT,
};

struct WithdrawalJournalEntry {
    //! Journal format version, so a future change can be detected rather than
    //! misparsed.
    uint32_t version{1};
    uint8_t state{static_cast<uint8_t>(WithdrawalJournalState::RESERVED)};

    uint256 m6id;
    uint256 sidechain_txid;
    uint32_t sidechain_vout{0};
    uint32_t sidechain_height{0};

    CAmount amount{0};
    CAmount mainchain_fee{0};

    //! The destination exactly as the user supplied it, kept for operator
    //! diagnostics, and the decoded script that the bundle actually pays.
    std::string destination;
    CScript payout_script;

    int32_t sidechain_slot{0};
    int64_t created_time{0};

    //! Full serialized M6 bundle, so recovery can resubmit the identical bytes
    //! rather than rebuilding them from state that may have moved on.
    std::vector<unsigned char> bundle_bytes;

    SERIALIZE_METHODS(WithdrawalJournalEntry, obj)
    {
        READWRITE(obj.version, obj.state, obj.m6id, obj.sidechain_txid,
                  obj.sidechain_vout, obj.sidechain_height, obj.amount,
                  obj.mainchain_fee, obj.destination, obj.payout_script,
                  obj.sidechain_slot, obj.created_time, obj.bundle_bytes);
    }

    WithdrawalJournalState GetState() const { return static_cast<WithdrawalJournalState>(state); }
    void SetState(WithdrawalJournalState s) { state = static_cast<uint8_t>(s); }
    COutPoint Outpoint() const { return COutPoint(Txid::FromUint256(sidechain_txid), sidechain_vout); }
};

//! Path of the journal file inside a data directory.
fs::path WithdrawalJournalPath(const fs::path& data_dir);

/**
 * Atomically write the journal entry and flush it to stable storage.
 *
 * Writes to a temporary file, fsyncs it, then renames over the destination, so
 * a crash leaves either the previous entry or the new one, never a partial
 * record. Returns false on any I/O failure; callers must treat that as a hard
 * stop and must not proceed to spend.
 */
bool WriteWithdrawalJournal(const fs::path& data_dir, const WithdrawalJournalEntry& entry);

/**
 * Read the journal without conflating an absent file with corrupted state.
 *
 * CORRUPT is fail-closed: callers must block new withdrawals until the
 * operator restores or removes the file deliberately.
 */
WithdrawalJournalReadResult ReadWithdrawalJournal(
    const fs::path& data_dir,
    WithdrawalJournalEntry& entry,
    std::string* error = nullptr);

//! Remove the journal entry for explicit maintenance and tests. Normal
//! operation retains a SETTLED tombstone until the next withdrawal replaces it.
bool ClearWithdrawalJournal(const fs::path& data_dir);

} // namespace node

#endif // BITCOIN_NODE_DRIVECHAIN_WITHDRAWAL_JOURNAL_H
