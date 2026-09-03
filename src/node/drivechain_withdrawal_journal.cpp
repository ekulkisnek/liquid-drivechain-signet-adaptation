// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/drivechain_withdrawal_journal.h>

#include <consensus/consensus.h>
#include <hash.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>

#include <cstdio>

namespace node {

namespace {
//! File name of the journal inside the network data directory.
const char* const JOURNAL_FILENAME{"drivechain_withdrawal.dat"};

//! Distinguishes this file from any other serialized blob if one is ever
//! pointed at the wrong path.
const std::string JOURNAL_MAGIC{"ELEMENTS_DRIVECHAIN_WITHDRAWAL_JOURNAL_V1"};

bool ValidJournalEntry(const WithdrawalJournalEntry& entry, std::string& error)
{
    if (entry.version != 1) {
        error = strprintf("unsupported journal version %d", entry.version);
        return false;
    }
    if (entry.state > static_cast<uint8_t>(WithdrawalJournalState::FAILED)) {
        error = strprintf("unknown journal state %d", entry.state);
        return false;
    }
    if (entry.m6id.IsNull() || entry.sidechain_txid.IsNull()) {
        error = "journal contains a null M6 or sidechain transaction id";
        return false;
    }
    if (entry.amount <= 0 || !MoneyRange(entry.amount) ||
        entry.mainchain_fee <= 0 || entry.mainchain_fee >= entry.amount ||
        !MoneyRange(entry.mainchain_fee)) {
        error = "journal amount or mainchain fee is out of range";
        return false;
    }
    if (entry.sidechain_slot < 0 || entry.sidechain_slot > 255 ||
        entry.destination.empty() || entry.payout_script.empty() ||
        entry.payout_script.IsUnspendable() || entry.bundle_bytes.empty()) {
        error = "journal identity, destination, payout script, or bundle is invalid";
        return false;
    }
    if (entry.created_time <= 0) {
        error = "journal creation time is invalid";
        return false;
    }
    if (entry.bundle_bytes.size() < 7 || entry.bundle_bytes[4] != 0 ||
        entry.bundle_bytes[5] != 1) {
        error = "journal bundle is not the expected witness-encoded M6 transaction";
        return false;
    }
    std::vector<unsigned char> no_witness_bytes;
    no_witness_bytes.reserve(entry.bundle_bytes.size() - 2);
    no_witness_bytes.insert(
        no_witness_bytes.end(), entry.bundle_bytes.begin(), entry.bundle_bytes.begin() + 4);
    no_witness_bytes.insert(
        no_witness_bytes.end(), entry.bundle_bytes.begin() + 6, entry.bundle_bytes.end());
    if (Hash(no_witness_bytes) != entry.m6id) {
        error = "journal M6 identity does not match its serialized bundle";
        return false;
    }
    return true;
}
} // namespace

fs::path WithdrawalJournalPath(const fs::path& data_dir)
{
    return data_dir / JOURNAL_FILENAME;
}

bool WriteWithdrawalJournal(const fs::path& data_dir, const WithdrawalJournalEntry& entry)
{
    const fs::path path = WithdrawalJournalPath(data_dir);

    std::string validation_error;
    if (!ValidJournalEntry(entry, validation_error)) {
        LogPrintf("%s: refusing invalid journal entry: %s\n", __func__, validation_error);
        return false;
    }

    uint16_t randv{0};
    GetRandBytes(Span{reinterpret_cast<unsigned char*>(&randv), sizeof(randv)});
    const fs::path path_tmp = data_dir / fs::PathFromString(strprintf("drivechain_withdrawal.dat.%04x", randv));

    try {
        HashWriter hasher;
        hasher << JOURNAL_MAGIC << entry;
        const uint256 checksum = hasher.GetHash();

        FILE* file = fsbridge::fopen(path_tmp, "wb");
        AutoFile fileout{file};
        if (fileout.IsNull()) {
            fileout.fclose();
            fs::remove(path_tmp);
            LogPrintf("%s: failed to open %s\n", __func__, fs::PathToString(path_tmp));
            return false;
        }

        fileout << JOURNAL_MAGIC << entry << checksum;

        // The entire point of this file is that it survives a crash, so the
        // data must be on stable storage before we return and let the caller
        // spend anything.
        if (!fileout.Commit()) {
            fileout.fclose();
            fs::remove(path_tmp);
            LogPrintf("%s: failed to flush %s\n", __func__, fs::PathToString(path_tmp));
            return false;
        }
        fileout.fclose();

        if (!RenameOver(path_tmp, path)) {
            fs::remove(path_tmp);
            LogPrintf("%s: rename into place failed for %s\n", __func__, fs::PathToString(path));
            return false;
        }
    } catch (const std::exception& e) {
        fs::remove(path_tmp);
        LogPrintf("%s: serialization error: %s\n", __func__, e.what());
        return false;
    }

    // Fsync the directory too, otherwise the rename itself can be lost.
    DirectoryCommit(data_dir);

    LogDebug(BCLog::VALIDATION,
             "drivechain withdrawal journal: recorded m6id=%s state=%d txid=%s\n",
             entry.m6id.GetHex(), int{entry.state}, entry.sidechain_txid.GetHex());
    return true;
}

WithdrawalJournalReadResult ReadWithdrawalJournal(
    const fs::path& data_dir,
    WithdrawalJournalEntry& entry,
    std::string* error)
{
    if (error) error->clear();
    const fs::path path = WithdrawalJournalPath(data_dir);
    if (!fs::exists(path)) return WithdrawalJournalReadResult::MISSING;

    try {
        FILE* file = fsbridge::fopen(path, "rb");
        AutoFile filein{file};
        if (filein.IsNull()) {
            const std::string message = strprintf("failed to open %s", fs::PathToString(path));
            if (error) *error = message;
            LogPrintf("%s: %s\n", __func__, message);
            return WithdrawalJournalReadResult::CORRUPT;
        }

        std::string magic;
        WithdrawalJournalEntry parsed;
        uint256 checksum;
        filein >> magic >> parsed >> checksum;

        if (magic != JOURNAL_MAGIC) {
            const std::string message = strprintf("%s is not a withdrawal journal", fs::PathToString(path));
            if (error) *error = message;
            LogPrintf("%s: %s\n", __func__, message);
            return WithdrawalJournalReadResult::CORRUPT;
        }

        HashWriter hasher;
        hasher << JOURNAL_MAGIC << parsed;
        if (hasher.GetHash() != checksum) {
            const std::string message = strprintf("checksum mismatch in %s", fs::PathToString(path));
            if (error) *error = message;
            LogPrintf("%s: %s; refusing to act on it\n", __func__, message);
            return WithdrawalJournalReadResult::CORRUPT;
        }
        std::string validation_error;
        if (!ValidJournalEntry(parsed, validation_error)) {
            if (error) *error = validation_error;
            LogPrintf("%s: invalid journal %s: %s\n", __func__, fs::PathToString(path), validation_error);
            return WithdrawalJournalReadResult::CORRUPT;
        }
        entry = std::move(parsed);
        return WithdrawalJournalReadResult::OK;
    } catch (const std::exception& e) {
        const std::string message = strprintf("failed to read %s: %s", fs::PathToString(path), e.what());
        if (error) *error = message;
        LogPrintf("%s: %s\n", __func__, message);
        return WithdrawalJournalReadResult::CORRUPT;
    }
}

bool ClearWithdrawalJournal(const fs::path& data_dir)
{
    const fs::path path = WithdrawalJournalPath(data_dir);
    if (!fs::exists(path)) return true;
    std::error_code ec;
    fs::remove(path, ec);
    if (ec) {
        LogPrintf("%s: failed to remove %s: %s\n", __func__, fs::PathToString(path), ec.message());
        return false;
    }
    DirectoryCommit(data_dir);
    return true;
}

} // namespace node
