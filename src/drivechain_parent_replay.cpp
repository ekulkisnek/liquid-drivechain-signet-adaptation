// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_parent_replay.h>

#include <consensus/amount.h>
#include <dbwrapper.h>
#include <hash.h>
#include <tinyformat.h>

#include <limits>
#include <set>
#include <utility>

namespace {

static constexpr uint8_t DB_REPLAY_IDENTITY{'I'};
static constexpr uint8_t DB_REPLAY_TIP{'T'};
static constexpr uint8_t DB_REPLAY_DEPOSIT{'d'};
static constexpr uint8_t DB_REPLAY_BMM_EDGE{'e'};
static constexpr uint8_t DB_REPLAY_SUCCESSFUL_WITHDRAWAL{'w'};

struct DrivechainReplayStoreIdentity {
    uint32_t schema_version{0};
    uint256 identity;

    SERIALIZE_METHODS(DrivechainReplayStoreIdentity, obj)
    {
        READWRITE(obj.schema_version, obj.identity);
    }
};

bool SetStoreError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

bool IsSaneTip(const DrivechainParentReplayTip& tip)
{
    if (tip.hash.IsNull()) return false;
    if (tip.state.required_proposal_activated) {
        if (tip.state.active_proposal_hash.IsNull() ||
            tip.state.required_activation_block_hash.IsNull() ||
            tip.state.required_activation_height > tip.height) {
            return false;
        }
    } else if (tip.state.required_activation_height != 0 ||
               !tip.state.required_activation_block_hash.IsNull()) {
        return false;
    }
    if (!tip.state.ctip && tip.state.ctip_value != 0) return false;
    if (tip.state.ctip && tip.state.active_proposal_hash.IsNull()) return false;
    if (tip.state.ctip_value < 0 || !MoneyRange(tip.state.ctip_value)) return false;
    for (const auto& proposal : tip.state.pending_proposals) {
        if (proposal.first.IsNull() ||
            proposal.second.proposal_height > tip.height ||
            proposal.second.votes >
                tip.height - proposal.second.proposal_height) {
            return false;
        }
    }
    std::set<uint256> configured_m6ids;
    for (const auto& withdrawal : tip.state.pending_withdrawals) {
        if (withdrawal.proposal_height > tip.height ||
            withdrawal.votes >
                static_cast<uint64_t>(tip.height - withdrawal.proposal_height) + 2 ||
            !configured_m6ids.insert(withdrawal.m6id).second) {
            return false;
        }
    }
    if (tip.state.active_proposal_hash.IsNull() &&
        !tip.state.pending_withdrawals.empty()) {
        return false;
    }
    std::set<Sidechain::Bitcoin::COutPoint> ctips;
    if (tip.state.ctip) ctips.insert(*tip.state.ctip);
    for (const auto& [slot, slot_state] : tip.state.other_slots) {
        if (slot_state.active_proposal_hash.IsNull() && slot_state.ctip) return false;
        if (!slot_state.ctip && slot_state.ctip_value != 0) return false;
        if (slot_state.ctip_value < 0 || !MoneyRange(slot_state.ctip_value)) return false;
        if (slot_state.ctip && !ctips.insert(*slot_state.ctip).second) return false;
        for (const auto& proposal : slot_state.pending_proposals) {
            if (proposal.first.IsNull() ||
                proposal.second.proposal_height > tip.height ||
                proposal.second.votes >
                    tip.height - proposal.second.proposal_height) {
                return false;
            }
        }
        std::set<uint256> m6ids;
        for (const auto& withdrawal : slot_state.pending_withdrawals) {
            if (withdrawal.proposal_height > tip.height ||
                withdrawal.votes >
                    static_cast<uint64_t>(tip.height - withdrawal.proposal_height) + 2 ||
                !m6ids.insert(withdrawal.m6id).second) {
                return false;
            }
        }
        if (slot_state.active_proposal_hash.IsNull() &&
            !slot_state.pending_withdrawals.empty()) {
            return false;
        }
    }
    bool configured_slot_action_seen{false};
    for (const auto& [slot, action] : tip.state.previous_m4_actions) {
        if ((action.type != DrivechainM4ActionType::UPVOTE &&
             action.type != DrivechainM4ActionType::ALARM) ||
            (action.type == DrivechainM4ActionType::ALARM && !action.m6id.IsNull())) {
            return false;
        }
        const auto other_slot = tip.state.other_slots.find(slot);
        if (other_slot != tip.state.other_slots.end()) {
            if (other_slot->second.active_proposal_hash.IsNull()) return false;
        } else {
            // other_slots deliberately excludes the configured slot. At most
            // one action key may therefore be absent from that map, and only
            // while the top-level configured slot is active.
            if (configured_slot_action_seen ||
                tip.state.active_proposal_hash.IsNull()) {
                return false;
            }
            configured_slot_action_seen = true;
        }
    }
    return true;
}

bool IsSaneDeposit(const DrivechainMintableDeposit& deposit)
{
    return !deposit.outpoint.hash.IsNull() &&
           deposit.outpoint.n != Sidechain::Bitcoin::COutPoint::NULL_INDEX &&
           !deposit.block_hash.IsNull() &&
           deposit.value > 0 && MoneyRange(deposit.value) &&
           !deposit.address.empty() && deposit.address.size() <= 128;
}

bool IsSaneEdge(const uint256& parent_hash,
                const DrivechainReplayedBmmEdge& edge)
{
    return !parent_hash.IsNull() && !edge.successor_hash.IsNull() &&
           edge.parent_height != std::numeric_limits<uint32_t>::max() &&
           edge.successor_height == edge.parent_height + 1 &&
           (!edge.has_canonical_commitment ||
            !edge.committed_sidechain_hash.IsNull());
}

bool IsSaneSuccessfulWithdrawal(
    const DrivechainSuccessfulWithdrawal& withdrawal)
{
    return !withdrawal.block_hash.IsNull();
}

auto SuccessfulWithdrawalKey(const uint8_t sidechain_slot,
                             const uint256& m6id)
{
    return std::make_pair(
        DB_REPLAY_SUCCESSFUL_WITHDRAWAL,
        std::make_pair(sidechain_slot, m6id));
}

template <typename Key, typename Value>
DrivechainReplayStoreReadStatus ReadRecord(const CDBWrapper& db,
                                           const Key& key,
                                           Value& value,
                                           const char* description,
                                           std::string* error)
{
    if (!db.Exists(key)) return DrivechainReplayStoreReadStatus::NOT_FOUND;
    if (!db.Read(key, value)) {
        if (error) *error = strprintf("persistent parent replay %s record is malformed", description);
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
    return DrivechainReplayStoreReadStatus::FOUND;
}

} // namespace

DrivechainParentReplayStore::DrivechainParentReplayStore(
    fs::path path, const size_t cache_bytes, const bool wipe)
    : m_path(std::move(path)),
      m_cache_bytes(cache_bytes),
      m_db(std::make_unique<CDBWrapper>(DBParams{
          .path = m_path, .cache_bytes = m_cache_bytes, .memory_only = false,
          .wipe_data = wipe, .obfuscate = false}))
{
}

DrivechainParentReplayStore::~DrivechainParentReplayStore() = default;

DrivechainReplayStoreLoadStatus DrivechainParentReplayStore::Load(
    const uint256& identity,
    DrivechainParentReplayTip& tip,
    std::string* error) const
{
    if (error) error->clear();
    if (!m_db) {
        SetStoreError(error, "persistent parent replay database is not open");
        return DrivechainReplayStoreLoadStatus::CORRUPT;
    }
    try {
        DrivechainReplayStoreIdentity stored_identity;
        const auto identity_status = ReadRecord(
            *m_db, DB_REPLAY_IDENTITY, stored_identity, "identity", error);
        if (identity_status == DrivechainReplayStoreReadStatus::NOT_FOUND) {
            if (m_db->Exists(DB_REPLAY_TIP)) {
                SetStoreError(error, "persistent parent replay has a tip but no identity");
                return DrivechainReplayStoreLoadStatus::CORRUPT;
            }
            return DrivechainReplayStoreLoadStatus::EMPTY;
        }
        if (identity_status == DrivechainReplayStoreReadStatus::CORRUPT) {
            return DrivechainReplayStoreLoadStatus::CORRUPT;
        }
        if (stored_identity.schema_version != SCHEMA_VERSION ||
            stored_identity.identity != identity) {
            SetStoreError(error, "persistent parent replay schema or immutable network identity does not match");
            return DrivechainReplayStoreLoadStatus::IDENTITY_MISMATCH;
        }

        const auto tip_status = ReadRecord(
            *m_db, DB_REPLAY_TIP, tip, "tip", error);
        if (tip_status != DrivechainReplayStoreReadStatus::FOUND || !IsSaneTip(tip)) {
            if (tip_status != DrivechainReplayStoreReadStatus::CORRUPT) {
                SetStoreError(error, "persistent parent replay tip is missing or internally inconsistent");
            }
            return DrivechainReplayStoreLoadStatus::CORRUPT;
        }
        return DrivechainReplayStoreLoadStatus::LOADED;
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay load failed: %s", e.what()));
        return DrivechainReplayStoreLoadStatus::CORRUPT;
    }
}

bool DrivechainParentReplayStore::Reset(
    const uint256& identity,
    const DrivechainParentReplayTip& seed,
    std::string* error)
{
    // The replay store is a derived cache. Its authenticated seed is normally
    // parent genesis, but a pruned-light-client profile may instead seed the
    // exact immutable checkpoint whose complete replay state is committed by
    // the network identity. Validate the record itself here; the caller owns
    // authentication of the seed against that identity commitment.
    if (!IsSaneTip(seed)) {
        return SetStoreError(error, "refusing to seed persistent parent replay with an invalid tip");
    }

    // Release LevelDB's directory lock before opening the same derived index
    // with fWipe. No reader can race this operation: callers hold the replay
    // mutex and the published epoch is zero.
    m_db.reset();
    try {
        m_db = std::make_unique<CDBWrapper>(DBParams{
            .path = m_path, .cache_bytes = m_cache_bytes, .memory_only = false,
            .wipe_data = true, .obfuscate = false});
        CDBBatch batch(*m_db);
        batch.Write(DB_REPLAY_IDENTITY,
                    DrivechainReplayStoreIdentity{SCHEMA_VERSION, identity});
        batch.Write(DB_REPLAY_TIP, seed);
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            return SetStoreError(error, "failed to atomically seed persistent parent replay");
        }
    } catch (const std::exception& e) {
        return SetStoreError(error, strprintf(
                                        "failed to rebuild persistent parent replay database: %s",
                                        e.what()));
    }
    return true;
}

bool DrivechainParentReplayStore::Append(
    const DrivechainParentReplayTip& previous,
    const DrivechainParentReplayTip& next,
    const std::vector<DrivechainMintableDeposit>& deposits,
    const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
    const std::vector<DrivechainSuccessfulWithdrawal>& successful_withdrawals,
    const std::vector<DrivechainWithdrawalProposalIdentity>& withdrawal_proposals,
    std::string* error)
{
    if (!m_db) {
        return SetStoreError(error, "persistent parent replay database is not open");
    }
    try {
        if (!IsSaneTip(previous) || !IsSaneTip(next) ||
            previous.height == std::numeric_limits<uint32_t>::max() ||
            next.height != previous.height + 1) {
            return SetStoreError(error, "refusing a non-contiguous persistent parent replay append");
        }

        DrivechainParentReplayTip stored_tip;
        const auto tip_status = ReadRecord(
            *m_db, DB_REPLAY_TIP, stored_tip, "tip", error);
        if (tip_status != DrivechainReplayStoreReadStatus::FOUND ||
            stored_tip.height != previous.height || stored_tip.hash != previous.hash ||
            (HashWriter{} << stored_tip.state).GetHash() !=
                (HashWriter{} << previous.state).GetHash()) {
            return SetStoreError(error, "persistent parent replay tip changed before append");
        }

        std::set<Sidechain::Bitcoin::COutPoint> block_outpoints;
        for (const auto& deposit : deposits) {
            if (!IsSaneDeposit(deposit) || deposit.block_height != next.height ||
                deposit.block_hash != next.hash ||
                !block_outpoints.insert(deposit.outpoint).second ||
                m_db->Exists(std::make_pair(DB_REPLAY_DEPOSIT, deposit.outpoint))) {
                return SetStoreError(error, "persistent parent replay append contains a duplicate or malformed deposit");
            }
        }
        if (edge.has_value()) {
            if (!IsSaneEdge(edge->first, edge->second) ||
                edge->second.parent_height != previous.height ||
                edge->second.successor_height != next.height ||
                edge->second.successor_hash != next.hash ||
                edge->first != previous.hash ||
                m_db->Exists(std::make_pair(DB_REPLAY_BMM_EDGE, edge->first))) {
                return SetStoreError(error, "persistent parent replay append contains a duplicate or malformed BMM edge");
            }
        }
        std::set<std::pair<uint8_t, uint256>> block_withdrawals;
        for (const auto& withdrawal : successful_withdrawals) {
            const auto identity = std::make_pair(
                withdrawal.sidechain_slot, withdrawal.m6id);
            if (!IsSaneSuccessfulWithdrawal(withdrawal) ||
                withdrawal.block_height != next.height ||
                withdrawal.block_hash != next.hash ||
                !block_withdrawals.insert(identity).second ||
                m_db->Exists(SuccessfulWithdrawalKey(
                    withdrawal.sidechain_slot, withdrawal.m6id))) {
                return SetStoreError(
                    error,
                    "persistent parent replay append contains a duplicate or malformed successful withdrawal");
            }
        }
        std::set<std::pair<uint8_t, uint256>> block_proposals;
        for (const auto& proposal : withdrawal_proposals) {
            const auto identity = std::make_pair(
                proposal.sidechain_slot, proposal.m6id);
            if (!block_proposals.insert(identity).second) {
                return SetStoreError(
                    error,
                    "persistent parent replay append contains a duplicate M3 proposal identity");
            }
            if (m_db->Exists(SuccessfulWithdrawalKey(
                    proposal.sidechain_slot, proposal.m6id))) {
                return SetStoreError(
                    error,
                    "M3 re-proposes a withdrawal that already succeeded on the active parent chain");
            }
        }

        CDBBatch batch(*m_db);
        for (const auto& deposit : deposits) {
            batch.Write(std::make_pair(DB_REPLAY_DEPOSIT, deposit.outpoint), deposit);
        }
        if (edge.has_value()) {
            batch.Write(std::make_pair(DB_REPLAY_BMM_EDGE, edge->first), edge->second);
        }
        for (const auto& withdrawal : successful_withdrawals) {
            batch.Write(
                SuccessfulWithdrawalKey(
                    withdrawal.sidechain_slot, withdrawal.m6id),
                withdrawal);
        }
        batch.Write(DB_REPLAY_TIP, next);
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            return SetStoreError(error, "failed to atomically append persistent parent replay block");
        }
        return true;
    } catch (const std::exception& e) {
        return SetStoreError(error, strprintf(
                                        "persistent parent replay append failed: %s", e.what()));
    }
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadDeposit(
    const Sidechain::Bitcoin::COutPoint& outpoint,
    DrivechainMintableDeposit& deposit,
    std::string* error) const
{
    if (!m_db) {
        SetStoreError(error, "persistent parent replay database is not open");
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
    try {
        const auto status = ReadRecord(
            *m_db, std::make_pair(DB_REPLAY_DEPOSIT, outpoint),
            deposit, "deposit", error);
        if (status == DrivechainReplayStoreReadStatus::FOUND &&
            (!IsSaneDeposit(deposit) || deposit.outpoint != outpoint)) {
            SetStoreError(error, "persistent parent replay deposit record is internally inconsistent");
            return DrivechainReplayStoreReadStatus::CORRUPT;
        }
        return status;
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay deposit read failed: %s", e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}

DrivechainReplayStoreReadStatus DrivechainParentReplayStore::ReadBmmEdge(
    const uint256& parent_hash,
    DrivechainReplayedBmmEdge& edge,
    std::string* error) const
{
    if (!m_db) {
        SetStoreError(error, "persistent parent replay database is not open");
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
    try {
        const auto status = ReadRecord(
            *m_db, std::make_pair(DB_REPLAY_BMM_EDGE, parent_hash),
            edge, "BMM edge", error);
        if (status == DrivechainReplayStoreReadStatus::FOUND &&
            !IsSaneEdge(parent_hash, edge)) {
            SetStoreError(error, "persistent parent replay BMM edge is internally inconsistent");
            return DrivechainReplayStoreReadStatus::CORRUPT;
        }
        return status;
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay BMM-edge read failed: %s", e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}

DrivechainReplayStoreReadStatus
DrivechainParentReplayStore::ReadSuccessfulWithdrawal(
    const uint8_t sidechain_slot,
    const uint256& m6id,
    DrivechainSuccessfulWithdrawal& withdrawal,
    std::string* error) const
{
    if (!m_db) {
        SetStoreError(error, "persistent parent replay database is not open");
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
    try {
        const auto status = ReadRecord(
            *m_db, SuccessfulWithdrawalKey(sidechain_slot, m6id),
            withdrawal, "successful withdrawal", error);
        if (status == DrivechainReplayStoreReadStatus::FOUND &&
            (!IsSaneSuccessfulWithdrawal(withdrawal) ||
             withdrawal.sidechain_slot != sidechain_slot ||
             withdrawal.m6id != m6id)) {
            SetStoreError(
                error,
                "persistent parent replay successful-withdrawal record is internally inconsistent");
            return DrivechainReplayStoreReadStatus::CORRUPT;
        }
        return status;
    } catch (const std::exception& e) {
        SetStoreError(error, strprintf(
                                 "persistent parent replay successful-withdrawal read failed: %s",
                                 e.what()));
        return DrivechainReplayStoreReadStatus::CORRUPT;
    }
}
