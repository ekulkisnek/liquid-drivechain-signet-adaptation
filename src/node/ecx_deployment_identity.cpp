// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include <node/ecx_deployment_identity.h>

#include <chain.h>
#include <chainparams.h>
#include <drivechain_bmm.h>
#include <ecx_exchange_state.h>
#include <hash.h>
#include <logging.h>
#include <tinyformat.h>
#include <txdb.h>
#include <util/readwritefile.h>
#include <util/system.h>
#include <validation.h>

#include <cstdio>
#include <limits>
#include <string>
#include <vector>

namespace node {
namespace {

constexpr const char* ECX_DEPLOYMENT_IDENTITY_FILENAME{
    "ecx_consensus.dat"};
constexpr size_t MAX_ECX_DEPLOYMENT_IDENTITY_BYTES{1024};

struct ExpectedIdentity
{
    fs::path path;
    std::string record;
    uint256 fingerprint;
    bool consensus_enabled{false};
    bool runtime_configured{false};
    int first_activation_height{std::numeric_limits<int>::max()};
};

bool BuildExpectedIdentity(ExpectedIdentity& identity, std::string& error)
{
    identity = {};
    if (!ecx::GetRuntimeConsensusFingerprint(
            identity.fingerprint,
            identity.runtime_configured,
            identity.first_activation_height,
            error)) {
        return false;
    }
    identity.consensus_enabled = Params().GetConsensus().elements_mode;
    identity.path = gArgs.GetDataDirNet() / ECX_DEPLOYMENT_IDENTITY_FILENAME;
    const std::string prefix{strprintf(
        "ecx-consensus-datadir-v3\nnetwork=%s\ngenesis=%s\nfingerprint=%s\n",
        Params().NetworkIDString(),
        Params().GetConsensus().hashGenesisBlock.GetHex(),
        identity.fingerprint.GetHex())};
    const std::vector<unsigned char> bytes(prefix.begin(), prefix.end());
    identity.record = prefix + strprintf("checksum=%s\n", Hash(bytes).GetHex());
    return true;
}

bool HasMaterialChainData()
{
    const fs::path datadir{gArgs.GetDataDirNet()};
    const auto has_any_entry = [](const fs::path& directory) {
        if (!fs::exists(directory) || !fs::is_directory(directory)) return false;
        return fs::directory_iterator(directory) != fs::directory_iterator();
    };
    const auto has_blocks = [](const fs::path& blocks) {
        if (fs::exists(blocks)) {
            for (const auto& entry : fs::directory_iterator(blocks)) {
                if (!fs::is_regular_file(entry.path())) continue;
                const std::string name{fs::PathToString(entry.path().filename())};
                if ((name.rfind("blk", 0) == 0 || name.rfind("rev", 0) == 0) &&
                    entry.path().extension() == ".dat") {
                    return true;
                }
            }
        }
        return false;
    };
    // CBlockTreeDB remains under the network datadir, while -blocksdir moves
    // flat block/undo files. Check both locations so neither can be silently
    // treated as a fresh deployment. A damaged/interrupted LevelDB missing
    // CURRENT is still material: any entry in its index directory preserves
    // evidence that must not be rebound or wiped under new consensus rules.
    if (has_any_entry(datadir / "blocks" / "index") ||
        has_any_entry(gArgs.GetBlocksDirPath() / "index") ||
        has_blocks(datadir / "blocks") ||
        has_blocks(gArgs.GetBlocksDirPath())) return true;
    if (!fs::exists(datadir)) return false;
    for (const auto& entry : fs::directory_iterator(datadir)) {
        if (!fs::is_directory(entry.path())) continue;
        const std::string name{fs::PathToString(entry.path().filename())};
        if (name.rfind("chainstate", 0) == 0 && has_any_entry(entry.path())) {
            return true;
        }
    }
    return false;
}

bool WriteIdentityAtomically(
    const ExpectedIdentity& identity,
    std::string& error)
{
    fs::path temporary{identity.path};
    temporary += ".new";
    fs::remove(temporary);
    FILE* file{fsbridge::fopen(temporary, "wb")};
    if (!file) {
        error = strprintf(
            "cannot create temporary ECX consensus identity %s",
            fs::PathToString(temporary));
        return false;
    }
    const bool wrote{
        std::fwrite(
            identity.record.data(),
            1,
            identity.record.size(),
            file) == identity.record.size()};
    if (!wrote || !FileCommit(file)) {
        std::fclose(file);
        fs::remove(temporary);
        error = "cannot durably write the ECX consensus identity";
        return false;
    }
    if (std::fclose(file) != 0) {
        fs::remove(temporary);
        error = "cannot close the ECX consensus identity";
        return false;
    }
    if (!RenameOver(temporary, identity.path)) {
        fs::remove(temporary);
        error = "cannot atomically install the ECX consensus identity";
        return false;
    }
    DirectoryCommit(identity.path.parent_path());
    LogPrintf(
        "Bound runtime ECX consensus configuration %s at %s\n",
        identity.fingerprint.GetHex(),
        fs::PathToString(identity.path));
    return true;
}

bool CheckPersistedHistory(
    ChainstateManager& chainman,
    const uint256& hash,
    const int first_activation_height,
    const std::string& label,
    std::string& error)
{
    if (hash.IsNull()) return true;
    const CBlockIndex* index{chainman.m_blockman.LookupBlockIndex(hash)};
    if (!index) {
        error = strprintf(
            "cannot first-bind ECX consensus: %s block %s is absent from the block index",
            label,
            hash.GetHex());
        return false;
    }
    constexpr uint32_t ecx_bmm_mask{
        CBlockHeader::BMM_PROOF_HF_MASK |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK};
    for (const CBlockIndex* cursor = index; cursor; cursor = cursor->pprev) {
        if ((static_cast<uint32_t>(cursor->nVersion) & ecx_bmm_mask) != 0 ||
            cursor->GetBlockHash() ==
                drivechain::LayerTwoLabsPublicSidechainBlock2()) {
            error = strprintf(
                "cannot first-bind ECX consensus: %s ancestry already contains "
                "an ECX/BMM header at height %d; recover the original frozen configuration",
                label,
                cursor->nHeight);
            return false;
        }
    }
    if (index->nHeight >= first_activation_height) {
        error = strprintf(
            "cannot first-bind ECX consensus at activation height %d: %s is already at height %d; "
            "restart under the original configuration, roll every chainstate back below activation, then retry",
            first_activation_height,
            label,
            index->nHeight);
        return false;
    }
    return true;
}

bool CheckLegacyHeaderTreeSafeToBind(
    ChainstateManager& chainman,
    const int first_activation_height,
    std::string& error)
{
    constexpr uint32_t ecx_bmm_mask{
        CBlockHeader::BMM_PROOF_HF_MASK |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK};
    for (const auto& entry : chainman.BlockIndex()) {
        const CBlockIndex* index{entry.second};
        if (!index) continue;
        if ((static_cast<uint32_t>(index->nVersion) & ecx_bmm_mask) != 0 ||
            index->GetBlockHash() == drivechain::LayerTwoLabsPublicSidechainBlock2()) {
            error = strprintf(
                "cannot first-bind ECX consensus: block-index branch already contains "
                "an ECX/BMM header %s at height %d; recover the original frozen configuration",
                index->GetBlockHash().GetHex(),
                index->nHeight);
            return false;
        }
        if (index->nHeight >= first_activation_height) {
            error = strprintf(
                "cannot first-bind ECX consensus at activation height %d: block-index "
                "branch already reaches header %s at height %d; recover the original "
                "configuration and roll every branch below activation",
                first_activation_height,
                index->GetBlockHash().GetHex(),
                index->nHeight);
            return false;
        }
    }
    return true;
}

bool AuditPersistedConsensusHeaders(
    ChainstateManager& chainman,
    std::string& error)
{
    size_t audited{0};
    for (const auto& entry : chainman.BlockIndex()) {
        const CBlockIndex* index{entry.second};
        if (!index || !index->pprev) continue;

        std::string header_error;
        if (!drivechain::CheckBmmIndexHeader(*index, header_error)) {
            error = strprintf(
                "persisted block-index header %s at height %d violates BMM rules: %s; "
                "restart with -reindex to rebuild the header index under the current rules",
                index->GetBlockHash().GetHex(),
                index->nHeight,
                header_error);
            return false;
        }
        if (!ecx::CheckExchangeStateIndexHeader(
                *index,
                header_error,
                ecx::LayerTwoLabsExchangeConsensus())) {
            error = strprintf(
                "persisted block-index header %s at height %d violates ECX rules: %s; "
                "restart with -reindex to rebuild the header index under the current rules",
                index->GetBlockHash().GetHex(),
                index->nHeight,
                header_error);
            return false;
        }
        ++audited;
    }
    LogPrintf(
        "Audited %u persisted ECX/BMM block-index headers\n",
        static_cast<unsigned int>(audited));
    return true;
}

} // namespace

bool CheckEcxDeploymentIdentity(std::string& error)
{
    error.clear();
    try {
        ExpectedIdentity identity;
        if (!BuildExpectedIdentity(identity, error)) return false;
        if (!identity.consensus_enabled) return true;
        if (!fs::exists(identity.path)) {
            const bool has_material_chain_data{HasMaterialChainData()};
            if (!has_material_chain_data) {
                // Bind a genuinely fresh data directory before opening the
                // block and chainstate databases.  Besides reducing the
                // crash window, this distinguishes a fresh -reindex startup
                // from a legacy database whose reset could erase the history
                // needed to validate its first binding.
                return WriteIdentityAtomically(identity, error);
            }
            if (gArgs.GetBoolArg("-reindex", false) ||
                gArgs.GetBoolArg("-reindex-chainstate", false)) {
                error =
                    "cannot first-bind an ECX consensus identity while reindexing existing data; "
                    "start once without reindex so the existing chainstate/history can be checked";
                return false;
            }
            return true;
        }
        const auto [read_ok, persisted]{ReadBinaryFile(
            identity.path, MAX_ECX_DEPLOYMENT_IDENTITY_BYTES)};
        if (!read_ok) {
            error = strprintf(
                "cannot read ECX consensus identity %s",
                fs::PathToString(identity.path));
            return false;
        }
        if (persisted != identity.record) {
            error = strprintf(
                "ECX consensus configuration does not match this data directory "
                "(expected fingerprint %s); use the original frozen parameters",
                identity.fingerprint.GetHex());
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool CheckEcxDeploymentResetAllowed(
    const bool reset_requested,
    const bool databases_in_memory,
    std::string& error)
{
    error.clear();
    if (!reset_requested || databases_in_memory) return true;
    try {
        ExpectedIdentity identity;
        if (!BuildExpectedIdentity(identity, error)) return false;
        if (!identity.consensus_enabled) return true;
        if (fs::exists(identity.path)) return CheckEcxDeploymentIdentity(error);
        if (!HasMaterialChainData()) return true;
        error =
            "cannot reset or reindex existing chain data before ECX consensus identity first-binding; "
            "start once without reindex so the existing chainstate/history can be checked";
        return false;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool BindEcxDeploymentIdentityIfNeeded(
    ChainstateManager& chainman,
    const bool databases_in_memory,
    std::string& error)
{
    error.clear();
    try {
        ExpectedIdentity identity;
        if (!BuildExpectedIdentity(identity, error)) return false;
        if (!identity.consensus_enabled) return true;
        if (databases_in_memory) return true;
        if (fs::exists(identity.path)) {
            if (!CheckEcxDeploymentIdentity(error)) return false;
            return AuditPersistedConsensusHeaders(chainman, error);
        }
        if (fReindex && HasMaterialChainData()) {
            error =
                "cannot first-bind an ECX consensus identity while a block-index reindex is in progress; "
                "restore the pre-reindex database and start once without reindex";
            return false;
        }

        // A missing identity means this tree may have been indexed by a binary
        // with different contextual rules. Refuse to bind if any side branch,
        // not merely a coins-view ancestry, has crossed an activation boundary
        // or already uses one of the ECX/BMM header namespaces.
        if (!CheckLegacyHeaderTreeSafeToBind(
                chainman,
                identity.first_activation_height,
                error)) {
            return false;
        }

        for (CChainState* chainstate : chainman.GetAll()) {
            const CCoinsViewDB& coins{chainstate->CoinsDB()};
            if (ecx::HasPersistedExchangeConsensusState(coins) ||
                drivechain::HasPersistedBmmConsensusState(coins)) {
                error =
                    "cannot first-bind ECX consensus: chainstate already contains "
                    "ECX/BMM tracker state; recover the original frozen configuration";
                return false;
            }
            if (!CheckPersistedHistory(
                    chainman,
                    coins.GetBestBlock(),
                    identity.first_activation_height,
                    "coins best block",
                    error)) {
                return false;
            }
            const std::vector<uint256> heads{coins.GetHeadBlocks()};
            for (size_t index = 0; index < heads.size(); ++index) {
                if (!CheckPersistedHistory(
                        chainman,
                        heads[index],
                        identity.first_activation_height,
                        strprintf(
                            "coins crash-recovery head %u",
                            static_cast<unsigned int>(index)),
                        error)) {
                    return false;
                }
            }
        }
        if (!AuditPersistedConsensusHeaders(chainman, error)) return false;
        return WriteIdentityAtomically(identity, error);
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

} // namespace node
