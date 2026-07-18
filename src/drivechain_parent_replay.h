// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_PARENT_REPLAY_H
#define BITCOIN_DRIVECHAIN_PARENT_REPLAY_H

#include <fs.h>
#include <mainchainrpc.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class CDBWrapper;

/** Persistent tip of the authenticated parent replay. */
struct DrivechainParentReplayTip {
    uint32_t height{0};
    uint256 hash;
    DrivechainParentReplayState state;

    SERIALIZE_METHODS(DrivechainParentReplayTip, obj)
    {
        READWRITE(obj.height, obj.hash, obj.state);
    }
};

enum class DrivechainReplayStoreLoadStatus {
    EMPTY,
    LOADED,
    CORRUPT,
    IDENTITY_MISMATCH,
};

enum class DrivechainReplayStoreReadStatus {
    FOUND,
    NOT_FOUND,
    CORRUPT,
};

/**
 * Bounded-memory LevelDB index derived exclusively from authenticated parent
 * blocks. It is a cache, never a consensus trust root: identity mismatch,
 * malformed records, and active-parent reorgs require a full derived rebuild.
 */
class DrivechainParentReplayStore final
{
public:
    static constexpr uint32_t SCHEMA_VERSION{1};

    DrivechainParentReplayStore(fs::path path, size_t cache_bytes, bool wipe);
    ~DrivechainParentReplayStore();

    DrivechainParentReplayStore(const DrivechainParentReplayStore&) = delete;
    DrivechainParentReplayStore& operator=(const DrivechainParentReplayStore&) = delete;

    DrivechainReplayStoreLoadStatus Load(const uint256& identity,
                                         DrivechainParentReplayTip& tip,
                                         std::string* error) const;

    /** Atomically wipe and seed the store with authenticated parent genesis. */
    bool Reset(const uint256& identity,
               const DrivechainParentReplayTip& genesis,
               std::string* error);

    /** Atomically and synchronously append one authenticated active block. */
    bool Append(const DrivechainParentReplayTip& previous,
                const DrivechainParentReplayTip& next,
                const std::vector<DrivechainMintableDeposit>& deposits,
                const std::optional<std::pair<uint256, DrivechainReplayedBmmEdge>>& edge,
                std::string* error);

    DrivechainReplayStoreReadStatus ReadDeposit(
        const Sidechain::Bitcoin::COutPoint& outpoint,
        DrivechainMintableDeposit& deposit,
        std::string* error) const;

    DrivechainReplayStoreReadStatus ReadBmmEdge(
        const uint256& parent_hash,
        DrivechainReplayedBmmEdge& edge,
        std::string* error) const;

private:
    fs::path m_path;
    size_t m_cache_bytes;
    std::unique_ptr<CDBWrapper> m_db;
};

#endif // BITCOIN_DRIVECHAIN_PARENT_REPLAY_H
