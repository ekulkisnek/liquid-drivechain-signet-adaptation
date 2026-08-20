// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef BITCOIN_ECX_EXCHANGE_STATE_H
#define BITCOIN_ECX_EXCHANGE_STATE_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <array>
#include <limits>
#include <optional>
#include <string>

class CBlockIndex;
class CCoinsViewCache;

namespace ecx {

static constexpr uint8_t EXCHANGE_STATE_INTERFACE_VERSION{1};
static constexpr uint16_t EXCHANGE_SCRIPT_CACHE_REVISION{3};

struct ExchangeConsensus
{
    int activation_height{std::numeric_limits<int>::max()};
    COutPoint genesis_state_outpoint;
    uint256 genesis_state_root;
    std::array<unsigned char, 32> chain_id{};
    std::array<unsigned char, 32> forced_action_domain{};
    std::array<unsigned char, 32> deposit_inbox_domain{};
    CScript collateral_vault_script;
    uint256 collateral_vault_script_hash;
};

struct InboxTracker
{
    uint256 root;
    uint64_t count{0};

    SERIALIZE_METHODS(InboxTracker, obj)
    {
        READWRITE(obj.root, obj.count);
    }
};

struct ExchangeStateTracker
{
    COutPoint outpoint;
    uint256 root;

    SERIALIZE_METHODS(ExchangeStateTracker, obj)
    {
        READWRITE(obj.outpoint, obj.root);
    }
};

/** Active, chainstate-backed source heads used by node RPC and matchers. */
struct ExchangeConsensusSnapshot
{
    uint256 exchange_state_root;
    uint256 forced_inbox_root;
    uint64_t forced_entry_count{0};
    uint256 deposit_inbox_root;
    uint64_t deposit_entry_count{0};
};

/** Reserved chainstate key used only for the persisted ECX tracker. */
bool IsExchangeStateInternalOutpoint(const COutPoint& outpoint);

/** Frozen genesis commitments shared verbatim with protocol-core. */
uint256 ComputeForcedInboxGenesis(const ExchangeConsensus& consensus);
uint256 ComputeDepositInboxGenesis(const ExchangeConsensus& consensus);

/**
 * Safe-disabled LayerTwoLabs parameters. Production activation requires
 * replacing all three values with a reviewed height, pre-existing singleton
 * outpoint and its nonzero ComputeStateUtxoRoot result.
 */
const ExchangeConsensus& LayerTwoLabsExchangeConsensus();

/** BIP340-style tagged SHA256 over outpoint || SHA256(CTxOut bytes). */
uint256 ComputeStateUtxoRoot(
    const uint256& child_genesis,
    const COutPoint& outpoint,
    const CTxOut& output);

/** Exact contextual header-bit rule; the extension is forbidden before H. */
bool CheckExchangeStateHeader(
    const CBlockHeader& block,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Fill the candidate header from the UTXO view and selected transactions. */
bool PrepareExchangeStateHeader(
    CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus(),
    std::optional<uint64_t> authenticated_parent_height = std::nullopt);

/** Validate, then persist the deterministically derived tracker. */
bool ConnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus(),
    std::optional<uint64_t> authenticated_parent_height = std::nullopt,
    bool allow_incomplete_candidate = false);

/** Restore the tracker after the normal transaction undo has run. */
bool DisconnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus(),
    std::optional<uint64_t> authenticated_parent_height = std::nullopt);

/**
 * Consensus source for prior_active_exchange_state_root_required. The caller
 * passes only the active tip (mempool) or pindex->pprev (candidate/connect/
 * reindex), which creates the intentional one-block lag.
 */
bool GetPriorActiveExchangeStateRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error);

bool GetPriorActiveForcedInboxRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error);

bool GetPriorActiveDepositInboxRoot(
    const CBlockIndex* previous,
    uint256& root,
    std::string& error);

/** Read all persisted heads atomically and require exact agreement with tip. */
bool GetExchangeConsensusSnapshot(
    const CCoinsViewCache& view,
    const CBlockIndex* tip,
    ExchangeConsensusSnapshot& snapshot,
    std::string& error);

} // namespace ecx

#endif // BITCOIN_ECX_EXCHANGE_STATE_H
