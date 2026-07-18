// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAINCHAINRPC_H
#define BITCOIN_MAINCHAINRPC_H

#include <rpc/client.h>
#include <rpc/protocol.h>
#include <primitives/transaction.h>
#include <primitives/bitcoin/block.h>
#include <uint256.h>

#include <consensus/amount.h>
#include <serialize.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <stdexcept>
#include <vector>

#include <univalue.h>

class CBlock;
struct DrivechainAnchor;

/** True only when slot is the BIP300/301 slot configured for this network. */
bool IsDrivechainSidechainSlot(int slot);

struct DrivechainParentBlockContext {
    uint256 parent_hash;
    uint256 parent_chainwork;
    uint32_t parent_height{0};
    uint64_t parent_median_time_past{0};
};

struct DrivechainBmmBlockContext : public DrivechainParentBlockContext {
    uint256 bmm_block_hash;
    uint256 bmm_chainwork;
    uint32_t bmm_height{0};
};

enum class DrivechainAnchorStatus {
    ACTIVE,
    ORPHANED,
    UNAVAILABLE,
};

/**
 * Result of authenticating a sidechain block's BIP301 commitment.
 *
 * INVALID is reserved for immutable malformed child-block bytes.
 * PARENT_REJECTED means the authenticated current P -> Q edge does not commit
 * to the child; it is retryable because Q can be replaced by a parent reorg.
 */
enum class DrivechainBmmStatus {
    VALID,
    INVALID,
    PARENT_REJECTED,
    UNAVAILABLE,
};

/**
 * Result of validating a native BIP300 deposit against the parent chain.
 *
 * INVALID is reserved for a deterministic mismatch between the sidechain
 * claim and an already authenticated, sufficiently buried active parent
 * block.  Every failure to obtain or authenticate that parent-chain view is
 * UNAVAILABLE so a transient RPC failure or reorg cannot permanently poison
 * the sidechain block carrying the claim.
 */
enum class DrivechainDepositStatus {
    VALID,
    INVALID,
    UNAVAILABLE,
};

/** Pure, deterministic state used to replay the configured parent slot. */
struct DrivechainPendingProposal {
    uint32_t proposal_height{0};
    uint32_t votes{0};

    SERIALIZE_METHODS(DrivechainPendingProposal, obj)
    {
        READWRITE(obj.proposal_height, obj.votes);
    }
};

struct DrivechainParentReplayState {
    uint256 active_proposal_hash;
    bool required_proposal_activated{false};
    uint32_t required_activation_height{0};
    uint256 required_activation_block_hash;
    std::map<uint256, DrivechainPendingProposal> pending_proposals;
    std::optional<Sidechain::Bitcoin::COutPoint> ctip;
    CAmount ctip_value{0};

    SERIALIZE_METHODS(DrivechainParentReplayState, obj)
    {
        READWRITE(obj.active_proposal_hash,
                  obj.required_proposal_activated,
                  obj.required_activation_height,
                  obj.required_activation_block_hash,
                  obj.pending_proposals);
        bool has_ctip = obj.ctip.has_value();
        READWRITE(has_ctip);
        SER_READ(obj, {
            if (has_ctip) {
                obj.ctip.emplace();
            } else {
                obj.ctip.reset();
            }
        });
        if (has_ctip) READWRITE(obj.ctip.value());
        READWRITE(obj.ctip_value);
    }
};

struct DrivechainMintableDeposit {
    Sidechain::Bitcoin::COutPoint outpoint;
    uint256 block_hash;
    uint32_t block_height{0};
    CAmount value{0};
    std::vector<unsigned char> address;

    SERIALIZE_METHODS(DrivechainMintableDeposit, obj)
    {
        READWRITE(obj.outpoint,
                  obj.block_hash,
                  obj.block_height,
                  obj.value,
                  obj.address);
    }
};

/** One authenticated active-parent P -> Q edge derived during replay. */
struct DrivechainReplayedBmmEdge {
    uint256 successor_hash;
    uint32_t parent_height{0};
    uint32_t successor_height{0};
    bool has_canonical_commitment{false};
    uint256 committed_sidechain_hash;

    SERIALIZE_METHODS(DrivechainReplayedBmmEdge, obj)
    {
        READWRITE(obj.successor_hash,
                  obj.parent_height,
                  obj.successor_height,
                  obj.has_canonical_commitment,
                  obj.committed_sidechain_hash);
    }
};

static const bool DEFAULT_NAMED=false;
static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/**
 * Bound synchronous parent-chain work performed while a caller holds sidechain
 * consensus locks. Nested scopes on the same thread share one deadline and one
 * uncached-replay allowance rather than resetting the budget.
 */
class DrivechainParentValidationBudget
{
public:
    explicit DrivechainParentValidationBudget(bool enable);
    ~DrivechainParentValidationBudget();

    DrivechainParentValidationBudget(const DrivechainParentValidationBudget&) = delete;
    DrivechainParentValidationBudget& operator=(const DrivechainParentValidationBudget&) = delete;

private:
    bool m_enabled{false};
};

/**
 * Mark an untrusted P2P block-admission scope. Cache misses in this scope may
 * consult only the background-authenticated replay M7 index; local mining,
 * reindex, and ConnectTip may perform live parent discovery.
 */
class DrivechainUntrustedParentAdmission
{
public:
    explicit DrivechainUntrustedParentAdmission(bool enable);
    ~DrivechainUntrustedParentAdmission();

    DrivechainUntrustedParentAdmission(const DrivechainUntrustedParentAdmission&) = delete;
    DrivechainUntrustedParentAdmission& operator=(const DrivechainUntrustedParentAdmission&) = delete;

private:
    bool m_enabled{false};
};

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params);

/**
 * Replay and authenticate the configured parent chain through its current tip.
 * This performs RPC and potentially substantial replay work and therefore must
 * be called only outside cs_main/mempool locks.
 */
bool WarmDrivechainParentState(std::string* error = nullptr);

/**
 * Return the current authenticated parent replay generation without RPC.
 * Zero means no replay identity is currently initialized. The value changes
 * whenever a parent reorganization forces a genesis replay rebuild.
 */
uint64_t GetDrivechainParentReplayEpoch();

/** Pure snapshot-ordering rule used by cold and cached BMM validation. */
bool ShouldReplaceDrivechainReplaySnapshot(bool current_authenticated,
                                           uint32_t current_height,
                                           bool current_explicit_target,
                                           bool next_explicit_target,
                                           uint32_t next_height);

// Verify if the block with given hash has at least the specified minimum number
// of confirmations.
// For validating merkle blocks, you can provide the nbTxs parameter to verify if
// it equals the number of transactions in the block.
bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs);

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error = nullptr);
/** Build the one canonical, domain-separated child coinbase P commitment. */
CScript CreateDrivechainParentCommitmentScript(const uint256& parent_hash);
bool IsDrivechainBmmCommitmentMined(const CBlock& block, int sidechain_slot, std::string* error = nullptr);
bool IsDrivechainBmmCommitmentMined(const uint256& sidechain_block_hash, const uint256& parent_hash, int sidechain_slot, std::string* error = nullptr);

/** Strictly parse the authenticated parent's getblockheader result. */
bool ParseDrivechainParentHeader(const UniValue& header,
                                 const uint256& expected_hash,
                                 uint64_t& median_time_past,
                                 std::string* error = nullptr);

/**
 * Authenticate the parent committed by a candidate block without requiring an
 * M7 successor that cannot exist until the candidate hash is known.
 */
bool GetDrivechainParentBlockContext(const CBlock& block,
                                     int sidechain_slot,
                                     DrivechainParentBlockContext& context,
                                     std::string* error = nullptr);

/** Compatibility overload while validation migrates to the parent-only type. */
bool GetDrivechainParentBlockContext(const CBlock& block,
                                     int sidechain_slot,
                                     DrivechainBmmBlockContext& context,
                                     std::string* error = nullptr);

/** Validate BMM and return block context tied to the committed parent hash. */
bool GetDrivechainBmmBlockContext(const CBlock& block,
                                  int sidechain_slot,
                                  DrivechainBmmBlockContext& context,
                                  std::string* error = nullptr);

/**
 * Status-preserving BMM validation for consensus callers.  Only INVALID may
 * be recorded as permanent block invalidity; PARENT_REJECTED and UNAVAILABLE
 * must remain reconsiderable.  Context is populated for VALID and
 * PARENT_REJECTED, identifying the exact authenticated P -> Q edge observed.
 */
DrivechainBmmStatus GetDrivechainBmmBlockStatus(const CBlock& block,
                                                int sidechain_slot,
                                                DrivechainBmmBlockContext& context,
                                                std::string* error = nullptr);

/**
 * Reconcile a persisted P -> Q anchor with the parent node's active chain.
 * Only a canonical active-height hash mismatch is ORPHANED.  RPC, transport,
 * decoding, or authentication failures are UNAVAILABLE and must never cause a
 * rollback.
 */
DrivechainAnchorStatus IsDrivechainAnchorActive(const DrivechainAnchor& anchor,
                                                int sidechain_slot,
                                                std::string* error = nullptr);

/** Validate exactly one canonical BIP301 M7 in a raw successor block. */
bool MatchDrivechainBmmCommitmentInBlock(const Sidechain::Bitcoin::CBlock& block,
                                         int sidechain_slot,
                                         const uint256& sidechain_block_hash,
                                         uint32_t* output_index = nullptr,
                                         std::string* error = nullptr);

/** Parse exactly one canonical M7 for a slot without a candidate-dependent comparison. */
bool ExtractCanonicalDrivechainBmmCommitmentInBlock(
    const Sidechain::Bitcoin::CBlock& block,
    int sidechain_slot,
    uint256& committed_sidechain_hash,
    uint32_t* output_index = nullptr,
    std::string* error = nullptr);

/** Independently validate one exact BIP300 M5 transaction in a raw Bitcoin block. */
bool MatchDrivechainDepositInBlock(
    const Sidechain::Bitcoin::CBlock& block,
    int sidechain_slot,
    const COutPoint& outpoint,
    CAmount value,
    const std::vector<unsigned char>& address,
    const std::map<Sidechain::Bitcoin::COutPoint, Sidechain::Bitcoin::CTxOut>& previous_outputs,
    std::string* error = nullptr);

/**
 * Apply one already-authenticated active parent block to slot proposal/CTIP
 * state.  This function is pure so the exact replay rules can be unit tested.
 */
bool ApplyDrivechainParentBlockState(
    const Sidechain::Bitcoin::CBlock& block,
    uint32_t height,
    int sidechain_slot,
    const uint256& required_active_proposal,
    uint16_t unused_slot_proposal_max_age,
    uint16_t unused_slot_activation_threshold,
    uint16_t used_slot_proposal_max_age,
    uint16_t used_slot_activation_threshold,
    DrivechainParentReplayState& state,
    std::vector<DrivechainMintableDeposit>* deposits = nullptr,
    std::string* error = nullptr);

/**
 * Authenticate the containing parent block and require one exact BIP300 M5
 * deposit.  Callers in consensus validation must preserve UNAVAILABLE as a
 * retryable validation stall rather than converting it to block invalidity.
 */
DrivechainDepositStatus GetConfirmedDrivechainDepositStatus(
    const uint256& mainchain_block_hash,
    int sidechain_slot,
    const COutPoint& outpoint,
    CAmount value,
    const std::vector<unsigned char>& address,
    std::string* error = nullptr);

/** Compatibility wrapper for non-consensus callers. */
bool IsConfirmedDrivechainDeposit(const uint256& mainchain_block_hash,
                                  int sidechain_slot,
                                  const COutPoint& outpoint,
                                  CAmount value,
                                  const std::vector<unsigned char>& address,
                                  std::string* error = nullptr);

#endif // BITCOIN_MAINCHAINRPC_H
