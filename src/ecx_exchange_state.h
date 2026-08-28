// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef BITCOIN_ECX_EXCHANGE_STATE_H
#define BITCOIN_ECX_EXCHANGE_STATE_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <ecx_bond_v2.h>
#include <uint256.h>

#include <cstdint>
#include <array>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#if defined(ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE) && \
    defined(ECX_SIMPLICITY_CATALOGUE_FROZEN)
#error "private E2E and frozen production Simplicity catalogues are mutually exclusive"
#endif
#if defined(ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN) && \
    !defined(ECX_SIMPLICITY_CATALOGUE_FROZEN)
#error "frozen ECX production profile requires the frozen Simplicity catalogue"
#endif

/* Source-frozen mirror of proof-core's twelve-child recovery theorem. Every
 * recursive child has an enforced reachable encoding ceiling below 16 MiB and
 * the outer recovery record contains only the exact custody descriptors. The
 * deliberately false legacy *monolithic* witness flag is not a release gate:
 * all simultaneous proof classes cannot and need not occupy one ciphertext. */
#define ECX_BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN 1
#if !ECX_BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN
#error "ECX bond V2 requires the proven partitioned incremental recovery bound"
#endif

class CBlockIndex;
class CCoinsView;
class CCoinsViewCache;

namespace ecx {

#ifdef ECX_ENABLE_SP1_GROTH16_VERIFIER
extern "C" bool ecx_witness_availability_verify_custody_receipts_v1(
    const unsigned char* bundle,
    size_t bundle_len,
    const unsigned char* registry,
    size_t registry_len,
    const unsigned char* receipts,
    size_t receipt_count);
#endif

static constexpr uint8_t EXCHANGE_STATE_INTERFACE_VERSION{1};
static constexpr uint16_t EXCHANGE_SCRIPT_CACHE_REVISION{12};
// Increment whenever fixed ECX/peg/Simplicity consensus semantics change.
// This is committed to ecx_consensus.dat in addition to selectable settings.
static constexpr uint32_t ECX_CONSENSUS_RULESET_REVISION{6};
/** The production successor recovers twelve independently bounded recursive
 * children. This does not freeze their program identities or authorize a
 * network activation; those remain catalogue/profile build boundaries. */
static constexpr bool BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN{
    ECX_BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN != 0};
static constexpr uint32_t FORCED_INCLUSION_BLOCKS{6};
static constexpr uint64_t MAX_COMBINED_UNCONSUMED{64};
static constexpr uint64_t MAX_COMBINED_SAME_PARENT_APPENDS{64};
static constexpr uint64_t MAX_COMBINED_PENDING_WITNESS_ENTRIES{448};
static constexpr uint32_t MAX_FORCED_TRANCHE_ORDER_WORK{64};

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

    struct BondV2FrozenConsensus {
        bool activation_enabled{false};
        bool identities_frozen{false};
        CTransactionRef deployment_transaction;
        CTransactionRef genesis_transaction;
        uint32_t issuance_input_index{0};
        uint32_t inventory_output_index{0};
        uint32_t reissuance_token_burn_output_index{0};
        uint32_t state_authority_source_output_index{0};
        uint256 inventory_asset_blinding_factor;
        uint256 inventory_value_blinding_factor;
        std::vector<unsigned char> canonical_configuration_bytes;
        uint256 transition_program_id;
        uint256 configuration_hash;
        uint256 collateral_vault_covenant_cmr;
        uint256 bond_asset_id;
        uint256 bond_deployment_commitment;
        uint256 inventory_covenant_script_sha256;
        uint256 reissuance_token_burn_script_sha256;
        uint256 redemption_queue_script_sha256;
        uint256 insurance_reserve_script_sha256;
        uint256 bond_inbox_redemption_staging_template_commitment;
        uint256 bond_inbox_redemption_staging_renderer_domain;
        uint256 bond_inbox_redemption_staging_internal_key;
        uint8_t bond_inbox_redemption_staging_tapleaf_version{0};
        uint256 bond_inbox_redemption_staging_process_cmr;
        uint256 bond_inbox_redemption_staging_refund_cmr;
        uint32_t bond_inbox_refund_minimum_parent_blocks{0};
        uint256 bond_inbox_domain;
        uint256 bond_inbox_custody_receipt_codec_hash;
        uint256 availability_scheme_hash;
        uint256 availability_custodian_registry_hash;
        std::array<std::array<unsigned char, 32>, 5> custodian_encryption_keys{};
        std::array<std::array<unsigned char, 32>, 5> custodian_attestation_keys{};
        uint32_t bond_inbox_inclusion_blocks{0};
        uint32_t bond_inbox_max_bundle_bytes{0};
        uint32_t bond_inbox_max_entries_per_sidechain_block{0};
        uint32_t bond_inbox_max_unique_source_witness_bytes_per_sidechain_block{0};
        uint32_t bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block{0};
        uint32_t bond_inbox_max_pending_entries_per_transition{0};
        uint32_t bond_inbox_max_consumed_entries_per_transition{0};
        uint32_t bond_redemption_max_queue_entries{0};
        uint32_t matcher_execution_inclusion_parent_blocks{0};
        uint64_t maximum_conversion_age_seconds{0};
        uint32_t maximum_conversion_proof_bytes{0};
        uint32_t recursive_proof_marker_bytes{0};
        uint64_t fixed_supply_atoms{0};
        uint64_t redemption_delay_parent_blocks{0};
        uint256 state_authority_asset_id;
        uint256 public_state_domain_sha256;
        uint256 state_node_domain_sha256;
        uint256 transition_journal_domain_sha256;
        uint256 transition_cmr;
        uint256 incremental_activation_program_id;
        uint256 incremental_activation_configuration_hash;
        uint256 incremental_activation_cmr;
        uint256 incremental_successor_program_id;
        uint256 incremental_successor_configuration_hash;
        uint256 incremental_successor_transition_cmr;
        uint256 incremental_successor_state_node_domain_sha256;
        uint256 insurance_reserve_covenant_cmr;
        uint256 inventory_cmr;
        uint256 redemption_queue_cmr;
        uint256 ecx_btc_conversion_program_id;
        uint256 ecx_btc_redemption_covenant_commitment;
        uint256 ecx_btc_source_checkpoint_commitment;
        uint256 usdd_usd_conversion_program_id;
        uint256 usdd_usd_redemption_covenant_commitment;
        uint256 usdd_usd_source_checkpoint_commitment;
        uint256 identity_derivation_record_sha256;
        uint256 matcher_genesis_receipt_hash;
        uint256 order_receipts_genesis_root;
        uint256 genesis_availability_root;
        CAsset usdd_asset_id;
        std::array<unsigned char, 32> keyless_internal_key{};
        uint64_t genesis_mark_price{0};
    } bond_v2;
};

/** Exact node-derived source record exported to a proof producer.  The
 * canonical entry is 700 bytes for finite V18 and 708 bytes for the u128
 * successor; source_transaction is the exact witness serialization committed
 * by wtxid. */
struct BondInboxSourceExport
{
    uint8_t proof_profile{0};
    uint64_t entry_index{0};
    BigEndianUint128 entry_index_u128;
    uint64_t sidechain_height{0};
    uint64_t observed_parent_height{0};
    uint64_t process_deadline_parent_height{0};
    uint64_t refund_not_before_parent_height{0};
    uint8_t marker_kind{0};
    uint256 action_id;
    uint32_t source_transaction_index{0};
    uint32_t marker_vout{0};
    uint256 source_txid;
    uint256 source_wtxid;
    std::vector<unsigned char> canonical_entry;
    std::vector<unsigned char> source_transaction;
};

const ExchangeConsensus& LayerTwoLabsExchangeConsensus();

/** Cross-language activation boundary for the exact 1,977-byte
 * FrozenConfigurationV2 version-5/V18 encoding.  On success the returned
 * digest is the V18 tagged configuration hash.  No opaque hash-only or older
 * configuration is accepted. */
bool ValidateBondV2FrozenConfigurationV18(
    const std::vector<unsigned char>& canonical_bytes,
    uint256& configuration_hash,
    std::string& error);

/** Exact cross-language V18 no-history staging renderer result.  The hidden
 * node is a raw TapNodeHash, not a spendable leaf. */
struct BondInboxStagingRenderV18
{
    uint256 process_leaf_hash;
    uint256 refund_leaf_hash;
    uint256 hidden_node_hash;
    uint256 lower_branch_hash;
    uint256 top_branch_hash;
    CScript script_pubkey;
};

/** Render Branch(process, Branch(refund, hidden_raw_node)) using the exact
 * frozen NUMS key, renderer domain, configuration and marker terms. */
bool RenderBondInboxStagingV18(
    const uint256& marker_signer,
    const uint256& stable_intent_id,
    uint32_t staging_vout,
    const uint256& refund_script_sha256,
    uint64_t refund_not_before_parent_height,
    BondInboxStagingRenderV18& rendered,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Narrow relay-policy classifier for one exact configuration-bound bond
 * inbox source transaction.  It verifies every 503-byte marker wrapper
 * signature and enforces the frozen per-transaction byte/entry bounds. */
bool IsCanonicalBondInboxSourceTransaction(
    const CTransaction& transaction,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Reconstruct every exact source entry in one active-chain block while
 * advancing the caller's authenticated node head. Used by consensus and the
 * bounded archival RPC; producer-supplied entry bytes are never accepted. */
bool AppendBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus(),
    std::vector<BondInboxSourceExport>* exported_entries = nullptr);

/** Reconstruct successor version-3 marker entries with exact u128 indices and
 * successor-specific signature/commitment/root domains. */
bool AppendIncrementalSuccessorBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus(),
    std::vector<BondInboxSourceExport>* exported_entries = nullptr);

/** Canonical empty source head used to seed activation-block reconstruction. */
uint256 BondInboxGenesisHead(
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Canonical empty successor source head.  It intentionally binds the V18
 * action configuration while using fresh u128 inbox domains. */
uint256 IncrementalSuccessorBondInboxGenesisHead(
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Strictly decode a version-4 SP1 annex/PublicValuesV5 projection. */
bool DecodeBondV2CapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Strictly decode a version-6 incremental-successor annex projection. */
bool DecodeBondV2IncrementalSuccessorCapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/**
 * Derive the reorg-safe per-block V2 projection after every input script and
 * Groth16 verifier has succeeded. A fresh activation remains fail-closed until
 * the physical deployment and exact canonical-genesis verifier is frozen.
 */
bool DeriveBondV2CapitalProjectionAfterScripts(
    const CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    int height,
    const uint256& prior_parent_block_hash,
    uint64_t prior_parent_height,
    uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Exact one-time physical deployment and canonical empty V2 initializer. */
bool VerifyBondV2DeploymentAndGenesis(
    const CCoinsViewCache& view,
    uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Deterministic finite-state singleton script. The Taproot tree preauthorizes
 * both ordinary V18 transitions and the one-shot incremental activation leaf. */
bool ComputeBondV2FiniteStateScript(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash,
    CScript& script);

/** Deterministic post-activation incremental successor singleton script. */
bool ComputeBondV2IncrementalSuccessorScript(
    const ExchangeConsensus& consensus,
    const uint256& successor_state_root,
    CScript& script);

/**
 * Versioned commitment to every runtime-selectable ECX/private-BMM consensus
 * parameter, the frozen ruleset revision, header namespaces and core tracker
 * constants. This is a data-directory identity guard, not a block-header
 * commitment; production parameters remain source-frozen.
 */
uint256 ComputeRuntimeConsensusFingerprint(
    const ExchangeConsensus& consensus,
    const std::string& network_id,
    const uint256& genesis_hash,
    const uint256& policy_asset,
    const uint256& bmm_consensus_fingerprint,
    bool private_bmm_enabled,
    uint32_t private_bmm_activation_height);

/** Parse the runtime configuration and return its canonical fingerprint. */
bool GetRuntimeConsensusFingerprint(
    uint256& fingerprint,
    bool& runtime_configured,
    int& first_activation_height,
    std::string& error);

/** Detect connected ECX tracker state while first-binding a legacy datadir. */
bool HasPersistedExchangeConsensusState(const CCoinsView& view);

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
    uint64_t forced_processed_cursor{0};
    uint256 deposit_inbox_root;
    uint64_t deposit_entry_count{0};
    uint64_t deposit_processed_cursor{0};
    uint64_t source_backlog_oldest_parent_height{0};
};

/** Consensus-authenticated preimage for the otherwise opaque BIP300 M6ID. */
struct WithdrawalBundleEnvelopeV1
{
    uint32_t checkpoint_height{0};
    uint256 checkpoint_block_hash;
    std::vector<unsigned char> m6_no_witness;
};

/** Canonical coinbase commitment carrying an M6 preimage for Elements nodes. */
CScript BuildWithdrawalBundleEnvelopeScript(const WithdrawalBundleEnvelopeV1& envelope);

/** Validate M6ID and PXST against an ancestor ECX checkpoint. */
bool CheckWithdrawalBundleEnvelope(
    const CBlock& block,
    const CBlockIndex* previous,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus);

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
/** Narrow relay-policy exception for one fully validated oversized ECXF output. */
bool IsCanonicalForcedActionOutput(
    const CTransaction& transaction,
    size_t output_index,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Reject reserved ECXF/ECXD lookalikes before they can poison block templates. */
bool CheckSourceTransactionPolicy(
    const CTransaction& transaction,
    int next_height,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/** Count canonical source markers after applying the fail-closed parser. */
bool CountSourceTransactionMarkers(
    const CTransaction& transaction,
    uint64_t& forced_count,
    uint64_t& deposit_count,
    std::string& error,
    const ExchangeConsensus& consensus = LayerTwoLabsExchangeConsensus());

/**
 * Exact successor resource reservation for one authenticated parent-height
 * ECXF tranche. Kinds are the already-canonical marker kinds: cancel=0,
 * reduce-only IOC=1, withdrawal=2.
 */
bool ComputeForcedTrancheOrderWork(
    const std::vector<uint8_t>& kinds,
    uint32_t& order_work,
    std::string& error);

/** Remaining safe source appends for a template built on this snapshot. */
bool ComputeSourceAppendBudget(
    const ExchangeConsensusSnapshot& snapshot,
    uint64_t& budget,
    std::string& error);

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

/** Revalidate ECX commitments retained in an already-persisted header index. */
bool CheckExchangeStateIndexHeader(
    const CBlockIndex& index,
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

bool GetPriorActiveInboxCursors(
    const CBlockIndex* previous,
    uint64_t& forced_cursor,
    uint64_t& deposit_cursor,
    std::string& error);

/** Read all persisted heads atomically and require exact agreement with tip. */
bool GetExchangeConsensusSnapshot(
    const CCoinsViewCache& view,
    const CBlockIndex* tip,
    ExchangeConsensusSnapshot& snapshot,
    std::string& error);

} // namespace ecx

#endif // BITCOIN_ECX_EXCHANGE_STATE_H
