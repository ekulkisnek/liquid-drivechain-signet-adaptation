// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
#define BITCOIN_SCRIPT_USDD_SP1_ANNEX_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <span.h>
#include <crypto/sha256.h>
#include <simplicity/elements/primitiveJetCost.inc>
#include <simplicity/limitations.h>
#include <elements_drivechain_identity.h>

#if defined(HAVE_USDD_SP1_VERIFIER)
#include <script/usdd_sp1_verifier_ffi.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

/**
 * Versioned envelope for an opaque SP1 proof carried in a Taproot annex.
 *
 * Parsing this envelope does not verify the proof. In particular, callers
 * must not interpret ParseUsddSp1ProofAnnex() success as authorization to mint
 * or release an asset. The mint controller must invoke the environmental SP1
 * verifier jet with both its frozen guest program ID and SHA-256 of the exact
 * canonical journal it consumed.
 *
 * All integer fields are unsigned big-endian:
 *
 *   0       1   Taproot annex tag (0x50)
 *   1       8   magic: "USDDSP1\0"
 *   9       1   envelope version (1)
 *   10      1   proof system (1 = SP1 compressed)
 *   11      1   statement kind (1 = finalized Ethereum state transition,
 *               3 = V11 controller strong execution)
 *   12      1   public digest mode (1 = SHA-256)
 *   13      2   flags (must be zero)
 *   15      4   public-values byte length
 *   19      4   proof byte length
 *   23     32   SP1 HashableKey::hash_bytes program ID: eight canonical
 *               KoalaBear field words in big-endian order (not SHA256(vkey))
 *   55      n   public values followed by opaque proof bytes
 */
namespace usdd {

static constexpr unsigned char SP1_ANNEX_TAG{0x50};
static constexpr std::array<unsigned char, 8> SP1_ANNEX_MAGIC{{'U', 'S', 'D', 'D', 'S', 'P', '1', 0x00}};
static constexpr std::size_t SP1_ANNEX_HEADER_SIZE{55};
static constexpr std::size_t SP1_ANNEX_MAX_SIZE{
    ElementsDrivechainIdentity::USDD_SP1_ANNEX_MAX_BYTES};
static constexpr std::size_t SP1_PUBLIC_VALUES_MAX_SIZE{16 * 1024};
static_assert(SP1_ANNEX_MAX_SIZE ==
              ElementsDrivechainIdentity::USDD_SP1_ANNEX_MAX_BYTES);
static_assert(SP1_PUBLIC_VALUES_MAX_SIZE ==
              ElementsDrivechainIdentity::USDD_SP1_PUBLIC_VALUES_MAX_BYTES);

enum class Sp1StatementKind : uint8_t {
    ETH_STATE_V1 = 1,
    CONTROLLER_STRONG_EXECUTION_V2 = 3,
};
static_assert(
    ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
            static_cast<uint8_t>(Sp1StatementKind::ETH_STATE_V1) ||
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
            static_cast<uint8_t>(Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2));

enum class Sp1AnnexError {
    OK,
    NOT_USDD,
    TOO_LARGE,
    TRUNCATED,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_PROOF_SYSTEM,
    BAD_STATEMENT_KIND,
    BAD_DIGEST_MODE,
    BAD_FLAGS,
    EMPTY_PUBLIC_VALUES,
    PUBLIC_VALUES_TOO_LARGE,
    INVALID_STRONG_EXECUTION_PUBLIC_VALUES,
    EMPTY_PROOF,
    ZERO_GUEST_PROGRAM_ID,
    LENGTH_MISMATCH,
};

enum class Sp1ConsensusGateResult {
    NOT_USDD,
    MALFORMED,
    WRONG_CONTROLLER_CMR,
    WRONG_GUEST_PROGRAM_ID,
    MALFORMED_PUBLIC_VALUES,
    DEPLOYMENT_UNCONFIGURED,
    WRONG_INBOUND_MINT_DOMAIN,
    BMM_CONTEXT_MISSING,
    VERIFIER_UNAVAILABLE,
    READY_FOR_JET,
};

enum class Sp1ProofIdentityResult {
    MATCH,
    WRONG_CONTROLLER_CMR,
    WRONG_GUEST_PROGRAM_ID,
    MALFORMED_PUBLIC_VALUES,
    DEPLOYMENT_UNCONFIGURED,
    WRONG_INBOUND_MINT_DOMAIN,
};

enum class Sp1JournalIdentityError {
    OK,
    TRUNCATED,
    BAD_MAGIC,
    BAD_SCHEMA,
    BAD_DIGEST_MODE,
    GUEST_NOT_SUCCESSFUL,
    BAD_STATEMENT_KIND,
    WRONG_GUEST_PROGRAM_ID,
    LENGTH_MISMATCH,
    PAYLOAD_DIGEST_MISMATCH,
    BAD_PAYLOAD_KIND,
    BAD_PAYLOAD_LENGTH,
};

/** Result exposed to the future generated environmental verifier jet. */
enum class Sp1VerifierResult {
    VERIFIED,
    REJECTED,
    UNAVAILABLE,
};

struct Sp1ProofAnnexView {
    Sp1StatementKind statement_kind{Sp1StatementKind::ETH_STATE_V1};
    Span<const unsigned char> guest_program_id{};
    Span<const unsigned char> public_values{};
    Span<const unsigned char> proof{};
};

/**
 * The exact frozen controller receives its exact analysed execution budget.
 *
 * Simplicity budgets are expressed in whole WU while generated jet costs are
 * milliWU. The ordinary witness-derived base budget is bounded by the reserved
 * proof-transaction lane. The host gate has already pinned the script CMR, and
 * Simplicity independently recomputes that CMR from the decoded 6,155-byte
 * program before execution. Therefore the exact controller program, rather
 * than a generic budget heuristic, is the structural invariant that fixes how
 * many verifier nodes can execute.
 *
 * The pinned cost below is the result of decoding that exact program with the
 * frozen Elements jet catalogue and running Simplicity's static bound analysis.
 * Granting less rejects the canonical controller before cryptographic proof
 * verification; granting more is unnecessary. A generic program containing a
 * duplicated verifier remains outside the exact CMR-gated lane.
 */
static constexpr uint64_t SP1_VERIFIER_JET_COST_MWU{
    SIMPLICITY_VERIFY_SP1_COMPRESSED_SHA256_COST_MWU};
static_assert(SP1_VERIFIER_JET_COST_MWU ==
              ElementsDrivechainIdentity::VERIFY_SP1_COMPRESSED_SHA256_JET_COST_MWU);
static constexpr uint64_t SP1_CONTROLLER_PROGRAM_COST_MWU{3'532'580'406ULL};
static constexpr int64_t SP1_CONTROLLER_PROGRAM_BUDGET_WU{
    static_cast<int64_t>((SP1_CONTROLLER_PROGRAM_COST_MWU + 999U) / 1000U)};
static constexpr int64_t SP1_VERIFIER_BASE_BUDGET_MAX_WU{
    ElementsDrivechainIdentity::USDD_SP1_PROOF_TX_MAX_WEIGHT};
static_assert(
    static_cast<uint64_t>(SP1_CONTROLLER_PROGRAM_BUDGET_WU - 1) * 1000U <
        SP1_CONTROLLER_PROGRAM_COST_MWU,
    "USDD controller budget must be the minimum whole-WU execution ceiling");
static_assert(
    static_cast<uint64_t>(SP1_CONTROLLER_PROGRAM_BUDGET_WU) * 1000U >=
        SP1_CONTROLLER_PROGRAM_COST_MWU,
    "USDD controller execution must fit its whole-WU budget");
static_assert(SP1_CONTROLLER_PROGRAM_BUDGET_WU <= BUDGET_MAX,
              "USDD controller execution must fit Simplicity's global budget");
static_assert(SP1_VERIFIER_BASE_BUDGET_MAX_WU <
                  SP1_CONTROLLER_PROGRAM_BUDGET_WU,
              "proof-lane base budget must remain below controller execution budget");

inline bool ComputeUsddSp1VerifierBudget(const int64_t base_budget_wu,
                                         int64_t& credited_budget_wu)
{
    if (base_budget_wu < 0 ||
        base_budget_wu > SP1_VERIFIER_BASE_BUDGET_MAX_WU) {
        return false;
    }
    if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
        // V11 has no global controller CMR/program pin. Consequently neither
        // an annex nor a mutable configuration may grant reserved execution
        // weight to an arbitrary leaf. Parameterized leaves must fit the
        // ordinary witness-derived budget and Simplicity's BUDGET_MAX.
        credited_budget_wu = base_budget_wu;
    } else {
        credited_budget_wu = SP1_CONTROLLER_PROGRAM_BUDGET_WU;
    }
    return true;
}

inline bool IsUsddSp1ProofAnnex(Span<const unsigned char> annex)
{
    // Reserve 0x50 || "USDD" as the protocol namespace.  A malformed annex in
    // this namespace is rejected instead of being mistaken for an unrelated
    // Taproot annex.
    static constexpr std::array<unsigned char, 5> PREFIX{{SP1_ANNEX_TAG, 'U', 'S', 'D', 'D'}};
    return annex.size() >= PREFIX.size() && std::equal(PREFIX.begin(), PREFIX.end(), annex.begin());
}

inline uint32_t ReadUint32BE(Span<const unsigned char> bytes, std::size_t offset)
{
    return (uint32_t{bytes[offset]} << 24) |
           (uint32_t{bytes[offset + 1]} << 16) |
           (uint32_t{bytes[offset + 2]} << 8) |
           uint32_t{bytes[offset + 3]};
}

/**
 * Extract the deployment domain from a canonical inbound strict journal.
 *
 * The proof verifier still performs the complete typed Rust decode. This
 * small consensus parser deliberately validates every field needed to make
 * the fixed offset unambiguous, verifies SHA256(payload), and accepts only
 * the exact V1 deposit/heartbeat payload length ranges. It never trusts a
 * parallel annex-header domain that the proved journal did not authenticate.
 */
inline Sp1JournalIdentityError ExtractUsddSp1InboundMintDomain(
    Span<const unsigned char> public_values,
    Span<const unsigned char> annex_guest_program_id,
    std::array<unsigned char, 32>& inbound_mint_domain_id)
{
    static constexpr std::array<unsigned char, 8> JOURNAL_MAGIC{{'U', 'S', 'D', 'D', 'J', 'N', 'L', '1'}};
    static constexpr std::array<unsigned char, 8> SUCCESS_MARKER{{'S', 'U', 'C', 'C', 'E', 'S', 'S', '!'}};
    static constexpr std::size_t JOURNAL_HEADER_SIZE{88};
    static constexpr std::size_t PAYLOAD_IDENTITY_SIZE{36};
    static constexpr uint32_t HEARTBEAT_PAYLOAD_SIZE{790};
    static constexpr uint32_t DEPOSIT_PAYLOAD_MIN_SIZE{892};
    static constexpr uint32_t DEPOSIT_PAYLOAD_MAX_SIZE{13'115};
    static constexpr uint16_t ENCODING_SCHEMA{2};
    static constexpr uint16_t DEPOSIT_PUBLIC_OUTPUT_TAG{0x5201};
    static constexpr uint16_t HEARTBEAT_PUBLIC_OUTPUT_TAG{0x5204};

    inbound_mint_domain_id.fill(0);
    if (public_values.size() < JOURNAL_HEADER_SIZE + PAYLOAD_IDENTITY_SIZE) {
        return Sp1JournalIdentityError::TRUNCATED;
    }
    if (!std::equal(JOURNAL_MAGIC.begin(), JOURNAL_MAGIC.end(), public_values.begin())) {
        return Sp1JournalIdentityError::BAD_MAGIC;
    }
    if (public_values[8] != 0 || public_values[9] != ENCODING_SCHEMA) {
        return Sp1JournalIdentityError::BAD_SCHEMA;
    }
    if (public_values[10] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE) {
        return Sp1JournalIdentityError::BAD_DIGEST_MODE;
    }
    if (!std::equal(SUCCESS_MARKER.begin(), SUCCESS_MARKER.end(), public_values.begin() + 11)) {
        return Sp1JournalIdentityError::GUEST_NOT_SUCCESSFUL;
    }
    if (public_values[19] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND) {
        return Sp1JournalIdentityError::BAD_STATEMENT_KIND;
    }
    if (annex_guest_program_id.size() != 32 ||
        !std::equal(annex_guest_program_id.begin(), annex_guest_program_id.end(),
                    public_values.begin() + 20)) {
        return Sp1JournalIdentityError::WRONG_GUEST_PROGRAM_ID;
    }

    const uint32_t payload_size = ReadUint32BE(public_values, 84);
    if (uint64_t{JOURNAL_HEADER_SIZE} + payload_size != public_values.size()) {
        return Sp1JournalIdentityError::LENGTH_MISMATCH;
    }
    const Span<const unsigned char> payload = public_values.subspan(JOURNAL_HEADER_SIZE, payload_size);
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> payload_sha256{};
    CSHA256().Write(payload.data(), payload.size()).Finalize(payload_sha256.data());
    if (!std::equal(payload_sha256.begin(), payload_sha256.end(), public_values.begin() + 52)) {
        return Sp1JournalIdentityError::PAYLOAD_DIGEST_MISMATCH;
    }
    if (payload[0] != 0 || payload[1] != ENCODING_SCHEMA) {
        return Sp1JournalIdentityError::BAD_SCHEMA;
    }
    const uint16_t payload_tag = (uint16_t{payload[2]} << 8) | uint16_t{payload[3]};
    if (payload_tag == HEARTBEAT_PUBLIC_OUTPUT_TAG) {
        if (payload_size != HEARTBEAT_PAYLOAD_SIZE) {
            return Sp1JournalIdentityError::BAD_PAYLOAD_LENGTH;
        }
    } else if (payload_tag == DEPOSIT_PUBLIC_OUTPUT_TAG) {
        if (payload_size < DEPOSIT_PAYLOAD_MIN_SIZE || payload_size > DEPOSIT_PAYLOAD_MAX_SIZE) {
            return Sp1JournalIdentityError::BAD_PAYLOAD_LENGTH;
        }
    } else {
        return Sp1JournalIdentityError::BAD_PAYLOAD_KIND;
    }

    std::copy(payload.begin() + 4, payload.begin() + 36,
              inbound_mint_domain_id.begin());
    return Sp1JournalIdentityError::OK;
}

inline Sp1AnnexError ParseUsddSp1ProofAnnex(Span<const unsigned char> annex, Sp1ProofAnnexView& result)
{
    result = {};
    if (!IsUsddSp1ProofAnnex(annex)) return Sp1AnnexError::NOT_USDD;
    if (annex.size() > SP1_ANNEX_MAX_SIZE) return Sp1AnnexError::TOO_LARGE;
    if (annex.size() < SP1_ANNEX_HEADER_SIZE) return Sp1AnnexError::TRUNCATED;
    if (!std::equal(SP1_ANNEX_MAGIC.begin(), SP1_ANNEX_MAGIC.end(), annex.begin() + 1)) {
        return Sp1AnnexError::BAD_MAGIC;
    }
    if (annex[9] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_ENVELOPE_VERSION) {
        return Sp1AnnexError::BAD_VERSION;
    }
    if (annex[10] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_PROOF_SYSTEM) {
        return Sp1AnnexError::BAD_PROOF_SYSTEM;
    }
    const auto statement_kind = static_cast<Sp1StatementKind>(annex[11]);
    if (statement_kind != Sp1StatementKind::ETH_STATE_V1 &&
        statement_kind != Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
        return Sp1AnnexError::BAD_STATEMENT_KIND;
    }
    if (annex[12] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE) {
        return Sp1AnnexError::BAD_DIGEST_MODE;
    }
    if (annex[13] != 0 || annex[14] != 0) return Sp1AnnexError::BAD_FLAGS;

    const uint32_t public_values_size = ReadUint32BE(annex, 15);
    const uint32_t proof_size = ReadUint32BE(annex, 19);
    if (public_values_size == 0) return Sp1AnnexError::EMPTY_PUBLIC_VALUES;
    if (public_values_size > SP1_PUBLIC_VALUES_MAX_SIZE) return Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE;
    if (statement_kind == Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2 &&
        public_values_size != 32) {
        return Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES;
    }
    if (proof_size == 0) return Sp1AnnexError::EMPTY_PROOF;

    const Span<const unsigned char> guest_program_id = annex.subspan(23, 32);
    if (std::all_of(guest_program_id.begin(), guest_program_id.end(), [](unsigned char byte) { return byte == 0; })) {
        return Sp1AnnexError::ZERO_GUEST_PROGRAM_ID;
    }

    const uint64_t expected_size = uint64_t{SP1_ANNEX_HEADER_SIZE} + public_values_size + proof_size;
    if (expected_size != annex.size()) return Sp1AnnexError::LENGTH_MISMATCH;

    result.statement_kind = statement_kind;
    result.guest_program_id = guest_program_id;
    result.public_values = annex.subspan(SP1_ANNEX_HEADER_SIZE, public_values_size);
    result.proof = annex.subspan(SP1_ANNEX_HEADER_SIZE + public_values_size, proof_size);
    if (statement_kind == Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2 &&
        std::all_of(result.public_values.begin(), result.public_values.end(),
                    [](const unsigned char byte) { return byte == 0; })) {
        result = {};
        return Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES;
    }
    return Sp1AnnexError::OK;
}

inline const char* Sp1AnnexErrorString(Sp1AnnexError error)
{
    switch (error) {
    case Sp1AnnexError::OK: return "ok";
    case Sp1AnnexError::NOT_USDD: return "not a USDD annex";
    case Sp1AnnexError::TOO_LARGE: return "annex exceeds frozen maximum";
    case Sp1AnnexError::TRUNCATED: return "truncated header";
    case Sp1AnnexError::BAD_MAGIC: return "invalid magic";
    case Sp1AnnexError::BAD_VERSION: return "unsupported envelope version";
    case Sp1AnnexError::BAD_PROOF_SYSTEM: return "unsupported proof system";
    case Sp1AnnexError::BAD_STATEMENT_KIND: return "unsupported statement kind";
    case Sp1AnnexError::BAD_DIGEST_MODE: return "unsupported public digest mode";
    case Sp1AnnexError::BAD_FLAGS: return "nonzero reserved flags";
    case Sp1AnnexError::EMPTY_PUBLIC_VALUES: return "empty public values";
    case Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE: return "public values exceed 16 KiB";
    case Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES: return "V11 strong-execution public values must be one nonzero 32-byte hash";
    case Sp1AnnexError::EMPTY_PROOF: return "empty proof";
    case Sp1AnnexError::ZERO_GUEST_PROGRAM_ID: return "zero SP1 guest program ID";
    case Sp1AnnexError::LENGTH_MISMATCH: return "declared lengths do not match annex";
    }
    return "unknown USDD annex error";
}

/**
 * Bind the reserved proof lane to the exact controller and guest, then apply
 * the chain's deployment-binding semantics.
 *
 * The CMR is the 32 bytes carried as the Tapsimplicity script item in witness
 * byte order. The guest ID is the exact 32-byte HashableKey representation in
 * the canonical annex. Callers must parse the annex before passing its view.
 */
inline Sp1ProofIdentityResult CheckUsddSp1ProofIdentityForDeployment(
    Span<const unsigned char> script_cmr,
    Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values,
    const uint32_t deployment_binding_version,
    Span<const unsigned char> expected_inbound_mint_domain_id)
{
    if (script_cmr.size() !=
            ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR.size() ||
        !std::equal(
            ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR.begin(),
            ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR.end(),
            script_cmr.begin())) {
        return Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR;
    }
    if (guest_program_id.size() !=
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.size() ||
        !std::equal(
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.begin(),
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID.end(),
            guest_program_id.begin())) {
        return Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID;
    }
    std::array<unsigned char, 32> journal_domain{};
    if (ExtractUsddSp1InboundMintDomain(
            public_values, guest_program_id, journal_domain) !=
        Sp1JournalIdentityError::OK) {
        return Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES;
    }
    if (expected_inbound_mint_domain_id.size() != 32) {
        return Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED;
    }

    const bool global_domain_is_zero = std::all_of(
        expected_inbound_mint_domain_id.begin(),
        expected_inbound_mint_domain_id.end(),
        [](const unsigned char byte) { return byte == 0; });
    const bool journal_domain_is_zero = std::all_of(
        journal_domain.begin(), journal_domain.end(),
        [](const unsigned char byte) { return byte == 0; });

    if (deployment_binding_version == 1) {
        if (global_domain_is_zero) {
            return Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED;
        }
        if (!std::equal(
                expected_inbound_mint_domain_id.begin(),
                expected_inbound_mint_domain_id.end(),
                journal_domain.begin())) {
            return Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN;
        }
        return Sp1ProofIdentityResult::MATCH;
    }

    // V2 is generic at the host boundary because an exact deployment domain
    // depends on the post-genesis asset/token issuance. The fixed controller
    // derives that nonzero domain from its authenticated configuration state,
    // hashes the same strict journal, and passes its digest to the verifier
    // jet. A nonzero global value under V2 is a configuration error, not an
    // alternate deployment allowlist.
    if (deployment_binding_version == 2) {
        if (!global_domain_is_zero) {
            return Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED;
        }
        return journal_domain_is_zero
            ? Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN
            : Sp1ProofIdentityResult::MATCH;
    }

    return Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED;
}

/**
 * Bind an incompatible V11 strong-execution annex to its exact controller
 * leaf and SP1 guest without importing the legacy V1 journal/domain codec.
 *
 * The caller must supply identities from one immutable V11 chain manifest.
 * This helper deliberately has no default using the active V7 constants, so
 * adding the codec cannot activate V11 or reinterpret a historical network.
 */
inline Sp1ProofIdentityResult CheckUsddSp1StrongExecutionIdentity(
    Span<const unsigned char> script_cmr,
    Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values,
    Span<const unsigned char> expected_controller_cmr,
    Span<const unsigned char> expected_guest_program_id)
{
    if (expected_controller_cmr.size() != 32 ||
        expected_guest_program_id.size() != 32 ||
        std::all_of(expected_controller_cmr.begin(),
                    expected_controller_cmr.end(),
                    [](const unsigned char byte) { return byte == 0; }) ||
        std::all_of(expected_guest_program_id.begin(),
                    expected_guest_program_id.end(),
                    [](const unsigned char byte) { return byte == 0; })) {
        return Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED;
    }
    if (script_cmr.size() != 32 ||
        !std::equal(expected_controller_cmr.begin(),
                    expected_controller_cmr.end(), script_cmr.begin())) {
        return Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR;
    }
    if (guest_program_id.size() != 32 ||
        !std::equal(expected_guest_program_id.begin(),
                    expected_guest_program_id.end(),
                    guest_program_id.begin())) {
        return Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID;
    }
    if (public_values.size() != 32 ||
        std::all_of(public_values.begin(), public_values.end(),
                    [](const unsigned char byte) { return byte == 0; })) {
        return Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES;
    }
    return Sp1ProofIdentityResult::MATCH;
}

/** Consensus callers must use the immutable chain-identity binding. */
inline Sp1ProofIdentityResult CheckUsddSp1ProofIdentity(
    Span<const unsigned char> script_cmr,
    Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values)
{
    return CheckUsddSp1ProofIdentityForDeployment(
        script_cmr, guest_program_id, public_values,
        ElementsDrivechainIdentity::USDD_SP1_DEPLOYMENT_BINDING_VERSION,
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID);
}

/**
 * Call the pinned Rust verifier boundary for an environmental Simplicity jet.
 *
 * This helper is deliberately not called by the interpreter's annex parser.
 * Verification only becomes authorization when a controller program invokes a
 * generated environmental jet and supplies the digest of the exact canonical
 * journal that the program uses for its state transition.
 */
inline Sp1VerifierResult VerifyUsddSp1AnnexForJournal(
    Span<const unsigned char> annex,
    Span<const unsigned char> expected_program_id,
    Span<const unsigned char> expected_public_values_sha256)
{
    if (expected_program_id.size() != 32 || expected_public_values_sha256.size() != 32) {
        return Sp1VerifierResult::REJECTED;
    }
#if defined(HAVE_USDD_SP1_VERIFIER)
    if (usdd_sp1_verifier_abi_version() != USDD_SP1_VERIFIER_ABI_VERSION) {
        return Sp1VerifierResult::UNAVAILABLE;
    }
    const uint32_t status = usdd_sp1_verify_annex(
        USDD_SP1_VERIFIER_ABI_VERSION,
        annex.data(), annex.size(),
        expected_program_id.data(), expected_program_id.size(),
        expected_public_values_sha256.data(), expected_public_values_sha256.size());
    return status == USDD_SP1_VERIFIER_ACCEPTED
        ? Sp1VerifierResult::VERIFIED
        : Sp1VerifierResult::REJECTED;
#else
    (void)annex;
    return Sp1VerifierResult::UNAVAILABLE;
#endif
}

inline Sp1ConsensusGateResult GateUsddSp1ProofAnnexForDeployment(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint,
    const uint32_t deployment_binding_version,
    Span<const unsigned char> expected_inbound_mint_domain_id,
    const bool verifier_activation_configured)
{
    if (!IsUsddSp1ProofAnnex(annex)) return Sp1ConsensusGateResult::NOT_USDD;
    Sp1ProofAnnexView parsed;
    if (ParseUsddSp1ProofAnnex(annex, parsed) != Sp1AnnexError::OK) {
        return Sp1ConsensusGateResult::MALFORMED;
    }
    // This helper is deliberately the legacy deployment-domain lane. The
    // chain-identity dispatcher below selects the separate V11 strong-
    // execution helper; never reinterpret this lane's CMR/program-ID
    // allowlist for an incompatible statement.
    if (parsed.statement_kind ==
        Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
        return Sp1ConsensusGateResult::DEPLOYMENT_UNCONFIGURED;
    }
    switch (CheckUsddSp1ProofIdentityForDeployment(
        script_cmr, parsed.guest_program_id, parsed.public_values,
        deployment_binding_version, expected_inbound_mint_domain_id)) {
    case Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR:
        return Sp1ConsensusGateResult::WRONG_CONTROLLER_CMR;
    case Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID:
        return Sp1ConsensusGateResult::WRONG_GUEST_PROGRAM_ID;
    case Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES:
        return Sp1ConsensusGateResult::MALFORMED_PUBLIC_VALUES;
    case Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED:
        return Sp1ConsensusGateResult::DEPLOYMENT_UNCONFIGURED;
    case Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN:
        return Sp1ConsensusGateResult::WRONG_INBOUND_MINT_DOMAIN;
    case Sp1ProofIdentityResult::MATCH:
        break;
    }
    if (!has_authenticated_atomic_bmm_endpoint) return Sp1ConsensusGateResult::BMM_CONTEXT_MISSING;
    // A linked verifier and matching ABI are not enough to activate consensus;
    // the chain identity must also configure activation. Active production
    // builds are required at startup to link the exact frozen verifier.
    return verifier_activation_configured
        ? Sp1ConsensusGateResult::READY_FOR_JET
        : Sp1ConsensusGateResult::VERIFIER_UNAVAILABLE;
}

/**
 * Host-side admission gate for the incompatible V11 strong-execution lane.
 *
 * Success grants only the fixed verifier-cost lane. The Simplicity program
 * must still hash its exact typed journal, invoke the environmental verifier
 * jet with the manifest-bound guest ID, and require true. No current network
 * calls this function until a separate V11 Signet identity selects it.
 */
inline Sp1ConsensusGateResult GateUsddSp1StrongExecutionAnnexForDeployment(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint,
    Span<const unsigned char> expected_controller_cmr,
    Span<const unsigned char> expected_guest_program_id,
    const bool verifier_activation_configured)
{
    if (!IsUsddSp1ProofAnnex(annex)) {
        return Sp1ConsensusGateResult::NOT_USDD;
    }
    Sp1ProofAnnexView parsed;
    if (ParseUsddSp1ProofAnnex(annex, parsed) != Sp1AnnexError::OK) {
        return Sp1ConsensusGateResult::MALFORMED;
    }
    if (parsed.statement_kind !=
        Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
        return Sp1ConsensusGateResult::DEPLOYMENT_UNCONFIGURED;
    }
    switch (CheckUsddSp1StrongExecutionIdentity(
        script_cmr, parsed.guest_program_id, parsed.public_values,
        expected_controller_cmr, expected_guest_program_id)) {
    case Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR:
        return Sp1ConsensusGateResult::WRONG_CONTROLLER_CMR;
    case Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID:
        return Sp1ConsensusGateResult::WRONG_GUEST_PROGRAM_ID;
    case Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES:
        return Sp1ConsensusGateResult::MALFORMED_PUBLIC_VALUES;
    case Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED:
        return Sp1ConsensusGateResult::DEPLOYMENT_UNCONFIGURED;
    case Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN:
        return Sp1ConsensusGateResult::WRONG_INBOUND_MINT_DOMAIN;
    case Sp1ProofIdentityResult::MATCH:
        break;
    }
    if (!has_authenticated_atomic_bmm_endpoint) {
        return Sp1ConsensusGateResult::BMM_CONTEXT_MISSING;
    }
    return verifier_activation_configured
        ? Sp1ConsensusGateResult::READY_FOR_JET
        : Sp1ConsensusGateResult::VERIFIER_UNAVAILABLE;
}

inline Sp1ConsensusGateResult GateUsddSp1ParameterizedStrongExecutionAnnex(
    Span<const unsigned char> annex,
    bool has_authenticated_atomic_bmm_endpoint,
    const bool verifier_activation_configured)
{
    if (!IsUsddSp1ProofAnnex(annex)) return Sp1ConsensusGateResult::NOT_USDD;
    Sp1ProofAnnexView parsed;
    if (ParseUsddSp1ProofAnnex(annex, parsed) != Sp1AnnexError::OK) {
        return Sp1ConsensusGateResult::MALFORMED;
    }
    if (parsed.statement_kind != Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
        return Sp1ConsensusGateResult::DEPLOYMENT_UNCONFIGURED;
    }
    if (parsed.guest_program_id.size() != 32 ||
        std::all_of(parsed.guest_program_id.begin(), parsed.guest_program_id.end(),
                    [](unsigned char byte) { return byte == 0; })) {
        return Sp1ConsensusGateResult::WRONG_GUEST_PROGRAM_ID;
    }
    if (parsed.public_values.size() != 32) {
        return Sp1ConsensusGateResult::MALFORMED_PUBLIC_VALUES;
    }
    if (!has_authenticated_atomic_bmm_endpoint) {
        return Sp1ConsensusGateResult::BMM_CONTEXT_MISSING;
    }
    // READY_FOR_JET is not authorization. The executed configuration-bound
    // leaf supplies and checks its exact program/configuration identities and
    // must require the environmental verifier jet to return true.
    return verifier_activation_configured
        ? Sp1ConsensusGateResult::READY_FOR_JET
        : Sp1ConsensusGateResult::VERIFIER_UNAVAILABLE;
}

inline Sp1ConsensusGateResult GateUsddSp1ProofAnnex(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint)
{
    static_assert(
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
                static_cast<uint8_t>(Sp1StatementKind::ETH_STATE_V1) ||
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
                static_cast<uint8_t>(
                    Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2),
        "the chain identity selects an unsupported USDD SP1 statement kind");

    // The chain-identity header is generated and committed by each network.
    // V7 continues through its deployment-domain journal. A separately
    // frozen V11 private-Signet identity selects statement kind 3 and reuses
    // the same fields as the expected strong-execution controller CMR and
    // program ID. This dispatch adds no runtime or operator-controlled switch.
    if constexpr (
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
        static_cast<uint8_t>(
            Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2)) {
        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            return GateUsddSp1ParameterizedStrongExecutionAnnex(
                annex, has_authenticated_atomic_bmm_endpoint,
                ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
        }
        return GateUsddSp1StrongExecutionAnnexForDeployment(
            annex, script_cmr, has_authenticated_atomic_bmm_endpoint,
            ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR,
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID,
            ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
    }
    return GateUsddSp1ProofAnnexForDeployment(
        annex, script_cmr, has_authenticated_atomic_bmm_endpoint,
        ElementsDrivechainIdentity::USDD_SP1_DEPLOYMENT_BINDING_VERSION,
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID,
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
}

} // namespace usdd

#endif // BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
