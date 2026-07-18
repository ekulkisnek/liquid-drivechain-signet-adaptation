// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
#define BITCOIN_SCRIPT_USDD_SP1_ANNEX_H

#include <span.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

/**
 * Versioned envelope for an opaque SP1 proof carried in a Taproot annex.
 *
 * Parsing this envelope does not verify the proof.  In particular, callers
 * must not interpret ParseUsddSp1ProofAnnex() success as authorization to mint
 * or release an asset.  Consensus code fails closed until a specific SP1
 * verifier and guest verification-key allowlist are implemented.
 *
 * All integer fields are unsigned big-endian:
 *
 *   0       1   Taproot annex tag (0x50)
 *   1       8   magic: "USDDSP1\0"
 *   9       1   envelope version (1)
 *   10      1   proof system (1 = SP1 compressed)
 *   11      1   statement kind (1 = finalized Ethereum state transition)
 *   12      1   public digest mode (1 = SHA-256)
 *   13      2   flags (must be zero)
 *   15      4   public-values byte length
 *   19      4   proof byte length
 *   23     32   SHA-256 digest of the authorized guest verification key
 *   55      n   public values followed by opaque proof bytes
 */
namespace usdd {

static constexpr unsigned char SP1_ANNEX_TAG{0x50};
static constexpr std::array<unsigned char, 8> SP1_ANNEX_MAGIC{{'U', 'S', 'D', 'D', 'S', 'P', '1', 0x00}};
static constexpr std::size_t SP1_ANNEX_HEADER_SIZE{55};
static constexpr std::size_t SP1_ANNEX_MAX_SIZE{512 * 1024};
static constexpr std::size_t SP1_PUBLIC_VALUES_MAX_SIZE{16 * 1024};

enum class Sp1StatementKind : uint8_t {
    ETH_STATE_V1 = 1,
};

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
    EMPTY_PROOF,
    ZERO_GUEST_VKEY,
    LENGTH_MISMATCH,
};

/** There is deliberately no ACCEPT value until cryptographic verification exists. */
enum class Sp1ConsensusGateResult {
    NOT_USDD,
    MALFORMED,
    BMM_CONTEXT_MISSING,
    VERIFIER_UNAVAILABLE,
};

struct Sp1ProofAnnexView {
    Sp1StatementKind statement_kind{Sp1StatementKind::ETH_STATE_V1};
    Span<const unsigned char> guest_vkey_hash{};
    Span<const unsigned char> public_values{};
    Span<const unsigned char> proof{};
};

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

inline Sp1AnnexError ParseUsddSp1ProofAnnex(Span<const unsigned char> annex, Sp1ProofAnnexView& result)
{
    result = {};
    if (!IsUsddSp1ProofAnnex(annex)) return Sp1AnnexError::NOT_USDD;
    if (annex.size() > SP1_ANNEX_MAX_SIZE) return Sp1AnnexError::TOO_LARGE;
    if (annex.size() < SP1_ANNEX_HEADER_SIZE) return Sp1AnnexError::TRUNCATED;
    if (!std::equal(SP1_ANNEX_MAGIC.begin(), SP1_ANNEX_MAGIC.end(), annex.begin() + 1)) {
        return Sp1AnnexError::BAD_MAGIC;
    }
    if (annex[9] != 1) return Sp1AnnexError::BAD_VERSION;
    if (annex[10] != 1) return Sp1AnnexError::BAD_PROOF_SYSTEM;
    if (annex[11] != static_cast<uint8_t>(Sp1StatementKind::ETH_STATE_V1)) {
        return Sp1AnnexError::BAD_STATEMENT_KIND;
    }
    if (annex[12] != 1) return Sp1AnnexError::BAD_DIGEST_MODE;
    if (annex[13] != 0 || annex[14] != 0) return Sp1AnnexError::BAD_FLAGS;

    const uint32_t public_values_size = ReadUint32BE(annex, 15);
    const uint32_t proof_size = ReadUint32BE(annex, 19);
    if (public_values_size == 0) return Sp1AnnexError::EMPTY_PUBLIC_VALUES;
    if (public_values_size > SP1_PUBLIC_VALUES_MAX_SIZE) return Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE;
    if (proof_size == 0) return Sp1AnnexError::EMPTY_PROOF;

    const Span<const unsigned char> guest_vkey_hash = annex.subspan(23, 32);
    if (std::all_of(guest_vkey_hash.begin(), guest_vkey_hash.end(), [](unsigned char byte) { return byte == 0; })) {
        return Sp1AnnexError::ZERO_GUEST_VKEY;
    }

    const uint64_t expected_size = uint64_t{SP1_ANNEX_HEADER_SIZE} + public_values_size + proof_size;
    if (expected_size != annex.size()) return Sp1AnnexError::LENGTH_MISMATCH;

    result.statement_kind = static_cast<Sp1StatementKind>(annex[11]);
    result.guest_vkey_hash = guest_vkey_hash;
    result.public_values = annex.subspan(SP1_ANNEX_HEADER_SIZE, public_values_size);
    result.proof = annex.subspan(SP1_ANNEX_HEADER_SIZE + public_values_size, proof_size);
    return Sp1AnnexError::OK;
}

inline const char* Sp1AnnexErrorString(Sp1AnnexError error)
{
    switch (error) {
    case Sp1AnnexError::OK: return "ok";
    case Sp1AnnexError::NOT_USDD: return "not a USDD annex";
    case Sp1AnnexError::TOO_LARGE: return "annex exceeds 512 KiB";
    case Sp1AnnexError::TRUNCATED: return "truncated header";
    case Sp1AnnexError::BAD_MAGIC: return "invalid magic";
    case Sp1AnnexError::BAD_VERSION: return "unsupported envelope version";
    case Sp1AnnexError::BAD_PROOF_SYSTEM: return "unsupported proof system";
    case Sp1AnnexError::BAD_STATEMENT_KIND: return "unsupported statement kind";
    case Sp1AnnexError::BAD_DIGEST_MODE: return "unsupported public digest mode";
    case Sp1AnnexError::BAD_FLAGS: return "nonzero reserved flags";
    case Sp1AnnexError::EMPTY_PUBLIC_VALUES: return "empty public values";
    case Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE: return "public values exceed 16 KiB";
    case Sp1AnnexError::EMPTY_PROOF: return "empty proof";
    case Sp1AnnexError::ZERO_GUEST_VKEY: return "zero guest verification-key hash";
    case Sp1AnnexError::LENGTH_MISMATCH: return "declared lengths do not match annex";
    }
    return "unknown USDD annex error";
}

inline Sp1ConsensusGateResult GateUsddSp1ProofAnnex(Span<const unsigned char> annex, bool has_authenticated_bmm_context)
{
    if (!IsUsddSp1ProofAnnex(annex)) return Sp1ConsensusGateResult::NOT_USDD;
    Sp1ProofAnnexView parsed;
    if (ParseUsddSp1ProofAnnex(annex, parsed) != Sp1AnnexError::OK) {
        return Sp1ConsensusGateResult::MALFORMED;
    }
    if (!has_authenticated_bmm_context) return Sp1ConsensusGateResult::BMM_CONTEXT_MISSING;
    return Sp1ConsensusGateResult::VERIFIER_UNAVAILABLE;
}

} // namespace usdd

#endif // BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
