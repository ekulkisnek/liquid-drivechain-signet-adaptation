// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
#define BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H

#ifdef ELEMENTS_DRIVECHAIN_IDENTITY_SELECTED
#error "Multiple frozen Elements network identities included in one translation unit"
#endif
#define ELEMENTS_DRIVECHAIN_IDENTITY_SELECTED

#include <array>
#include <cstdint>
#include <limits>

/**
 * Frozen identity of the sole built-in Elements Drivechain network.
 *
 * These values are intentionally collected in one dependency-free header so
 * startup gates, chain parameters, and wire codecs cannot silently drift.
 * Changing any network/consensus value defines a different network and
 * requires a new genesis. The explicitly labelled enforcer compatibility pin
 * instead invalidates the derived replay store through its identity hash.
 */
namespace ElementsDrivechainIdentity {

inline constexpr char NETWORK_ID[]{"elements"};
inline constexpr uint8_t SIDECHAIN_SLOT{24};

// Explicit operator-authorized Betanet testing on activated Elements slot 24.
// The existing proposal describes replay v4; this distinct child uses Beta v5.
// Enabling this requires a new frozen child identity/genesis, not a runtime
// bypass. The exact parent proposal remains authenticated by normal replay.
inline constexpr bool BETANET_EXISTING_ELEMENTS_TEST_PROFILE{true};
inline constexpr char BETANET_EXISTING_ELEMENTS_PROPOSAL_HEX[]{"0008456c656d656e7473456c656d656e7473204472697665636861696e207631313b20706172616d65746572697a656420636f6e74726f6c6c65722070726f66696c653b207265706c61792076343b20616e6e65782076323b206f6e65204d362070657220706172656e7420626c6f636b3b207769746864726177616c20616363756d756c61746f722076313b2042495033303120636865636b706f696e742076313b2053696d706c6963697479206163746976653b20736c6f74203234e6092dd9fb9b1510a02ac535bbdde72f8b06716131c289337a0e0e592258d5fb28406cdece9df4823d01a88eca6b5793560fea88"};
inline constexpr char BETANET_EXISTING_ELEMENTS_PROPOSAL_HASH[]{
    "866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400"};

inline constexpr char P2P_MAGIC_DOMAIN[]{"ecash-elements-drivechain-betanet-slot24-p2p-v1"};
inline constexpr std::array<uint8_t, 4> P2P_MESSAGE_START{{0x3b, 0x5f, 0xf1, 0x8b}};
inline constexpr uint16_t P2P_PORT{7066};
inline constexpr uint16_t RPC_PORT{7065};
inline constexpr uint16_t MAINCHAIN_RPC_PORT{28532};
inline constexpr uint16_t ONION_TARGET_PORT{37066};
inline constexpr char DATA_DIR[]{"elements-betanet-slot24-v1"};

// Canonical child coinbase commitment: OP_RETURN || PUSHBYTES_37 ||
// "ELMTP" || parent_hash_internal_bytes.
inline constexpr std::array<uint8_t, 5> PARENT_COMMITMENT_TAG{{'E', 'L', 'M', 'T', 'P'}};

inline constexpr uint8_t PUBKEY_ADDRESS_PREFIX{68};
inline constexpr uint8_t SCRIPT_ADDRESS_PREFIX{13};
inline constexpr uint8_t BLINDED_ADDRESS_PREFIX{6};
inline constexpr uint8_t PARENT_PUBKEY_ADDRESS_PREFIX{0};
inline constexpr uint8_t PARENT_SCRIPT_ADDRESS_PREFIX{5};

// First byte(s) of SHA256 over the documented ASCII derivation domains.
inline constexpr char WIF_PREFIX_DOMAIN[]{"ecash-elements-drivechain-wif-v1"};
inline constexpr uint8_t SECRET_KEY_PREFIX{0x37};
inline constexpr char EXT_PUBLIC_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extpub-v1"};
inline constexpr std::array<uint8_t, 4> EXT_PUBLIC_KEY_PREFIX{{0x18, 0x71, 0x7d, 0xf5}};
inline constexpr char EXT_SECRET_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extprv-v1"};
inline constexpr std::array<uint8_t, 4> EXT_SECRET_KEY_PREFIX{{0xb2, 0x63, 0xbd, 0x77}};

inline constexpr char BECH32_HRP[]{"elements"};
inline constexpr char BLECH32_HRP[]{"elementsl"};
inline constexpr char PARENT_BECH32_HRP[]{"bc"};
inline constexpr char PARENT_BLECH32_HRP[]{"bc"};

inline constexpr char PARENT_GENESIS[]{
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};
inline constexpr char PARENT_POW_LIMIT[]{
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
inline constexpr char PARENT_SIGNET_CHALLENGE[]{
    ""};
// Base LayerTwo-Labs/bip300301_enforcer revision whose parent-consensus
// parsing and state transitions are mirrored by the authenticated replay.
inline constexpr char BIP300301_ENFORCER_REVISION[]{
    "0e27251ef351a522c72ab9ef079f75e06075390f"};
// Betanet compatibility rules mirrored in the accompanying enforcer:
// sequential authenticated M6/CTIP transitions and bundle reproposal.
// BIP300301_LOCAL_RULE_ID is raw SHA256 of this exact ASCII domain (no NUL).
inline constexpr char BIP300301_LOCAL_RULE_DOMAIN[]{
    "ELEMENTS_SLOT24_SEQUENTIAL_M6_REPROPOSAL_V1"};
inline constexpr char BIP300301_LOCAL_RULE_ID[]{"e3aef07fcbf7c2a8e1b51d1deba7d552df546079f4b4e49b966dd9b5d059fb39"};
inline constexpr uint32_t PEGIN_MIN_DEPTH{100};

inline constexpr char GENESIS_STYLE[]{"elements"};
inline constexpr uint8_t SIGNBLOCK_CHALLENGE_OPCODE{0x51}; // OP_TRUE
inline constexpr uint32_t MAX_BLOCK_SIGNATURE_SIZE{1};
inline constexpr uint32_t GENESIS_TIME{1784334600};
inline constexpr uint32_t GENESIS_NONCE{0};
inline constexpr uint32_t GENESIS_BITS{0x207fffff};
inline constexpr int32_t GENESIS_VERSION{1};

inline constexpr int TAPROOT_DEPLOYMENT_BIT{2};
inline constexpr int SIMPLICITY_DEPLOYMENT_BIT{21};
inline constexpr int64_t DEPLOYMENT_ALWAYS_ACTIVE{-1};
inline constexpr int64_t DEPLOYMENT_NO_TIMEOUT{std::numeric_limits<int64_t>::max()};
inline constexpr int DEPLOYMENT_MIN_ACTIVATION_HEIGHT{0};

inline constexpr char HISTORICAL_PROPOSAL_DESCRIPTION_HEX[]{""};
inline constexpr char HISTORICAL_PROPOSAL_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t HISTORICAL_PROPOSAL_HEIGHT{0};
inline constexpr char HISTORICAL_PROPOSAL_BLOCK_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t HISTORICAL_ACTIVATION_HEIGHT{0};
inline constexpr char HISTORICAL_ACTIVATION_BLOCK_HASH[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};

inline constexpr uint32_t PARENT_CHECKPOINT_HEIGHT{967679};
inline constexpr char PARENT_CHECKPOINT_HASH[]{
    "00000000000000000001b58cb69869f6067f0ecb3f2fe0f2263e62ba1ccb0c41"};
inline constexpr char PARENT_CHECKPOINT_CHAINWORK[]{
    "000000000000000000000000000000000000000148a384d49682843d3c74a5a0"};
inline constexpr char PARENT_CHECKPOINT_CTIP_TXID[]{
    "0000000000000000000000000000000000000000000000000000000000000000"};
inline constexpr uint32_t PARENT_CHECKPOINT_CTIP_VOUT{4294967295};
inline constexpr int64_t PARENT_CHECKPOINT_CTIP_VALUE{0};
// SHA256 of the canonical authenticated parent replay bootstrap state. Zero
// means the legacy genesis-derived bootstrap. A nonzero value is inseparable
// from the child identity and replay-store identity.
inline constexpr char PARENT_CHECKPOINT_BOOTSTRAP_STATE_COMMITMENT[]{
    "d03b3b5cb1d1afdb48645d258335fa8407a8ff5d71459568e4ddf419f75b6f5b"};

inline constexpr uint16_t UNUSED_PROPOSAL_MAX_AGE{2016};
inline constexpr uint16_t UNUSED_ACTIVATION_THRESHOLD{1008};
inline constexpr uint16_t USED_PROPOSAL_MAX_AGE{26300};
inline constexpr uint16_t USED_ACTIVATION_THRESHOLD{13150};
inline constexpr uint16_t WITHDRAWAL_BUNDLE_MAX_AGE{26300};
inline constexpr uint16_t WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD{13150};
inline constexpr uint32_t PARENT_REPLAY_VERSION{5};
inline constexpr uint32_t ANNEX_FEATURE_VERSION{2};
inline constexpr uint32_t WITHDRAWAL_ACCUMULATOR_VERSION{1};
// The BIP301 critical hash is an opaque 32-byte value to the parent enforcer.
// Elements v7 assigns that value a single consensus meaning: a SHA-256
// commitment to the exact child block and its validated withdrawal-accumulator
// transition. Changing either constant is a new, incompatible child network.
inline constexpr uint32_t WITHDRAWAL_BIP301_CHECKPOINT_VERSION{1};
inline constexpr char WITHDRAWAL_BIP301_CHECKPOINT_DOMAIN[]{
    "Elements/USDD/BIP301-checkpoint/v1"};

// Pre-genesis resource schedule for the sole built-in Elements network.  A
// measured stock SP1 v6.3.1 compressed proof does not fit the old 512 KiB
// annex lane.  The enlarged lane is therefore inseparable from this V7
// network identity and its new genesis/datadir. V7 activates this lane for
// prototype consensus testing; P99 and independent audit gates remain release
// requirements rather than mutable consensus switches.
inline constexpr uint32_t CONSENSUS_MAX_BLOCK_SERIALIZED_SIZE{6'000'000U};
inline constexpr uint32_t CONSENSUS_MAX_BLOCK_WEIGHT{6'000'000U};
inline constexpr uint32_t USDD_SP1_ANNEXES_PER_BLOCK{1U};
inline constexpr uint32_t USDD_SP1_PROOF_TX_MAX_WEIGHT{1'500'000U};
inline constexpr uint32_t USDD_SP1_ANNEX_MAX_BYTES{1'310'720U}; // 1.25 MiB
inline constexpr uint32_t USDD_SP1_PUBLIC_VALUES_MAX_BYTES{16U * 1024U};
inline constexpr uint32_t USDD_SP1_MEASURED_RAW_PROOF_BYTES{1'272'546U};
inline constexpr uint32_t USDD_SP1_MEASURED_PUBLIC_VALUES_BYTES{1'001U};
inline constexpr uint32_t USDD_SP1_MEASURED_ANNEX_BYTES{1'273'602U};
// Witness attribution for one annex item is CompactSize(payload) plus payload.
// A payload above 65535 bytes uses a five-byte CompactSize encoding.
inline constexpr uint32_t USDD_SP1_MEASURED_ANNEX_WEIGHT{1'273'607U};
inline constexpr uint32_t USDD_SP1_MAX_ANNEX_WEIGHT{1'310'725U};
inline constexpr uint32_t USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT{189'275U};
static_assert(USDD_SP1_PROOF_TX_MAX_WEIGHT * 4U <=
              CONSENSUS_MAX_BLOCK_WEIGHT);
static_assert(USDD_SP1_MEASURED_RAW_PROOF_BYTES +
                  USDD_SP1_MEASURED_PUBLIC_VALUES_BYTES + 55U ==
              USDD_SP1_MEASURED_ANNEX_BYTES);
static_assert(USDD_SP1_MEASURED_ANNEX_BYTES <=
              USDD_SP1_ANNEX_MAX_BYTES);
static_assert(USDD_SP1_MAX_ANNEX_WEIGHT <
              USDD_SP1_PROOF_TX_MAX_WEIGHT);
static_assert(USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT +
                  USDD_SP1_MAX_ANNEX_WEIGHT ==
              USDD_SP1_PROOF_TX_MAX_WEIGHT);

// V7 activates the verifier as a generic Elements consensus facility. The
// host pins the exact controller CMR, guest, verifier semantics, and resource
// schedule; the controller binds each nonzero inbound-mint domain to its
// authenticated on-chain configuration state. This avoids a cryptographic
// cycle in which a genesis-frozen deployment domain would itself depend on the
// Elements genesis and post-genesis issuance identities.
inline constexpr bool USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED{true};
inline constexpr uint32_t REQUIRED_USDD_SP1_VERIFIER_ABI_VERSION{1};
inline constexpr uint32_t REQUIRED_USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_VERSION{1};
inline constexpr std::array<uint8_t, 32> USDD_SP1_VERIFIER_SEMANTIC_IDENTITY{{
    0x6b, 0x02, 0x92, 0x57, 0x0f, 0xa1, 0x20, 0xae,
    0x88, 0x57, 0x43, 0xa3, 0x91, 0xeb, 0xa1, 0x8a,
    0x1e, 0x53, 0x04, 0x55, 0x28, 0x46, 0x48, 0xcf,
    0xde, 0x30, 0xdc, 0x28, 0xbf, 0x3b, 0x64, 0xa9,
}};

inline constexpr uint32_t USDD_SP1_PROOF_BUNDLE_VERSION{1};
inline constexpr char USDD_SP1_VERSION[]{"6.3.1"};
inline constexpr char USDD_SP1_GIT_COMMIT[]{
    "8252c2905ce32964df68248117015c61ebb854db"};
inline constexpr uint32_t USDD_SP1_COMPRESSED_CIRCUIT_VERSION{1};
inline constexpr uint32_t USDD_SP1_COMPRESSED_CODEC_VERSION{1};
inline constexpr char USDD_SP1_PROOF_MODE[]{"SP1Proof::Compressed"};
inline constexpr char USDD_SP1_PROOF_CODEC[]{
    "bincode-1.3.3;fixed-int;little-endian;reject-trailing-bytes"};
inline constexpr char USDD_SP1_PUBLIC_VALUES_DIGEST_MODE[]{"SHA256_ONLY"};
inline constexpr std::array<uint8_t, 32> USDD_SP1_RECURSION_CONSTANTS_COMMITMENT{{
    0x0f, 0x4d, 0x8d, 0x04, 0x95, 0xd4, 0x3e, 0x37,
    0x09, 0x80, 0x3b, 0x60, 0x06, 0x74, 0xe1, 0xe9,
    0x48, 0xa5, 0xcd, 0xcb, 0x16, 0xd1, 0x66, 0x39,
    0x45, 0xad, 0x83, 0x8d, 0xe5, 0xef, 0xad, 0xba,
}};

inline constexpr uint8_t USDD_SP1_ANNEX_ENVELOPE_VERSION{1};
inline constexpr uint8_t USDD_SP1_ANNEX_PROOF_SYSTEM{1};
inline constexpr uint8_t USDD_SP1_ANNEX_STATEMENT_KIND{3};
inline constexpr uint8_t USDD_SP1_ANNEX_DIGEST_MODE{1};
// Binding version 2 deliberately carries no genesis-global deployment domain.
// The exact generic controller derives a nonzero inboundMintDomainId from its
// committed configuration hash and verifies that same domain in the strict
// SP1 journal. The zero array below therefore means "no global domain" under
// version 2; it is not the version-0 preactivation sentinel.
inline constexpr uint32_t USDD_SP1_DEPLOYMENT_BINDING_VERSION{2};
inline constexpr std::array<uint8_t, 32> USDD_SP1_INBOUND_MINT_DOMAIN_ID{{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}};

inline constexpr uint16_t CURRENT_BMM_PARENT_MTP_JET_CATALOGUE_ITEM{51};
inline constexpr std::array<uint8_t, 3> CURRENT_BMM_PARENT_MTP_JET_ENCODING{{
    0x7c, 0x38, 0xcc,
}};
inline constexpr std::array<uint8_t, 32> CURRENT_BMM_PARENT_MTP_JET_CMR{{
    0x12, 0xdc, 0x3d, 0x4f, 0x22, 0x46, 0x68, 0x73,
    0xda, 0xaf, 0x83, 0xb1, 0x0e, 0x1c, 0xfa, 0x1e,
    0xa5, 0x51, 0xe2, 0x3a, 0xe7, 0xd0, 0xfb, 0xd6,
    0xd9, 0xda, 0x64, 0xce, 0x7e, 0x89, 0xa3, 0xe2,
}};
inline constexpr uint64_t CURRENT_BMM_PARENT_MTP_JET_COST_MWU{108};

inline constexpr uint16_t VERIFY_SP1_COMPRESSED_SHA256_JET_CATALOGUE_ITEM{52};
inline constexpr std::array<uint8_t, 3> VERIFY_SP1_COMPRESSED_SHA256_JET_ENCODING{{
    0x7c, 0x38, 0xd0,
}};
inline constexpr std::array<uint8_t, 32> VERIFY_SP1_COMPRESSED_SHA256_JET_CMR{{
    0x59, 0x5c, 0xfa, 0x3a, 0xdb, 0xc8, 0x3e, 0x61,
    0x69, 0x18, 0xa6, 0xa5, 0x14, 0x41, 0xba, 0x84,
    0x7f, 0x19, 0xfa, 0xf7, 0xe7, 0x7f, 0x3c, 0xb9,
    0x7d, 0x21, 0x31, 0x4e, 0x28, 0x92, 0x83, 0x99,
}};
inline constexpr uint64_t VERIFY_SP1_COMPRESSED_SHA256_JET_COST_MWU{900'007'720ULL};

// V11 commits the parameterized controller family before genesis. Concrete
// controller/anchor program identities are selected by, and authenticated
// from, the executed configuration-bound leaf; they are not global network
// allow-list entries.
inline constexpr bool V11_PARAMETERIZED_CONTROLLER_PROFILE{true};
inline constexpr std::array<uint8_t, 32> PARAMETERIZED_CONTROLLER_PROFILE_ID{{
    0x6f, 0xd5, 0xa5, 0xe5, 0x57, 0x69, 0x32, 0x0c,
    0xc1, 0xc6, 0xa4, 0x97, 0x64, 0x4d, 0x0b, 0xc7,
    0xa6, 0x42, 0xee, 0xd8, 0x44, 0x2a, 0xb1, 0x70,
    0x3a, 0xf3, 0x04, 0xcf, 0xac, 0x25, 0x3d, 0x25,
}};
// Retained solely by the explicitly parameterized historical V7/V8 helper
// tests. It is not serialized into, nor consulted by, the V11 identity/gate.
inline constexpr std::array<uint8_t, 32> HISTORICAL_V8_CONTROLLER_CMR{{
    0xa3, 0xbe, 0x18, 0x4f, 0x5f, 0xbf, 0xf9, 0x9b,
    0x3b, 0xb9, 0x61, 0xb2, 0x65, 0x05, 0x51, 0x9c,
    0xc1, 0xcd, 0x44, 0xfe, 0xc3, 0x31, 0x05, 0x7a,
    0x9a, 0xc0, 0xee, 0x12, 0x5b, 0x16, 0xb0, 0xa1,
}};
inline constexpr std::array<uint8_t, 32> USDD_SP1_GUEST_PROGRAM_ID{{
    0x4e, 0x44, 0xd1, 0x8d, 0x51, 0x2d, 0x56, 0x11,
    0x28, 0xda, 0xe5, 0x3d, 0x10, 0xbe, 0xe2, 0xb3,
    0x6b, 0xd5, 0x39, 0x0d, 0x1e, 0x4c, 0x4b, 0x72,
    0x68, 0x84, 0x64, 0xea, 0x54, 0x49, 0x43, 0xec,
}};
inline constexpr uint64_t USDD_SP1_GUEST_ELF_BYTES{527'432ULL};
inline constexpr std::array<uint8_t, 32> USDD_SP1_GUEST_ELF_SHA256{{
    0x19, 0x30, 0xe2, 0x4d, 0x92, 0x8f, 0x02, 0x42,
    0xe1, 0x08, 0x78, 0xa3, 0xe0, 0x51, 0x77, 0xa5,
    0xe5, 0x8e, 0x82, 0x75, 0xee, 0x0a, 0x54, 0xe4,
    0x71, 0xad, 0x81, 0x10, 0xd5, 0x76, 0x06, 0x13,
}};

// Exact generic withdrawal-accumulator codec committed by the protocol
// manifest and genesis. This pre-deployment index is deliberately not an
// authorizing USDD root by itself. This sole Elements network identity is
// final; the exact production asset ID and Ethereum vault ID must instead be
// frozen by the separate immutable USDD deployment manifest and vault.
inline constexpr std::array<uint8_t, 4> WITHDRAWAL_MAGIC{{'U', 'S', 'D', 'D'}};
inline constexpr uint8_t WITHDRAWAL_SCRIPT_PUSH_SIZE{65};
inline constexpr uint32_t WITHDRAWAL_PROTOCOL_VERSION{1};
inline constexpr uint8_t WITHDRAWAL_LEAF_PREFIX{0x00};
inline constexpr uint8_t WITHDRAWAL_NODE_PREFIX{0x01};
inline constexpr uint8_t WITHDRAWAL_TREE_DEPTH{64};
inline constexpr uint64_t USDD_UNITS_PER_USDT_MICRO{100};
inline constexpr uint64_t MAX_WITHDRAWAL_USDT_MICRO{20'000'000ULL * 1'000'000ULL};
inline constexpr std::array<uint8_t, 32> WITHDRAWAL_BURN_ID_DOMAIN{{
    0x58, 0x11, 0xf3, 0xff, 0x8b, 0x8f, 0x31, 0xfb,
    0x49, 0xff, 0xb9, 0x1a, 0xfa, 0xb1, 0x31, 0x97,
    0xc3, 0xd7, 0x2e, 0x92, 0x65, 0x49, 0xae, 0x29,
    0xdb, 0xda, 0x46, 0xc6, 0x99, 0x8a, 0x3e, 0x45,
}};
inline constexpr std::array<uint8_t, 32> WITHDRAWAL_LEAF_DOMAIN{{
    0xa2, 0x04, 0x23, 0x80, 0x92, 0x68, 0x79, 0x09,
    0x8c, 0x0f, 0x42, 0x3f, 0x49, 0xe3, 0xa0, 0x7a,
    0x12, 0x48, 0xed, 0x08, 0x53, 0x57, 0x93, 0xa4,
    0xa1, 0xc4, 0xaf, 0xe6, 0x2d, 0x99, 0x88, 0x69,
}};

// Filled from the reproducible CElementsDrivechainParams construction. These
// strings are compared by the release-mode startup identity gate.
inline constexpr char PROTOCOL_MANIFEST_HASH[]{"5c3d0dab899b95e05a47691bed1a0bdca87938faca69ab04985a4c43a970a673"};
inline constexpr char PROPOSAL_DESCRIPTION_HEX[]{"0008456c656d656e7473456c656d656e7473204472697665636861696e207631313b20706172616d65746572697a656420636f6e74726f6c6c65722070726f66696c653b207265706c61792076343b20616e6e65782076323b206f6e65204d362070657220706172656e7420626c6f636b3b207769746864726177616c20616363756d756c61746f722076313b2042495033303120636865636b706f696e742076313b2053696d706c6963697479206163746976653b20736c6f74203234e6092dd9fb9b1510a02ac535bbdde72f8b06716131c289337a0e0e592258d5fb28406cdece9df4823d01a88eca6b5793560fea88"};
inline constexpr char PROPOSAL_HASH[]{"866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400"};
inline constexpr char IDENTITY_COMMITMENT[]{"8e69c7b145bdf13b59d2866fbc8d8a167fdac4cb114666765a26c0bccbf95cde"};
inline constexpr char GENESIS_HASH[]{"a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"};
inline constexpr char GENESIS_MERKLE_ROOT[]{"4dfba0f3ac9d10a3dd44eb16f2925693b47787c4060bdf5b5bab2dd97f99505f"};
inline constexpr char PEGGED_ASSET[]{"5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8"};

} // namespace ElementsDrivechainIdentity

#endif // BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
