// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
#define BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H

#include <array>
#include <cstdint>
#include <limits>

/**
 * Frozen public identity of the sole built-in Elements Drivechain network.
 *
 * These values are intentionally collected in one dependency-free header so
 * startup gates, chain parameters, and wire codecs cannot silently drift.
 * Changing any value defines a different network and requires a new genesis.
 */
namespace ElementsDrivechainIdentity {

inline constexpr char NETWORK_ID[]{"elements"};
inline constexpr uint8_t SIDECHAIN_SLOT{24};

inline constexpr char P2P_MAGIC_DOMAIN[]{"ecash-elements-drivechain-p2p-v2"};
inline constexpr std::array<uint8_t, 4> P2P_MESSAGE_START{{0x2a, 0xc5, 0x9d, 0x38}};
inline constexpr uint16_t P2P_PORT{7046};
inline constexpr uint16_t RPC_PORT{7045};
inline constexpr uint16_t MAINCHAIN_RPC_PORT{38332};
inline constexpr uint16_t ONION_TARGET_PORT{37046};
inline constexpr char DATA_DIR[]{"elements-v1"};

// Canonical child coinbase commitment: OP_RETURN || PUSHBYTES_37 ||
// "ELMTP" || parent_hash_internal_bytes.
inline constexpr std::array<uint8_t, 5> PARENT_COMMITMENT_TAG{{'E', 'L', 'M', 'T', 'P'}};

inline constexpr uint8_t PUBKEY_ADDRESS_PREFIX{68};
inline constexpr uint8_t SCRIPT_ADDRESS_PREFIX{13};
inline constexpr uint8_t BLINDED_ADDRESS_PREFIX{6};
inline constexpr uint8_t PARENT_PUBKEY_ADDRESS_PREFIX{111};
inline constexpr uint8_t PARENT_SCRIPT_ADDRESS_PREFIX{196};

// First byte(s) of SHA256 over the documented ASCII derivation domains.
inline constexpr char WIF_PREFIX_DOMAIN[]{"ecash-elements-drivechain-wif-v1"};
inline constexpr uint8_t SECRET_KEY_PREFIX{0x37};
inline constexpr char EXT_PUBLIC_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extpub-v1"};
inline constexpr std::array<uint8_t, 4> EXT_PUBLIC_KEY_PREFIX{{0x18, 0x71, 0x7d, 0xf5}};
inline constexpr char EXT_SECRET_KEY_PREFIX_DOMAIN[]{"ecash-elements-drivechain-extprv-v1"};
inline constexpr std::array<uint8_t, 4> EXT_SECRET_KEY_PREFIX{{0xb2, 0x63, 0xbd, 0x77}};

inline constexpr char BECH32_HRP[]{"elements"};
inline constexpr char BLECH32_HRP[]{"elementsl"};
inline constexpr char PARENT_BECH32_HRP[]{"tb"};
inline constexpr char PARENT_BLECH32_HRP[]{"tb"};

inline constexpr char PARENT_GENESIS[]{
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"};
inline constexpr char PARENT_POW_LIMIT[]{
    "00000377ae000000000000000000000000000000000000000000000000000000"};
inline constexpr char PARENT_SIGNET_CHALLENGE[]{
    "00148835832e28c816b7acd8fdb19772ab2199603a56"};
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

inline constexpr char HISTORICAL_PROPOSAL_DESCRIPTION_HEX[]{
    "0008456c656d656e7473426c6f636b73747265616d7320656c656d656e74732c"
    "20656e61626c696e672073696d706c6963697479207363726970745883560531"
    "f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74bb2b7b20f3"
    "fbc4baf50e9d39f58661c6168e279d4"};
inline constexpr char HISTORICAL_PROPOSAL_HASH[]{
    "169a8a4dc3b3c57df20620306d05486bedadf5aa2ddee2314ee1313bf5ccaab8"};
inline constexpr uint32_t HISTORICAL_PROPOSAL_HEIGHT{257};
inline constexpr char HISTORICAL_PROPOSAL_BLOCK_HASH[]{
    "000000093777d0d4b242a14af82db56cbabee4580cd9efe90320fd599bf1363e"};
inline constexpr uint32_t HISTORICAL_ACTIVATION_HEIGHT{263};
inline constexpr char HISTORICAL_ACTIVATION_BLOCK_HASH[]{
    "000002863c2d984711924c0514badf736fe2630b3d0426e92e8bd44366643484"};

inline constexpr uint32_t PARENT_CHECKPOINT_HEIGHT{5580};
inline constexpr char PARENT_CHECKPOINT_HASH[]{
    "000002a28e4f1c4599a7878da30ce0197be99ffd1d8e6d20d1a032011448011e"};
inline constexpr char PARENT_CHECKPOINT_CHAINWORK[]{
    "0000000000000000000000000000000000000000000000000000000649bd5c3f"};
inline constexpr char PARENT_CHECKPOINT_CTIP_TXID[]{
    "010a70b5ea6e545af594dad90ce1886387f5b4418577800644a65dd244e4edab"};
inline constexpr uint32_t PARENT_CHECKPOINT_CTIP_VOUT{0};
inline constexpr int64_t PARENT_CHECKPOINT_CTIP_VALUE{14400000};

inline constexpr uint16_t UNUSED_PROPOSAL_MAX_AGE{10};
inline constexpr uint16_t UNUSED_ACTIVATION_THRESHOLD{5};
inline constexpr uint16_t USED_PROPOSAL_MAX_AGE{10};
inline constexpr uint16_t USED_ACTIVATION_THRESHOLD{5};
inline constexpr uint32_t PARENT_REPLAY_VERSION{2};
inline constexpr uint32_t ANNEX_FEATURE_VERSION{1};

// Filled from the reproducible CElementsDrivechainParams construction. These
// strings are compared by the release-mode startup identity gate.
inline constexpr char PROTOCOL_MANIFEST_HASH[]{
    "66502fac27a0e0628ea950b056b55bab0cfd3974c24f964f9ffc3a11c42aeca8"};
inline constexpr char PROPOSAL_DESCRIPTION_HEX[]{
    "0008456c656d656e7473456c656d656e7473204472697665636861696e207631"
    "3b206e617469766520555344443b207265706c61792076323b2053696d706c69"
    "63697479206163746976653b20736c6f74203234a8ec2ac4113afc9f4f964fc2"
    "7439fd0cab5bb556b050a98e62e0a027ac2f5066f49d0cbac06d5a79012d6dc3"
    "43d96b5181a1d00d"};
inline constexpr char PROPOSAL_HASH[]{
    "b27b2b233f9db48be36046b72cac4876efd24a3055bbb0c25392f52e55042f98"};
inline constexpr char IDENTITY_COMMITMENT[]{
    "eafb6204c62b654a38ee2dc7b6b0ab9035f7d515807718e106f1c4cd5adc458a"};
inline constexpr char GENESIS_HASH[]{
    "d758e40eace8dc9c95a9dd44f7be84c241a4f8c5a3bd72812f2346a5801e3e9e"};
inline constexpr char GENESIS_MERKLE_ROOT[]{
    "39e74e4f8248c056e9765ba9d725b045daa2727f0352a89d8be0737b63c14823"};
inline constexpr char PEGGED_ASSET[]{
    "3ec133267a9eef1e20cfc949ef05f0d9eac944050d2151275bc9fd57a123fc3e"};

} // namespace ElementsDrivechainIdentity

#endif // BITCOIN_ELEMENTS_DRIVECHAIN_IDENTITY_H
