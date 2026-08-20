// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_bmm.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <hash.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace drivechain {
namespace {

const uint256 PUBLIC_SIDECHAIN_BLOCK_1{
    uint256S("942f31cb89241342064af42a0367405eef490061d2ffe259a6f34d4939dee543")};
const uint256 PUBLIC_SIDECHAIN_BLOCK_2{
    uint256S("ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998")};
const COutPoint BMM_STATE_OUTPOINT{
    uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9"),
    0};
const std::vector<unsigned char> BMM_STATE_MARKER{
    'd', 'r', 'i', 'v', 'e', 'c', 'h', 'a', 'i', 'n', '-', 'b', 'm', 'm', '-', 'v', '1'};
constexpr std::array<unsigned char, 4> SIGNET_HEADER{{0xec, 0xc7, 0xda, 0xa2}};
constexpr std::array<unsigned char, 4> M8_MAGIC{{0xd1, 0x61, 0x73, 0x68}};
constexpr unsigned int SIGNET_SCRIPT_FLAGS{
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_NULLDUMMY};

const BmmConsensus LAYER_TWO_LABS_CONSENSUS{
    uint256S("00000377ae000000000000000000000000000000000000000000000000000000"),
    14 * 24 * 60 * 60,
    10 * 60,
    [] {
        const std::vector<unsigned char> challenge{
            ParseHex("00148835832e28c816b7acd8fdb19772ab2199603a56")};
        return CScript(challenge.begin(), challenge.end());
    }(),
    BMM_SIDECHAIN_SLOT,
    MAX_BMM_PROOF_ENTRIES,
    MAX_BMM_PROOF_BYTES};

const BmmL1State LAYER_TWO_LABS_INITIAL_STATE{
    uint256S("0000031bb69e844ed1ebd48cc0ab6cee90de29fb98ff7fb439d49b0b19747665"),
    6400,
    1784826005,
    0x1e0376cc,
    6048,
    1784614805,
    {
        1784820005,
        1784820605,
        1784821205,
        1784821805,
        1784822405,
        1784823005,
        1784823605,
        1784824205,
        1784824805,
        1784825405,
        1784826005,
    }};

template <typename T>
bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
        stream >> value;
        return stream.empty();
    } catch (...) {
        return false;
    }
}

template <typename T>
std::vector<unsigned char> SerializeValue(const T& value, int version = PROTOCOL_VERSION)
{
    CDataStream stream(SER_NETWORK, version);
    stream << value;
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

bool ValidState(const BmmL1State& state, const BmmConsensus& consensus, std::string& error)
{
    const int64_t interval = consensus.DifficultyAdjustmentInterval();
    if (state.block_hash.IsNull() ||
        state.height == 0 ||
        state.block_time == 0 ||
        state.n_bits == 0 ||
        interval <= 0 ||
        state.period_start_height > state.height ||
        state.period_start_height % interval != 0 ||
        state.height - state.period_start_height >= static_cast<uint32_t>(interval) ||
        state.period_start_time == 0 ||
        state.recent_times.size() != 11 ||
        state.recent_times.back() != state.block_time) {
        error = "BMM parent-chain state is malformed";
        return false;
    }
    return true;
}

uint32_t MedianTimePast(const std::vector<uint32_t>& times)
{
    std::vector<uint32_t> sorted{times};
    std::sort(sorted.begin(), sorted.end());
    return sorted[sorted.size() / 2];
}

uint32_t ExpectedNextBits(
    const BmmL1State& previous,
    const Sidechain::Bitcoin::CBlockHeader& header,
    const BmmConsensus& consensus)
{
    const int64_t interval = consensus.DifficultyAdjustmentInterval();
    if ((static_cast<int64_t>(previous.height) + 1) % interval != 0) {
        return previous.n_bits;
    }

    int64_t actual_timespan =
        static_cast<int64_t>(previous.block_time) - previous.period_start_time;
    actual_timespan = std::max(consensus.target_timespan / 4, actual_timespan);
    actual_timespan = std::min(consensus.target_timespan * 4, actual_timespan);

    arith_uint256 next;
    next.SetCompact(previous.n_bits);
    next *= actual_timespan;
    next /= consensus.target_timespan;
    const arith_uint256 limit = UintToArith256(consensus.pow_limit);
    if (next > limit) next = limit;
    return next.GetCompact();
}

bool CheckParentProofOfWork(
    const Sidechain::Bitcoin::CBlockHeader& header,
    const BmmConsensus& consensus,
    std::string& error)
{
    bool negative{false};
    bool overflow{false};
    arith_uint256 target;
    target.SetCompact(header.nBits, &negative, &overflow);
    if (negative || target == 0 || overflow ||
        target > UintToArith256(consensus.pow_limit) ||
        UintToArith256(header.GetHash()) > target) {
        error = "BMM proof contains an invalid parent-chain proof-of-work header";
        return false;
    }
    return true;
}

int WitnessCommitmentIndex(const Sidechain::Bitcoin::CMutableTransaction& coinbase)
{
    int result{-1};
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        const CScript& script = coinbase.vout[i].scriptPubKey;
        if (script.size() >= 38 &&
            script[0] == OP_RETURN &&
            script[1] == 0x24 &&
            script[2] == 0xaa &&
            script[3] == 0x21 &&
            script[4] == 0xa9 &&
            script[5] == 0xed) {
            result = i;
        }
    }
    return result;
}

bool FetchAndClearSignetSolution(CScript& witness_commitment, std::vector<unsigned char>& result)
{
    CScript replacement;
    bool found{false};
    result.clear();

    opcodetype opcode;
    CScript::const_iterator cursor = witness_commitment.begin();
    std::vector<unsigned char> pushdata;
    while (witness_commitment.GetOp(cursor, opcode, pushdata)) {
        if (!pushdata.empty()) {
            if (!found &&
                pushdata.size() > SIGNET_HEADER.size() &&
                std::equal(SIGNET_HEADER.begin(), SIGNET_HEADER.end(), pushdata.begin())) {
                result.insert(
                    result.end(),
                    pushdata.begin() + SIGNET_HEADER.size(),
                    pushdata.end());
                pushdata.erase(
                    pushdata.begin() + SIGNET_HEADER.size(),
                    pushdata.end());
                found = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }
    if (cursor != witness_commitment.end()) return false;
    if (found) witness_commitment = replacement;
    return true;
}

uint256 BitcoinWitnessV0SignatureHash(
    const CScript& script_code,
    const Sidechain::Bitcoin::CTransaction& transaction,
    const unsigned int input_index,
    const int hash_type)
{
    uint256 hash_prevouts;
    uint256 hash_sequence;
    uint256 hash_outputs;
    const int base_type = hash_type & 0x1f;

    if (!(hash_type & SIGHASH_ANYONECANPAY)) {
        CHashWriter writer(SER_GETHASH, 0);
        for (const auto& input : transaction.vin) writer << input.prevout;
        hash_prevouts = writer.GetHash();
    }
    if (!(hash_type & SIGHASH_ANYONECANPAY) &&
        base_type != SIGHASH_SINGLE &&
        base_type != SIGHASH_NONE) {
        CHashWriter writer(SER_GETHASH, 0);
        for (const auto& input : transaction.vin) writer << input.nSequence;
        hash_sequence = writer.GetHash();
    }
    if (base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        CHashWriter writer(SER_GETHASH, 0);
        for (const auto& output : transaction.vout) writer << output;
        hash_outputs = writer.GetHash();
    } else if (base_type == SIGHASH_SINGLE && input_index < transaction.vout.size()) {
        hash_outputs = (CHashWriter(SER_GETHASH, 0) << transaction.vout[input_index]).GetHash();
    }

    CHashWriter writer(SER_GETHASH, 0);
    writer << transaction.nVersion;
    writer << hash_prevouts;
    writer << hash_sequence;
    writer << transaction.vin[input_index].prevout;
    writer << script_code;
    writer << int64_t{0};
    writer << transaction.vin[input_index].nSequence;
    writer << hash_outputs;
    writer << transaction.nLockTime;
    writer << hash_type;
    return writer.GetHash();
}

class BitcoinSignatureChecker final : public BaseSignatureChecker
{
private:
    const Sidechain::Bitcoin::CTransaction& m_transaction;
    const unsigned int m_input_index;

public:
    BitcoinSignatureChecker(
        const Sidechain::Bitcoin::CTransaction& transaction,
        const unsigned int input_index)
        : m_transaction{transaction}, m_input_index{input_index}
    {
    }

    bool CheckECDSASignature(
        const std::vector<unsigned char>& signature_with_type,
        const std::vector<unsigned char>& public_key,
        const CScript& script_code,
        const SigVersion sigversion,
        unsigned int) const override
    {
        if (sigversion != SigVersion::WITNESS_V0 ||
            signature_with_type.empty() ||
            m_input_index >= m_transaction.vin.size()) {
            return false;
        }
        const CPubKey pubkey{public_key};
        if (!pubkey.IsValid()) return false;

        std::vector<unsigned char> signature{signature_with_type};
        const int hash_type = signature.back();
        signature.pop_back();
        return pubkey.Verify(
            BitcoinWitnessV0SignatureHash(
                script_code,
                m_transaction,
                m_input_index,
                hash_type),
            signature);
    }
};

bool CheckSignetSolution(
    const Sidechain::Bitcoin::CMutableTransaction& original_coinbase,
    Sidechain::Bitcoin::CMerkleBlock proof,
    const BmmConsensus& consensus,
    std::string& error)
{
    Sidechain::Bitcoin::CMutableTransaction modified_coinbase{original_coinbase};
    const int commitment_index = WitnessCommitmentIndex(modified_coinbase);
    if (commitment_index < 0) {
        error = "BMM parent block has no Bitcoin witness commitment";
        return false;
    }

    std::vector<unsigned char> signet_solution;
    if (!FetchAndClearSignetSolution(
            modified_coinbase.vout[commitment_index].scriptPubKey,
            signet_solution)) {
        error = "BMM parent block has a malformed signet commitment script";
        return false;
    }

    Sidechain::Bitcoin::CMutableTransaction transaction_to_spend;
    transaction_to_spend.nVersion = 0;
    transaction_to_spend.nLockTime = 0;
    transaction_to_spend.vin.emplace_back(
        Sidechain::Bitcoin::COutPoint(),
        CScript(OP_0),
        0);
    transaction_to_spend.vout.emplace_back(0, consensus.signet_challenge);

    Sidechain::Bitcoin::CMutableTransaction transaction_spending;
    transaction_spending.nVersion = 0;
    transaction_spending.nLockTime = 0;
    transaction_spending.vin.emplace_back(
        Sidechain::Bitcoin::COutPoint(),
        CScript(),
        0);
    transaction_spending.vout.emplace_back(0, CScript(OP_RETURN));

    if (!signet_solution.empty()) {
        try {
            CDataStream stream(signet_solution, SER_NETWORK, INIT_PROTO_VERSION);
            stream >> transaction_spending.vin[0].scriptSig;
            stream >> transaction_spending.vin[0].scriptWitness.stack;
            if (!stream.empty()) {
                error = "BMM parent block signet solution contains trailing data";
                return false;
            }
        } catch (...) {
            error = "BMM parent block signet solution cannot be decoded";
            return false;
        }
    }

    std::vector<uint256> matches;
    std::vector<unsigned int> indices;
    const uint256 modified_merkle_root = proof.txn.ExtractMatchesWithReplacement(
        matches,
        indices,
        0,
        modified_coinbase.GetHash());
    if (modified_merkle_root.IsNull() ||
        matches.size() != 1 ||
        indices.size() != 1 ||
        indices[0] != 0 ||
        matches[0] != original_coinbase.GetHash()) {
        error = "BMM signet proof does not authenticate exactly the coinbase";
        return false;
    }

    std::vector<unsigned char> block_data;
    CVectorWriter writer(SER_NETWORK, INIT_PROTO_VERSION, block_data, 0);
    writer << proof.header.nVersion;
    writer << proof.header.hashPrevBlock;
    writer << modified_merkle_root;
    writer << proof.header.nTime;
    transaction_to_spend.vin[0].scriptSig << block_data;
    transaction_spending.vin[0].prevout = {
        transaction_to_spend.GetHash(),
        0};

    const Sidechain::Bitcoin::CTransaction immutable_to_spend{
        transaction_to_spend};
    const Sidechain::Bitcoin::CTransaction immutable_spending{
        transaction_spending};
    const BitcoinSignatureChecker checker{immutable_spending, 0};
    if (!VerifyScript(
            immutable_spending.vin[0].scriptSig,
            immutable_to_spend.vout[0].scriptPubKey,
            &immutable_spending.vin[0].scriptWitness,
            SIGNET_SCRIPT_FLAGS,
            checker)) {
        error = "BMM parent block signet solution is invalid";
        return false;
    }
    return true;
}

bool ExtractM8Commitment(
    const Sidechain::Bitcoin::CMutableTransaction& coinbase,
    const int sidechain_slot,
    uint256& commitment,
    std::string& error)
{
    bool found{false};
    for (const auto& output : coinbase.vout) {
        CScript::const_iterator cursor = output.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) || opcode != OP_RETURN) continue;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) ||
            opcode > OP_PUSHDATA4 ||
            data.size() != 37 ||
            cursor != output.scriptPubKey.end() ||
            !std::equal(M8_MAGIC.begin(), M8_MAGIC.end(), data.begin()) ||
            data[4] != sidechain_slot) {
            continue;
        }
        if (found) {
            error = "BMM successor coinbase contains multiple M8 commitments for slot 24";
            return false;
        }
        commitment = uint256S(HexStr(Span<const unsigned char>{data}.subspan(5)));
        found = true;
    }
    if (!found) error = "BMM successor coinbase has no M8 commitment for slot 24";
    return found;
}

bool ExtractSidechainParentHash(
    const CBlock& block,
    uint256& parent_hash,
    std::string& error)
{
    if (block.vtx.empty()) {
        error = "sidechain block has no coinbase transaction";
        return false;
    }
    bool found{false};
    for (const CTxOut& output : block.vtx[0]->vout) {
        CScript::const_iterator cursor = output.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) || opcode != OP_RETURN) continue;
        if (!output.scriptPubKey.GetOp(cursor, opcode, data) ||
            opcode > OP_PUSHDATA4 ||
            data.size() != 32 ||
            cursor != output.scriptPubKey.end()) {
            continue;
        }
        if (found) {
            error = "sidechain block has multiple L1 parent commitments";
            return false;
        }
        parent_hash = uint256{data};
        found = true;
    }
    if (!found) error = "sidechain block has no L1 parent commitment";
    return found;
}

CScript EncodeBmmState(const BmmL1State& state)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << BMM_STATE_MARKER << state;
    return CScript()
        << std::vector<unsigned char>(
            UCharCast(stream.data()),
            UCharCast(stream.data()) + stream.size())
        << OP_DROP
        << OP_FALSE;
}

bool DecodeBmmState(const Coin& coin, BmmL1State& state, std::string& error)
{
    if (coin.IsSpent() ||
        !coin.out.nAsset.IsExplicit() ||
        coin.out.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
        !coin.out.nValue.IsExplicit() ||
        coin.out.nValue.GetAmount() != 0) {
        error = "persisted BMM state has invalid asset or value encoding";
        return false;
    }
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!coin.out.scriptPubKey.GetOp(cursor, opcode, data) ||
        opcode > OP_PUSHDATA4 ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) ||
        opcode != OP_DROP ||
        !coin.out.scriptPubKey.GetOp(cursor, opcode) ||
        opcode != OP_FALSE ||
        cursor != coin.out.scriptPubKey.end()) {
        error = "persisted BMM state script is malformed";
        return false;
    }
    try {
        CDataStream stream(data, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> marker;
        stream >> marker >> state;
        if (!stream.empty() ||
            marker != BMM_STATE_MARKER ||
            !ValidState(state, LayerTwoLabsBmmConsensus(), error)) {
            if (error.empty()) error = "persisted BMM state payload is invalid";
            return false;
        }
    } catch (...) {
        error = "persisted BMM state payload cannot be decoded";
        return false;
    }
    return true;
}

void SetBmmState(CCoinsViewCache& view, const BmmL1State& state, const int height)
{
    view.SpendCoin(BMM_STATE_OUTPOINT);
    CTxOut output(
        Params().GetConsensus().pegged_asset,
        0,
        EncodeBmmState(state));
    view.AddCoin(
        BMM_STATE_OUTPOINT,
        Coin(std::move(output), std::max(height, 0), false),
        true);
}

} // namespace

const BmmConsensus& LayerTwoLabsBmmConsensus()
{
    return LAYER_TWO_LABS_CONSENSUS;
}

const BmmL1State& LayerTwoLabsInitialBmmState()
{
    return LAYER_TWO_LABS_INITIAL_STATE;
}

const uint256& LayerTwoLabsPublicSidechainBlock1()
{
    return PUBLIC_SIDECHAIN_BLOCK_1;
}

const uint256& LayerTwoLabsPublicSidechainBlock2()
{
    return PUBLIC_SIDECHAIN_BLOCK_2;
}

bool BmmProofRequiredAfter(const CBlockIndex* previous)
{
    return previous != nullptr &&
        (previous->GetBlockHash() == PUBLIC_SIDECHAIN_BLOCK_2 ||
         (static_cast<uint32_t>(previous->nVersion) &
          CBlockHeader::BMM_PROOF_HF_MASK) != 0);
}

bool CheckBmmHeader(
    const CBlockHeader& block,
    const CBlockIndex* previous,
    std::string& error)
{
    error.clear();
    if (!previous) return true;
    if (previous->GetBlockHash() == PUBLIC_SIDECHAIN_BLOCK_1 &&
        block.GetHash() != PUBLIC_SIDECHAIN_BLOCK_2) {
        error = "public-signet height 2 does not match its immutable checkpoint";
        return false;
    }

    const bool required = BmmProofRequiredAfter(previous);
    if (required && !block.HasBmmProof()) {
        error = "public-signet descendant does not signal deterministic BMM proof";
        return false;
    }
    if (!required && block.HasBmmProof()) {
        error = "deterministic BMM proof cannot activate outside the public-signet checkpoint";
        return false;
    }
    return true;
}

bool SerializeBmmProof(
    const BmmProof& proof,
    std::vector<unsigned char>& bytes,
    std::string& error)
{
    error.clear();
    try {
        bytes = SerializeValue(proof);
        if (bytes.empty() || bytes.size() > MAX_BMM_PROOF_BYTES) {
            error = "serialized BMM proof exceeds its consensus size bound";
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool DeserializeBmmProof(
    const std::vector<unsigned char>& bytes,
    BmmProof& proof,
    std::string& error)
{
    error.clear();
    if (bytes.empty() || bytes.size() > MAX_BMM_PROOF_BYTES) {
        error = "BMM proof is empty or exceeds its consensus size bound";
        return false;
    }
    if (!DeserializeExactly(bytes, proof) ||
        proof.version != BMM_PROOF_SCHEMA_VERSION ||
        proof.entries.empty() ||
        proof.entries.size() > MAX_BMM_PROOF_ENTRIES ||
        SerializeValue(proof) != bytes) {
        error = "BMM proof is malformed or non-canonical";
        return false;
    }
    return true;
}

uint256 BmmProofCommitment(const std::vector<unsigned char>& bytes)
{
    return Hash(bytes);
}

bool AttachBmmProof(CBlock& block, const BmmProof& proof, std::string& error)
{
    error.clear();
    if (!block.HasBmmProof()) {
        error = "cannot attach BMM proof without the header version bit";
        return false;
    }
    if (!SerializeBmmProof(proof, block.m_bmm_proof, error)) return false;
    block.hashBmmProof = BmmProofCommitment(block.m_bmm_proof);
    return true;
}

bool VerifyBmmProofEntries(
    const BmmProof& proof,
    const uint256& expected_critical_hash,
    const uint256& expected_parent_hash,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    error.clear();
    if (proof.version != BMM_PROOF_SCHEMA_VERSION ||
        proof.entries.empty() ||
        proof.entries.size() > consensus.max_entries ||
        !ValidState(proof.previous_state, consensus, error)) {
        if (error.empty()) error = "BMM proof envelope is invalid";
        return false;
    }

    BmmL1State state{proof.previous_state};
    Sidechain::Bitcoin::CMutableTransaction final_coinbase;
    Sidechain::Bitcoin::CBlockHeader final_header;
    for (size_t i = 0; i < proof.entries.size(); ++i) {
        const BmmProofEntry& entry = proof.entries[i];
        if (entry.coinbase_tx.empty() ||
            entry.coinbase_tx.size() > MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR ||
            entry.coinbase_proof.empty() ||
            entry.coinbase_proof.size() > MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR) {
            error = "BMM proof entry exceeds its transaction or Merkle proof bound";
            return false;
        }

        Sidechain::Bitcoin::CMutableTransaction coinbase;
        Sidechain::Bitcoin::CMerkleBlock merkle_proof;
        if (!DeserializeExactly(entry.coinbase_tx, coinbase) ||
            !DeserializeExactly(entry.coinbase_proof, merkle_proof) ||
            SerializeValue(coinbase) != entry.coinbase_tx ||
            SerializeValue(merkle_proof) != entry.coinbase_proof ||
            coinbase.vin.size() != 1 ||
            !coinbase.vin[0].prevout.IsNull()) {
            error = "BMM proof entry has a malformed or non-canonical coinbase proof";
            return false;
        }

        std::vector<uint256> matches;
        std::vector<unsigned int> indices;
        if (merkle_proof.txn.ExtractMatches(matches, indices) !=
                merkle_proof.header.hashMerkleRoot ||
            matches.size() != 1 ||
            indices.size() != 1 ||
            indices[0] != 0 ||
            matches[0] != coinbase.GetHash()) {
            error = "BMM Merkle proof does not authenticate exactly the parent coinbase";
            return false;
        }

        const auto& header = merkle_proof.header;
        if (header.hashPrevBlock != state.block_hash ||
            header.nBits != ExpectedNextBits(state, header, consensus) ||
            header.nTime <= MedianTimePast(state.recent_times) ||
            !CheckParentProofOfWork(header, consensus, error) ||
            !CheckSignetSolution(coinbase, merkle_proof, consensus, error)) {
            if (error.empty()) {
                error = "BMM parent header does not extend the authenticated state";
            }
            return false;
        }

        ++state.height;
        state.block_hash = header.GetHash();
        state.block_time = header.nTime;
        state.n_bits = header.nBits;
        state.recent_times.erase(state.recent_times.begin());
        state.recent_times.push_back(header.nTime);
        if (state.height % consensus.DifficultyAdjustmentInterval() == 0) {
            state.period_start_height = state.height;
            state.period_start_time = state.block_time;
        }
        if (i + 1 == proof.entries.size()) {
            final_coinbase = std::move(coinbase);
            final_header = header;
        }
    }

    if (final_header.hashPrevBlock != expected_parent_hash) {
        error = "BMM proof final header is not the successor of the committed L1 parent";
        return false;
    }
    uint256 mined_commitment;
    if (!ExtractM8Commitment(
            final_coinbase,
            consensus.sidechain_slot,
            mined_commitment,
            error)) {
        return false;
    }
    if (mined_commitment != expected_critical_hash) {
        error = "BMM successor commitment does not match the sidechain critical hash";
        return false;
    }

    next_state = std::move(state);
    return true;
}

bool VerifyBmmProof(
    const CBlock& block,
    const BmmL1State& expected_previous,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    error.clear();
    if (!block.HasBmmProof() ||
        block.hashBmmProof.IsNull() ||
        block.m_bmm_proof.empty() ||
        block.m_bmm_proof.size() > consensus.max_proof_bytes ||
        BmmProofCommitment(block.m_bmm_proof) != block.hashBmmProof) {
        error = "sidechain block does not commit its exact BMM proof bytes";
        return false;
    }
    BmmProof proof;
    if (!DeserializeBmmProof(block.m_bmm_proof, proof, error)) return false;
    if (!(proof.previous_state == expected_previous)) {
        error = "BMM proof does not extend the locally authenticated parent-chain state";
        return false;
    }
    uint256 parent_hash;
    if (!ExtractSidechainParentHash(block, parent_hash, error)) return false;
    return VerifyBmmProofEntries(
        proof,
        block.GetBmmCriticalHash(),
        parent_hash,
        next_state,
        error,
        consensus);
}

bool GetBmmState(
    const CCoinsViewCache& view,
    BmmL1State& state,
    std::string* error)
{
    const Coin& coin = view.AccessCoin(BMM_STATE_OUTPOINT);
    if (coin.IsSpent()) return false;
    std::string decode_error;
    if (!DecodeBmmState(coin, state, decode_error)) {
        if (error) *error = decode_error;
        return false;
    }
    return true;
}

bool GetBmmParentContext(
    const BmmL1State& state,
    BmmParentContext& context,
    std::string& error)
{
    error.clear();
    context = {};
    if (!ValidState(state, LayerTwoLabsBmmConsensus(), error)) return false;
    const uint32_t median_time_past{MedianTimePast(state.recent_times)};
    if (median_time_past == 0) {
        error = "authenticated BMM parent median time past is zero";
        return false;
    }
    context.block_hash = state.block_hash;
    context.height = state.height;
    context.median_time_past = median_time_past;
    return true;
}

bool GetEffectiveBmmState(
    const CCoinsViewCache& view,
    const CBlockIndex* previous,
    BmmL1State& state,
    std::string& error)
{
    std::string state_error;
    if (GetBmmState(view, state, &state_error)) return true;
    if (!state_error.empty()) {
        error = state_error;
        return false;
    }
    if (previous && previous->GetBlockHash() == PUBLIC_SIDECHAIN_BLOCK_2) {
        state = LAYER_TWO_LABS_INITIAL_STATE;
        return true;
    }
    error = "authenticated BMM parent-chain state is missing";
    return false;
}

bool ConnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    const bool allow_incomplete_candidate,
    std::string& error)
{
    if (block.GetHash() == PUBLIC_SIDECHAIN_BLOCK_2 &&
        previous &&
        previous->GetBlockHash() == PUBLIC_SIDECHAIN_BLOCK_1) {
        BmmL1State existing;
        std::string state_error;
        if (GetBmmState(view, existing, &state_error)) {
            error = "public BMM checkpoint cannot overwrite existing parent-chain state";
            return false;
        }
        if (!state_error.empty()) {
            error = state_error;
            return false;
        }
        SetBmmState(view, LAYER_TWO_LABS_INITIAL_STATE, height);
        return true;
    }

    if (!BmmProofRequiredAfter(previous) && !block.HasBmmProof()) return true;
    if (allow_incomplete_candidate &&
        block.HasBmmProof() &&
        block.hashBmmProof.IsNull() &&
        block.m_bmm_proof.empty()) {
        return true;
    }

    BmmL1State previous_state;
    if (!GetEffectiveBmmState(view, previous, previous_state, error)) return false;
    BmmL1State next_state;
    if (!VerifyBmmProof(
            block,
            previous_state,
            next_state,
            error,
            LAYER_TWO_LABS_CONSENSUS)) {
        return false;
    }
    SetBmmState(view, next_state, height);
    return true;
}

bool DisconnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error)
{
    if (block.GetHash() == PUBLIC_SIDECHAIN_BLOCK_2 &&
        previous &&
        previous->GetBlockHash() == PUBLIC_SIDECHAIN_BLOCK_1) {
        BmmL1State current;
        std::string state_error;
        if (GetBmmState(view, current, &state_error) &&
            current == LAYER_TWO_LABS_INITIAL_STATE) {
            if (!view.SpendCoin(BMM_STATE_OUTPOINT)) {
                error = "public BMM checkpoint state could not be removed";
                return false;
            }
            return true;
        }
        if (!state_error.empty()) error = state_error;
        else error = "public BMM checkpoint state is inconsistent during disconnect";
        return false;
    }
    if (!block.HasBmmProof()) return true;

    BmmProof proof;
    if (!DeserializeBmmProof(block.m_bmm_proof, proof, error)) return false;
    BmmL1State current;
    std::string state_error;
    if (!GetBmmState(view, current, &state_error)) {
        error = state_error.empty()
            ? "cannot disconnect BMM proof without authenticated state"
            : state_error;
        return false;
    }
    BmmL1State expected_next;
    uint256 parent_hash;
    if (!ExtractSidechainParentHash(block, parent_hash, error) ||
        !VerifyBmmProofEntries(
            proof,
            block.GetBmmCriticalHash(),
            parent_hash,
            expected_next,
            error,
            LAYER_TWO_LABS_CONSENSUS) ||
        !(current == expected_next)) {
        if (error.empty()) error = "BMM state is inconsistent during disconnect";
        return false;
    }
    SetBmmState(view, proof.previous_state, height - 1);
    return true;
}

} // namespace drivechain
