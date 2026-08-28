// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signet.h>

#include <array>
#include <cstdint>
#include <vector>

#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <span.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <uint256.h>

static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

static constexpr unsigned int BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY;

namespace Bitcoin = Sidechain::Bitcoin;

static bool FetchAndClearCommitmentSection(const Span<const uint8_t> header, CScript& witness_commitment, std::vector<uint8_t>& result)
{
    CScript replacement;
    bool found_header = false;
    result.clear();

    opcodetype opcode;
    CScript::const_iterator pc = witness_commitment.begin();
    std::vector<uint8_t> pushdata;
    while (witness_commitment.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (!found_header && pushdata.size() > (size_t)header.size() && Span{pushdata}.first(header.size()) == header) {
                // pushdata only counts if it has the header _and_ some data
                result.insert(result.end(), pushdata.begin() + header.size(), pushdata.end());
                pushdata.erase(pushdata.begin() + header.size(), pushdata.end());
                found_header = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }

    if (found_header) witness_commitment = replacement;
    return found_header;
}

static uint256 ComputeModifiedMerkleRoot(const CMutableTransaction& cb, const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0] = cb.GetHash();
    for (size_t s = 1; s < block.vtx.size(); ++s) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves));
}

std::optional<SignetTxs> SignetTxs::Create(const CBlock& block, const CScript& challenge)
{
    CMutableTransaction tx_to_spend;
    tx_to_spend.nVersion = 0;
    tx_to_spend.nLockTime = 0;
    tx_to_spend.vin.emplace_back(COutPoint(), CScript(OP_0), 0);
    tx_to_spend.vout.emplace_back(CAsset(), 0, challenge);

    CMutableTransaction tx_spending;
    tx_spending.nVersion = 0;
    tx_spending.nLockTime = 0;
    tx_spending.vin.emplace_back(COutPoint(), CScript(), 0);
    tx_spending.witness.vtxinwit.resize(1);
    tx_spending.vout.emplace_back(CAsset(), 0, CScript(OP_RETURN));

    // can't fill any other fields before extracting signet
    // responses from block coinbase tx

    // find and delete signet signature
    if (block.vtx.empty()) return std::nullopt; // no coinbase tx in block; invalid
    CMutableTransaction modified_cb(*block.vtx.at(0));

    const int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        return std::nullopt; // require a witness commitment
    }

    CScript& witness_commitment = modified_cb.vout.at(cidx).scriptPubKey;

    std::vector<uint8_t> signet_solution;
    if (!FetchAndClearCommitmentSection(SIGNET_HEADER, witness_commitment, signet_solution)) {
        // no signet solution -- allow this to support OP_TRUE as trivial block challenge
    } else {
        try {
            SpanReader v{SER_NETWORK, INIT_PROTO_VERSION, signet_solution};
            v >> tx_spending.vin[0].scriptSig;
            v >> tx_spending.witness.vtxinwit[0].scriptWitness.stack;
            if (!v.empty()) return std::nullopt; // extraneous data encountered
        } catch (const std::exception&) {
            return std::nullopt; // parsing error
        }
    }
    uint256 signet_merkle = ComputeModifiedMerkleRoot(modified_cb, block);

    std::vector<uint8_t> block_data;
    CVectorWriter writer(SER_NETWORK, INIT_PROTO_VERSION, block_data, 0);
    writer << block.nVersion;
    writer << block.hashPrevBlock;
    writer << signet_merkle;
    writer << block.nTime;
    tx_to_spend.vin[0].scriptSig << block_data;
    tx_spending.vin[0].prevout = COutPoint(tx_to_spend.GetHash(), 0);

    return SignetTxs{tx_to_spend, tx_spending};
}

// Signet block solution checker
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    if (block.GetHash() == consensusParams.hashGenesisBlock) {
        // genesis block solution is always valid
        return true;
    }

    const CScript challenge(consensusParams.signet_challenge.begin(), consensusParams.signet_challenge.end());
    const std::optional<SignetTxs> signet_txs = SignetTxs::Create(block, challenge);

    if (!signet_txs) {
        LogPrint(BCLog::VALIDATION, "CheckSignetBlockSolution: Errors in block (block solution parse failure)\n");
        return false;
    }

    const CScript& scriptSig = signet_txs->m_to_sign.vin[0].scriptSig;
    const CScriptWitness& witness = signet_txs->m_to_sign.witness.vtxinwit[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(signet_txs->m_to_sign, {signet_txs->m_to_spend.vout[0]});
    TransactionSignatureChecker sigcheck(&signet_txs->m_to_sign, /* nInIn= */ 0, /* amountIn= */ signet_txs->m_to_spend.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);

    if (!VerifyScript(scriptSig, signet_txs->m_to_spend.vout[0].scriptPubKey, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        LogPrint(BCLog::VALIDATION, "CheckSignetBlockSolution: Errors in block (block solution invalid)\n");
        return false;
    }
    return true;
}

namespace {

int GetBitcoinWitnessCommitmentIndex(const Bitcoin::CBlock& block)
{
    int commit_pos{-1};
    if (block.vtx.empty()) return commit_pos;
    for (size_t i = 0; i < block.vtx[0]->vout.size(); ++i) {
        const CScript& script = block.vtx[0]->vout[i].scriptPubKey;
        if (script.size() >= 38 && script[0] == OP_RETURN && script[1] == 0x24 &&
            script[2] == 0xaa && script[3] == 0x21 && script[4] == 0xa9 && script[5] == 0xed) {
            commit_pos = static_cast<int>(i);
        }
    }
    return commit_pos;
}

uint256 ComputeBitcoinModifiedMerkleRoot(const Bitcoin::CMutableTransaction& coinbase,
                                         const Bitcoin::CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.reserve(block.vtx.size());
    leaves.push_back(coinbase.GetHash());
    for (size_t i = 1; i < block.vtx.size(); ++i) leaves.push_back(block.vtx[i]->GetHash());
    return ComputeMerkleRoot(std::move(leaves));
}

uint256 BitcoinWitnessV0SignatureHash(const CScript& script_code,
                                      const Bitcoin::CTransaction& transaction,
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
    if (!(hash_type & SIGHASH_ANYONECANPAY) && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        CHashWriter writer(SER_GETHASH, 0);
        for (const auto& input : transaction.vin) writer << input.nSequence;
        hash_sequence = writer.GetHash();
    }
    if (base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        CHashWriter writer(SER_GETHASH, 0);
        for (const auto& output : transaction.vout) writer << output;
        hash_outputs = writer.GetHash();
    } else if (base_type == SIGHASH_SINGLE && input_index < transaction.vout.size()) {
        CHashWriter writer(SER_GETHASH, 0);
        writer << transaction.vout[input_index];
        hash_outputs = writer.GetHash();
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
    writer << static_cast<uint32_t>(hash_type);
    return writer.GetHash();
}

class BitcoinSignetSignatureChecker final : public BaseSignatureChecker
{
private:
    const Bitcoin::CTransaction& m_transaction;

public:
    explicit BitcoinSignetSignatureChecker(const Bitcoin::CTransaction& transaction)
        : m_transaction(transaction) {}

    bool CheckECDSASignature(const std::vector<unsigned char>& signature_with_hash_type,
                             const std::vector<unsigned char>& public_key,
                             const CScript& script_code,
                             const SigVersion sig_version,
                             const unsigned int flags) const override
    {
        if (sig_version != SigVersion::WITNESS_V0 || signature_with_hash_type.empty()) return false;
        ScriptError script_error{SCRIPT_ERR_OK};
        if (!CheckSignatureEncoding(signature_with_hash_type, flags, &script_error)) return false;

        CPubKey pubkey(public_key);
        if (!pubkey.IsValid()) return false;

        std::vector<unsigned char> signature(signature_with_hash_type.begin(), signature_with_hash_type.end() - 1);
        const int hash_type = signature_with_hash_type.back();
        const uint256 signature_hash = BitcoinWitnessV0SignatureHash(script_code, m_transaction, 0, hash_type);
        return pubkey.Verify(signature_hash, signature);
    }
};

bool SetSignetError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

} // namespace

bool CheckBitcoinSignetBlockSolution(const Bitcoin::CBlock& block,
                                     const CScript& challenge,
                                     const uint256& genesis_hash,
                                     std::string* error)
{
    if (block.GetHash() == genesis_hash) return true;
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        return SetSignetError(error, "parent signet block has no coinbase transaction");
    }

    const int commitment_index = GetBitcoinWitnessCommitmentIndex(block);
    if (commitment_index < 0) {
        return SetSignetError(error, "parent signet block has no witness commitment");
    }

    Bitcoin::CMutableTransaction modified_coinbase(*block.vtx[0]);
    CScript& witness_commitment = modified_coinbase.vout[commitment_index].scriptPubKey;
    std::vector<uint8_t> signet_solution;
    FetchAndClearCommitmentSection(SIGNET_HEADER, witness_commitment, signet_solution);

    Bitcoin::CMutableTransaction transaction_to_spend;
    transaction_to_spend.nVersion = 0;
    transaction_to_spend.nLockTime = 0;
    transaction_to_spend.vin.emplace_back(Bitcoin::COutPoint(), CScript(OP_0), 0);
    transaction_to_spend.vout.emplace_back(0, challenge);

    Bitcoin::CMutableTransaction transaction_to_sign;
    transaction_to_sign.nVersion = 0;
    transaction_to_sign.nLockTime = 0;
    transaction_to_sign.vin.emplace_back(Bitcoin::COutPoint(), CScript(), 0);
    transaction_to_sign.vout.emplace_back(0, CScript(OP_RETURN));

    if (!signet_solution.empty()) {
        try {
            SpanReader reader{SER_NETWORK, INIT_PROTO_VERSION, signet_solution};
            reader >> transaction_to_sign.vin[0].scriptSig;
            reader >> transaction_to_sign.vin[0].scriptWitness.stack;
            if (!reader.empty()) return SetSignetError(error, "parent signet solution has trailing bytes");
        } catch (const std::exception&) {
            return SetSignetError(error, "parent signet solution is not canonically encoded");
        }
    }

    const uint256 modified_merkle_root = ComputeBitcoinModifiedMerkleRoot(modified_coinbase, block);
    std::vector<uint8_t> block_data;
    CVectorWriter writer(SER_NETWORK, INIT_PROTO_VERSION, block_data, 0);
    writer << block.nVersion;
    writer << block.hashPrevBlock;
    writer << modified_merkle_root;
    writer << block.nTime;
    transaction_to_spend.vin[0].scriptSig << block_data;
    transaction_to_sign.vin[0].prevout = Bitcoin::COutPoint(transaction_to_spend.GetHash(), 0);

    const Bitcoin::CTransaction immutable_transaction{std::move(transaction_to_sign)};
    const BitcoinSignetSignatureChecker checker{immutable_transaction};
    ScriptError script_error{SCRIPT_ERR_OK};
    if (!VerifyScript(immutable_transaction.vin[0].scriptSig,
                      challenge,
                      &immutable_transaction.vin[0].scriptWitness,
                      BLOCK_SCRIPT_VERIFY_FLAGS,
                      checker,
                      &script_error)) {
        return SetSignetError(error, strprintf("parent signet solution failed challenge validation: %s", ScriptErrorString(script_error)));
    }
    return true;
}
