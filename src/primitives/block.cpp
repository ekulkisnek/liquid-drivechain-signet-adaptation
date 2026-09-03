// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>


bool g_con_blockheightinheader = false;
bool g_signed_blocks = false;

std::string CProof::ToString() const
{
    return strprintf("CProof(challenge=%s, solution=%s)",
                     HexStr(challenge), HexStr(solution));
}

// ELEMENTS: GetHash manually implemented for CBlockHeader.
// SER_GETHASH removed in #28508 so CProof now always serializes `solution`.
// Only include `challenge` of CProof here, and no signblock witness
uint256 CBlockHeader::GetHash() const
{
    HashWriter s{};
    const bool has_withdrawal_bundle_hash = g_con_elementsmode &&
        !hashWithdrawalBundle.IsNull();
    // Bits 16--20 are ordinary BIP9/unknown-version bits on Bitcoin-mode
    // networks. They acquire ECX/BMM serialization meaning only on an
    // Elements-mode chain, where those bit assignments are reserved by
    // this consensus implementation.
    const bool has_bmm_proof = g_con_elementsmode &&
        (static_cast<uint32_t>(this->nVersion) & BMM_PROOF_HF_MASK) != 0;
    const bool has_exchange_state = g_con_elementsmode &&
        (static_cast<uint32_t>(this->nVersion) & EXCHANGE_STATE_HF_MASK) != 0;
    const bool has_forced_inbox = g_con_elementsmode &&
        (static_cast<uint32_t>(this->nVersion) & FORCED_INBOX_HF_MASK) != 0;
    const bool has_deposit_inbox = g_con_elementsmode &&
        (static_cast<uint32_t>(this->nVersion) & DEPOSIT_INBOX_HF_MASK) != 0;
    const bool has_inbox_cursors = g_con_elementsmode &&
        (static_cast<uint32_t>(this->nVersion) & INBOX_CURSOR_HF_MASK) != 0;

    // Detect dynamic federation block serialization using "HF bit",
    // or the signed bit which is invalid in Bitcoin
    bool is_dyna = false;
    int32_t nVersion = this->nVersion;
    if (g_con_elementsmode) {
        nVersion = static_cast<int32_t>(
            static_cast<uint32_t>(nVersion) &
            ~(DYNAFED_HF_MASK | WITHDRAWAL_BUNDLE_HF_MASK));
    }
    if (g_con_elementsmode && !m_dynafed_params.IsNull()) {
        nVersion |= DYNAFED_HF_MASK;
        is_dyna = true;
    }
    if (has_withdrawal_bundle_hash) {
        nVersion |= WITHDRAWAL_BUNDLE_HF_MASK;
    }
    s << (nVersion);
    s << hashPrevBlock;
    s << hashMerkleRoot;
    if (has_withdrawal_bundle_hash) s << hashWithdrawalBundle;
    if (has_bmm_proof) s << hashBmmProof;
    s << nTime;

    if (is_dyna) {
        s << block_height;
        s << m_dynafed_params;
    } else {
        if (g_con_blockheightinheader) {
            s << block_height;
        }
        if (g_signed_blocks) {
            s << proof.challenge;
        } else {
            s << nBits;
            s << nNonce;
        }
    }
    if (has_exchange_state) s << hashExchangeStateRoot;
    if (has_forced_inbox) s << hashForcedInboxRoot;
    if (has_deposit_inbox) s << hashDepositInboxRoot;
    if (has_forced_inbox && has_deposit_inbox) s << ecxParentHeight;
    if (has_inbox_cursors) {
        s << forcedProcessedCursor;
        s << depositProcessedCursor;
        s << sourceBacklogOldestParentHeight;
    }
    return s.GetHash();
}

uint256 CBlockHeader::GetBmmCriticalHash() const
{
    CBlockHeader critical_header{*this};
    critical_header.hashBmmProof.SetNull();
    return critical_header.GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, critical=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, hashWithdrawalBundle=%s, hashBmmProof=%s, hashExchangeStateRoot=%s, hashForcedInboxRoot=%s, hashDepositInboxRoot=%s, ecxParentHeight=%u, forcedProcessedCursor=%llu, depositProcessedCursor=%llu, sourceBacklogOldestParentHeight=%llu, nTime=%u, nBits=%08x, nNonce=%u, proof=%u, vtx=%u)\n",
        GetHash().ToString(),
        GetBmmCriticalHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashWithdrawalBundle.ToString(),
        hashBmmProof.ToString(),
        hashExchangeStateRoot.ToString(),
        hashForcedInboxRoot.ToString(),
        hashDepositInboxRoot.ToString(),
        ecxParentHeight,
        static_cast<unsigned long long>(forcedProcessedCursor),
        static_cast<unsigned long long>(depositProcessedCursor),
        static_cast<unsigned long long>(sourceBacklogOldestParentHeight),
        nTime, nBits, nNonce, proof.ToString(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

uint256 DynaFedParamEntry::CalculateRoot() const
{
    if (m_serialize_type == 0) {
        return uint256();
    }

    std::vector<uint256> compact_leaves;
    compact_leaves.push_back((HashWriter{} << m_signblockscript).GetHash());
    compact_leaves.push_back((HashWriter{} << m_signblock_witness_limit).GetHash());
    uint256 compact_root(ComputeFastMerkleRoot(compact_leaves));

    uint256 extra_root;
    if (m_serialize_type ==1 ) {
        // It's pruned, take the stored value
        extra_root = m_elided_root;
    } else if (m_serialize_type == 2) {
        // It's unpruned, compute the node value
        extra_root = CalculateExtraRoot();
    }

    std::vector<uint256> leaves;
    leaves.push_back(compact_root);
    leaves.push_back(extra_root);
    return ComputeFastMerkleRoot(leaves);
}

uint256 DynaFedParamEntry::CalculateExtraRoot() const
{
    std::vector<uint256> extra_leaves;
    extra_leaves.push_back((HashWriter{} << m_fedpeg_program).GetHash());
    extra_leaves.push_back((HashWriter{} << m_fedpegscript).GetHash());
    extra_leaves.push_back((HashWriter{} << m_extension_space).GetHash());
    return ComputeFastMerkleRoot(extra_leaves);
}

uint256 DynaFedParams::CalculateRoot() const
{
    if (IsNull()) {
        return uint256();
    }

    std::vector<uint256> leaves;
    leaves.push_back(m_current.CalculateRoot());
    leaves.push_back(m_proposed.CalculateRoot());
    return ComputeFastMerkleRoot(leaves);
}
