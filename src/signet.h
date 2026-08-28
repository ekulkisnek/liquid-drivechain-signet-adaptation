// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNET_H
#define BITCOIN_SIGNET_H

#include <consensus/params.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <primitives/transaction.h>

#include <optional>
#include <string>

/**
 * Extract signature and check whether a block has a valid solution
 */
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams);

/**
 * Verify BIP325 for a raw Bitcoin-format parent block.
 *
 * Elements keeps separate Bitcoin transaction primitives for peg proofs.  The
 * ordinary CheckSignetBlockSolution overload cannot be used for those blocks:
 * translating a Bitcoin transaction into an Elements transaction changes its
 * txid and therefore changes both the Merkle root and the signet sighash.
 */
bool CheckBitcoinSignetBlockSolution(const Sidechain::Bitcoin::CBlock& block,
                                     const CScript& challenge,
                                     const uint256& genesis_hash,
                                     std::string* error = nullptr);

/**
 * Generate the signet tx corresponding to the given block
 *
 * The signet tx commits to everything in the block except:
 * 1. It hashes a modified merkle root with the signet signature removed.
 * 2. It skips the nonce.
 */
class SignetTxs {
    template<class T1, class T2>
    SignetTxs(const T1& to_spend, const T2& to_sign) : m_to_spend{to_spend}, m_to_sign{to_sign} { }

public:
    static std::optional<SignetTxs> Create(const CBlock& block, const CScript& challenge);

    const CTransaction m_to_spend;
    const CTransaction m_to_sign;
};

#endif // BITCOIN_SIGNET_H
