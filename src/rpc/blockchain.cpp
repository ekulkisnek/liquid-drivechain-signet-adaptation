// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <ecx_exchange_state.h>
#include <drivechain_withdrawal.h>
#include <fs.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <init.h>
#include <logging/timer.h>
#include <mainchainrpc.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/coinstats.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/translation.h>
#include <usdd_withdrawal_accumulator.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <warnings.h>
#include <pegins.h>
#include <dynafed.h>

#include <stdint.h>

#include <univalue.h>

#include <chrono>
#include <condition_variable>
#include <algorithm>
#include <array>
#include <memory>
#include <mutex>
#include <string>

using node::BlockManager;
using node::CCoinsStats;
using node::CoinStatsHashType;
using node::GetUTXOStats;
using node::IsBlockPruned;
using node::NodeContext;
using node::ReadBlockFromDisk;
using node::SnapshotMetadata;
using node::UndoReadFromDisk;

struct CUpdatedBlock
{
    uint256 hash;
    int height;
};

static Mutex cs_blockchange;
static std::condition_variable cond_blockchange;
static std::mutex g_usdd_withdrawal_proof_mutex;
static CUpdatedBlock latestblock GUARDED_BY(cs_blockchange);

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex* blockindex)
{
    CHECK_NONFATAL(blockindex);

    int nShift = (blockindex->nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue paramEntryToJSON(const DynaFedParamEntry& entry)
{
    UniValue result(UniValue::VOBJ);

    // set the type
    if (entry.m_serialize_type == 0) {
        result.pushKV("type", "null");
    } else if (entry.m_serialize_type == 1) {
        result.pushKV("type", "compact");
    } else if (entry.m_serialize_type == 2) {
        result.pushKV("type", "full");
    }

    // nothing more to do for null
    if (entry.m_serialize_type == 0) {
        return result;
    }

    // fields all params have
    result.pushKV("root", entry.CalculateRoot().GetHex());
    result.pushKV("signblockscript", HexStr(entry.m_signblockscript));
    result.pushKV("max_block_witness", (uint64_t)entry.m_signblock_witness_limit);

    // add the extra root which is stored for compact and calculated for full
    if (entry.m_serialize_type == 1) {
        // compact
        result.pushKV("extra_root", entry.m_elided_root.GetHex());
    } else if (entry.m_serialize_type == 2) {
        // full
        result.pushKV("extra_root", entry.CalculateExtraRoot().GetHex());
    }

    // some extra fields only present on full params
    if (entry.m_serialize_type == 2) {
        result.pushKV("fedpeg_program", HexStr(entry.m_fedpeg_program));
        result.pushKV("fedpegscript", HexStr(entry.m_fedpegscript));
        UniValue result_extension(UniValue::VARR);
        for (auto& item : entry.m_extension_space) {
            result_extension.push_back(HexStr(item));
        }
        result.pushKV("extension_space", result_extension);
    }

    return result;
}

UniValue dynaParamsToJSON(const DynaFedParams& dynafed_params)
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("current", paramEntryToJSON(dynafed_params.m_current));
    ret.pushKV("proposed", paramEntryToJSON(dynafed_params.m_proposed));
    return ret;
}

static int ComputeNextBlockAndDepth(const CBlockIndex* tip, const CBlockIndex* blockindex, const CBlockIndex*& next)
{
    next = tip->GetAncestor(blockindex->nHeight + 1);
    if (next && next->pprev == blockindex) {
        return tip->nHeight - blockindex->nHeight + 1;
    }
    next = nullptr;
    return blockindex == tip ? 1 : -1;
}

CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman) {
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.get_int()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex* tip, const CBlockIndex* blockindex_)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    CBlockIndex tmpBlockIndexFull;
    const CBlockIndex* blockindex;
    {
        LOCK(cs_main);
        blockindex = blockindex_->untrim_to(&tmpBlockIndexFull);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex_, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex->nVersion));
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    if (Params().GetConsensus().elements_mode) {
        result.pushKV("withdrawalbundlehash", blockindex->hashWithdrawalBundle.GetHex());
        result.pushKV("bmmproofhash", blockindex->hashBmmProof.GetHex());
        result.pushKV("exchangestateroot", blockindex->hashExchangeStateRoot.GetHex());
        result.pushKV("forcedinboxroot", blockindex->hashForcedInboxRoot.GetHex());
        result.pushKV("depositinboxroot", blockindex->hashDepositInboxRoot.GetHex());
        result.pushKV("ecxparentheight", static_cast<uint64_t>(blockindex->ecxParentHeight));
        result.pushKV("forcedprocessedcursor", blockindex->forcedProcessedCursor);
        result.pushKV("depositprocessedcursor", blockindex->depositProcessedCursor);
        result.pushKV(
            "sourcebacklogoldestparentheight",
            blockindex->sourceBacklogOldestParentHeight);
    }
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    if (!g_signed_blocks) {
        result.pushKV("nonce", (uint64_t)blockindex->nNonce);
        result.pushKV("bits", strprintf("%08x", blockindex->nBits));
        result.pushKV("difficulty", GetDifficulty(blockindex));
        result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    } else {
        if (!blockindex->is_dynafed_block()) {
            if (blockindex->trimmed()) {
                result.pushKV("signblock_witness_asm", "<trimmed>");
                result.pushKV("signblock_witness_hex", "<trimmed>");
                result.pushKV("signblock_challenge", "<trimmed>");
                result.pushKV("warning", "Fields missing due to -trim_headers flag.");
            } else {
                result.pushKV("signblock_witness_asm", ScriptToAsmStr(blockindex->get_proof().solution));
                result.pushKV("signblock_witness_hex", HexStr(blockindex->get_proof().solution));
                result.pushKV("signblock_challenge", HexStr(blockindex->get_proof().challenge));
            }
        } else {
            if (blockindex->trimmed()) {
                result.pushKV("signblock_witness_hex", "<trimmed>");
                result.pushKV("dynamic_parameters", "<trimmed>");
                result.pushKV("warning", "Fields missing due to -trim_headers flag.");
            } else {
                result.pushKV("signblock_witness_hex", EncodeHexScriptWitness(blockindex->signblock_witness()));
                result.pushKV("dynamic_parameters", dynaParamsToJSON(blockindex->dynafed_params()));
            }
        }
    }
    result.pushKV("nTx", (uint64_t)blockindex->nTx);
    if (blockindex_->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* tip, const CBlockIndex* blockindex, TxVerbosity verbosity)
{
    UniValue result = blockheaderToJSON(tip, blockindex);

    result.pushKV("strippedsize", (int)::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS));
    result.pushKV("size", (int)::GetSerializeSize(block, PROTOCOL_VERSION));
    result.pushKV("weight", (int)::GetBlockWeight(block));
    UniValue txs(UniValue::VARR);

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (const CTransactionRef& tx : block.vtx) {
                txs.push_back(tx->GetHash().GetHex());
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool have_undo{WITH_LOCK(::cs_main, return !IsBlockPruned(blockindex) && UndoReadFromDisk(blockUndo, blockindex))};

            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, uint256(), objTx, true, RPCSerializationFlags(), txundo, verbosity);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{"getblockcount",
                "\nReturns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{"getbestblockhash",
                "\nReturns the hash of the best (tip) block in the most-work fully-validated chain.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

void RPCNotifyBlockChange(const CBlockIndex* pindex)
{
    if(pindex) {
        LOCK(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{"waitfornewblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].get_int();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{"waitforblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].get_int();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{"waitforblockheight",
                "\nWaits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].get_int();

    if (!request.params[1].isNull())
        timeout = request.params[1].get_int();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{"syncwithvalidationinterfacequeue",
                "\nWaits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    SyncWithValidationInterfaceQueue();
    return NullUniValue;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{"getdifficulty",
                "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetDifficulty(chainman.ActiveChain().Tip());
},
    };
}

static std::vector<RPCResult> MempoolEntryDescription() { return {
    RPCResult{RPCResult::Type::NUM, "vsize", "virtual transaction size as defined in BIP 141. This is different from actual serialized size for witness transactions as witness data is discounted."},
    RPCResult{RPCResult::Type::NUM, "weight", "transaction weight as defined in BIP 141."},
    RPCResult{RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true,
              "transaction fee, denominated in " + CURRENCY_UNIT + " (DEPRECATED, returned only if config option -deprecatedrpc=fees is passed)"},
    RPCResult{RPCResult::Type::STR_AMOUNT, "modifiedfee", /*optional=*/true,
              "transaction fee with fee deltas used for mining priority, denominated in " + CURRENCY_UNIT +
                  " (DEPRECATED, returned only if config option -deprecatedrpc=fees is passed)"},
    RPCResult{RPCResult::Type::NUM_TIME, "time", "local time transaction entered pool in seconds since 1 Jan 1970 GMT"},
    RPCResult{RPCResult::Type::NUM, "height", "block height when transaction entered pool"},
    RPCResult{RPCResult::Type::NUM, "descendantcount", "number of in-mempool descendant transactions (including this one)"},
    RPCResult{RPCResult::Type::NUM, "descendantsize", "virtual transaction size of in-mempool descendants (including this one)"},
    RPCResult{RPCResult::Type::STR_AMOUNT, "descendantfees", /*optional=*/true,
              "transaction fees of in-mempool descendants (including this one) with fee deltas used for mining priority, denominated in " +
                  CURRENCY_ATOM + "s (DEPRECATED, returned only if config option -deprecatedrpc=fees is passed)"},
    RPCResult{RPCResult::Type::NUM, "ancestorcount", "number of in-mempool ancestor transactions (including this one)"},
    RPCResult{RPCResult::Type::NUM, "ancestorsize", "virtual transaction size of in-mempool ancestors (including this one)"},
    RPCResult{RPCResult::Type::STR_AMOUNT, "ancestorfees", /*optional=*/true,
              "transaction fees of in-mempool ancestors (including this one) with fee deltas used for mining priority, denominated in " +
                  CURRENCY_ATOM + "s (DEPRECATED, returned only if config option -deprecatedrpc=fees is passed)"},
    RPCResult{RPCResult::Type::STR_HEX, "wtxid", "hash of serialized transaction, including witness data"},
    RPCResult{RPCResult::Type::OBJ, "fees", "",
        {
            RPCResult{RPCResult::Type::STR_AMOUNT, "base", "transaction fee, denominated in " + CURRENCY_UNIT},
            RPCResult{RPCResult::Type::STR_AMOUNT, "modified", "transaction fee with fee deltas used for mining priority, denominated in " + CURRENCY_UNIT},
            RPCResult{RPCResult::Type::STR_AMOUNT, "ancestor", "transaction fees of in-mempool ancestors (including this one) with fee deltas used for mining priority, denominated in " + CURRENCY_UNIT},
            RPCResult{RPCResult::Type::STR_AMOUNT, "descendant", "transaction fees of in-mempool descendants (including this one) with fee deltas used for mining priority, denominated in " + CURRENCY_UNIT},
        }},
    RPCResult{RPCResult::Type::ARR, "depends", "unconfirmed transactions used as inputs for this transaction",
        {RPCResult{RPCResult::Type::STR_HEX, "transactionid", "parent transaction id"}}},
    RPCResult{RPCResult::Type::ARR, "spentby", "unconfirmed transactions spending outputs from this transaction",
        {RPCResult{RPCResult::Type::STR_HEX, "transactionid", "child transaction id"}}},
    RPCResult{RPCResult::Type::BOOL, "bip125-replaceable", "Whether this transaction could be replaced due to BIP125 (replace-by-fee)"},
    RPCResult{RPCResult::Type::BOOL, "unbroadcast", "Whether this transaction is currently unbroadcast (initial broadcast not yet acknowledged by any peers)"},
};}

static void entryToJSON(const CTxMemPool& pool, UniValue& info, const CTxMemPoolEntry& e) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    AssertLockHeld(pool.cs);

    info.pushKV("vsize", (int)e.GetTxSize());
    info.pushKV("weight", (int)e.GetTxWeight());
    // TODO: top-level fee fields are deprecated. deprecated_fee_fields_enabled blocks should be removed in v24
    const bool deprecated_fee_fields_enabled{IsDeprecatedRPCEnabled("fees")};
    if (deprecated_fee_fields_enabled) {
        info.pushKV("fee", ValueFromAmount(e.GetFee()));
        info.pushKV("modifiedfee", ValueFromAmount(e.GetModifiedFee()));
    }
    info.pushKV("time", count_seconds(e.GetTime()));
    info.pushKV("height", (int)e.GetHeight());
    info.pushKV("descendantcount", e.GetCountWithDescendants());
    info.pushKV("descendantsize", e.GetSizeWithDescendants());
    if (deprecated_fee_fields_enabled) {
        info.pushKV("descendantfees", e.GetModFeesWithDescendants());
    }
    info.pushKV("ancestorcount", e.GetCountWithAncestors());
    info.pushKV("ancestorsize", e.GetSizeWithAncestors());
    if (deprecated_fee_fields_enabled) {
        info.pushKV("ancestorfees", e.GetModFeesWithAncestors());
    }
    info.pushKV("wtxid", pool.vTxHashes[e.vTxHashesIdx].first.ToString());

    UniValue fees(UniValue::VOBJ);
    fees.pushKV("base", ValueFromAmount(e.GetFee()));
    fees.pushKV("modified", ValueFromAmount(e.GetModifiedFee()));
    fees.pushKV("ancestor", ValueFromAmount(e.GetModFeesWithAncestors()));
    fees.pushKV("descendant", ValueFromAmount(e.GetModFeesWithDescendants()));
    info.pushKV("fees", fees);

    const CTransaction& tx = e.GetTx();
    std::set<std::string> setDepends;
    for (const CTxIn& txin : tx.vin)
    {
        if (pool.exists(GenTxid::Txid(txin.prevout.hash)))
            setDepends.insert(txin.prevout.hash.ToString());
    }

    UniValue depends(UniValue::VARR);
    for (const std::string& dep : setDepends)
    {
        depends.push_back(dep);
    }

    info.pushKV("depends", depends);

    UniValue spent(UniValue::VARR);
    const CTxMemPool::txiter& it = pool.mapTx.find(tx.GetHash());
    const CTxMemPoolEntry::Children& children = it->GetMemPoolChildrenConst();
    for (const CTxMemPoolEntry& child : children) {
        spent.push_back(child.GetTx().GetHash().ToString());
    }

    info.pushKV("spentby", spent);

    // Add opt-in RBF status
    bool rbfStatus = false;
    RBFTransactionState rbfState = IsRBFOptIn(tx, pool);
    if (rbfState == RBFTransactionState::UNKNOWN) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction is not in mempool");
    } else if (rbfState == RBFTransactionState::REPLACEABLE_BIP125) {
        rbfStatus = true;
    }

    info.pushKV("bip125-replaceable", rbfStatus);
    info.pushKV("unbroadcast", pool.IsUnbroadcastTx(tx.GetHash()));
}

UniValue MempoolToJSON(const CTxMemPool& pool, bool verbose, bool include_mempool_sequence)
{
    if (verbose) {
        if (include_mempool_sequence) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Verbose results cannot contain mempool sequence values.");
        }
        LOCK(pool.cs);
        UniValue o(UniValue::VOBJ);
        for (const CTxMemPoolEntry& e : pool.mapTx) {
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(pool, info, e);
            // Mempool has unique entries so there is no advantage in using
            // UniValue::pushKV, which checks if the key already exists in O(N).
            // UniValue::__pushKV is used instead which currently is O(1).
            o.__pushKV(hash.ToString(), info);
        }
        return o;
    } else {
        uint64_t mempool_sequence;
        std::vector<uint256> vtxid;
        {
            LOCK(pool.cs);
            pool.queryHashes(vtxid);
            mempool_sequence = pool.GetSequence();
        }
        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        if (!include_mempool_sequence) {
            return a;
        } else {
            UniValue o(UniValue::VOBJ);
            o.pushKV("txids", a);
            o.pushKV("mempool_sequence", mempool_sequence);
            return o;
        }
    }
}

static RPCHelpMan getrawmempool()
{
    return RPCHelpMan{"getrawmempool",
                "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
                "\nHint: use getmempoolentry to fetch a specific transaction from the mempool.\n",
                {
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "True for a json object, false for array of transaction ids"},
                    {"mempool_sequence", RPCArg::Type::BOOL, RPCArg::Default{false}, "If verbose=false, returns a json object with transaction list and mempool sequence number attached."},
                },
                {
                    RPCResult{"for verbose = false",
                        RPCResult::Type::ARR, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "", "The transaction id"},
                        }},
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ_DYN, "", "",
                        {
                            {RPCResult::Type::OBJ, "transactionid", "", MempoolEntryDescription()},
                        }},
                    RPCResult{"for verbose = false and mempool_sequence = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ARR, "txids", "",
                            {
                                {RPCResult::Type::STR_HEX, "", "The transaction id"},
                            }},
                            {RPCResult::Type::NUM, "mempool_sequence", "The mempool sequence value."},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawmempool", "true")
            + HelpExampleRpc("getrawmempool", "true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    bool fVerbose = false;
    if (!request.params[0].isNull())
        fVerbose = request.params[0].get_bool();

    bool include_mempool_sequence = false;
    if (!request.params[1].isNull()) {
        include_mempool_sequence = request.params[1].get_bool();
    }

    return MempoolToJSON(EnsureAnyMemPool(request.context), fVerbose, include_mempool_sequence);
},
    };
}

static RPCHelpMan getmempoolancestors()
{
    return RPCHelpMan{"getmempoolancestors",
                "\nIf txid is in the mempool, returns all in-mempool ancestors.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id (must be in mempool)"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "True for a json object, false for array of transaction ids"},
                },
                {
                    RPCResult{"for verbose = false",
                        RPCResult::Type::ARR, "", "",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id of an in-mempool ancestor transaction"}}},
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ_DYN, "", "",
                        {
                            {RPCResult::Type::OBJ, "transactionid", "", MempoolEntryDescription()},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getmempoolancestors", "\"mytxid\"")
            + HelpExampleRpc("getmempoolancestors", "\"mytxid\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    bool fVerbose = false;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setAncestors;
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    mempool.CalculateMemPoolAncestors(*it, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            o.push_back(ancestorIt->GetTx().GetHash().ToString());
        }
        return o;
    } else {
        UniValue o(UniValue::VOBJ);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            const CTxMemPoolEntry &e = *ancestorIt;
            const uint256& _hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(mempool, info, e);
            o.pushKV(_hash.ToString(), info);
        }
        return o;
    }
},
    };
}

static RPCHelpMan getmempooldescendants()
{
    return RPCHelpMan{"getmempooldescendants",
                "\nIf txid is in the mempool, returns all in-mempool descendants.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id (must be in mempool)"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "True for a json object, false for array of transaction ids"},
                },
                {
                    RPCResult{"for verbose = false",
                        RPCResult::Type::ARR, "", "",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id of an in-mempool descendant transaction"}}},
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ_DYN, "", "",
                        {
                            {RPCResult::Type::OBJ, "transactionid", "", MempoolEntryDescription()},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getmempooldescendants", "\"mytxid\"")
            + HelpExampleRpc("getmempooldescendants", "\"mytxid\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    bool fVerbose = false;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setDescendants;
    mempool.CalculateDescendants(it, setDescendants);
    // CTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        for (CTxMemPool::txiter descendantIt : setDescendants) {
            o.push_back(descendantIt->GetTx().GetHash().ToString());
        }

        return o;
    } else {
        UniValue o(UniValue::VOBJ);
        for (CTxMemPool::txiter descendantIt : setDescendants) {
            const CTxMemPoolEntry &e = *descendantIt;
            const uint256& _hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(mempool, info, e);
            o.pushKV(_hash.ToString(), info);
        }
        return o;
    }
},
    };
}

static RPCHelpMan getmempoolentry()
{
    return RPCHelpMan{"getmempoolentry",
                "\nReturns mempool data for given transaction\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id (must be in mempool)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", MempoolEntryDescription()},
                RPCExamples{
                    HelpExampleCli("getmempoolentry", "\"mytxid\"")
            + HelpExampleRpc("getmempoolentry", "\"mytxid\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    const CTxMemPoolEntry &e = *it;
    UniValue info(UniValue::VOBJ);
    entryToJSON(mempool, info, e);
    return info;
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "Subsequent calls for the same block and a new peer will cause the response from the previous peer to be ignored.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].get_int64()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto err{peerman.FetchBlock(peer_id, *index)}) {
        throw JSONRPCError(RPC_MISC_ERROR, err.value());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{"getblockhash",
                "\nReturns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    int nHeight = request.params[0].get_int();
    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{"getblockheader",
                "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::STR_HEX, "withdrawalbundlehash", "The current drivechain withdrawal bundle hash committed by this block header"},
                            {RPCResult::Type::STR_HEX, "bmmproofhash", "The BMM proof commitment appended by the existing header extension"},
                            {RPCResult::Type::STR_HEX, "exchangestateroot", "The append-only ECX state singleton root, or zero before activation"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", "The bits"},
                            {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the current chain"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::STR, "signblock_witness_asm", "ASM of sign block witness data"},
                            {RPCResult::Type::STR_HEX, "signblock_witness_hex", "Hex of sign block witness data"},
                            {RPCResult::Type::OBJ, "dynamic_parameters", "Dynamic federation parameters in the block, if any",
                            {
                                {RPCResult::Type::OBJ, "current", "enforced dynamic federation parameters. The signblockscript is published for each block, while others are published only at epoch start",
                                {
                                    {RPCResult::Type::STR_HEX, "signblockscript", "signblock script"},
                                    {RPCResult::Type::NUM, "max_block_witness", "Maximum serialized size of the block witness stack"},
                                    {RPCResult::Type::STR_HEX, "fedpegscript", "fedpeg script"},
                                    {RPCResult::Type::ARR, "extension_space", "array of hex-encoded strings",
                                    {
                                        {RPCResult::Type::ELISION, "", ""}
                                    }}
                                }},
                                {RPCResult::Type::OBJ, "proposed", "Proposed parameters. Uninforced. Must be published in full",
                                {
                                    {RPCResult::Type::ELISION, "", "same entries as current"}
                                }},
                            }},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        LOCK(cs_main);
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        CBlockIndex tmpBlockIndexFull;
        const CBlockIndex* pblockindexfull=pblockindex->untrim_to(&tmpBlockIndexFull);
        ssBlock << pblockindexfull->GetBlockHeader();
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(tip, pblockindex);
},
    };
}

static CBlock GetBlockChecked(const CBlockIndex* pblockindex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    CBlock block;
    if (IsBlockPruned(pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
    }

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        // Block not found on disk. This could be because we have the block
        // header in our index but not yet have the block or did not accept the
        // block.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static CBlockUndo GetUndoChecked(const CBlockIndex* pblockindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(::cs_main);
    CBlockUndo blockUndo;
    if (IsBlockPruned(pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available (pruned data)");
    }

    if (!UndoReadFromDisk(blockUndo, pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

static RPCHelpMan getblock()
{
    return RPCHelpMan{"getblock",
                "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs"},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::STR_HEX, "withdrawalbundlehash", "The current drivechain withdrawal bundle hash committed by this block header"},
                    {RPCResult::Type::STR_HEX, "bmmproofhash", "The BMM proof commitment appended by the existing header extension"},
                    {RPCResult::Type::STR_HEX, "exchangestateroot", "The append-only ECX state singleton root, or zero before activation"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", "The bits"},
                    {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the chain up to this block (in hex)"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::STR, "signblock_witness_asm", "ASM of sign block witness data"},
                    {RPCResult::Type::STR_HEX, "signblock_witness_hex", "Hex of sign block witness data"},
                    {RPCResult::Type::OBJ, "dynamic_parameters", "Dynamic federation parameters in the block, if any",
                    {
                        {RPCResult::Type::OBJ, "current", "enforced dynamic federation parameters. The signblockscript is published for each block, while others are published only at epoch start",
                        {
                            {RPCResult::Type::STR_HEX, "signblockscript", "signblock script"},
                            {RPCResult::Type::NUM, "max_block_witness", "Maximum serialized size of the block witness stack"},
                            {RPCResult::Type::STR_HEX, "fedpegscript", "fedpeg script"},
                            {RPCResult::Type::ARR, "extension_space", "array of hex-encoded strings",
                            {
                                {RPCResult::Type::ELISION, "", ""}
                            }},
                        }},
                        {RPCResult::Type::OBJ, "proposed", "Proposed parameters. Uninforced. Must be published in full",
                        {
                            {RPCResult::Type::ELISION, "", "same entries as current"}
                        }},
                    }},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
                                    {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::NUM, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "",
                                        {
                                            {RPCResult::Type::STR, "asm", "The asm"},
                                            {RPCResult::Type::STR, "hex", "The hex"},
                                            {RPCResult::Type::STR, "address", /* optional */ true, "The Bitcoin address (only if a well-defined address exists)"},
                                            {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                                        }},
                                    }},
                                }},
                            }},
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity = 1;
    if (!request.params[1].isNull()) {
        if (request.params[1].isBool()) {
            verbosity = request.params[1].get_bool() ? 1 : 0;
        } else {
            verbosity = request.params[1].get_int();
        }
    }

    CBlock block;
    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        block = GetBlockChecked(pblockindex);
    }

    if (verbosity <= 0)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
        ssBlock << block;
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(block, tip, pblockindex, tx_verbosity);
},
    };
}

static RPCHelpMan pruneblockchain()
{
    return RPCHelpMan{"pruneblockchain", "",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Height of the last block pruned"},
                RPCExamples{
                    HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!node::fPruneMode)
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChainState& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;

    int heightParam = request.params[0].get_int();
    if (heightParam < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) active_chain.Height();
    if (chainHeight < Params().PruneAfterHeight())
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    else if (height > chainHeight)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogPrint(BCLog::RPC, "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(active_chainstate, height);
    const CBlockIndex* block = active_chain.Tip();
    CHECK_NONFATAL(block);
    while (block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA)) {
        block = block->pprev;
    }
    return uint64_t(block->nHeight);
},
    };
}

CoinStatsHashType ParseHashType(const std::string& hash_type_input)
{
    if (hash_type_input == "hash_serialized_2") {
        return CoinStatsHashType::HASH_SERIALIZED;
    } else if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{"gettxoutsetinfo",
                "\nReturns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_2"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_2' (the legacy algorithm), 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "The block hash or height of the target height (only available with coinstatsindex).", "", {"", "string or numeric"}},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "hash_serialized_2", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_2' hash_type is chosen)"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "bip30", "Transactions overridden by duplicates (no longer possible with BIP30)"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
    CCoinsStats stats{hash_type};
    stats.index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    CChainState& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk();

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
        pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (stats.m_hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_2 hash type cannot be queried for a specific block");
        }

        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (stats.index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    if (GetUTXOStats(coins_view, *blockman, stats, node.rpc_interruption_point, pindex)) {
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            ret.pushKV("hash_serialized_2", stats.hashSerialized.GetHex());
        }
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.hashSerialized.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            ret.pushKV("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

            CCoinsStats prev_stats{hash_type};

            if (pindex->nHeight > 0) {
                GetUTXOStats(coins_view, *blockman, prev_stats, node.rpc_interruption_point, pindex->pprev);
            }

            UniValue block_info(UniValue::VOBJ);
            block_info.pushKV("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount));
            block_info.pushKV("coinbase", ValueFromAmount(stats.total_coinbase_amount - prev_stats.total_coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount));
            block_info.pushKV("unspendable", ValueFromAmount(stats.total_unspendable_amount - prev_stats.total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("bip30", ValueFromAmount(stats.total_unspendables_bip30 - prev_stats.total_unspendables_bip30));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", unspendables);

            ret.pushKV("block_info", block_info);
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{"gettxout",
        "\nReturns details about an unspent transaction output.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", ""},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", ""},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    int n = request.params[1].get_int();
    COutPoint out(hash, n);
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    Coin coin;
    CChainState& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!view.GetCoin(out, coin) || mempool.isSpent(out)) {
            return NullUniValue;
        }
    } else {
        if (!coins_view->GetCoin(out, coin)) {
            return NullUniValue;
        }
    }

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin.nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin.nHeight + 1));
    }
    if (coin.out.nValue.IsExplicit()) {
        ret.pushKV("value", ValueFromAmount(coin.out.nValue.GetAmount()));
    } else {
        ret.pushKV("valuecommitment", coin.out.nValue.GetHex());
    }
    if (g_con_elementsmode) {
        if (coin.out.nAsset.IsExplicit()) {
            ret.pushKV("asset", coin.out.nAsset.GetAsset().GetHex());
        } else {
            ret.pushKV("assetcommitment", coin.out.nAsset.GetHex());
        }

        ret.pushKV("commitmentnonce", coin.out.nNonce.GetHex());
    }
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToUniv(coin.out.scriptPubKey, o, true);
    ret.pushKV("scriptPubKey", o);
    ret.pushKV("coinbase", (bool)coin.fCoinBase);

    return ret;
},
    };
}

static RPCHelpMan getecxstateutxoroot()
{
    return RPCHelpMan{"getecxstateutxoroot",
        "Compute the exact consensus ECX header root for an existing unspent output.\n"
        "This is intended for freezing an activated-regtest genesis singleton.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The singleton transaction id"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The singleton output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "root", "ECX/header-state/v1 root in display hex"},
            {RPCResult::Type::BOOL, "eligible", "Whether the output has the required explicit asset/value, null nonce and P2TR shape"},
            {RPCResult::Type::NUM, "height", "UTXO creation height"},
        }},
        RPCExamples{
            HelpExampleCli("getecxstateutxoroot", "\"txid\" 0") +
            HelpExampleRpc("getecxstateutxoroot", "\"txid\", 0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().GetConsensus().elements_mode) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "ECX state is unavailable outside an Elements-mode chain");
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    const uint256 txid{ParseHashV(request.params[0], "txid")};
    const int vout = request.params[1].get_int();
    if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be nonnegative");
    const COutPoint outpoint{txid, static_cast<uint32_t>(vout)};
    Coin coin;
    if (!chainman.ActiveChainstate().CoinsTip().GetCoin(outpoint, coin)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "ECX singleton UTXO not found");
    }

    const bool eligible = coin.out.nAsset.IsExplicit() &&
        coin.out.nValue.IsExplicit() && coin.out.nNonce.IsNull() &&
        coin.out.scriptPubKey.size() == 34 &&
        coin.out.scriptPubKey[0] == OP_1 && coin.out.scriptPubKey[1] == 0x20;
    UniValue result(UniValue::VOBJ);
    result.pushKV(
        "root",
        ecx::ComputeStateUtxoRoot(
            Params().GetConsensus().hashGenesisBlock,
            outpoint,
            coin.out).GetHex());
    result.pushKV("eligible", eligible);
    result.pushKV("height", static_cast<uint64_t>(coin.nHeight));
    return result;
},
    };
}

static RPCHelpMan getecxconsensuscontext()
{
    return RPCHelpMan{"getecxconsensuscontext",
        "Return the fail-closed ECX source heads and authenticated BMM clock "
        "used for mempool and next-block Simplicity execution.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "sidechainheight", "Active sidechain height"},
            {RPCResult::Type::STR_HEX, "sidechainblockhash", "Active sidechain block hash"},
            {RPCResult::Type::STR_HEX, "exchangestateroot", "Active ECX singleton root"},
            {RPCResult::Type::OBJ, "forcedinbox", "Consensus forced-action source head", {
                {RPCResult::Type::STR_HEX, "headroot", "Append-only forced inbox root"},
                {RPCResult::Type::NUM, "entrycount", "Number of forced actions committed through this head"},
                {RPCResult::Type::NUM, "nextindex", "Index assigned to the next forced action"},
                {RPCResult::Type::NUM, "processedcursor", "First unprocessed forced-action index"},
            }},
            {RPCResult::Type::OBJ, "depositinbox", "Consensus confidential-deposit source head", {
                {RPCResult::Type::STR_HEX, "headroot", "Append-only deposit inbox root"},
                {RPCResult::Type::NUM, "entrycount", "Number of deposits committed through this head"},
                {RPCResult::Type::NUM, "nextindex", "Index assigned to the next deposit"},
                {RPCResult::Type::NUM, "processedcursor", "First unprocessed deposit index"},
            }},
            {RPCResult::Type::OBJ, "bmm", "Authenticated prior-parent context", {
                {RPCResult::Type::BOOL, "authenticated", "Whether the context was derived from verified BMM state rather than the explicit regtest clock"},
                {RPCResult::Type::NUM, "parentheight", "BMM-authenticated parent height"},
                {RPCResult::Type::NUM, "parentmtp", "BMM-authenticated parent median time past"},
                {RPCResult::Type::STR_HEX, "parentblockhash", "BMM-authenticated parent block hash"},
            }},
            {RPCResult::Type::NUM, "sourceparentheight", "Approval height committed by the active ECX header"},
            {RPCResult::Type::OBJ, "capital", /*optional=*/true, "Verified V2 public capital projection (present only for a frozen V2 deployment)", {
                {RPCResult::Type::NUM, "version", "Capital projection version"},
                {RPCResult::Type::STR_HEX, "exchangestateroot", "Root selecting this exact projection"},
                {RPCResult::Type::STR_HEX, "configurationhash", "Frozen V2 configuration"},
                {RPCResult::Type::STR_HEX, "bondassetid", "Verified fixed-supply bond asset"},
                {RPCResult::Type::STR_HEX, "bonddeploymentcommitment", "Verified deployment envelope"},
                {RPCResult::Type::STR_HEX, "transitionprogramid", "Frozen SP1 transition program"},
                {RPCResult::Type::STR_HEX, "transitioncmr", "Frozen Simplicity transition CMR"},
                {RPCResult::Type::NUM, "insurancereservequoteunits", "Public aggregate insurance reserve"},
                {RPCResult::Type::NUM, "outstandingbondunits", "Public outstanding share atoms"},
                {RPCResult::Type::NUM, "navquoteunitsperbond", "Execution-time NAV per whole share"},
                {RPCResult::Type::NUM, "deficitquoteunits", "Worst full-range portfolio deficit"},
                {RPCResult::Type::NUM, "targetreservequoteunits", "Ceiling of 125% deficit coverage"},
                {RPCResult::Type::NUM, "coveragebps", "Public coverage ratio"},
                {RPCResult::Type::STR, "mode", "Normal, ReduceOnly, or Recovery"},
                {RPCResult::Type::NUM, "fundingepoch", "Last deterministic funding epoch"},
                {RPCResult::Type::STR_HEX, "redemptionqueueroot", "FIFO redemption queue root"},
                {RPCResult::Type::NUM, "redemptionhead", "FIFO head"},
                {RPCResult::Type::NUM, "redemptiontail", "FIFO tail"},
                {RPCResult::Type::NUM, "queuedredemptionbondunits", "Public queued share aggregate"},
                {RPCResult::Type::NUM, "legacyfeepoolquoteunits", "Always zero in V2"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getecxconsensuscontext", "") +
            HelpExampleRpc("getecxconsensuscontext", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().GetConsensus().elements_mode) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "ECX consensus context is unavailable outside an Elements-mode chain");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!tip) throw JSONRPCError(RPC_MISC_ERROR, "active sidechain tip is unavailable");

    std::string context_error;
    ecx::ExchangeConsensusSnapshot exchange;
    if (!ecx::GetExchangeConsensusSnapshot(
            chainman.ActiveChainstate().CoinsTip(),
            tip,
            exchange,
            context_error)) {
        throw JSONRPCError(RPC_MISC_ERROR, context_error);
    }
    drivechain::BmmParentContext bmm;
    bool bmm_authenticated{true};
    drivechain::BmmL1State bmm_state;
    if (drivechain::GetEffectiveBmmState(
            chainman.ActiveChainstate().CoinsTip(),
            tip,
            bmm_state,
            context_error)) {
        if (!drivechain::GetBmmParentContext(bmm_state, bmm, context_error)) {
            throw JSONRPCError(RPC_MISC_ERROR, context_error);
        }
    } else {
        const std::string& network = Params().NetworkIDString();
        if (network != "elementsregtest") {
            throw JSONRPCError(RPC_MISC_ERROR, context_error);
        }
        if (tip->ecxParentHeight == 0) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX regtest tip has no synthetic parent height");
        }
        bmm.block_hash.SetNull();
        bmm.height = tip->ecxParentHeight;
        bmm.median_time_past = tip->GetMedianTimePast();
        bmm_authenticated = false;
    }
    if (tip->ecxParentHeight == 0 || tip->ecxParentHeight != bmm.height) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "active ECX header approval height disagrees with BMM chainstate");
    }

    UniValue forced(UniValue::VOBJ);
    forced.pushKV("headroot", exchange.forced_inbox_root.GetHex());
    forced.pushKV("entrycount", exchange.forced_entry_count);
    forced.pushKV("nextindex", exchange.forced_entry_count);
    forced.pushKV("processedcursor", exchange.forced_processed_cursor);
    UniValue deposits(UniValue::VOBJ);
    deposits.pushKV("headroot", exchange.deposit_inbox_root.GetHex());
    deposits.pushKV("entrycount", exchange.deposit_entry_count);
    deposits.pushKV("nextindex", exchange.deposit_entry_count);
    deposits.pushKV("processedcursor", exchange.deposit_processed_cursor);
    UniValue parent(UniValue::VOBJ);
    parent.pushKV("authenticated", bmm_authenticated);
    parent.pushKV("parentheight", bmm.height);
    parent.pushKV("parentmtp", bmm.median_time_past);
    parent.pushKV("parentblockhash", bmm.block_hash.GetHex());

    UniValue result(UniValue::VOBJ);
    result.pushKV("sidechainheight", static_cast<uint64_t>(tip->nHeight));
    result.pushKV("sidechainblockhash", tip->GetBlockHash().GetHex());
    result.pushKV("exchangestateroot", exchange.exchange_state_root.GetHex());
    result.pushKV("forcedinbox", forced);
    result.pushKV("depositinbox", deposits);
    result.pushKV("bmm", parent);
    result.pushKV("sourceparentheight", static_cast<uint64_t>(tip->ecxParentHeight));
    result.pushKV(
        "sourcebacklogoldestparentheight",
        exchange.source_backlog_oldest_parent_height);
    const ecx::ExchangeConsensus& frozen{ecx::LayerTwoLabsExchangeConsensus()};
    if (frozen.bond_v2.activation_enabled) {
        if (!tip->ecxBondV2Capital.has_value()) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX V2 tip has no fully verified capital projection");
        }
        const ecx::BondV2CapitalSnapshot& capital{*tip->ecxBondV2Capital};
        const bool finite_identity{
            capital.proof_profile == 0 &&
            capital.configuration_hash == frozen.bond_v2.configuration_hash &&
            capital.transition_program_id == frozen.bond_v2.transition_program_id &&
            capital.transition_cmr == frozen.bond_v2.transition_cmr};
        const bool successor_identity{
            capital.proof_profile == 1 &&
            capital.configuration_hash ==
                frozen.bond_v2.incremental_successor_configuration_hash &&
            capital.transition_program_id ==
                frozen.bond_v2.incremental_successor_program_id &&
            capital.transition_cmr ==
                frozen.bond_v2.incremental_successor_transition_cmr};
        if (capital.version != ecx::BOND_V2_CAPITAL_SNAPSHOT_VERSION ||
            capital.exchange_state_root != exchange.exchange_state_root ||
            (!finite_identity && !successor_identity) ||
            capital.bond_asset_id != frozen.bond_v2.bond_asset_id ||
            capital.bond_deployment_commitment !=
                frozen.bond_v2.bond_deployment_commitment ||
            capital.bond_inventory_covenant_hash !=
                frozen.bond_v2.inventory_covenant_script_sha256 ||
            capital.capital_mode > 2 ||
            capital.oracle_mode > 3 ||
            capital.operationally_safe > 1 ||
            std::any_of(
                capital.legacy_fee_pool.begin(),
                capital.legacy_fee_pool.end(),
                [](unsigned char byte) { return byte != 0; })) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "active ECX V2 capital projection is not root/frozen-identity bound");
        }
        const auto u128_number = [](const std::array<unsigned char, 16>& bytes) {
            std::string decimal{"0"};
            for (const unsigned char byte : bytes) {
                unsigned int carry{byte};
                for (auto digit = decimal.rbegin(); digit != decimal.rend(); ++digit) {
                    const unsigned int value{
                        static_cast<unsigned int>(*digit - '0') * 256U + carry};
                    *digit = static_cast<char>('0' + value % 10U);
                    carry = value / 10U;
                }
                while (carry != 0) {
                    decimal.insert(decimal.begin(), static_cast<char>('0' + carry % 10U));
                    carry /= 10U;
                }
            }
            UniValue number;
            if (!number.setNumStr(decimal)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "cannot encode ECX V2 u128");
            }
            return number;
        };
        const auto counter_number = [&u128_number](const ecx::BigEndianUint128& value) {
            return u128_number(value.bytes);
        };
        const auto i128_number = [&u128_number](std::array<unsigned char, 16> bytes) {
            const bool negative{(bytes[0] & 0x80) != 0};
            if (!negative) return u128_number(bytes);
            unsigned int carry{1};
            for (auto cursor = bytes.rbegin(); cursor != bytes.rend(); ++cursor) {
                const unsigned int value{static_cast<unsigned int>(~*cursor & 0xff) + carry};
                *cursor = static_cast<unsigned char>(value & 0xff);
                carry = value >> 8;
            }
            UniValue magnitude{u128_number(bytes)};
            UniValue number;
            if (!number.setNumStr("-" + magnitude.getValStr())) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "cannot encode ECX V2 i128");
            }
            return number;
        };
        UniValue capital_json(UniValue::VOBJ);
        capital_json.pushKV("version", capital.version);
        capital_json.pushKV(
            "proofprofile", capital.proof_profile == 0 ? "finite-v18" : "incremental-successor");
        capital_json.pushKV("exchangestateroot", capital.exchange_state_root.GetHex());
        capital_json.pushKV("configurationhash", capital.configuration_hash.GetHex());
        capital_json.pushKV(
            "bondactionconfigurationhash", frozen.bond_v2.configuration_hash.GetHex());
        capital_json.pushKV("bondassetid", capital.bond_asset_id.GetHex());
        capital_json.pushKV(
            "bonddeploymentcommitment",
            capital.bond_deployment_commitment.GetHex());
        capital_json.pushKV("transitionprogramid", capital.transition_program_id.GetHex());
        capital_json.pushKV("transitioncmr", capital.transition_cmr.GetHex());
        capital_json.pushKV("covenantstatehash", capital.covenant_state_hash.GetHex());
        capital_json.pushKV("bondstateroot", capital.bond_state_root.GetHex());
        capital_json.pushKV("fundingstateroot", capital.funding_state_root.GetHex());
        capital_json.pushKV(
            "bondinventorycovenanthash", capital.bond_inventory_covenant_hash.GetHex());
        capital_json.pushKV("insurancereservequoteunits", u128_number(capital.insurance_reserve));
        capital_json.pushKV("issuedbondunits", capital.issued_share_atoms);
        capital_json.pushKV("outstandingbondunits", capital.outstanding_share_atoms);
        capital_json.pushKV("inventorybondunits", capital.inventory_share_atoms);
        capital_json.pushKV("navquoteunitsperbond", u128_number(capital.nav_per_whole_share));
        capital_json.pushKV("deficitquoteunits", u128_number(capital.full_bound_deficit));
        capital_json.pushKV("targetreservequoteunits", u128_number(capital.target_reserve));
        capital_json.pushKV("coveragebps", u128_number(capital.coverage_bps));
        capital_json.pushKV("controlledquoteunits", u128_number(capital.controlled_usdd_atoms));
        capital_json.pushKV(
            "mode",
            capital.capital_mode == 0 ? "Normal" :
            capital.capital_mode == 1 ? "ReduceOnly" : "Recovery");
        capital_json.pushKV("minimumauthenticatedprice", capital.minimum_authenticated_price);
        capital_json.pushKV("maximumauthenticatedprice", capital.maximum_authenticated_price);
        capital_json.pushKV("fundingepoch", capital.funding_epoch);
        capital_json.pushKV("fundingrateppm", capital.funding_rate_ppm);
        capital_json.pushKV(
            "globalfundingindexnumerator", i128_number(capital.global_funding_index_numerator));
        capital_json.pushKV("redemptionqueueroot", capital.redemption_queue_root.GetHex());
        capital_json.pushKV("redemptionhead", counter_number(capital.redemption_head));
        capital_json.pushKV("redemptiontail", counter_number(capital.redemption_tail));
        capital_json.pushKV(
            "queuedredemptionbondunits",
            capital.queued_redemption_share_atoms);
        UniValue oracle_json(UniValue::VOBJ);
        oracle_json.pushKV("certificatehash", capital.oracle_certificate_hash.GetHex());
        oracle_json.pushKV(
            "validthroughparentmtp", capital.oracle_valid_through_parent_mtp);
        oracle_json.pushKV(
            "mode",
            capital.oracle_mode == 0 ? "Normal" :
            capital.oracle_mode == 1 ? "ReduceOnly" :
            capital.oracle_mode == 2 ? "Disputed" : "Halt");
        capital_json.pushKV("oracle", oracle_json);
        capital_json.pushKV(
            "encryptedavailabilityroot", capital.encrypted_availability_root.GetHex());
        UniValue bond_inbox_json(UniValue::VOBJ);
        bond_inbox_json.pushKV("headroot", capital.bond_inbox_head_root.GetHex());
        bond_inbox_json.pushKV("entrycount", counter_number(capital.bond_inbox_entry_count));
        bond_inbox_json.pushKV("processedroot", capital.bond_inbox_processed_root.GetHex());
        bond_inbox_json.pushKV(
            "processedcursor", counter_number(capital.bond_inbox_processed_cursor));
        bond_inbox_json.pushKV("outcomeroot", capital.bond_inbox_outcome_root.GetHex());
        bond_inbox_json.pushKV(
            "outcomecount", counter_number(capital.bond_inbox_outcome_count));
        bond_inbox_json.pushKV(
            "nodeverifiedsourceheadroot", capital.node_bond_inbox_head_root.GetHex());
        bond_inbox_json.pushKV(
            "nodeverifiedsourceentrycount", counter_number(capital.node_bond_inbox_entry_count));
        capital_json.pushKV("bondinbox", bond_inbox_json);
        UniValue execution_json(UniValue::VOBJ);
        execution_json.pushKV(
            "receiptbatchroot", capital.matcher_execution_receipt_batch_root.GetHex());
        execution_json.pushKV(
            "previoussequence", counter_number(capital.previous_matcher_execution_sequence));
        execution_json.pushKV("sequence", counter_number(capital.matcher_execution_sequence));
        capital_json.pushKV("matcherexecution", execution_json);
        capital_json.pushKV(
            "lasttransitionsidechainheight", capital.last_transition_sidechain_height);
        capital_json.pushKV("operationallysafe", capital.operationally_safe == 1);
        capital_json.pushKV("legacyfeepoolquoteunits", u128_number(capital.legacy_fee_pool));
        result.pushKV("capital", capital_json);
    }
    return result;
},
    };
}


static RPCHelpMan getecxbondinboxentries()
{
    return RPCHelpMan{"getecxbondinboxentries",
        "Reconstruct a bounded range of exact node-verified bond-inbox source "
        "entries from active-chain archival blocks. The returned finite "
        "700-byte or incremental-successor 708-byte records and "
        "witness-bearing source transactions are derived by the "
        "same parser used by consensus; producer-supplied projections are "
        "never accepted. The call fails if a block was pruned or the active "
        "chain changes while it is being read.\n",
        {
            {"start_height", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "First active sidechain height to scan (at or after V2 activation)"},
            {"block_count", RPCArg::Type::NUM, RPCArg::Default{1},
                "Number of active blocks to scan, 1..64; output stops before "
                "a block that would exceed eight returned entries"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "schema_version", "Exact export schema, currently 4"},
            {RPCResult::Type::STR_HEX, "configurationhash", "Frozen V18 configuration"},
            {RPCResult::Type::NUM, "activationheight", "First height accepted by this frozen source lane"},
            {RPCResult::Type::STR_HEX, "capturedtiphash", "Active tip used for this reconstruction"},
            {RPCResult::Type::NUM, "capturedtipheight", "Captured active-tip height"},
            {RPCResult::Type::NUM, "startheight", "First reconstructed block"},
            {RPCResult::Type::NUM, "endheight", "Last reconstructed block, inclusive"},
            {RPCResult::Type::NUM, "nextheight", "Next block for a bounded continuation"},
            {RPCResult::Type::BOOL, "truncated", "Whether another block remains in the requested range"},
            {RPCResult::Type::STR_HEX, "endingheadroot", "Reconstructed node source head"},
            {RPCResult::Type::NUM, "endingentrycount", "Reconstructed node source count"},
            {RPCResult::Type::ARR, "entries", "Exact source entries", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "entryindex", "Canonical append index"},
                    {RPCResult::Type::NUM, "sidechainheight", "Containing active block height"},
                    {RPCResult::Type::NUM, "observedparentheight", "Authenticated observed parent height"},
                    {RPCResult::Type::NUM, "processdeadlineparentheight", "Exact ExpiredUnavailable boundary, observed parent height plus six"},
                    {RPCResult::Type::NUM, "refundnotbeforeparentheight", "Signed enqueue refund boundary, or zero for non-enqueue markers"},
                    {RPCResult::Type::NUM, "markerkind", "Canonical marker kind, 0..3"},
                    {RPCResult::Type::STR_HEX, "actionid", "Authenticated marker action identifier"},
                    {RPCResult::Type::NUM, "transactionindex", "Transaction index in the block"},
                    {RPCResult::Type::NUM, "markervout", "Exact marker output index"},
                    {RPCResult::Type::STR_HEX, "txid", "Source txid in display order"},
                    {RPCResult::Type::STR_HEX, "wtxid", "Source wtxid in display order"},
                    {RPCResult::Type::STR_HEX, "canonicalentryhex", "Exact canonical entry: 700 bytes for finite-v18 or 708 bytes for incremental-successor"},
                    {RPCResult::Type::STR_HEX, "sourcetransactionhex", "Exact witness-bearing transaction serialization"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getecxbondinboxentries", "100 1") +
            HelpExampleRpc("getecxbondinboxentries", "100, 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const ecx::ExchangeConsensus& frozen{ecx::LayerTwoLabsExchangeConsensus()};
    if (!Params().GetConsensus().elements_mode ||
        !frozen.bond_v2.activation_enabled || !frozen.bond_v2.identities_frozen) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "frozen ECX bond V2 source export is unavailable");
    }
    const int start_height{request.params[0].get_int()};
    const int block_count{
        request.params[1].isNull() ? 1 : request.params[1].get_int()};
    if (start_height < frozen.activation_height || block_count < 1 ||
        block_count > 64) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "start_height must be at/after V2 activation and block_count must be 1..64");
    }

    uint256 captured_tip_hash;
    int captured_tip_height{0};
    int requested_end{0};
    ecx::BondV2CapitalSnapshot working;
    std::vector<std::pair<const CBlockIndex*, ecx::BondV2CapitalSnapshot>> blocks;
    {
        LOCK(cs_main);
        const CBlockIndex* tip{chainman.ActiveChain().Tip()};
        if (tip == nullptr || start_height > tip->nHeight) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, "start_height is beyond the active tip");
        }
        captured_tip_hash = tip->GetBlockHash();
        captured_tip_height = tip->nHeight;
        requested_end = std::min(
            tip->nHeight,
            start_height + block_count - 1);
        if (start_height == frozen.activation_height) {
            working.bond_inbox_head_root = ecx::BondInboxGenesisHead(frozen);
            working.node_bond_inbox_head_root = working.bond_inbox_head_root;
        } else {
            const CBlockIndex* previous{chainman.ActiveChain()[start_height - 1]};
            if (previous == nullptr || !previous->ecxBondV2Capital.has_value()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "predecessor lacks a verified bond-inbox projection");
            }
            working = *previous->ecxBondV2Capital;
        }
        for (int height = start_height; height <= requested_end; ++height) {
            const CBlockIndex* index{chainman.ActiveChain()[height]};
            if (index == nullptr || !index->ecxBondV2Capital.has_value()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    strprintf("height %d lacks a verified bond-inbox projection", height));
            }
            blocks.emplace_back(index, *index->ecxBondV2Capital);
        }
    }

    std::vector<ecx::BondInboxSourceExport> exported;
    int end_height{start_height - 1};
    bool truncated{false};
    for (const auto& [index, expected] : blocks) {
        CBlock block;
        if (!ReadBlockFromDisk(block, index, Params().GetConsensus())) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                strprintf("archival block unavailable at height %d", index->nHeight));
        }
        ecx::BondV2CapitalSnapshot candidate{working};
        if (expected.proof_profile == 1 && working.proof_profile == 0) {
            candidate.proof_profile = 1;
            candidate.bond_inbox_head_root =
                ecx::IncrementalSuccessorBondInboxGenesisHead(frozen);
            candidate.node_bond_inbox_head_root = candidate.bond_inbox_head_root;
            candidate.bond_inbox_entry_count = 0;
            candidate.node_bond_inbox_entry_count = 0;
        }
        std::vector<ecx::BondInboxSourceExport> block_entries;
        std::string error;
        const bool reconstructed{expected.proof_profile == 1
            ? ecx::AppendIncrementalSuccessorBondInboxSourcesForBlock(
                block,
                static_cast<uint64_t>(index->nHeight),
                static_cast<uint64_t>(index->ecxParentHeight),
                candidate,
                error,
                frozen,
                &block_entries)
            : ecx::AppendBondInboxSourcesForBlock(
                block,
                static_cast<uint64_t>(index->nHeight),
                static_cast<uint64_t>(index->ecxParentHeight),
                candidate,
                error,
                frozen,
                &block_entries)};
        if (!reconstructed) {
            throw JSONRPCError(RPC_MISC_ERROR, error);
        }
        if (candidate.node_bond_inbox_head_root !=
                expected.node_bond_inbox_head_root ||
            candidate.node_bond_inbox_entry_count !=
                expected.node_bond_inbox_entry_count) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "archival source reconstruction disagrees with the verified block index");
        }
        if (!exported.empty() && exported.size() + block_entries.size() > 8) {
            truncated = true;
            break;
        }
        exported.insert(
            exported.end(),
            std::make_move_iterator(block_entries.begin()),
            std::make_move_iterator(block_entries.end()));
        working = expected;
        end_height = index->nHeight;
    }

    {
        LOCK(cs_main);
        const CBlockIndex* tip{chainman.ActiveChain().Tip()};
        if (tip == nullptr || tip->GetBlockHash() != captured_tip_hash ||
            tip->nHeight != captured_tip_height) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "active chain changed while reconstructing bond-inbox entries");
        }
        for (const auto& [index, expected] : blocks) {
            if (index->nHeight > end_height) break;
            if (chainman.ActiveChain()[index->nHeight] != index) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "bond-inbox export range was reorganized during reconstruction");
            }
        }
    }

    const auto u128_number = [](const ecx::BigEndianUint128& value) {
        std::string decimal{"0"};
        for (const unsigned char byte : value.bytes) {
            unsigned int carry{byte};
            for (auto cursor = decimal.rbegin(); cursor != decimal.rend(); ++cursor) {
                const unsigned int digit = static_cast<unsigned int>(*cursor - '0') * 256 + carry;
                *cursor = static_cast<char>('0' + digit % 10);
                carry = digit / 10;
            }
            while (carry != 0) {
                decimal.insert(decimal.begin(), static_cast<char>('0' + carry % 10));
                carry /= 10;
            }
        }
        UniValue result(UniValue::VNUM);
        result.setNumStr(decimal);
        return result;
    };
    UniValue entries(UniValue::VARR);
    for (const auto& entry : exported) {
        UniValue object(UniValue::VOBJ);
        object.pushKV("proofprofile", static_cast<uint64_t>(entry.proof_profile));
        object.pushKV("entryindex", u128_number(entry.entry_index_u128));
        object.pushKV("sidechainheight", entry.sidechain_height);
        object.pushKV("observedparentheight", entry.observed_parent_height);
        object.pushKV(
            "processdeadlineparentheight",
            entry.process_deadline_parent_height);
        object.pushKV(
            "refundnotbeforeparentheight",
            entry.refund_not_before_parent_height);
        object.pushKV("markerkind", static_cast<uint64_t>(entry.marker_kind));
        object.pushKV("actionid", entry.action_id.GetHex());
        object.pushKV(
            "transactionindex",
            static_cast<uint64_t>(entry.source_transaction_index));
        object.pushKV("markervout", static_cast<uint64_t>(entry.marker_vout));
        object.pushKV("txid", entry.source_txid.GetHex());
        object.pushKV("wtxid", entry.source_wtxid.GetHex());
        object.pushKV("canonicalentryhex", HexStr(entry.canonical_entry));
        object.pushKV("sourcetransactionhex", HexStr(entry.source_transaction));
        entries.push_back(object);
    }
    const int next_height{std::max(start_height, end_height + 1)};
    if (end_height < requested_end) truncated = true;
    UniValue result(UniValue::VOBJ);
    result.pushKV("schema_version", 4);
    result.pushKV("configurationhash", frozen.bond_v2.configuration_hash.GetHex());
    result.pushKV("activationheight", frozen.activation_height);
    result.pushKV("capturedtiphash", captured_tip_hash.GetHex());
    result.pushKV("capturedtipheight", captured_tip_height);
    result.pushKV("startheight", start_height);
    result.pushKV("endheight", end_height);
    result.pushKV("nextheight", next_height);
    result.pushKV("truncated", truncated);
    result.pushKV("endingheadroot", working.node_bond_inbox_head_root.GetHex());
    result.pushKV(
        "endingentrycount", u128_number(working.node_bond_inbox_entry_count));
    result.pushKV("entries", entries);
    return result;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{"verifychain",
                "\nVerifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verified or not"},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].get_int()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].get_int()};

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    CChainState& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB().VerifyDB(
        active_chainstate, Params().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth);
},
    };
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    // For buried deployments.

    if (!DeploymentEnabled(params, dep)) return;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "buried");
    // getdeploymentinfo reports the softfork as active from when the chain height is
    // one below the activation height
    rv.pushKV("active", DeploymentActiveAfter(blockindex, params, dep));
    rv.pushKV("height", params.DeploymentHeight(dep));
    softforks.pushKV(DeploymentName(dep), rv);
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    // For BIP9 deployments.

    if (!DeploymentEnabled(consensusParams, id)) return;
    if (blockindex == nullptr) return;

    auto get_state_name = [](const ThresholdState state) -> std::string {
        switch (state) {
        case ThresholdState::DEFINED: return "defined";
        case ThresholdState::STARTED: return "started";
        case ThresholdState::LOCKED_IN: return "locked_in";
        case ThresholdState::ACTIVE: return "active";
        case ThresholdState::FAILED: return "failed";
        }
        return "invalid";
    };

    UniValue bip9(UniValue::VOBJ);

    const ThresholdState next_state = g_versionbitscache.State(blockindex, consensusParams, id);
    const ThresholdState current_state = g_versionbitscache.State(blockindex->pprev, consensusParams, id);

    const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);

    // BIP9 parameters
    if (has_signal) {
        bip9.pushKV("bit", consensusParams.vDeployments[id].bit);
    }
    bip9.pushKV("start_time", consensusParams.vDeployments[id].nStartTime);
    bip9.pushKV("timeout", consensusParams.vDeployments[id].nTimeout);
    bip9.pushKV("min_activation_height", consensusParams.vDeployments[id].min_activation_height);

    // BIP9 status
    bip9.pushKV("status", get_state_name(current_state));
    bip9.pushKV("since", g_versionbitscache.StateSinceHeight(blockindex->pprev, consensusParams, id));
    bip9.pushKV("status_next", get_state_name(next_state));

    // BIP9 signalling status, if applicable
    if (has_signal) {
        UniValue statsUV(UniValue::VOBJ);
        std::vector<bool> signals;
        BIP9Stats statsStruct = g_versionbitscache.Statistics(blockindex, consensusParams, id, &signals);
        statsUV.pushKV("period", statsStruct.period);
        statsUV.pushKV("elapsed", statsStruct.elapsed);
        statsUV.pushKV("count", statsStruct.count);
        if (ThresholdState::LOCKED_IN != current_state) {
            statsUV.pushKV("threshold", statsStruct.threshold);
            statsUV.pushKV("possible", statsStruct.possible);
        }
        bip9.pushKV("statistics", statsUV);

        std::string sig;
        sig.reserve(signals.size());
        for (const bool s : signals) {
            sig.push_back(s ? '#' : '-');
        }
        bip9.pushKV("signalling", sig);
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "bip9");
    if (ThresholdState::ACTIVE == next_state) {
        rv.pushKV("height", g_versionbitscache.StateSinceHeight(blockindex, consensusParams, id));
    }
    rv.pushKV("active", ThresholdState::ACTIVE == next_state);
    rv.pushKV("bip9", bip9);

    softforks.pushKV(DeploymentName(id), rv);
}

namespace {
/* TODO: when -deprecatedrpc=softforks is removed, drop these */
UniValue DeploymentInfo(const CBlockIndex* tip, const Consensus::Params& consensusParams);
extern const std::vector<RPCResult> RPCHelpForDeployment;
}

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    /* TODO: from v24, remove -deprecatedrpc=softforks */
    return RPCHelpMan{"getblockchaininfo",
                "Returns an object containing various state info regarding blockchain processing.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "chain", "current network name (always elements in production)"},
                        {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                        {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                        {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                        {RPCResult::Type::NUM, "difficulty", "the current difficulty"},
                        {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                        {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                        {RPCResult::Type::STR_HEX, "chainwork", "total amount of work in active chain, in hexadecimal"},
                        {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                        {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                        {RPCResult::Type::STR_HEX, "current_params_root", "the root of the currently active dynafed params"},
                        {RPCResult::Type::STR, "signblock_asm", "ASM of sign block challenge data from genesis block"},
                        {RPCResult::Type::STR_HEX, "signblock_hex", "Hex of sign block challenge data from genesis block"},
                        {RPCResult::Type::STR, "current_signblock_asm", "ASM of sign block challenge data enforced on the next block"},
                        {RPCResult::Type::STR_HEX, "current_signblock_hex", "Hex of sign block challenge data enforced on the next block"},
                        {RPCResult::Type::NUM, "max_block_witness", "maximum sized block witness serialized size for the next block"},
                        {RPCResult::Type::NUM, "epoch_length", "length of dynamic federations epoch, or signaling period"},
                        {RPCResult::Type::NUM, "total_valid_epochs", "number of epochs a given fedpscript is valid for, defined per chain"},
                        {RPCResult::Type::NUM, "epoch_age", "number of blocks into a dynamic federation epoch chain tip is. This number is between 0 to epoch_length-1"},
                        {RPCResult::Type::ARR, "extension_space", "array of extension fields in dynamic blockheader",
                        {
                            {RPCResult::Type::ELISION, "", ""}
                        }},
                        {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "lowest-height complete block stored (only present if pruning is enabled)"},
                        {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                        {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                        {RPCResult::Type::OBJ_DYN, "softforks", "(DEPRECATED, returned only if config option -deprecatedrpc=softforks is passed) status of softforks",
                        {
                            {RPCResult::Type::OBJ, "xxxx", "name of the softfork",
                                RPCHelpForDeployment
                            },
                        }},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChainState& active_chainstate = chainman.ActiveChainstate();

    const CChainParams& chainparams = Params();
    const CBlockIndex* tip = active_chainstate.m_chain.Tip();
    CHECK_NONFATAL(tip);
    const int height = tip->nHeight;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain",                 chainparams.NetworkIDString());
    obj.pushKV("blocks",                height);
    obj.pushKV("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1);
    obj.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
    if (!g_signed_blocks) {
        obj.pushKV("difficulty",            (double)GetDifficulty(tip));
    }
    obj.pushKV("time",                  (int64_t)tip->nTime);
    obj.pushKV("mediantime",            (int64_t)tip->GetMedianTimePast());
    obj.pushKV("verificationprogress",  GuessVerificationProgress(tip, Params().GetConsensus().nPowTargetSpacing));
    obj.pushKV("initialblockdownload",  active_chainstate.IsInitialBlockDownload());
    if (!g_signed_blocks) {
        obj.pushKV("chainwork", tip->nChainWork.GetHex());
    }
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("pruned",                node::fPruneMode);
    obj.pushKV("trim_headers",          node::fTrimHeaders); // ELEMENTS
    if (g_signed_blocks) {
        if (!DeploymentActiveAfter(tip, chainparams.GetConsensus(), Consensus::DEPLOYMENT_DYNA_FED)) {
            CScript sign_block_script = chainparams.GetConsensus().signblockscript;
            obj.pushKV("current_signblock_asm", ScriptToAsmStr(sign_block_script));
            obj.pushKV("current_signblock_hex", HexStr(sign_block_script));
            obj.pushKV("max_block_witness", (uint64_t)chainparams.GetConsensus().max_block_signature_size);
            UniValue arr(UniValue::VARR);
            for (const auto& extension : chainparams.GetConsensus().first_extension_space) {
                arr.push_back(HexStr(extension));
            }
            obj.pushKV("extension_space", arr);
        } else {
            const DynaFedParamEntry entry = ComputeNextBlockFullCurrentParameters(tip, chainparams.GetConsensus());
            obj.pushKV("current_params_root", entry.CalculateRoot().GetHex());
            obj.pushKV("current_signblock_asm", ScriptToAsmStr(entry.m_signblockscript));
            obj.pushKV("current_signblock_hex", HexStr(entry.m_signblockscript));
            obj.pushKV("max_block_witness", (uint64_t)entry.m_signblock_witness_limit);
            obj.pushKV("current_fedpeg_program", HexStr(entry.m_fedpeg_program));
            obj.pushKV("current_fedpeg_script", HexStr(entry.m_fedpegscript));
            UniValue arr(UniValue::VARR);
            for (const auto& extension : entry.m_extension_space) {
                arr.push_back(HexStr(extension));
            }
            obj.pushKV("extension_space", arr);
            obj.pushKV("epoch_length", (uint64_t)chainparams.GetConsensus().dynamic_epoch_length);
            obj.pushKV("total_valid_epochs", (uint64_t)chainparams.GetConsensus().total_valid_epochs);
            obj.pushKV("epoch_age", (uint64_t)(tip->nHeight % chainparams.GetConsensus().dynamic_epoch_length));
        }
    }

    if (node::fPruneMode) {
        const CBlockIndex* block = tip;
        CHECK_NONFATAL(block);
        while (block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA)) {
            block = block->pprev;
        }

        obj.pushKV("pruneheight",        block->nHeight);

        // if 0, execution bypasses the whole if block.
        bool automatic_pruning{args.GetIntArg("-prune", 0) != 1};
        obj.pushKV("automatic_pruning",  automatic_pruning);
        if (automatic_pruning) {
            obj.pushKV("prune_target_size",  node::nPruneTarget);
        }
    }

    if (IsDeprecatedRPCEnabled("softforks")) {
        const Consensus::Params& consensusParams = Params().GetConsensus();
        obj.pushKV("softforks", DeploymentInfo(tip, consensusParams));
    }

    obj.pushKV("warnings", GetWarnings(false).original);
    return obj;
},
    };
}

namespace {
const std::vector<RPCResult> RPCHelpForDeployment{
    {RPCResult::Type::STR, "type", "one of \"buried\", \"bip9\""},
    {RPCResult::Type::NUM, "height", /*optional=*/true, "height of the first block which the rules are or will be enforced (only for \"buried\" type, or \"bip9\" type with \"active\" status)"},
    {RPCResult::Type::BOOL, "active", "true if the rules are enforced for the mempool and the next block"},
    {RPCResult::Type::OBJ, "bip9", /*optional=*/true, "status of bip9 softforks (only for \"bip9\" type)",
    {
        {RPCResult::Type::NUM, "bit", /*optional=*/true, "the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)"},
        {RPCResult::Type::NUM_TIME, "start_time", "the minimum median time past of a block at which the bit gains its meaning"},
        {RPCResult::Type::NUM_TIME, "timeout", "the median time past of a block at which the deployment is considered failed if not yet locked in"},
        {RPCResult::Type::NUM, "min_activation_height", "minimum height of blocks for which the rules may be enforced"},
        {RPCResult::Type::STR, "status", "status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\")"},
        {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
        {RPCResult::Type::STR, "status_next", "status of deployment at the next block"},
        {RPCResult::Type::OBJ, "statistics", /*optional=*/true, "numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)",
        {
            {RPCResult::Type::NUM, "period", "the length in blocks of the signalling period"},
            {RPCResult::Type::NUM, "threshold", /*optional=*/true, "the number of blocks with the version bit set required to activate the feature (only for \"started\" status)"},
            {RPCResult::Type::NUM, "elapsed", "the number of blocks elapsed since the beginning of the current period"},
            {RPCResult::Type::NUM, "count", "the number of blocks with the version bit set in the current period"},
            {RPCResult::Type::BOOL, "possible", /*optional=*/true, "returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)"},
        }},
        {RPCResult::Type::STR, "signalling", "indicates blocks that signalled with a # and blocks that did not with a -"},
    }},
};

UniValue DeploymentInfo(const CBlockIndex* blockindex, const Consensus::Params& consensusParams)
{
    UniValue softforks(UniValue::VOBJ);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_HEIGHTINCB);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_DERSIG);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_CLTV);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_CSV);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_SEGWIT);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_DYNA_FED);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_TESTDUMMY);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_TAPROOT);
    SoftForkDescPushBack(blockindex, softforks, consensusParams, Consensus::DEPLOYMENT_SIMPLICITY);
    return softforks;
}
} // anon namespace

static RPCHelpMan getdeploymentinfo()
{
    return RPCHelpMan{"getdeploymentinfo",
        "Returns an object containing various state info regarding deployments of consensus changes.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                {RPCResult::Type::OBJ, "deployments", "", {
                    {RPCResult::Type::OBJ, "xxxx", "name of the deployment", RPCHelpForDeployment}
                }},
            }
        },
        RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const CChainState& active_chainstate = chainman.ActiveChainstate();

            const CBlockIndex* blockindex;
            if (request.params[0].isNull()) {
                blockindex = active_chainstate.m_chain.Tip();
                CHECK_NONFATAL(blockindex);
            } else {
                const uint256 hash(ParseHashV(request.params[0], "blockhash"));
                blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                if (!blockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            const Consensus::Params& consensusParams = Params().GetConsensus();

            UniValue deploymentinfo(UniValue::VOBJ);
            deploymentinfo.pushKV("hash", blockindex->GetBlockHash().ToString());
            deploymentinfo.pushKV("height", blockindex->nHeight);
            deploymentinfo.pushKV("deployments", DeploymentInfo(blockindex, consensusParams));
            return deploymentinfo;
        },
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const std::pair<const uint256, CBlockIndex*>& item : chainman.BlockIndex()) {
        if (!active_chain.Contains(item.second)) {
            setOrphans.insert(item.second);
            setPrevs.insert(item.second->pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveTxsDownloaded()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(obj);
    }

    return res;
},
    };
}

UniValue MempoolInfoToJSON(const CTxMemPool& pool)
{
    // Make sure this call is atomic in the pool.
    LOCK(pool.cs);
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("loaded", pool.IsLoaded());
    ret.pushKV("size", (int64_t)pool.size());
    ret.pushKV("bytes", (int64_t)pool.GetTotalTxSize());
    ret.pushKV("usage", (int64_t)pool.DynamicMemoryUsage());
    ret.pushKV("total_fee", ValueFromAmount(pool.GetTotalFee()));
    size_t maxmempool = gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    ret.pushKV("maxmempool", (int64_t) maxmempool);
    ret.pushKV("mempoolminfee", ValueFromAmount(std::max(pool.GetMinFee(maxmempool), ::minRelayTxFee).GetFeePerK()));
    ret.pushKV("minrelaytxfee", ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    ret.pushKV("unbroadcastcount", uint64_t{pool.GetUnbroadcastTxs().size()});
    return ret;
}

static RPCHelpMan getmempoolinfo()
{
    return RPCHelpMan{"getmempoolinfo",
                "\nReturns details on the active state of the TX memory pool.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "loaded", "True if the mempool is fully loaded"},
                        {RPCResult::Type::NUM, "size", "Current tx count"},
                        {RPCResult::Type::NUM, "bytes", "Sum of all virtual transaction sizes as defined in BIP 141. Differs from actual serialized size because witness data is discounted"},
                        {RPCResult::Type::NUM, "usage", "Total memory usage for the mempool"},
                        {RPCResult::Type::STR_AMOUNT, "total_fee", "Total fees for the mempool in " + CURRENCY_UNIT + ", ignoring modified fees through prioritisetransaction"},
                        {RPCResult::Type::NUM, "maxmempool", "Maximum memory usage for the mempool"},
                        {RPCResult::Type::STR_AMOUNT, "mempoolminfee", "Minimum fee rate in " + CURRENCY_UNIT + "/kvB for tx to be accepted. Is the maximum of minrelaytxfee and minimum mempool fee"},
                        {RPCResult::Type::STR_AMOUNT, "minrelaytxfee", "Current minimum relay fee for transactions"},
                        {RPCResult::Type::NUM, "unbroadcastcount", "Current number of transactions that haven't passed initial broadcast yet"}
                    }},
                RPCExamples{
                    HelpExampleCli("getmempoolinfo", "")
            + HelpExampleRpc("getmempoolinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return MempoolInfoToJSON(EnsureAnyMemPool(request.context));
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{"preciousblock",
                "\nTreats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return NullUniValue;
},
    };
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{"invalidateblock",
                "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    BlockValidationState state;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    CBlockIndex* pblockindex;
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return NullUniValue;
},
    };
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{"reconsiderblock",
                "\nRemoves invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    {
        LOCK(cs_main);
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return NullUniValue;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{"getchaintxstats",
                "\nCompute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", "The total number of transactions in the chain up to that point"},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true, "The number of transactions in the window. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true, "The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0"},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / Params().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].get_int();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex* pindexPast = pindex->GetAncestor(pindex->nHeight - blockcount);
    int nTimeDiff = pindex->GetMedianTimePast() - pindexPast->GetMedianTimePast();
    int nTxDiff = pindex->nChainTx - pindexPast->nChainTx;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    ret.pushKV("txcount", (int64_t)pindex->nChainTx);
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_tx_count", nTxDiff);
        ret.pushKV("window_interval", nTimeDiff);
        if (nTimeDiff > 0) {
            ret.pushKV("txrate", ((double)nTxDiff) / nTimeDiff);
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{"getblockstats",
                "\nCompute per block statistics for a given window. All amounts are in satoshis.\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block", "", {"", "string or numeric"}},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        "stats"},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                {
                    {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                    {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                    {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                    {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                    {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                }},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CBlockIndex* pindex{ParseHashOrHeight(request.params[0], chainman)};
    CHECK_NONFATAL(pindex != nullptr);

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    // ELEMENTS:
    const CAsset asset = policyAsset; // TODO Make configurable

    const CBlock block = GetBlockChecked(pindex);
    const CBlockUndo blockUndo = GetUndoChecked(pindex);

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_size_inc", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxo_size_inc = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        // ELEMENTS:
        CAmount elements_txfee = 0;
        if (g_con_elementsmode) {
            if (loop_outputs) {
                for (const CTxOut& out : tx->vout) {
                    if (out.IsFee() && out.nAsset.GetAsset() == asset) {
                        elements_txfee += out.nValue.GetAmount();
                    }
                    if (out.nValue.IsExplicit() && out.nAsset.IsExplicit() && out.nAsset.GetAsset() == asset) {
                        tx_total_out += out.nValue.GetAmount();
                    }
                    utxo_size_inc += GetSerializeSize(out, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
                }
            }
        } else {
            if (loop_outputs) {
                for (const CTxOut& out : tx->vout) {
                    tx_total_out += out.nValue.GetAmount();
                    utxo_size_inc += GetSerializeSize(out, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
                }
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in = 0;
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += g_con_elementsmode ? 0 : prevoutput.nValue.GetAmount();
                utxo_size_inc -= GetSerializeSize(prevoutput, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
            }

            CAmount txfee = g_con_elementsmode ? elements_txfee : (tx_total_in - tx_total_out);
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(std::make_pair(feerate, weight));
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    CalculatePercentilesByWeight(feerate_percentiles, feerate_array, total_weight);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(feerate_percentiles[i]);
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex->GetBlockHash().GetHex());
    ret_all.pushKV("feerate_percentiles", feerates_res);
    ret_all.pushKV("height", (int64_t)pindex->nHeight);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", pindex->GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", GetBlockSubsidy(pindex->nHeight, Params().GetConsensus()));
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", pindex->GetBlockTime());
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
},
    };
}

static RPCHelpMan savemempool()
{
    return RPCHelpMan{"savemempool",
                "\nDumps the mempool to disk. It will fail until the previous dump is fully loaded.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "filename", "the directory and file where the mempool was saved"},
                    }},
                RPCExamples{
                    HelpExampleCli("savemempool", "")
            + HelpExampleRpc("savemempool", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);

    if (!mempool.IsLoaded()) {
        throw JSONRPCError(RPC_MISC_ERROR, "The mempool was not loaded yet");
    }

    if (!DumpMempool(mempool)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unable to dump mempool to disk");
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filename", fs::path((args.GetDataDirNet() / "mempool.dat")).u8string());

    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *key.hash.begin() + *(key.hash.begin() + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve;
public:
    explicit CoinsViewScanReserver() : m_could_reserve(false) {}

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress.exchange(true)) {
            return false;
        }
        CHECK_NONFATAL(g_scan_progress == 0);
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            g_scan_in_progress = false;
            g_scan_progress = 0;
        }
    }
};

static RPCHelpMan scantxoutset()
{
    // scriptPubKey corresponding to mainnet address 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

    return RPCHelpMan{"scantxoutset",
        "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                      Outputs whose scriptPubKey corresponds to the specified address (does not include P2PK)\n"
        "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
        "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
        "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
        "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
        {
            {"action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
                "\"start\" for starting a scan\n"
                "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
                "\"status\" for progress report (in %) of the current scan"},
            {"scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
                "Every scan object is either a string descriptor or an object:",
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
                {
                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                    {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
                }},
            },
                        "[scanobjects,...]"},
        },
        {
            RPCResult{"When action=='abort'", RPCResult::Type::BOOL, "", ""},
            RPCResult{"When action=='status' and no scan is in progress", RPCResult::Type::NONE, "", ""},
            RPCResult{"When action=='status' and scan is in progress", RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "progress", "The scan progress"},
            }},
            RPCResult{"When action=='start'", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The current block height (index)"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The script key"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched scriptPubKey"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::STR_HEX, "asset", "The asset ID"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                    }},
                    {RPCResult::Type::STR_AMOUNT, "total_unblinded_bitcoin_amount", "The total amount of all found unspent unblinded outputs in " + CURRENCY_UNIT},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR});

    UniValue result(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        result.pushKV("progress", g_scan_progress);
        return result;
    } else if (request.params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params.size() < 2) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const auto& script : scripts) {
                std::string inferred = InferDescriptor(script, provider)->ToString();
                needles.emplace(script);
                descriptors.emplace(std::move(script), std::move(inferred));
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        CBlockIndex* tip;
        NodeContext& node = EnsureAnyNodeContext(request.context);
        {
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            CChainState& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
            pcursor = active_chainstate.CoinsDB().Cursor();
            CHECK_NONFATAL(pcursor);
            tip = active_chainstate.m_chain.Tip();
            CHECK_NONFATAL(tip);
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
        result.pushKV("success", res);
        result.pushKV("txouts", count);
        result.pushKV("height", tip->nHeight);
        result.pushKV("bestblock", tip->GetBlockHash().GetHex());

        if (!g_con_elementsmode) {
            for (const auto& it : coins) {
                const COutPoint& outpoint = it.first;
                const Coin& coin = it.second;
                const CTxOut& txo = coin.out;
                input_txos.push_back(txo);
                total_in += txo.nValue.GetAmount();

                UniValue unspent(UniValue::VOBJ);
                unspent.pushKV("txid", outpoint.hash.GetHex());
                unspent.pushKV("vout", (int32_t)outpoint.n);
                unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
                unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
                unspent.pushKV("amount", ValueFromAmount(txo.nValue.GetAmount()));
                unspent.pushKV("height", (int32_t)coin.nHeight);

                unspents.push_back(unspent);
            }
            result.pushKV("unspents", unspents);
            result.pushKV("total_amount", ValueFromAmount(total_in));
        } else {
            CAmount total_in_explicit_parent = 0;
            for (const auto& it : coins) {
                const COutPoint& outpoint = it.first;
                const Coin& coin = it.second;
                const CTxOut& txo = coin.out;
                input_txos.push_back(txo);
                if (txo.nValue.IsExplicit() && txo.nAsset.IsExplicit() && txo.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) {
                    total_in_explicit_parent += txo.nValue.GetAmount();
                }

                UniValue unspent(UniValue::VOBJ);
                unspent.pushKV("txid", outpoint.hash.GetHex());
                unspent.pushKV("vout", (int32_t)outpoint.n);
                unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
                unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
                if (txo.nValue.IsExplicit()) {
                    unspent.pushKV("amount", ValueFromAmount(txo.nValue.GetAmount()));
                } else {
                    unspent.pushKV("amountcommitment", HexStr(txo.nValue.vchCommitment));
                }
                if (txo.nAsset.IsExplicit()) {
                    unspent.pushKV("asset", txo.nAsset.GetAsset().GetHex());
                } else {
                    unspent.pushKV("assetcommitment", HexStr(txo.nAsset.vchCommitment));
                }
                unspent.pushKV("height", (int32_t)coin.nHeight);

                unspents.push_back(unspent);
            }
            result.pushKV("unspents", unspents);
            result.pushKV("total_unblinded_bitcoin_amount", ValueFromAmount(total_in_explicit_parent));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
    }
    return result;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{"getblockfilter",
                "\nRetrieve a BIP 157 content filter for a particular block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{"basic"}, "The type name of the filter"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    std::string filtertype_name = "basic";
    if (!request.params[1].isNull()) {
        filtertype_name = request.params[1].get_str();
    }

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to disk.",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
        },
        RPCExamples{
            HelpExampleCli("dumptxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.u8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    CAutoFile afile{file, SER_DISK, CLIENT_VERSION};
    NodeContext& node = EnsureAnyNodeContext(request.context);
    UniValue result = CreateUTXOSnapshot(
        node, node.chainman->ActiveChainstate(), afile, path, temppath);
    fs::rename(temppath, path);

    result.pushKV("path", path.u8string());
    return result;
},
    };
}

UniValue CreateUTXOSnapshot(
    NodeContext& node,
    CChainState& chainstate,
    CAutoFile& afile,
    const fs::path& path,
    const fs::path& temppath)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    CCoinsStats stats{CoinStatsHashType::HASH_SERIALIZED};
    CBlockIndex* tip;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use below this block.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        LOCK(::cs_main);

        chainstate.ForceFlushStateToDisk();

        if (!GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, stats, node.rpc_interruption_point)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = chainstate.m_blockman.LookupBlockIndex(stats.hashBlock);
        CHECK_NONFATAL(tip);
    }

    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{tip->GetBlockHash(), stats.coins_count, tip->nChainTx};

    afile << metadata;

    COutPoint key;
    Coin coin;
    unsigned int iter{0};

    while (pcursor->Valid()) {
        if (iter % 5000 == 0) node.rpc_interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            afile << key;
            afile << coin;
        }

        pcursor->Next();
    }

    afile.fclose();

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", stats.coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.u8string());
    result.pushKV("txoutset_hash", stats.hashSerialized.ToString());
    // Cast required because univalue doesn't have serialization specified for
    // `unsigned int`, nChainTx's type.
    result.pushKV("nchaintx", uint64_t{tip->nChainTx});
    return result;
}

//
// ELEMENTS:

namespace {

UniValue FetchDrivechainL1PegEvents(int sidechain_id)
{
    UniValue response(UniValue::VOBJ);
    std::string error;
    if (!GetDrivechainTwoWayPegData(sidechain_id, response, &error)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("GetTwoWayPegData failed: %s", error));
    }
    return drivechain::NormalizeL1PegEvents(response, sidechain_id);
}

} // namespace

static RPCHelpMan getdrivechainpegevents()
{
    return RPCHelpMan{"getdrivechainpegevents",
                "Returns versioned BIP300 deposit, withdrawal, bundle, and acknowledgement events.\n"
                "Sidechain events are reconstructed from active-chain consensus data and therefore follow reorgs.\n"
                "Set include_l1 to query and normalize CUSF GetTwoWayPegData from the configured enforcer.\n",
                {
                    {"start_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"tip - 999"}, "First sidechain height to scan."},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{1000}, "Number of sidechain blocks to scan (1-10000)."},
                    {"include_l1", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include normalized L1 CUSF lifecycle events."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Versioned drivechain event response.",
                    {
                        {RPCResult::Type::NUM, "schema_version", "Event contract version."},
                        {RPCResult::Type::NUM, "sidechain_id", "BIP300 sidechain slot."},
                        {RPCResult::Type::OBJ, "sidechain_tip", "Active sidechain tip.",
                            {
                                {RPCResult::Type::STR_HEX, "hash", "Sidechain tip hash."},
                                {RPCResult::Type::NUM, "height", "Sidechain tip height."},
                            }},
                        {RPCResult::Type::OBJ, "range", "Scanned sidechain range.",
                            {
                                {RPCResult::Type::NUM, "start_height", "First scanned height."},
                                {RPCResult::Type::NUM, "end_height", "Last scanned height."},
                            }},
                        {RPCResult::Type::ARR, "events", "Normalized events in deterministic chain order.",
                            {{RPCResult::Type::OBJ, "", "Deposit, withdrawal, bundle commitment, or L1 lifecycle event.",
                                {
                                    {RPCResult::Type::STR, "event_id", "Stable event identity."},
                                    {RPCResult::Type::STR, "source", "Event source: sidechain or l1."},
                                    {RPCResult::Type::STR, "kind", "Event kind."},
                                    {RPCResult::Type::STR, "status", "Lifecycle status."},
                                    {RPCResult::Type::NUM, "sidechain_id", /*optional=*/true, "BIP300 sidechain slot."},
                                    {RPCResult::Type::STR_HEX, "sidechain_txid", /*optional=*/true, "Sidechain transaction id."},
                                    {RPCResult::Type::NUM, "vin", /*optional=*/true, "Sidechain transaction input index."},
                                    {RPCResult::Type::NUM, "vout", /*optional=*/true, "Sidechain transaction output index."},
                                    {RPCResult::Type::STR_HEX, "mainchain_txid", /*optional=*/true, "Mainchain transaction id."},
                                    {RPCResult::Type::NUM, "mainchain_vout", /*optional=*/true, "Mainchain output index."},
                                    {RPCResult::Type::STR_HEX, "m6id", /*optional=*/true, "Withdrawal bundle id."},
                                    {RPCResult::Type::NUM, "value_sats", /*optional=*/true, "Explicit value in satoshis."},
                                    {RPCResult::Type::STR_HEX, "asset", /*optional=*/true, "Elements asset id."},
                                    {RPCResult::Type::STR_HEX, "claim_script", /*optional=*/true, "Drivechain deposit claim script."},
                                    {RPCResult::Type::STR_HEX, "address_hex", /*optional=*/true, "Enforcer deposit address bytes."},
                                    {RPCResult::Type::NUM, "sequence_number", /*optional=*/true, "Enforcer sequence number."},
                                    {RPCResult::Type::STR, "acknowledgement", /*optional=*/true, "Bundle acknowledgement state."},
                                    {RPCResult::Type::STR_HEX, "mainchain_transaction", /*optional=*/true, "Final mainchain transaction."},
                                    {RPCResult::Type::STR_HEX, "mainchain_genesis_hash", /*optional=*/true, "Parent-chain genesis hash."},
                                    {RPCResult::Type::STR_HEX, "mainchain_script", /*optional=*/true, "Parent-chain destination script."},
                                    {RPCResult::Type::OBJ, "sidechain", /*optional=*/true, "Sidechain block location.",
                                        {
                                            {RPCResult::Type::STR_HEX, "block_hash", "Sidechain block hash."},
                                            {RPCResult::Type::NUM, "height", "Sidechain block height."},
                                        }},
                                    {RPCResult::Type::OBJ, "l1", /*optional=*/true, "Mainchain block location.",
                                        {
                                            {RPCResult::Type::STR_HEX, "block_hash", "Mainchain block hash."},
                                            {RPCResult::Type::NUM, "height", "Mainchain block height."},
                                            {RPCResult::Type::NUM, "timestamp", /*optional=*/true, "Mainchain block timestamp."},
                                        }},
                                }}}},
                    }},
                RPCExamples{
                    HelpExampleCli("getdrivechainpegevents", "0 1000 true")
                    + HelpExampleRpc("getdrivechainpegevents", "0, 1000, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto& consensus = Params().GetConsensus();
    if (!consensus.elements_mode || !consensus.has_parent_chain) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "getdrivechainpegevents is unavailable outside an Elements parent-chain configuration");
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const int sidechain_id = gArgs.GetIntArg("-drivechainbmmslot", 24);
    if (sidechain_id < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "-drivechainbmmslot must be non-negative");

    int tip_height;
    uint256 tip_hash;
    std::vector<const CBlockIndex*> blocks;
    int start_height;
    int end_height;
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        if (tip == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "Sidechain tip is unavailable");
        tip_height = tip->nHeight;
        tip_hash = tip->GetBlockHash();

        start_height = request.params[0].isNull() ? std::max(0, tip_height - 999) : request.params[0].get_int();
        const int count = request.params[1].isNull() ? 1000 : request.params[1].get_int();
        if (start_height < 0 || start_height > tip_height) throw JSONRPCError(RPC_INVALID_PARAMETER, "start_height is outside the active sidechain");
        if (count < 1 || count > 10000) throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 10000");
        end_height = std::min(tip_height, start_height + count - 1);
        blocks.reserve(end_height - start_height + 1);
        for (int height = start_height; height <= end_height; ++height) {
            blocks.push_back(chainman.ActiveChain()[height]);
        }
    }

    UniValue events(UniValue::VARR);
    for (const CBlockIndex* block_index : blocks) {
        CBlock block;
        if (!ReadBlockFromDisk(block, block_index, Params().GetConsensus())) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Block not available at height %d", block_index->nHeight));
        }
        const uint256 previous_bundle_hash = block_index->pprev == nullptr ? uint256::ZERO : block_index->pprev->hashWithdrawalBundle;
        const UniValue block_events = drivechain::ExtractSidechainPegEvents(block, block_index->nHeight, previous_bundle_hash);
        for (const UniValue& event : block_events.getValues()) {
            events.push_back(event);
        }
    }

    const bool include_l1 = request.params[2].isNull() ? false : request.params[2].get_bool();
    if (include_l1) {
        const UniValue l1_events = FetchDrivechainL1PegEvents(sidechain_id);
        for (const UniValue& event : l1_events.getValues()) events.push_back(event);
    }

    UniValue tip(UniValue::VOBJ);
    tip.pushKV("hash", tip_hash.GetHex());
    tip.pushKV("height", tip_height);
    UniValue range(UniValue::VOBJ);
    range.pushKV("start_height", start_height);
    range.pushKV("end_height", end_height);

    UniValue result(UniValue::VOBJ);
    result.pushKV("schema_version", drivechain::PEG_EVENT_SCHEMA_VERSION);
    result.pushKV("sidechain_id", sidechain_id);
    result.pushKV("sidechain_tip", tip);
    result.pushKV("range", range);
    result.pushKV("events", events);
    return result;
},
    };
}

static RPCHelpMan getsidechaininfo()
{
    return RPCHelpMan{"getsidechaininfo",
                "Returns an object containing various state info regarding sidechain functionality.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "fedpegscript", "The fedpegscript from genesis block"},
                        {RPCResult::Type::ARR, "current_fedpegscripts", "The currently-enforced fedpegscripts in hex. Peg-ins for any entries on this list are honored by consensus and policy. Newest first. Two total entries are possible",
                            {{RPCResult::Type::STR_HEX, "", "active fedpegscript"}}},
                        {RPCResult::Type::ARR, "current_fedpeg_programs", "The currently-enforced fedpegscript scriptPubKeys in hex. Prior to a transition this may be P2SH scriptpubkey, otherwise it will be a native segwit script. Results are paired in-order with current_fedpegscripts",
                            {{RPCResult::Type::STR_HEX, "", "active fedpegscript scriptPubKeys"}}},
                        {RPCResult::Type::STR_HEX, "pegged_asset", "Pegged asset type"},
                        {RPCResult::Type::STR, "min_peg_diff", "The minimum difficulty parent chain header target. Peg-in headers that have less work will be rejected as an anti-Dos measure"},
                        {RPCResult::Type::STR_HEX, "parent_blockhash", "The parent genesis blockhash as source of pegged-in funds"},
                        {RPCResult::Type::BOOL, "parent_chain_has_pow", "Whether parent chain has pow or signed blocks"},
                        {RPCResult::Type::STR, "parent_chain_signblockscript_asm", "If the parent chain has signed blocks, its signblockscript in ASM"},
                        {RPCResult::Type::STR_HEX, "parent_chain_signblockscript_hex", "If the parent chain has signed blocks, its signblockscript in hex"},
                        {RPCResult::Type::STR_HEX, "parent_pegged_asset", "If the parent chain has Confidential Assets, the asset id of the pegged asset in that chain"},
                        {RPCResult::Type::NUM, "pegin_confirmation_depth", "The number of mainchain confirmations required for a peg-in transaction to become valid"},
                        {RPCResult::Type::BOOL, "enforce_pak", "If peg-out authorization is being enforced"},
                    }},
                RPCExamples{
                    HelpExampleCli("getsidechaininfo", "")
                    + HelpExampleRpc("getsidechaininfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256& parent_blockhash = Params().ParentGenesisBlockHash();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("fedpegscript", HexStr(consensus.fedpegScript));
    // We use mempool_validation as true to show what is enforced for *next* block
    std::vector<std::pair<CScript, CScript>> fedpegscripts = GetValidFedpegScripts(chainman.ActiveChain().Tip(), consensus, true /* nextblock_validation */);
    UniValue fedpeg_prog_entries(UniValue::VARR);
    UniValue fedpeg_entries(UniValue::VARR);
    for (const auto& scripts : fedpegscripts) {
        fedpeg_prog_entries.push_back(HexStr(scripts.first));
        fedpeg_entries.push_back(HexStr(scripts.second));
    }
    obj.pushKV("current_fedpeg_programs", fedpeg_prog_entries);
    obj.pushKV("current_fedpegscripts", fedpeg_entries);
    obj.pushKV("pegged_asset", consensus.pegged_asset.GetHex());
    obj.pushKV("min_peg_diff", consensus.parentChainPowLimit.GetHex());
    obj.pushKV("parent_blockhash", parent_blockhash.GetHex());
    obj.pushKV("parent_chain_has_pow", consensus.ParentChainHasPow());
    obj.pushKV("enforce_pak", Params().GetEnforcePak());
    obj.pushKV("pegin_confirmation_depth", (uint64_t)consensus.pegin_min_depth);
    if (!consensus.ParentChainHasPow()) {
        obj.pushKV("parent_chain_signblockscript_asm", ScriptToAsmStr(consensus.parent_chain_signblockscript));
        obj.pushKV("parent_chain_signblockscript_hex", HexStr(consensus.parent_chain_signblockscript));
        obj.pushKV("parent_pegged_asset", consensus.parent_pegged_asset.GetHex());
    }

    PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pegin_minimum.amount > 0) {
        obj.pushKV("pegin_min_amount", FormatMoney(pegin_minimum.amount));
    }
    if (pegin_minimum.height < std::numeric_limits<int>::max()) {
        obj.pushKV("pegin_min_height", pegin_minimum.height);
        obj.pushKV("pegin_min_active", chainman.ActiveTip()->nHeight >= pegin_minimum.height);
    }

    PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    if (pegin_subsidy.threshold > 0) {
        obj.pushKV("pegin_subsidy_threshold", FormatMoney(pegin_subsidy.threshold));
    }
    if (pegin_subsidy.height < std::numeric_limits<int>::max()) {
        obj.pushKV("pegin_subsidy_height", pegin_subsidy.height);
        obj.pushKV("pegin_subsidy_active", chainman.ActiveTip()->nHeight >= pegin_subsidy.height);
    }

    return obj;
},
    };
}

namespace {

struct AuthenticatedNativeWithdrawal
{
    uint256 txid;
    uint32_t vout{0};
    uint256 block_hash;
    int block_height{0};
    int confirmations{0};
    drivechain::NativeWithdrawal withdrawal;
    drivechain::NativeWithdrawalM6 m6;
    std::optional<DrivechainSuccessfulWithdrawal> successful_parent_withdrawal;
};

bool IsSupportedNativeWithdrawalDestination(const CScript& script)
{
    TxoutType type;
    if (!IsStandard(script, type)) return false;
    switch (type) {
    case TxoutType::PUBKEY:
    case TxoutType::PUBKEYHASH:
    case TxoutType::SCRIPTHASH:
    case TxoutType::MULTISIG:
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    case TxoutType::WITNESS_V0_KEYHASH:
    case TxoutType::WITNESS_V1_TAPROOT:
        return true;
    default:
        return false;
    }
}

CAmount NativeWithdrawalParentDustThreshold(const CScript& script)
{
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    const bool witness = script.IsWitnessProgram(
        witness_version, witness_program);
    const size_t output_size = ::GetSerializeSize(
        Sidechain::Bitcoin::CTxOut(0, script), PROTOCOL_VERSION);
    return CFeeRate(DUST_RELAY_TX_FEE_BITCOIN).GetFee(
        static_cast<uint32_t>(output_size) + (witness ? 67 : 148));
}

AuthenticatedNativeWithdrawal LoadNativeWithdrawal(
    ChainstateManager& chainman,
    const uint256& txid,
    const uint32_t vout,
    const uint256& block_hash,
    const int min_confirmations)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!consensus.drivechain_slot.has_value() ||
        !consensus.DrivechainWithdrawalValidationEnabled()) {
        throw JSONRPCError(
            RPC_METHOD_NOT_FOUND,
            "Native BIP300 withdrawals are not enabled on this network");
    }
    if (min_confirmations < 1 || min_confirmations > 100000) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "minconfirmations must be between 1 and 100000");
    }

    const CBlockIndex* block_index{nullptr};
    int confirmations{0};
    {
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        const CChain& active = chainman.ActiveChain();
        if (!block_index || !active.Contains(block_index)) {
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                "Confirming block is not in the active Elements chain");
        }
        if (!(block_index->nStatus & BLOCK_HAVE_DATA)) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "Confirming block data is unavailable on this pruned node");
        }
        confirmations = active.Height() - block_index->nHeight + 1;
        if (confirmations < min_confirmations) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                strprintf("Native withdrawal burn has %d confirmation(s); %d required",
                          confirmations, min_confirmations));
        }
    }

    CBlock block;
    if (!ReadBlockFromDisk(block, block_index, consensus)) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Unable to read the confirming Elements block");
    }
    BlockValidationState block_state;
    if (!CheckBlock(block, block_state, consensus,
                    /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            strprintf("Confirming Elements block body failed context-free validation: %s",
                      block_state.ToString()));
    }
    CTransactionRef transaction;
    for (const CTransactionRef& candidate : block.vtx) {
        if (candidate && candidate->GetHash() == txid) {
            if (transaction) {
                throw JSONRPCError(
                    RPC_INTERNAL_ERROR,
                    "Confirming block contains the withdrawal txid more than once");
            }
            transaction = candidate;
        }
    }
    if (!transaction) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Withdrawal transaction is not in the specified confirming block");
    }
    if (vout >= transaction->vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Withdrawal vout is outside the transaction");
    }

    // A native V1 withdrawal is exactly one canonical parent-genesis peg-out
    // output in its transaction. Its explicit pegged-asset value is destroyed
    // by ordinary Elements consensus because OP_RETURN is never added to the
    // UTXO set. Nothing in this RPC can turn the burn back into a spendable
    // output.
    std::optional<uint32_t> canonical_vout;
    drivechain::NativeWithdrawal withdrawal;
    for (uint32_t index = 0; index < transaction->vout.size(); ++index) {
        const CTxOut& output = transaction->vout[index];
        if (!output.scriptPubKey.IsPegoutScript(
                Params().ParentGenesisBlockHash())) {
            continue;
        }
        const CTxOutWitness* output_witness =
            index < transaction->witness.vtxoutwit.size()
            ? &transaction->witness.vtxoutwit[index]
            : nullptr;
        drivechain::NativeWithdrawal parsed;
        std::string parse_error;
        if (!drivechain::ParseNativeWithdrawalOutput(
                output, output_witness, consensus.pegged_asset,
                Params().ParentGenesisBlockHash(), parsed, &parse_error)) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                strprintf("Malformed native withdrawal output %u: %s",
                          index, parse_error));
        }
        if (canonical_vout.has_value()) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                "Native withdrawal V1 permits exactly one withdrawal burn per Elements transaction");
        }
        canonical_vout = index;
        withdrawal = std::move(parsed);
    }
    if (!canonical_vout.has_value() || *canonical_vout != vout) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "Requested outpoint is not the transaction's sole canonical native withdrawal burn");
    }
    if (!transaction->vout[vout].scriptPubKey.IsUnspendable()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Canonical native withdrawal output is unexpectedly spendable");
    }
    if (!IsSupportedNativeWithdrawalDestination(withdrawal.destination)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "Native withdrawal Bitcoin destination is not a recognized, currently spendable standard script");
    }
    if (withdrawal.payout_amount <
        NativeWithdrawalParentDustThreshold(withdrawal.destination)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "Native withdrawal Bitcoin payout is dust for its destination");
    }

    drivechain::NativeWithdrawalM6 m6;
    std::string m6_error;
    if (!drivechain::BuildNativeWithdrawalM6(
            consensus.hashGenesisBlock,
            static_cast<uint8_t>(*consensus.drivechain_slot),
            txid, vout, withdrawal, m6, &m6_error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, m6_error);
    }
    drivechain::NativeWithdrawalM6 reparsed_m6;
    if (!drivechain::ParseNativeWithdrawalM6(
            m6.blinded_transaction, consensus.hashGenesisBlock,
            static_cast<uint8_t>(*consensus.drivechain_slot), txid, vout,
            reparsed_m6, &m6_error) ||
        reparsed_m6.m6id != m6.m6id ||
        reparsed_m6.legacy_serialization != m6.legacy_serialization) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            m6_error.empty()
                ? "Internally generated native withdrawal M6 failed canonical round-trip"
                : m6_error);
    }

    // Close the disk-read/reorg race immediately before returning an object
    // that may be submitted to the enforcer.
    {
        LOCK(cs_main);
        const CChain& active = chainman.ActiveChain();
        if (!active.Contains(block_index) ||
            block_index->GetBlockHash() != block_hash) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                "Confirming block left the active Elements chain while the withdrawal was authenticated");
        }
        confirmations = active.Height() - block_index->nHeight + 1;
        if (confirmations < min_confirmations) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                "Withdrawal no longer has the required active-chain depth");
        }
    }

    AuthenticatedNativeWithdrawal result;
    result.txid = txid;
    result.vout = vout;
    result.block_hash = block_hash;
    result.block_height = block_index->nHeight;
    result.confirmations = confirmations;
    result.withdrawal = std::move(withdrawal);
    result.m6 = std::move(m6);
    std::string parent_error;
    if (!GetDrivechainSuccessfulWithdrawal(
            *consensus.drivechain_slot, result.m6.m6id,
            result.successful_parent_withdrawal, &parent_error)) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            strprintf("Unable to authenticate completed BIP300 withdrawals on the active parent chain: %s",
                      parent_error));
    }

    // Parent replay can be slow on a cold node. Recheck the Elements anchor
    // after that work so an orphaned burn is never reported as valid.
    {
        LOCK(cs_main);
        const CChain& active = chainman.ActiveChain();
        if (!active.Contains(block_index) ||
            block_index->GetBlockHash() != block_hash) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                "Confirming block left the active Elements chain during parent withdrawal replay");
        }
        result.confirmations = active.Height() - block_index->nHeight + 1;
        if (result.confirmations < min_confirmations) {
            throw JSONRPCError(
                RPC_VERIFY_ERROR,
                "Withdrawal lost the required active-chain depth during parent withdrawal replay");
        }
    }
    return result;
}

UniValue NativeWithdrawalToJSON(const AuthenticatedNativeWithdrawal& claim)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", claim.txid.GetHex());
    result.pushKV("vout", static_cast<uint64_t>(claim.vout));
    result.pushKV("blockhash", claim.block_hash.GetHex());
    result.pushKV("blockheight", claim.block_height);
    result.pushKV("confirmations", claim.confirmations);
    result.pushKV("burn_amount", ValueFromAmount(claim.withdrawal.burn_amount));
    result.pushKV("payout_amount", ValueFromAmount(claim.withdrawal.payout_amount));
    result.pushKV("mainchain_fee", ValueFromAmount(claim.withdrawal.parent_fee));
    result.pushKV("bitcoin_script_pub_key", HexStr(claim.withdrawal.destination));
    result.pushKV("burn_commitment", HexStr(claim.m6.burn_commitment));
    result.pushKV("m6id", claim.m6.m6id.GetHex());
    result.pushKV("blinded_m6", HexStr(claim.m6.legacy_serialization));
    result.pushKV("burn_is_unspendable", true);
    const bool paid = claim.successful_parent_withdrawal.has_value();
    result.pushKV("paid_on_parent_chain", paid);
    if (paid) {
        result.pushKV(
            "parent_payment_blockhash",
            claim.successful_parent_withdrawal->block_hash.GetHex());
        result.pushKV(
            "parent_payment_blockheight",
            static_cast<uint64_t>(
                claim.successful_parent_withdrawal->block_height));
    }
    result.pushKV(
        "conservation",
        "burn_amount = payout_amount + mainchain_fee");
    return result;
}

void RejectPaidNativeWithdrawal(const AuthenticatedNativeWithdrawal& claim)
{
    if (!claim.successful_parent_withdrawal.has_value()) return;
    throw JSONRPCError(
        RPC_VERIFY_ALREADY_IN_CHAIN,
        strprintf("Native withdrawal M6 %s was already paid in parent block %s at height %u",
                  claim.m6.m6id.GetHex(),
                  claim.successful_parent_withdrawal->block_hash.GetHex(),
                  claim.successful_parent_withdrawal->block_height));
}

uint32_t ParseWithdrawalVout(const UniValue& value)
{
    const int64_t parsed = value.get_int64();
    if (parsed < 0 ||
        parsed >= static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "vout is outside the canonical uint32 range");
    }
    return static_cast<uint32_t>(parsed);
}

} // namespace

static RPCHelpMan getdrivechainwithdrawalbundle()
{
    return RPCHelpMan{"getdrivechainwithdrawalbundle",
                "Authenticates a confirmed native pegged-asset burn and deterministically derives its blinded BIP300 M6. This call does not submit anything.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Elements burn transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Canonical burn output index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active-chain block containing the burn"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{1}, "Required active Elements confirmations"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Authenticated burn and exact blinded M6"},
                RPCExamples{
                    HelpExampleCli("getdrivechainwithdrawalbundle", "\"<txid>\" 0 \"<blockhash>\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const int min_confirmations = request.params[3].isNull()
        ? 1
        : request.params[3].get_int();
    return NativeWithdrawalToJSON(LoadNativeWithdrawal(
        chainman,
        ParseHashV(request.params[0], "txid"),
        ParseWithdrawalVout(request.params[1]),
        ParseHashV(request.params[2], "blockhash"),
        min_confirmations));
},
    };
}

static RPCHelpMan submitdrivechainwithdrawal()
{
    return RPCHelpMan{"submitdrivechainwithdrawal",
                "Authenticates a confirmed native pegged-asset burn, derives its unique blinded M6, and submits it idempotently to the configured BIP300 enforcer.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Elements burn transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Canonical burn output index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active-chain block containing the burn"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{6}, "Required active Elements confirmations before proposing the M6"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Authenticated burn, exact blinded M6, and enforcer submission result"},
                RPCExamples{
                    HelpExampleCli("submitdrivechainwithdrawal", "\"<txid>\" 0 \"<blockhash>\" 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const int min_confirmations = request.params[3].isNull()
        ? 6
        : request.params[3].get_int();
    AuthenticatedNativeWithdrawal claim = LoadNativeWithdrawal(
        chainman,
        ParseHashV(request.params[0], "txid"),
        ParseWithdrawalVout(request.params[1]),
        ParseHashV(request.params[2], "blockhash"),
        min_confirmations);
    RejectPaidNativeWithdrawal(claim);

    std::string response;
    std::string submission_error;
    if (!SubmitDrivechainWithdrawalBundle(
            *Params().GetConsensus().drivechain_slot,
            claim.m6.legacy_serialization, &response, &submission_error)) {
        throw JSONRPCError(RPC_MISC_ERROR, submission_error);
    }

    UniValue result = NativeWithdrawalToJSON(claim);
    result.pushKV("submitted", true);
    result.pushKV("enforcer_response", response);
    result.pushKV(
        "security_model",
        "burn authenticated by this Elements node; M6 authorization follows BIP300 miner voting");
    return result;
},
    };
}

static RPCHelpMan verifydrivechainwithdrawalbundle()
{
    return RPCHelpMan{"verifydrivechainwithdrawalbundle",
                "Verifies that an externally proposed blinded BIP300 M6 is the unique canonical bundle for a confirmed native pegged-asset burn. This call does not submit anything.\n"
                "Miners and operators can use this RPC to reject fabricated or altered native withdrawal proposals before voting.\n",
                {
                    {"blinded_m6", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact legacy zero-input blinded M6 serialization"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active Elements block containing the burn referenced by the M6"},
                    {"minconfirmations", RPCArg::Type::NUM, RPCArg::Default{6}, "Required active Elements confirmations"},
                },
                RPCResult{RPCResult::Type::OBJ, "", "Verified burn and exact blinded M6"},
                RPCExamples{
                    HelpExampleCli("verifydrivechainwithdrawalbundle", "\"<blinded_m6_hex>\" \"<blockhash>\" 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string encoded = request.params[0].get_str();
    if (!IsHex(encoded)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "blinded_m6 must be canonical hexadecimal");
    }
    std::vector<unsigned char> serialized = ParseHex(encoded);
    if (serialized.empty() ||
        serialized.size() >
            drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE) {
        throw JSONRPCError(
            RPC_DESERIALIZATION_ERROR,
            "blinded_m6 exceeds the canonical native-withdrawal serialization bound");
    }

    Sidechain::Bitcoin::CMutableTransaction proposed;
    std::string parse_error;
    if (!drivechain::DeserializeNativeWithdrawalM6Legacy(
            serialized, proposed, &parse_error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, parse_error);
    }
    if (proposed.vout.size() < 2) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "blinded M6 has no native withdrawal burn reference output");
    }

    uint256 referenced_genesis;
    uint8_t referenced_slot{0};
    uint256 burn_txid;
    uint32_t burn_vout{0};
    if (!drivechain::ParseNativeWithdrawalM6Commitment(
            proposed.vout[1].scriptPubKey, referenced_genesis,
            referenced_slot, burn_txid, burn_vout, &parse_error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, parse_error);
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    if (!consensus.drivechain_slot.has_value() ||
        referenced_genesis != consensus.hashGenesisBlock ||
        referenced_slot != static_cast<uint8_t>(*consensus.drivechain_slot)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "blinded M6 references a different Elements chain or sidechain slot");
    }

    drivechain::NativeWithdrawalM6 structurally_valid;
    if (!drivechain::ParseNativeWithdrawalM6(
            proposed, referenced_genesis, referenced_slot,
            burn_txid, burn_vout, structurally_valid, &parse_error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, parse_error);
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const int min_confirmations = request.params[2].isNull()
        ? 6
        : request.params[2].get_int();
    AuthenticatedNativeWithdrawal claim = LoadNativeWithdrawal(
        chainman, burn_txid, burn_vout,
        ParseHashV(request.params[1], "blockhash"), min_confirmations);
    if (claim.m6.legacy_serialization != serialized ||
        claim.m6.m6id != drivechain::ComputeNativeWithdrawalM6Id(proposed)) {
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "blinded M6 payout, fee, reference, or canonical encoding does not match the confirmed Elements burn");
    }
    RejectPaidNativeWithdrawal(claim);

    UniValue result = NativeWithdrawalToJSON(claim);
    result.pushKV("valid", true);
    result.pushKV(
        "security_model",
        "verified against the active Elements chain; BIP300 payout still requires miner approval");
    return result;
},
    };
}

static RPCHelpMan getusddwithdrawalaccumulator()
{
    return RPCHelpMan{"getusddwithdrawalaccumulator",
                "Returns the deterministic canonical Ethereum-withdrawal accumulator at an active-chain block.\n"
                "This generic index binds each leaf's actual asset and vault but is not, by itself, an authorizing\n"
                "USDD root. The immutable external deployment manifest and vault must enforce their exact IDs.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "Optional active-chain block hash"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "blockhash", "Block whose derived state is returned"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::NUM, "count", "Cumulative canonical withdrawal-leaf count"},
                        {RPCResult::Type::STR_HEX, "root", "Depth-64 SHA-256 sparse-Merkle root"},
                        {RPCResult::Type::BOOL, "authorizing", "Always false: the node cannot authenticate an external USDD deployment"},
                        {RPCResult::Type::STR, "scope", "Exact scope of the generic accumulator"},
                    }},
                RPCExamples{
                    HelpExampleCli("getusddwithdrawalaccumulator", "")
                    + HelpExampleRpc("getusddwithdrawalaccumulator", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* blockindex{nullptr};
    usdd::WithdrawalAccumulatorState accumulator;
    {
        LOCK(cs_main);
        const CChain& active = chainman.ActiveChain();
        blockindex = request.params[0].isNull()
            ? active.Tip()
            : chainman.m_blockman.LookupBlockIndex(ParseHashV(request.params[0], "blockhash"));
        if (!blockindex || !active.Contains(blockindex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is not in the active chain");
        }
        if (!blockindex->m_usdd_withdrawal_accumulator.has_value()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Withdrawal accumulator unavailable; reindex required");
        }
        accumulator = *blockindex->m_usdd_withdrawal_accumulator;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("blockhash", blockindex->GetBlockHash().GetHex());
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("count", accumulator.count);
    result.pushKV("root", HexStr(accumulator.root));
    result.pushKV("authorizing", false);
    result.pushKV("scope", "generic exact USDD-v1-shaped burns; leaf binds actual asset and vault");
    return result;
},
    };
}

static RPCHelpMan getusddwithdrawalproof()
{
    return RPCHelpMan{"getusddwithdrawalproof",
                "Reconstructs a canonical withdrawal inclusion proof from retained active-chain blocks.\n"
                "Proof reconstruction requires unpruned blocks containing withdrawals, is single-flight,\n"
                "and is limited to 10,000 leaves and a ten-second work budget per call.\n",
                {
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Zero-based cumulative claim index"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "Optional active-chain block hash"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Withdrawal claim and bottom-up 64-sibling branch",
                    {
                        {RPCResult::Type::NUM, "index", "Claim index"},
                        {RPCResult::Type::STR_HEX, "root", "Accumulator root"},
                        {RPCResult::Type::NUM, "count", "Accumulator leaf count"},
                        {RPCResult::Type::STR_HEX, "leaf", "Canonical Solidity-compatible leaf"},
                        {RPCResult::Type::STR_HEX, "burn_id", "Canonical burn identity"},
                        {RPCResult::Type::STR_HEX, "txid", "Elements burn transaction ID in display order"},
                        {RPCResult::Type::NUM, "vout", "Burn output index"},
                        {RPCResult::Type::STR_HEX, "asset", "Explicit burned asset ID"},
                        {RPCResult::Type::STR_HEX, "vault_id", "Vault ID from the burn payload"},
                        {RPCResult::Type::STR_HEX, "recipient", "Fixed Ethereum recipient"},
                        {RPCResult::Type::NUM, "amount_usdt_micro", "Six-decimal USDT amount"},
                        {RPCResult::Type::ARR, "siblings", "64 sibling hashes, bottom-up",
                            {{RPCResult::Type::STR_HEX, "hash", "Sibling hash"}}},
                        {RPCResult::Type::BOOL, "authorizing", "Always false: the node cannot authenticate an external USDD deployment"},
                    }},
                RPCExamples{
                    HelpExampleCli("getusddwithdrawalproof", "0")
                    + HelpExampleRpc("getusddwithdrawalproof", "0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int64_t requested_index = request.params[0].get_int64();
    if (requested_index < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Withdrawal index must not be negative");
    }
    const uint64_t index = static_cast<uint64_t>(requested_index);
    static constexpr uint64_t MAX_RECONSTRUCTION_LEAVES{10'000};
    static constexpr auto MAX_RECONSTRUCTION_TIME{std::chrono::seconds{10}};
    std::unique_lock<std::mutex> proof_lock(
        g_usdd_withdrawal_proof_mutex, std::defer_lock);
    if (!proof_lock.try_lock()) {
        throw JSONRPCError(
            RPC_MISC_ERROR, "A withdrawal-proof reconstruction is already running");
    }
    const auto deadline = std::chrono::steady_clock::now() + MAX_RECONSTRUCTION_TIME;
    const auto interruption_point = [&] {
        RpcInterruptionPoint();
        if (std::chrono::steady_clock::now() >= deadline) {
            throw JSONRPCError(
                RPC_MISC_ERROR, "Withdrawal-proof reconstruction work budget exhausted");
        }
    };

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* target{nullptr};
    usdd::WithdrawalAccumulatorState accumulator;
    std::vector<const CBlockIndex*> blocks_with_withdrawals;
    {
        LOCK(cs_main);
        const CChain& active = chainman.ActiveChain();
        target = request.params[1].isNull()
            ? active.Tip()
            : chainman.m_blockman.LookupBlockIndex(ParseHashV(request.params[1], "blockhash"));
        if (!target || !active.Contains(target)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is not in the active chain");
        }
        if (!target->m_usdd_withdrawal_accumulator.has_value()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Withdrawal accumulator unavailable; reindex required");
        }
        accumulator = *target->m_usdd_withdrawal_accumulator;
        if (index >= accumulator.count) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Withdrawal index is outside this accumulator");
        }
        if (accumulator.count > MAX_RECONSTRUCTION_LEAVES) {
            throw JSONRPCError(RPC_MISC_ERROR,
                "Proof reconstruction exceeds the safe RPC limit; use a dedicated permissionless indexer");
        }
        uint64_t prior_count{0};
        for (int height = 1; height <= target->nHeight; ++height) {
            if ((height & 0x0fff) == 0) interruption_point();
            const CBlockIndex* cursor = active[height];
            if (!cursor->m_usdd_withdrawal_accumulator.has_value()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Discontinuous withdrawal accumulator; reindex required");
            }
            const uint64_t count = cursor->m_usdd_withdrawal_accumulator->count;
            if (count < prior_count) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Nonmonotonic withdrawal accumulator; reindex required");
            }
            if (count != prior_count) blocks_with_withdrawals.push_back(cursor);
            prior_count = count;
        }
    }

    std::vector<usdd::EthereumWithdrawalClaim> claims;
    claims.reserve(static_cast<size_t>(accumulator.count));
    for (const CBlockIndex* blockindex : blocks_with_withdrawals) {
        interruption_point();
        CBlock block;
        if (!ReadBlockFromDisk(block, blockindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_MISC_ERROR,
                "A withdrawal-containing block is pruned or unreadable; use an archival node or indexer");
        }
        std::vector<usdd::EthereumWithdrawalClaim> appended;
        std::string extraction_error;
        if (!usdd::ExtractEthereumWithdrawals(
                block, Params().GetConsensus().hashGenesisBlock,
                claims.size(), appended, &extraction_error)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, extraction_error);
        }
        claims.insert(claims.end(), appended.begin(), appended.end());
    }
    interruption_point();
    if (claims.size() != accumulator.count) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
            "Reconstructed withdrawal count disagrees with the persisted accumulator");
    }

    usdd::WithdrawalInclusionProof proof;
    usdd::WithdrawalHash reconstructed_root;
    std::string proof_error;
    if (!usdd::BuildWithdrawalInclusionProof(
            claims, index, proof, reconstructed_root, &proof_error) ||
        reconstructed_root != accumulator.root) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
            proof_error.empty() ? "Reconstructed withdrawal root mismatch" : proof_error);
    }

    UniValue siblings(UniValue::VARR);
    for (const auto& sibling : proof.siblings) siblings.push_back(HexStr(sibling));
    UniValue result(UniValue::VOBJ);
    result.pushKV("index", index);
    result.pushKV("root", HexStr(accumulator.root));
    result.pushKV("count", accumulator.count);
    result.pushKV("leaf", HexStr(proof.claim.leaf));
    result.pushKV("burn_id", HexStr(proof.claim.burn_id));
    result.pushKV("txid", HexStr(proof.claim.burn_txid_display));
    result.pushKV("vout", static_cast<uint64_t>(proof.claim.burn_vout));
    result.pushKV("asset", HexStr(proof.claim.asset_id));
    result.pushKV("vault_id", HexStr(proof.claim.vault_id));
    result.pushKV("recipient", HexStr(proof.claim.recipient));
    result.pushKV("amount_usdt_micro", proof.claim.amount_usdt_micro);
    result.pushKV("siblings", siblings);
    result.pushKV("authorizing", false);
    return result;
},
    };
}

// END ELEMENTS
//

void RegisterBlockchainRPCCommands(CRPCTable &t)
{
// clang-format off

static const CRPCCommand commands[] =
{ //  category              actor (function)
  //  --------------------- ------------------------
    { "blockchain",         &getblockchaininfo,                  },
    { "blockchain",         &getchaintxstats,                    },
    { "blockchain",         &getblockstats,                      },
    { "blockchain",         &getbestblockhash,                   },
    { "blockchain",         &getblockcount,                      },
    { "blockchain",         &getblock,                           },
    { "blockchain",         &getblockfrompeer,                   },
    { "blockchain",         &getblockhash,                       },
    { "blockchain",         &getblockheader,                     },
    { "blockchain",         &getchaintips,                       },
    { "blockchain",         &getdifficulty,                      },
    { "blockchain",         &getdeploymentinfo,                  },
    { "blockchain",         &getmempoolancestors,                },
    { "blockchain",         &getmempooldescendants,              },
    { "blockchain",         &getmempoolentry,                    },
    { "blockchain",         &getmempoolinfo,                     },
    { "blockchain",         &getrawmempool,                      },
    { "blockchain",         &gettxout,                           },
    { "blockchain",         &getecxstateutxoroot,                },
    { "blockchain",         &getecxconsensuscontext,             },
    { "blockchain",         &getecxbondinboxentries,             },
    { "blockchain",         &gettxoutsetinfo,                    },
    { "blockchain",         &pruneblockchain,                    },
    { "blockchain",         &savemempool,                        },
    { "blockchain",         &verifychain,                        },

    { "blockchain",         &preciousblock,                      },
    { "blockchain",         &scantxoutset,                       },
    { "blockchain",         &getblockfilter,                     },

    // ELEMENTS:
    { "blockchain",         &getdrivechainpegevents,            },
    { "blockchain",         &getsidechaininfo,                   },
    { "blockchain",         &getdrivechainwithdrawalbundle,      },
    { "blockchain",         &verifydrivechainwithdrawalbundle,   },
    { "blockchain",         &submitdrivechainwithdrawal,         },
    { "blockchain",         &getusddwithdrawalaccumulator,       },
    { "blockchain",         &getusddwithdrawalproof,             },

    /* Not shown in help */
    { "hidden",              &invalidateblock,                   },
    { "hidden",              &reconsiderblock,                   },
    { "hidden",              &waitfornewblock,                   },
    { "hidden",              &waitforblock,                      },
    { "hidden",              &waitforblockheight,                },
    { "hidden",              &syncwithvalidationinterfacequeue,  },
    { "hidden",              &dumptxoutset,                      },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
