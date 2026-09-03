// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <clientversion.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <node/miner.h>
#include <pow.h>
#include <random.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <set>
#include <thread>

using node::BlockAssembler;

namespace validation_block_tests {
struct MinerTestingSetup : public TestingSetup {
    MinerTestingSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {"-con_elementsmode=0"}}} {}

    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};
} // namespace validation_block_tests

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

BOOST_AUTO_TEST_CASE(bits16_through20_remain_ordinary_on_standard_regtest)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(
        std::make_shared<CBlock>(Params().GenesisBlock()), /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));

    auto block{Block(Params().GenesisBlock().GetHash())};
    block->nVersion |=
        CBlockHeader::BMM_PROOF_HF_MASK |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK;
    block->hashBmmProof = uint256S("01");
    block->hashExchangeStateRoot = uint256S("01");
    block->hashForcedInboxRoot = uint256S("02");
    block->hashDepositInboxRoot = uint256S("03");
    block->ecxParentHeight = 123;
    block->forcedProcessedCursor = 4;
    block->depositProcessedCursor = 5;
    block->sourceBacklogOldestParentHeight = 6;
    CBlockHeader without_hidden_ecx_data{block->GetBlockHeader()};
    without_hidden_ecx_data.hashBmmProof.SetNull();
    without_hidden_ecx_data.hashExchangeStateRoot.SetNull();
    without_hidden_ecx_data.hashForcedInboxRoot.SetNull();
    without_hidden_ecx_data.hashDepositInboxRoot.SetNull();
    without_hidden_ecx_data.ecxParentHeight = 0;
    without_hidden_ecx_data.forcedProcessedCursor = 0;
    without_hidden_ecx_data.depositProcessedCursor = 0;
    without_hidden_ecx_data.sourceBacklogOldestParentHeight = 0;
    BOOST_CHECK_EQUAL(block->GetHash(), without_hidden_ecx_data.GetHash());
    BOOST_CHECK_EQUAL(
        GetSerializeSize(block->GetBlockHeader()),
        80U);
    while (!CheckProofOfWork(
        block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
    }

    BlockValidationState state;
    const CBlockIndex* accepted{nullptr};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(
        std::array{block->GetBlockHeader()}, /*min_pow_checked=*/true, state, &accepted));
    BOOST_CHECK(state.IsValid());
    BOOST_REQUIRE(accepted != nullptr);
    BOOST_CHECK_EQUAL(accepted->GetBlockHash(), block->GetHash());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash()) !=
            nullptr));

    CDiskBlockIndex disk_index{accepted};
    DataStream disk_bytes;
    disk_bytes << disk_index;
    CDiskBlockIndex decoded_disk_index;
    disk_bytes >> decoded_disk_index;
    BOOST_CHECK(disk_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_disk_index.nVersion, accepted->nVersion);
    BOOST_CHECK(decoded_disk_index.hashBmmProof.IsNull());
    BOOST_CHECK(decoded_disk_index.hashExchangeStateRoot.IsNull());
    BOOST_CHECK(decoded_disk_index.hashForcedInboxRoot.IsNull());
    BOOST_CHECK(decoded_disk_index.hashDepositInboxRoot.IsNull());
    BOOST_CHECK_EQUAL(decoded_disk_index.ecxParentHeight, 0U);
    BOOST_CHECK_EQUAL(decoded_disk_index.forcedProcessedCursor, 0U);
    BOOST_CHECK_EQUAL(decoded_disk_index.depositProcessedCursor, 0U);
    BOOST_CHECK_EQUAL(
        decoded_disk_index.sourceBacklogOldestParentHeight, 0U);
}

BOOST_AUTO_TEST_CASE(bit20_does_not_extend_standard_regtest_block_body)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(
        std::make_shared<CBlock>(Params().GenesisBlock()), /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));

    auto block{Block(Params().GenesisBlock().GetHash())};
    block->nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    block->m_bmm_proof = {0xde, 0xad, 0xbe, 0xef};
    const auto finalized{FinalizeBlock(block)};

    CBlock without_bmm_payload{*finalized};
    without_bmm_payload.m_bmm_proof.clear();
    BOOST_CHECK_EQUAL(
        GetSerializeSize(TX_WITH_WITNESS(*finalized)),
        GetSerializeSize(TX_WITH_WITNESS(without_bmm_payload)));
    BOOST_CHECK_EQUAL(
        GetBlockWeight(*finalized),
        GetBlockWeight(without_bmm_payload));

    DataStream encoded;
    encoded << TX_WITH_WITNESS(*finalized);
    CBlock decoded;
    encoded >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK(decoded.m_bmm_proof.empty());
    BOOST_CHECK_EQUAL(decoded.GetHash(), finalized->GetHash());

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(
        std::make_shared<CBlock>(decoded), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
}

BOOST_AUTO_TEST_CASE(bit30_withdrawal_extension_is_elements_only)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(
        std::make_shared<CBlock>(Params().GenesisBlock()), /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));

    auto block{Block(Params().GenesisBlock().GetHash())};
    block->nVersion |= CBlockHeader::WITHDRAWAL_BUNDLE_HF_MASK;
    block->hashWithdrawalBundle = uint256S("01");

    CBlockHeader without_hidden_withdrawal{block->GetBlockHeader()};
    without_hidden_withdrawal.hashWithdrawalBundle.SetNull();
    BOOST_CHECK_EQUAL(block->GetHash(), without_hidden_withdrawal.GetHash());
    BOOST_CHECK_EQUAL(
        GetSerializeSize(block->GetBlockHeader()),
        80U);

    DataStream header_bytes;
    header_bytes << block->GetBlockHeader();
    CBlockHeader decoded_header;
    header_bytes >> decoded_header;
    BOOST_CHECK(header_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_header.nVersion, block->nVersion);
    BOOST_CHECK(decoded_header.hashWithdrawalBundle.IsNull());

    const auto finalized{FinalizeBlock(block)};
    DataStream block_bytes;
    block_bytes << TX_WITH_WITNESS(*finalized);
    CBlock decoded_block;
    block_bytes >> TX_WITH_WITNESS(decoded_block);
    BOOST_CHECK(block_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_block.nVersion, finalized->nVersion);
    BOOST_CHECK(decoded_block.hashWithdrawalBundle.IsNull());
    BOOST_CHECK_EQUAL(decoded_block.GetHash(), finalized->GetHash());
    BOOST_CHECK_EQUAL(decoded_block.vtx.size(), finalized->vtx.size());

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(
        std::make_shared<CBlock>(decoded_block), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    const CBlockIndex* accepted{WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            finalized->GetHash()))};
    BOOST_REQUIRE(accepted != nullptr);
    CDiskBlockIndex disk_index{accepted};
    DataStream disk_bytes;
    disk_bytes << disk_index;
    CDiskBlockIndex decoded_disk_index;
    disk_bytes >> decoded_disk_index;
    BOOST_CHECK(disk_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_disk_index.nVersion, accepted->nVersion);
    BOOST_CHECK(decoded_disk_index.hashWithdrawalBundle.IsNull());
}

BOOST_AUTO_TEST_CASE(bit31_dynafed_extension_is_elements_only)
{
    auto block{Block(Params().GenesisBlock().GetHash())};
    block->nVersion = static_cast<int32_t>(
        static_cast<uint32_t>(block->nVersion) |
        CBlockHeader::DYNAFED_HF_MASK);
    const DynaFedParamEntry hidden_current{
        CScript{} << OP_TRUE, 1, uint256S("01")};
    block->m_dynafed_params =
        DynaFedParams{hidden_current, DynaFedParamEntry{}};

    CBlockHeader without_hidden_dynafed{block->GetBlockHeader()};
    without_hidden_dynafed.m_dynafed_params.SetNull();
    BOOST_CHECK_EQUAL(block->GetHash(), without_hidden_dynafed.GetHash());
    BOOST_CHECK_EQUAL(
        GetSerializeSize(block->GetBlockHeader()),
        80U);

    DataStream header_bytes;
    header_bytes << block->GetBlockHeader();
    CBlockHeader decoded_header;
    header_bytes >> decoded_header;
    BOOST_CHECK(header_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_header.nVersion, block->nVersion);
    BOOST_CHECK(decoded_header.m_dynafed_params.IsNull());

    DataStream block_bytes;
    block_bytes << TX_WITH_WITNESS(*block);
    CBlock decoded_block;
    block_bytes >> TX_WITH_WITNESS(decoded_block);
    BOOST_CHECK(block_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_block.nVersion, block->nVersion);
    BOOST_CHECK(decoded_block.m_dynafed_params.IsNull());
    BOOST_CHECK_EQUAL(decoded_block.GetHash(), block->GetHash());
    BOOST_CHECK_EQUAL(decoded_block.vtx.size(), block->vtx.size());

    CBlockIndex memory_index{block->GetBlockHeader()};
    CDiskBlockIndex disk_index{&memory_index};
    DataStream disk_bytes;
    disk_bytes << disk_index;
    CDiskBlockIndex decoded_disk_index;
    disk_bytes >> decoded_disk_index;
    BOOST_CHECK(disk_bytes.empty());
    BOOST_CHECK_EQUAL(decoded_disk_index.nVersion, memory_index.nVersion);
    BOOST_CHECK(!decoded_disk_index.is_dynafed_block());
    BOOST_CHECK(decoded_disk_index.dynafed_params().IsNull());
}

BOOST_AUTO_TEST_CASE(ecx_reserved_outpoints_are_ordinary_on_standard_regtest)
{
    CCoinsView base;
    CCoinsViewCache view{&base};
    const std::vector<COutPoint> outpoints{
        {Txid::FromUint256(uint256S("e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041")), 0},
        {Txid::FromUint256(uint256S("c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1")), 0},
        {Txid::FromUint256(uint256S("0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")), 0},
        {Txid::FromUint256(uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")), 0},
        {Txid::FromUint256(uint256S("2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1")), 0},
    };

    for (const COutPoint& outpoint : outpoints) {
        view.AddCoin(
            outpoint,
            Coin{CTxOut{CAsset{}, 2 * COIN, CScript{} << OP_TRUE}, 1, false},
            false);
        CMutableTransaction mutable_tx;
        mutable_tx.vin.emplace_back(outpoint);
        mutable_tx.vout.emplace_back(
            CAsset{}, COIN, CScript{} << OP_TRUE);
        const CTransaction tx{mutable_tx};
        TxValidationState state;
        CAmountMap fees;
        std::set<std::pair<uint256, COutPoint>> pegins;
        BOOST_CHECK(Consensus::CheckTxInputs(
            tx,
            state,
            view,
            2,
            fees,
            pegins,
            nullptr,
            false,
            false,
            {}));
        BOOST_CHECK(state.IsValid());
    }
}

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << i++ << OP_TRUE;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.witness.vtxoutwit.resize(2);
    txCoinbase.vout[1].scriptPubKey = P2WSH_OP_TRUE;
    txCoinbase.vout[1].nValue = txCoinbase.vout[0].nValue;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.witness.vtxinwit.resize(1);
    txCoinbase.witness.vtxinwit[0].scriptWitness.SetNull();
    // Always pad with OP_0 at the end to avoid bad-cb-length error
    txCoinbase.vin[0].scriptSig = CScript{} << WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight + 1) << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};
    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev_block);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }

    // submit block header, so that miner can get the block height from the
    // global state and the node has the topology of the chain
    BlockValidationState ignored;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{pblock->GetBlockHeader()}}, true, ignored));

    return pblock;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.emplace_back(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0);
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

// NOLINTNEXTLINE(misc-no-recursion)
void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = m_rng.randrange(100U) < invalid_rate;
    bool gen_fork = m_rng.randrange(100U) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = m_node.chainman->ActiveChain().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                const auto& block = blocks[insecure.randrange(blocks.size() - 1)];
                Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (const auto& block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    m_node.validation_signals->UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits txns spending from their coinbase to the mempool. A fork chain is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&](std::shared_ptr<const CBlock> block) -> bool {
        return Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&ignored);
    };

    // Process all mined blocks
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));
    auto last_mined = GoodBlock(Params().GenesisBlock().GetHash());
    BOOST_REQUIRE(ProcessBlock(last_mined));

    // Run the test multiple times
    for (int test_runs = 3; test_runs > 0; --test_runs) {
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // Later on split from here
        const uint256 split_hash{last_mined->hashPrevBlock};

        // Create a bunch of transactions to spend the miner rewards of the
        // most recent blocks
        std::vector<CTransactionRef> txs;
        for (int num_txs = 22; num_txs > 0; --num_txs) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{last_mined->vtx[0]->GetHash(), 1}, CScript{});
            mtx.witness.vtxinwit.resize(1);
            mtx.witness.vtxinwit[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
            mtx.vout.push_back(last_mined->vtx[0]->vout[1]);
            mtx.vout[0].nValue = mtx.vout[0].nValue.GetAmount() - 1000;
            txs.push_back(MakeTransactionRef(mtx));

            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mature the inputs of the txs
        for (int j = COINBASE_MATURITY; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mine a reorg (and hold it back) before adding the txs to the mempool
        const uint256 tip_init{last_mined->GetHash()};

        std::vector<std::shared_ptr<const CBlock>> reorg;
        last_mined = GoodBlock(split_hash);
        reorg.push_back(last_mined);
        for (size_t j = COINBASE_MATURITY + txs.size() + 1; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            reorg.push_back(last_mined);
        }

        // Add the txs to the tx pool
        {
            LOCK(cs_main);
            for (const auto& tx : txs) {
                const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx);
                BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            }
        }

        // Check that all txs are in the pool
        {
            BOOST_CHECK_EQUAL(m_node.mempool->size(), txs.size());
        }

        // Run a thread that simulates an RPC caller that is polling while
        // validation is doing a reorg
        std::thread rpc_thread{[&]() {
            // This thread is checking that the mempool either contains all of
            // the transactions invalidated by the reorg, or none of them, and
            // not some intermediate amount.
            while (true) {
                LOCK(m_node.mempool->cs);
                if (m_node.mempool->size() == 0) {
                    // We are done with the reorg
                    break;
                }
                // Internally, we might be in the middle of the reorg, but
                // externally the reorg to the most-proof-of-work chain should
                // be atomic. So the caller assumes that the returned mempool
                // is consistent. That is, it has all txs that were there
                // before the reorg.
                assert(m_node.mempool->size() == txs.size());
                continue;
            }
            LOCK(cs_main);
            // We are done with the reorg, so the tip must have changed
            assert(tip_init != m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }};

        // Submit the reorg in this thread to invalidate and remove the txs from the tx pool
        for (const auto& b : reorg) {
            ProcessBlock(b);
        }
        // Check that the reorg was eventually successful
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // We can join the other thread, which returns when the reorg was successful
        rpc_thread.join();
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_index)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    CScript pubKey;
    pubKey << 1 << OP_TRUE;
    BlockAssembler::Options options;
    options.coinbase_output_script = pubKey;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    CBlock pblock = ptemplate->block;

    CTxOut witness;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;

    // A witness larger than the minimum size is still valid
    CTxOut min_plus_one = witness;
    min_plus_one.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT + 1);

    CTxOut invalid = witness;
    invalid.scriptPubKey[0] = OP_VERIFY;

    CMutableTransaction txCoinbase(*pblock.vtx[0]);
    txCoinbase.vout.resize(4);
    txCoinbase.vout[0] = witness;
    txCoinbase.vout[1] = witness;
    txCoinbase.vout[2] = min_plus_one;
    txCoinbase.vout[3] = invalid;
    pblock.vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(pblock), 2);
}
BOOST_AUTO_TEST_SUITE_END()
