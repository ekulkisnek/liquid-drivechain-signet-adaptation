// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <script/ecx_activation_annex.h>
#include <crypto/sha256.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>

BOOST_AUTO_TEST_SUITE(policy_fee_tests)

BOOST_AUTO_TEST_CASE(FeeRounder)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    FeeFilterRounder fee_rounder{CFeeRate{1000}, rng};

    // check that 1000 rounds to 974 or 1071
    std::set<CAmount> results;
    while (results.size() < 2) {
        results.emplace(fee_rounder.round(1000));
    }
    BOOST_CHECK_EQUAL(*results.begin(), 974);
    BOOST_CHECK_EQUAL(*++results.begin(), 1071);

    // check that negative amounts rounds to 0
    BOOST_CHECK_EQUAL(fee_rounder.round(-0), 0);
    BOOST_CHECK_EQUAL(fee_rounder.round(-1), 0);

    // check that MAX_MONEY rounds to 9170997
    BOOST_CHECK_EQUAL(fee_rounder.round(MAX_MONEY), 9170997);
}

BOOST_AUTO_TEST_CASE(bmm_work_fee_quote)
{
    BmmWorkFeeQuote quote;
    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(20'000, 1'500'000, 1'000, 500, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1'500);
    BOOST_CHECK_EQUAL(quote.producer_reserve, 500);
    BOOST_CHECK_EQUAL(quote.bid, 18'000);

    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(10, 1, 1, 0, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1);
    BOOST_CHECK_EQUAL(quote.bid, 9);

    BOOST_CHECK(!CalculateBmmWorkFeeQuote(1'000, 2'000'000, 1'000, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(-1, 0, 0, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(
        MAX_MONEY,
        std::numeric_limits<uint64_t>::max(),
        MAX_MONEY,
        0,
        quote));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ecx_activation_annex_tests)

// Transport-only fixture. Its zero proof is deliberately NOT cryptographically
// valid; budget eligibility must never be confused with script acceptance.
static std::vector<std::vector<unsigned char>> ActivationStack()
{
    std::vector<std::vector<unsigned char>> stack(5);
    stack[2].assign(ecx::ACTIVATION_BUDGET_CMR.begin(), ecx::ACTIVATION_BUDGET_CMR.end());
    stack[3].resize(33); stack[3][0] = 0xbe;
    auto& a = stack[4]; a.resize(800);
    const unsigned char prefix[]{0x50,'E','C','X','S','P','1',0,5,2,1,0};
    std::copy(std::begin(prefix), std::end(prefix), a.begin());
    a[15] = 1; // canonical nonzero program ID word
    a[78] = 1; a[79] = 100; // 356 proof bytes
    a[439] = 1; // public-value version
    for (unsigned i=0; i<10; ++i) a[436+4+32*i+31] = i+1;
    for (unsigned offset : {324,332,340,348,356}) a[436+offset+7] = 1;
    CSHA256().Write(a.data()+436,364).Finalize(a.data()+44);
    return stack;
}

BOOST_AUTO_TEST_CASE(exact_frozen_budget_and_fail_closed_mutations)
{
    const auto stack = ActivationStack();
    uint256 cmr, program;
    std::copy(stack[2].begin(),stack[2].end(),cmr.begin());
    std::copy(stack[4].begin()+12,stack[4].begin()+44,program.begin());
    std::array<unsigned char,32> parsed_program{};
    std::array<unsigned char,364> values{};
    BOOST_REQUIRE(ecx::ParseActivationAnnex(stack,parsed_program,values));
    const auto allowance=ecx::ACTIVATION_EXECUTION_BUDGET_WU;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,&program),allowance);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(-1,0,stack,&cmr,&program),-1);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(allowance+1,0,stack,&cmr,&program),allowance+1);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,1,stack,&cmr,&program),4161);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,nullptr,&program),4161);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,nullptr),4161);
    uint256 wrong=program; wrong.begin()[0]^=1;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,&wrong),4161);
    auto other=stack; other[2][0]^=1;
    std::copy(other[2].begin(),other[2].end(),wrong.begin());
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,other,&wrong,&program),4161);
    for (size_t offset : {0,1,8,9,10,11,44,76,79,436,799}) {
        auto bad=stack; bad[4][offset]^=1;
        BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    }
    for (size_t size : {0,32,34,4130}) {
        auto bad=stack; bad[3].resize(size);
        BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    }
    auto bad=stack; bad[3][0]=0xc0;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    bad=stack; bad.push_back({});
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    bad=stack; bad[4].pop_back();
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    // Even a rehashed malformed public statement must fail the native parser.
    bad=stack; std::fill(bad[4].begin()+440,bad[4].begin()+472,0);
    CSHA256().Write(bad[4].data()+436,364).Finalize(bad[4].data()+44);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
}

BOOST_AUTO_TEST_SUITE_END()
