// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/fees.h>
#include <policy/policy.h>

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
