// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <elements_drivechain_identity.h>
#include <primitives/confidential.h>
#include <script/usdd_sp1_verifier_ffi.h>
#include <usdd_sp1_verifier_identity.h>

#include <array>
#include <optional>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(usdd_sp1_verifier_identity_tests)

BOOST_AUTO_TEST_CASE(inactive_gate_does_not_require_a_native_archive)
{
    std::string error;
    std::array<uint8_t, 32> unset{};
    BOOST_CHECK(CheckUsddSp1VerifierStartupIdentity(false, unset, &error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(activation_rejects_an_unfrozen_identity)
{
    std::string error;
    std::array<uint8_t, 32> unset{};
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, unset, &error));
    BOOST_CHECK_EQUAL(
        error,
        "USDD SP1 activation has no frozen verifier semantic identity");
}

BOOST_AUTO_TEST_CASE(activation_requires_the_exact_linked_semantics)
{
    std::string error;
    std::array<uint8_t, 32> expected{};
    expected[0] = 1;
#if defined(HAVE_USDD_SP1_VERIFIER)
    BOOST_REQUIRE_EQUAL(
        usdd_sp1_verifier_semantic_identity(expected.data(), expected.size()),
        USDD_SP1_VERIFIER_ACCEPTED);
    BOOST_CHECK(CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    expected.back() ^= 1;
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    BOOST_CHECK_EQUAL(
        error,
        "linked USDD SP1 verifier semantics do not match the production identity");
#else
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    BOOST_CHECK_EQUAL(
        error,
        "USDD SP1 activation requires the pinned verifier, but this binary was built without it");
#endif
}

BOOST_AUTO_TEST_CASE(linked_verifier_matches_the_v11_parameterized_profile_identity)
{
    static constexpr std::array<uint8_t, 32> CORRECTED_VERIFIER{{
        0x6b, 0x02, 0x92, 0x57, 0x0f, 0xa1, 0x20, 0xae,
        0x88, 0x57, 0x43, 0xa3, 0x91, 0xeb, 0xa1, 0x8a,
        0x1e, 0x53, 0x04, 0x55, 0x28, 0x46, 0x48, 0xcf,
        0xde, 0x30, 0xdc, 0x28, 0xbf, 0x3b, 0x64, 0xa9,
    }};
    static constexpr std::array<uint8_t, 32> CORRECTED_PROFILE{{
        0x6f, 0xd5, 0xa5, 0xe5, 0x57, 0x69, 0x32, 0x0c,
        0xc1, 0xc6, 0xa4, 0x97, 0x64, 0x4d, 0x0b, 0xc7,
        0xa6, 0x42, 0xee, 0xd8, 0x44, 0x2a, 0xb1, 0x70,
        0x3a, 0xf3, 0x04, 0xcf, 0xac, 0x25, 0x3d, 0x25,
    }};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.begin(),
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.end(),
        CORRECTED_VERIFIER.begin(), CORRECTED_VERIFIER.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ElementsDrivechainIdentity::PARAMETERIZED_CONTROLLER_PROFILE_ID.begin(),
        ElementsDrivechainIdentity::PARAMETERIZED_CONTROLLER_PROFILE_ID.end(),
        CORRECTED_PROFILE.begin(), CORRECTED_PROFILE.end());
#if defined(HAVE_USDD_SP1_VERIFIER)
    std::array<uint8_t, 32> linked{};
    BOOST_REQUIRE_EQUAL(
        usdd_sp1_verifier_semantic_identity(linked.data(), linked.size()),
        USDD_SP1_VERIFIER_ACCEPTED);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        linked.begin(), linked.end(),
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.begin(),
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.end());
#endif
}

BOOST_AUTO_TEST_CASE(production_fee_asset_is_immutable)
{
    const CAsset pegged{uint256S(ElementsDrivechainIdentity::PEGGED_ASSET)};
    CAsset resolved;
    std::string error;

    BOOST_CHECK(ResolveElementsFeeAsset(std::nullopt, pegged, true, resolved, &error));
    BOOST_CHECK(resolved == pegged);
    BOOST_CHECK(ResolveElementsFeeAsset(pegged.GetHex(), pegged, true, resolved, &error));
    BOOST_CHECK(resolved == pegged);

    BOOST_CHECK(!ResolveElementsFeeAsset(std::string(64, '1'), pegged, true, resolved, &error));
    BOOST_CHECK_EQUAL(error, "-feeasset must equal the immutable Elements pegged asset");
    BOOST_CHECK(!ResolveElementsFeeAsset("not-an-asset", pegged, true, resolved, &error));
    BOOST_CHECK_EQUAL(error, "-feeasset must be exactly 64 hexadecimal characters");
}

BOOST_AUTO_TEST_SUITE_END()
