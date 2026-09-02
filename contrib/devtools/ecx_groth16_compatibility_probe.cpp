// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Offline cryptographic regression probe, NOT an Alpha activation preflight.
// Link the exact verifier archive used by the candidate node. Fixtures remain
// external and must be hash-pinned by the caller; a private/regtest fixture is
// never evidence of an authorized Alpha statement, transaction, or catalogue.

#include <crypto/sha256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" bool ecx_sp1_6_3_1_verify_groth16_sha256(
    void* context, const unsigned char* proof, size_t proof_len,
    const uint32_t program_id_words[8],
    const unsigned char public_values_sha256[32]);

namespace {
constexpr size_t PROOF_LEN{356};
constexpr uint32_t KOALA_BEAR_MODULUS{0x7f000001};
using Digest = std::array<unsigned char, 32>;
using Program = std::array<uint32_t, 8>;

unsigned char Nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    throw std::runtime_error("expected a hexadecimal character");
}

Digest ParseDigest(const std::string& hex)
{
    if (hex.size() != 64) throw std::runtime_error("expected exactly 64 hex characters");
    Digest result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = (Nibble(hex[2 * i]) << 4) | Nibble(hex[2 * i + 1]);
    }
    return result;
}

std::string Hex(const Digest& bytes)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (auto byte : bytes) out << std::setw(2) << static_cast<unsigned int>(byte);
    return out.str();
}

std::vector<unsigned char> ReadBounded(const char* path, size_t maximum)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open input fixture");
    const auto end = input.tellg();
    if (end <= 0 || end > static_cast<std::streamoff>(maximum)) {
        throw std::runtime_error("input fixture is empty or exceeds the size limit");
    }
    std::vector<unsigned char> bytes(static_cast<size_t>(end));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), bytes.size())) {
        throw std::runtime_error("cannot read complete input fixture");
    }
    if (input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("input fixture changed length during read");
    }
    return bytes;
}

Digest Hash(const std::vector<unsigned char>& bytes)
{
    Digest hash{};
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(hash.data());
    return hash;
}

Program ParseProgram(const Digest& bytes)
{
    Program program{};
    for (size_t i = 0; i < program.size(); ++i) {
        for (size_t j = 0; j < 4; ++j) program[i] = (program[i] << 8) | bytes[4 * i + j];
        if (program[i] >= KOALA_BEAR_MODULUS) {
            throw std::runtime_error("program ID has a noncanonical KoalaBear word");
        }
    }
    if (program == Program{}) throw std::runtime_error("program ID is zero");
    return program;
}

struct Result {
    std::string name;
    bool expected;
    bool actual;
};
} // namespace

int main(int argc, char** argv)
{
    if (argc != 6) {
        std::cerr << "usage: ecx_groth16_compatibility_probe RAW_PROOF PUBLIC_VALUES "
                     "PROGRAM_ID_HEX EXPECTED_PROOF_SHA256 EXPECTED_PUBLIC_VALUES_SHA256\n";
        return 2;
    }
    try {
        const auto proof = ReadBounded(argv[1], PROOF_LEN);
        if (proof.size() != PROOF_LEN) throw std::runtime_error("proof must be 356 bytes");
        const auto public_values = ReadBounded(argv[2], 1024 * 1024);
        const auto proof_hash = Hash(proof);
        const auto digest = Hash(public_values);
        if (proof_hash != ParseDigest(argv[4]) || digest != ParseDigest(argv[5])) {
            throw std::runtime_error("fixture SHA-256 differs from the caller's expected identity");
        }
        const auto program_bytes = ParseDigest(argv[3]);
        const auto program = ParseProgram(program_bytes);
        std::vector<Result> results;
        auto check = [&](const std::string& name, bool expected, const auto& candidate,
                         const Program& words, const Digest& pv_hash) {
            results.push_back({name, expected, ecx_sp1_6_3_1_verify_groth16_sha256(
                nullptr, candidate.data(), candidate.size(), words.data(), pv_hash.data())});
        };
        check("exact_hash_pinned_fixture", true, proof, program, digest);

        for (const auto& mutation : std::vector<std::pair<std::string, size_t>>{
                 {"wrapper_key_prefix", 0}, {"nonzero_exit_code", 35},
                 {"recursion_key_root", 67}, {"proof_nonce", 99},
                 {"raw_proof_first_byte", 100}, {"raw_proof_coordinate_a", 131},
                 {"raw_proof_coordinate_b", 195}, {"raw_proof_coordinate_c", 259},
                 {"raw_proof_last_byte", 355}}) {
            auto changed = proof;
            changed[mutation.second] ^= 1;
            check("reject_changed_" + mutation.first, false, changed, program, digest);
        }
        auto changed_digest = digest;
        changed_digest.back() ^= 1;
        check("reject_changed_public_values_digest", false, proof, program, changed_digest);

        auto changed_program = program;
        changed_program.back() ^= 1;
        check("reject_changed_program_id", false, proof, changed_program, digest);
        check("reject_zero_program_id", false, proof, Program{}, digest);
        changed_program = program;
        changed_program[0] = KOALA_BEAR_MODULUS;
        check("reject_noncanonical_program_id", false, proof, changed_program, digest);
        changed_program = program;
        std::reverse(changed_program.begin(), changed_program.end());
        check("reject_reversed_program_words", false, proof, changed_program, digest);

        auto changed_length = proof;
        changed_length.pop_back();
        check("reject_truncated_proof", false, changed_length, program, digest);
        changed_length = proof;
        changed_length.push_back(0);
        check("reject_trailing_proof_bytes", false, changed_length, program, digest);

        auto pointer_check = [&](const std::string& name, void* context,
                                 const unsigned char* candidate, const uint32_t* words,
                                 const unsigned char* pv_hash) {
            results.push_back({name, false, ecx_sp1_6_3_1_verify_groth16_sha256(
                context, candidate, PROOF_LEN, words, pv_hash)});
        };
        int reserved_context{0};
        pointer_check("reject_nonnull_context", &reserved_context, proof.data(), program.data(), digest.data());
        pointer_check("reject_null_proof", nullptr, nullptr, program.data(), digest.data());
        pointer_check("reject_null_program", nullptr, proof.data(), nullptr, digest.data());
        pointer_check("reject_null_digest", nullptr, proof.data(), program.data(), nullptr);
        alignas(uint32_t) std::array<unsigned char, sizeof(Program) + 1> unaligned{};
        std::memcpy(unaligned.data() + 1, program.data(), sizeof(Program));
        pointer_check("reject_misaligned_program", nullptr, proof.data(),
                      reinterpret_cast<const uint32_t*>(unaligned.data() + 1), digest.data());

        // SP1 intentionally clears exactly three high bits at the BN254
        // circuit boundary. This checks the documented algebraic conversion,
        // NOT equality of the complete public values required by the annex.
        changed_digest = digest;
        changed_digest[0] ^= 0xe0;
        check("documented_bn254_high_three_bit_mapping", true, proof, program, changed_digest);
        check("exact_fixture_after_negative_checks", true, proof, program, digest);

        const bool passed = std::all_of(results.begin(), results.end(),
            [](const Result& result) { return result.actual == result.expected; });
        std::cout << "{\n  \"scope\": \"offline-cryptographic-regression-only\",\n"
                     "  \"alphaProofReady\": false,\n  \"productionAuthorized\": false,\n"
                     "  \"fixtureNetworkAuthorized\": false,\n"
                     "  \"proofBytes\": " << proof.size() << ",\n"
                     "  \"publicValuesBytes\": " << public_values.size() << ",\n"
                     "  \"proofSha256\": \"" << Hex(proof_hash) << "\",\n"
                     "  \"publicValuesSha256\": \"" << Hex(digest) << "\",\n"
                     "  \"programId\": \"" << Hex(program_bytes) << "\",\n"
                     "  \"cases\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            std::cout << "    {\"name\":\"" << result.name << "\",\"expected\":"
                      << std::boolalpha << result.expected << ",\"actual\":" << result.actual
                      << ",\"passed\":" << (result.expected == result.actual) << "}"
                      << (i + 1 == results.size() ? "\n" : ",\n");
        }
        std::cout << "  ],\n  \"allPassed\": " << std::boolalpha << passed << "\n}\n";
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "probe input rejected: " << error.what() << '\n';
        return 2;
    }
}
