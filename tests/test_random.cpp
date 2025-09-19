/*
 * Ecliptix Security Library - Random Number Generation Tests
 * Tests for cryptographically secure random generation
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <set>
#include <algorithm>

using namespace ecliptix;

TEST_CASE("Random Bytes Generation", "[random][crypto]") {
    SECTION("Fixed size random generation") {
        // Initialize library for random operations
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto result1 = random::bytes<32>();
        auto result2 = random::bytes<32>();

        REQUIRE(result1.has_value());
        REQUIRE(result2.has_value());

        // Results should be different (with overwhelming probability)
        REQUIRE_FALSE(std::equal(result1->begin(), result1->end(), result2->begin()));

        library::shutdown();
    }

    SECTION("Different sizes") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto small = random::bytes<1>();
        auto medium = random::bytes<64>();
        auto large = random::bytes<1024>();

        REQUIRE(small.has_value());
        REQUIRE(medium.has_value());
        REQUIRE(large.has_value());

        REQUIRE(small->size() == 1);
        REQUIRE(medium->size() == 64);
        REQUIRE(large->size() == 1024);

        library::shutdown();
    }

    SECTION("Container filling") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::vector<uint8_t> buffer(256);
        auto result = random::fill(buffer);
        REQUIRE(result.has_value());

        // Check that buffer was modified (not all zeros)
        bool has_nonzero = std::any_of(buffer.begin(), buffer.end(),
                                      [](uint8_t b) { return b != 0; });
        REQUIRE(has_nonzero);

        library::shutdown();
    }
}

TEST_CASE("Random Key Generation", "[random][keys]") {
    SECTION("ChaCha20 key generation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key1 = random::key<32>();
        auto key2 = random::key<32>();

        REQUIRE(key1.has_value());
        REQUIRE(key2.has_value());

        // Keys should be different
        REQUIRE_FALSE(std::equal(key1->get().begin(), key1->get().end(),
                                key2->get().begin()));

        library::shutdown();
    }

    SECTION("Ed25519 key size") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto private_key = random::key<crypto::ED25519_PRIVATE_KEY_SIZE>();
        auto public_key = random::key<crypto::ED25519_PUBLIC_KEY_SIZE>();

        REQUIRE(private_key.has_value());
        REQUIRE(public_key.has_value());

        REQUIRE(private_key->get().size() == 32);
        REQUIRE(public_key->get().size() == 32);

        library::shutdown();
    }
}

TEST_CASE("Random Nonce Generation", "[random][nonces]") {
    SECTION("ChaCha20 nonces") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto nonce1 = random::nonce<12>();
        auto nonce2 = random::nonce<12>();

        REQUIRE(nonce1.has_value());
        REQUIRE(nonce2.has_value());

        // Nonces should be different (critical for security)
        REQUIRE_FALSE(std::equal(nonce1->get().begin(), nonce1->get().end(),
                                nonce2->get().begin()));

        library::shutdown();
    }

    SECTION("Large nonces") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto nonce = random::nonce<24>();
        REQUIRE(nonce.has_value());
        REQUIRE(nonce->get().size() == 24);

        library::shutdown();
    }
}

TEST_CASE("Uniform Random Integers", "[random][uniform]") {
    SECTION("Basic uniform generation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate random numbers in range [0, 100)
        std::set<uint32_t> seen_values;
        for (int i = 0; i < 50; ++i) {
            auto result = random::uniform(100);
            REQUIRE(result.has_value());
            REQUIRE(result.value() < 100);
            seen_values.insert(result.value());
        }

        // Should have seen multiple different values
        REQUIRE(seen_values.size() > 10);

        library::shutdown();
    }

    SECTION("Edge cases") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Single value range
        auto result = random::uniform(1);
        REQUIRE(result.has_value());
        REQUIRE(result.value() == 0);

        // Small range
        for (int i = 0; i < 10; ++i) {
            auto small_result = random::uniform(2);
            REQUIRE(small_result.has_value());
            REQUIRE((small_result.value() == 0 || small_result.value() == 1));
        }

        library::shutdown();
    }
}

TEST_CASE("Statistical Quality Tests", "[random][quality]") {
    SECTION("Byte distribution") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate a lot of random data
        constexpr size_t sample_size = 10000;
        std::array<int, 256> byte_counts{};

        for (size_t i = 0; i < sample_size; ++i) {
            auto result = random::bytes<1>();
            REQUIRE(result.has_value());
            uint8_t byte_val = static_cast<uint8_t>((*result)[0]);
            byte_counts[byte_val]++;
        }

        // Check that all byte values appear at least once
        // (This could occasionally fail due to randomness, but very unlikely)
        size_t zero_counts = std::count(byte_counts.begin(), byte_counts.end(), 0);
        REQUIRE(zero_counts < 50);  // Most byte values should appear

        // Check that distribution is roughly uniform
        // Average should be around sample_size / 256
        double average = static_cast<double>(sample_size) / 256.0;
        int values_near_average = 0;
        for (int count : byte_counts) {
            if (count > 0 && std::abs(count - average) < average * 0.5) {
                values_near_average++;
            }
        }
        REQUIRE(values_near_average > 100);  // Many values should be near average

        library::shutdown();
    }

    SECTION("Bit independence") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Test that consecutive bytes are independent
        constexpr size_t pairs = 1000;
        int bit_correlations[8][8] = {};

        for (size_t i = 0; i < pairs; ++i) {
            auto result = random::bytes<2>();
            REQUIRE(result.has_value());

            uint8_t byte1 = static_cast<uint8_t>((*result)[0]);
            uint8_t byte2 = static_cast<uint8_t>((*result)[1]);

            for (int bit1 = 0; bit1 < 8; ++bit1) {
                for (int bit2 = 0; bit2 < 8; ++bit2) {
                    if (((byte1 >> bit1) & 1) == ((byte2 >> bit2) & 1)) {
                        bit_correlations[bit1][bit2]++;
                    }
                }
            }
        }

        // Each correlation should be around pairs/2 (50%)
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                double correlation = static_cast<double>(bit_correlations[i][j]) / pairs;
                REQUIRE(correlation > 0.3);  // Should be roughly 50%, allow wide variance
                REQUIRE(correlation < 0.7);
            }
        }

        library::shutdown();
    }
}