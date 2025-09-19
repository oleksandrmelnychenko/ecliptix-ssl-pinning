/*
 * Ecliptix Security Library - Type System Tests
 * Tests for strong types, concepts, and error handling
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/core/types.hpp"

using namespace ecliptix::core;

// Remove the using declaration since we use std::unexpected in C++23

TEST_CASE("Strong Types", "[types][core]") {
    SECTION("Key types are distinct") {
        auto key1 = Key<32>{};
        auto key2 = Key<32>{};

        // Should be able to compare keys of same size
        REQUIRE(key1.get() == key2.get());

        // Different size keys should be different types (compile-time check)
        // Key<32> and Key<16> are different types
        REQUIRE(sizeof(Key<32>) != sizeof(Key<16>));
    }

    SECTION("Strong types prevent mixing") {
        // This section documents that mixing types is caught at compile time
        // Uncomment these lines to verify compilation errors:

        // ChaCha20Key key{};
        // ChaCha20Nonce nonce{};
        // key = nonce;  // Should not compile
    }

    SECTION("Type conversions work correctly") {
        std::array<std::byte, 32> raw_data{};
        raw_data[0] = std::byte{0xAB};
        raw_data[1] = std::byte{0xCD};

        auto key = crypto::ChaCha20Key{raw_data};

        REQUIRE(key.get()[0] == std::byte{0xAB});
        REQUIRE(key.get()[1] == std::byte{0xCD});
    }
}

TEST_CASE("Concepts", "[types][concepts]") {
    SECTION("ByteLike concept") {
        REQUIRE(ByteLike<std::byte>);
        REQUIRE(ByteLike<uint8_t>);
        REQUIRE(ByteLike<char>);
        REQUIRE(ByteLike<unsigned char>);
        REQUIRE_FALSE(ByteLike<int>);
        REQUIRE_FALSE(ByteLike<double>);
    }

    SECTION("CryptographicKey concept") {
        REQUIRE(CryptographicKey<crypto::ChaCha20Key>);
        REQUIRE(CryptographicKey<crypto::Ed25519PublicKey>);
        REQUIRE_FALSE(CryptographicKey<int>);
        REQUIRE_FALSE(CryptographicKey<std::string>);
    }
}

TEST_CASE("Error Handling", "[types][errors]") {
    SECTION("Error codes have string representations") {
        REQUIRE(error::to_string(error::Code::Success) == "Success");
        REQUIRE(error::to_string(error::Code::InvalidParameter) == "Invalid parameter");
        REQUIRE(error::to_string(error::Code::DecryptionFailed) == "Decryption failed");
    }

    SECTION("Result type works correctly") {
        auto success_result = Result<int>{42};
        REQUIRE(success_result.has_value());
        REQUIRE(success_result.value() == 42);

        auto error_result = Result<int>{std::unexpected(error::Code::InvalidParameter)};
        REQUIRE_FALSE(error_result.has_value());
        REQUIRE(error_result.error() == error::Code::InvalidParameter);
    }
}

TEST_CASE("Constants", "[types][constants]") {
    SECTION("Crypto constants are correct") {
        REQUIRE(crypto::CHACHA20_KEY_SIZE == 32);
        REQUIRE(crypto::CHACHA20_NONCE_SIZE == 12);
        REQUIRE(crypto::ED25519_PUBLIC_KEY_SIZE == 32);
        REQUIRE(crypto::ED25519_PRIVATE_KEY_SIZE == 32);
        REQUIRE(crypto::ED25519_SIGNATURE_SIZE == 64);
        REQUIRE(crypto::BLAKE2B_DEFAULT_SIZE == 32);
        REQUIRE(crypto::SSL_PIN_SIZE == 48);
    }

    SECTION("Type aliases work") {
        static_assert(std::is_same_v<crypto::ChaCha20Key, Key<32>>);
        static_assert(std::is_same_v<crypto::Ed25519PublicKey, Key<32>>);
        static_assert(std::is_same_v<crypto::Ed25519Signature, Signature<64>>);
    }
}