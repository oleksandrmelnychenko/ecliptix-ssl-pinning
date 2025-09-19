/*
 * Ecliptix Security Library - Encryption Tests
 * Tests for authenticated encryption (AEAD) operations
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <string>
#include <string_view>

using namespace ecliptix;

TEST_CASE("ChaCha20-Poly1305 Encryption", "[encryption][aead]") {
    SECTION("Basic encryption/decryption") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate key
        auto key = random::key<32>();
        REQUIRE(key.has_value());

        // Test message
        std::string message = "Hello, world! This is a test message.";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Encrypt
        auto encrypted = aead::encrypt(plaintext, *key);
        REQUIRE(encrypted.has_value());

        // Verify encrypted data is different from plaintext
        auto& ciphertext_bytes = encrypted->ciphertext.get();
        REQUIRE(ciphertext_bytes.size() == message.size() + 16);  // +16 for tag

        // Decrypt
        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE(decrypted.has_value());

        // Verify decrypted message matches original
        std::string recovered_message{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered_message == message);

        library::shutdown();
    }

    SECTION("Encryption with associated data") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Secret message";
        std::string associated_data = "public_metadata";

        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };
        std::span<const std::byte> aad{
            reinterpret_cast<const std::byte*>(associated_data.data()),
            associated_data.size()
        };

        // Encrypt with AAD
        auto encrypted = aead::encrypt(plaintext, *key, aad);
        REQUIRE(encrypted.has_value());

        // Decrypt with same AAD
        auto decrypted = aead::decrypt(std::move(*encrypted), *key, aad);
        REQUIRE(decrypted.has_value());

        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == message);

        library::shutdown();
    }

    SECTION("Different AAD causes decryption failure") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Secret message";
        std::string aad1 = "correct_metadata";
        std::string aad2 = "wrong_metadata";

        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Encrypt with first AAD
        auto encrypted = aead::encrypt(plaintext, *key,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(aad1.data()),
                aad1.size()
            });
        REQUIRE(encrypted.has_value());

        // Try to decrypt with different AAD
        auto decrypted = aead::decrypt(std::move(*encrypted), *key,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(aad2.data()),
                aad2.size()
            });
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error() == error::Code::DecryptionFailed);

        library::shutdown();
    }

    SECTION("Empty message encryption") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::span<const std::byte> empty_plaintext;

        auto encrypted = aead::encrypt(empty_plaintext, *key);
        REQUIRE(encrypted.has_value());
        REQUIRE(encrypted->ciphertext.get().size() == 16);  // Only tag

        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted->get().empty());

        library::shutdown();
    }
}

TEST_CASE("Explicit Nonce Operations", "[encryption][nonce]") {
    SECTION("Encrypt with explicit nonce") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        auto nonce = random::nonce<12>();
        REQUIRE(key.has_value());
        REQUIRE(nonce.has_value());

        std::string message = "Test message";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto ciphertext = aead::encrypt_with_nonce(plaintext, *key, *nonce);
        REQUIRE(ciphertext.has_value());

        auto decrypted = aead::decrypt(*ciphertext, *key, *nonce);
        REQUIRE(decrypted.has_value());

        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == message);

        library::shutdown();
    }

    SECTION("Same nonce with different keys") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key1 = random::key<32>();
        auto key2 = random::key<32>();
        auto nonce = random::nonce<12>();
        REQUIRE(key1.has_value());
        REQUIRE(key2.has_value());
        REQUIRE(nonce.has_value());

        std::string message = "Test message";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto ciphertext1 = aead::encrypt_with_nonce(plaintext, *key1, *nonce);
        auto ciphertext2 = aead::encrypt_with_nonce(plaintext, *key2, *nonce);

        REQUIRE(ciphertext1.has_value());
        REQUIRE(ciphertext2.has_value());

        // Same nonce but different keys should produce different ciphertext
        REQUIRE_FALSE(ciphertext1->get().secure_equals(ciphertext2->get()));

        library::shutdown();
    }
}

TEST_CASE("Large Data Encryption", "[encryption][performance]") {
    SECTION("Large message handling") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        // Create large test data (1MB)
        const size_t large_size = 1024 * 1024;
        std::vector<uint8_t> large_data(large_size);

        // Fill with pattern
        for (size_t i = 0; i < large_size; ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(large_data.data()),
            large_data.size()
        };

        auto encrypted = aead::encrypt(plaintext, *key);
        REQUIRE(encrypted.has_value());
        REQUIRE(encrypted->ciphertext.get().size() == large_size + 16);

        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted->get().size() == large_size);

        // Verify data integrity
        bool data_matches = std::equal(
            large_data.begin(), large_data.end(),
            reinterpret_cast<const uint8_t*>(decrypted->get().data())
        );
        REQUIRE(data_matches);

        library::shutdown();
    }
}

TEST_CASE("Error Conditions", "[encryption][errors]") {
    SECTION("Tampered ciphertext") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Original message";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto encrypted = aead::encrypt(plaintext, *key);
        REQUIRE(encrypted.has_value());

        // Tamper with ciphertext
        if (!encrypted->ciphertext.get().empty()) {
            encrypted->ciphertext.get()[0] =
                static_cast<std::byte>(static_cast<uint8_t>(encrypted->ciphertext.get()[0]) ^ 0x01);
        }

        // Decryption should fail
        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error() == error::Code::DecryptionFailed);

        library::shutdown();
    }

    SECTION("Wrong key") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key1 = random::key<32>();
        auto key2 = random::key<32>();
        REQUIRE(key1.has_value());
        REQUIRE(key2.has_value());

        std::string message = "Secret message";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Encrypt with first key
        auto encrypted = aead::encrypt(plaintext, *key1);
        REQUIRE(encrypted.has_value());

        // Try to decrypt with second key
        auto decrypted = aead::decrypt(std::move(*encrypted), *key2);
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error() == error::Code::DecryptionFailed);

        library::shutdown();
    }
}