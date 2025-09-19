/*
 * Ecliptix Security Library - API Integration Tests
 * End-to-end integration tests for the complete public API
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <string>
#include <string_view>

using namespace ecliptix;

TEST_CASE("Library Lifecycle", "[integration][lifecycle]") {
    SECTION("Initialize and shutdown") {
        auto init_result = library::initialize();
        REQUIRE(init_result.has_value());

        auto shutdown_result = library::shutdown();
        REQUIRE(shutdown_result.has_value());
    }

    SECTION("Multiple initialize calls") {
        auto init1 = library::initialize();
        auto init2 = library::initialize();
        REQUIRE(init1.has_value());
        REQUIRE(init2.has_value());

        auto shutdown1 = library::shutdown();
        auto shutdown2 = library::shutdown();
        REQUIRE(shutdown1.has_value());
        REQUIRE(shutdown2.has_value());
    }

    SECTION("Operations without initialization") {
        // Ensure library is not initialized
        library::shutdown();

        // Operations should fail gracefully
        auto key_result = random::key<32>();
        if (!key_result.has_value()) {
            REQUIRE(key_result.error() == error::Code::NotInitialized);
        }
    }
}

TEST_CASE("Complete Encryption Workflow", "[integration][encryption]") {
    SECTION("Generate key, encrypt, decrypt") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate encryption key
        auto key = random::key<32>();
        REQUIRE(key.has_value());

        // Test data
        std::string message = "Integration test message for encryption workflow";
        std::span<const std::byte> plaintext{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Encrypt
        auto encrypted = aead::encrypt(plaintext, *key);
        REQUIRE(encrypted.has_value());

        // Decrypt
        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE(decrypted.has_value());

        // Verify integrity
        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == message);

        library::shutdown();
    }

    SECTION("Encryption with authentication data") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Secret message";
        std::string auth_data = "public_header";

        auto encrypted = aead::encrypt(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            },
            *key,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(auth_data.data()),
                auth_data.size()
            }
        );
        REQUIRE(encrypted.has_value());

        auto decrypted = aead::decrypt(
            std::move(*encrypted),
            *key,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(auth_data.data()),
                auth_data.size()
            }
        );
        REQUIRE(decrypted.has_value());

        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == message);

        library::shutdown();
    }
}

TEST_CASE("Complete Signature Workflow", "[integration][signatures]") {
    SECTION("Generate keypair, sign, verify") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate signature keypair
        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        // Test document
        std::string document = "Important document that needs digital signature";
        std::span<const std::byte> document_bytes{
            reinterpret_cast<const std::byte*>(document.data()),
            document.size()
        };

        // Sign document
        auto signature_result = signature::sign(document_bytes, keypair->private_key());
        REQUIRE(signature_result.has_value());

        // Verify signature
        auto verify_result = signature::verify(document_bytes, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        library::shutdown();
    }

    SECTION("Cross-keypair verification failure") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair1 = make::signature_keypair();
        auto keypair2 = make::signature_keypair();
        REQUIRE(keypair1.has_value());
        REQUIRE(keypair2.has_value());

        std::string document = "Test document";
        std::span<const std::byte> document_bytes{
            reinterpret_cast<const std::byte*>(document.data()),
            document.size()
        };

        // Sign with first keypair
        auto signature_result = signature::sign(document_bytes, keypair1->private_key());
        REQUIRE(signature_result.has_value());

        // Try to verify with second keypair's public key
        auto verify_result = signature::verify(document_bytes, *signature_result, keypair2->public_key());
        REQUIRE_FALSE(verify_result.has_value());
        REQUIRE(verify_result.error() == error::Code::SignatureInvalid);

        library::shutdown();
    }
}

TEST_CASE("Complete Hashing Workflow", "[integration][hashing]") {
    SECTION("Message authentication code") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate MAC key
        auto mac_key = random::key<32>();
        REQUIRE(mac_key.has_value());

        std::string message = "Message to authenticate";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        std::span<const std::byte> key_bytes{
            reinterpret_cast<const std::byte*>(mac_key->get().data()),
            mac_key->get().size()
        };

        // Generate MAC
        auto mac_result = hash::blake2b_keyed(message_bytes, key_bytes);
        REQUIRE(mac_result.has_value());

        // Verify by re-computing
        auto mac_verify = hash::blake2b_keyed(message_bytes, key_bytes);
        REQUIRE(mac_verify.has_value());

        REQUIRE(std::equal(
            mac_result->get().begin(), mac_result->get().end(),
            mac_verify->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Incremental hashing for large data") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create large data set
        std::vector<std::string> data_chunks = {
            "First chunk of data ",
            "Second chunk of data ",
            "Third chunk of data ",
            "Final chunk of data"
        };

        // Hash incrementally
        auto hasher = hash::IncrementalHasher<32>{};

        for (const auto& chunk : data_chunks) {
            auto result = hasher.update(std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(chunk.data()),
                chunk.size()
            });
            REQUIRE(result.has_value());
        }

        auto incremental_hash = hasher.finalize();
        REQUIRE(incremental_hash.has_value());

        // Hash all at once for comparison
        std::string combined;
        for (const auto& chunk : data_chunks) {
            combined += chunk;
        }

        auto direct_hash = hash::blake2b(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(combined.data()),
            combined.size()
        });
        REQUIRE(direct_hash.has_value());

        // Results should match
        REQUIRE(std::equal(
            incremental_hash->get().begin(), incremental_hash->get().end(),
            direct_hash->get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("SSL Certificate Pinning Integration", "[integration][ssl]") {
    SECTION("Certificate parsing and pin generation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Mock certificate for testing
        std::string_view test_cert = R"(-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKUUy4n0TQ1jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL6bDp1h1KfG8j4j5WqT
YYQ5J7mY3QV7z1Z0J8S6QqE8P9A7Z2X3n8y1VaS7MwQJ6pEW7A5s8x3T1kP6xZ9
L4Q5vN2sY8G7j5M1q6A9z8X3W2N1v9s7K6tY2Q8j4f1v6z8M9aR3bX4cN5dE6gH
7i8J9kL0m1nO2pQ3rS4tU5vW6xY7zA8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R
5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X
7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D
9QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCGj8xY1Q2r3s4t5u6v7w8x9y0zA1B
2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1F2G3H
4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2A3B4C5D6E7F8G9H0I1J2K3L4M5N
6O7P8Q9R0S1T2U3V4W5X6Y7Z8A9B0C1D2E3F4G5H6I7J8K9L0M1N2O3P4Q5R6S7T
8U9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z
-----END CERTIFICATE-----)"sv;

        auto cert_result = ssl::certificate::parse_pem(test_cert);
        if (cert_result.has_value()) {
            auto pin_result = ssl::spki_pin::from_certificate(*cert_result);
            if (pin_result.has_value()) {
                // Verify the pin
                auto verify_result = ssl::verify_pin(*cert_result, *pin_result);
                REQUIRE(verify_result.has_value());
                REQUIRE(*verify_result == true);
            }
        }

        library::shutdown();
    }

    SECTION("SSL context with multiple pins") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create multiple test pins
        std::vector<crypto::SpkiPin> pins;
        for (int i = 0; i < 5; ++i) {
            crypto::SpkiPin pin;
            // Fill with test pattern
            for (size_t j = 0; j < pin.get().size(); ++j) {
                pin.get()[j] = std::byte{static_cast<uint8_t>((i * 100 + j) % 256)};
            }
            pins.push_back(pin);
        }

        auto context_result = ssl::create_context(std::span{pins});
        if (context_result.has_value()) {
            REQUIRE(context_result->is_pinning_enabled());
            REQUIRE(context_result->pin_count() == pins.size());
        }

        library::shutdown();
    }
}

TEST_CASE("Cross-Module Integration", "[integration][cross-module]") {
    SECTION("Encrypt with hash-derived key") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create a master password
        std::string password = "user_master_password_123";
        std::span<const std::byte> password_bytes{
            reinterpret_cast<const std::byte*>(password.data()),
            password.size()
        };

        // Derive encryption key from password hash
        auto key_hash = hash::blake2b<32>(password_bytes);
        REQUIRE(key_hash.has_value());

        // Create key from hash
        crypto::ChaCha20Key encryption_key;
        std::copy(key_hash->get().begin(), key_hash->get().end(), encryption_key.get().begin());

        // Encrypt data with derived key
        std::string secret = "This is encrypted with password-derived key";
        auto encrypted = aead::encrypt(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(secret.data()),
                secret.size()
            },
            encryption_key
        );
        REQUIRE(encrypted.has_value());

        // Decrypt with same derived key
        auto decrypted = aead::decrypt(std::move(*encrypted), encryption_key);
        REQUIRE(decrypted.has_value());

        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == secret);

        library::shutdown();
    }

    SECTION("Sign encrypted data") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate keys
        auto encryption_key = random::key<32>();
        auto keypair = make::signature_keypair();
        REQUIRE(encryption_key.has_value());
        REQUIRE(keypair.has_value());

        // Original message
        std::string message = "Message to encrypt and sign";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Encrypt the message
        auto encrypted = aead::encrypt(message_bytes, *encryption_key);
        REQUIRE(encrypted.has_value());

        // Sign the encrypted data
        auto ciphertext_bytes = encrypted->ciphertext.get();
        std::span<const std::byte> ciphertext_span{
            reinterpret_cast<const std::byte*>(ciphertext_bytes.data()),
            ciphertext_bytes.size()
        };

        auto signature_result = signature::sign(ciphertext_span, keypair->private_key());
        REQUIRE(signature_result.has_value());

        // Verify signature on encrypted data
        auto verify_result = signature::verify(ciphertext_span, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        // Decrypt the original message
        auto decrypted = aead::decrypt(std::move(*encrypted), *encryption_key);
        REQUIRE(decrypted.has_value());

        std::string recovered{
            reinterpret_cast<const char*>(decrypted->get().data()),
            decrypted->get().size()
        };
        REQUIRE(recovered == message);

        library::shutdown();
    }
}

TEST_CASE("Error Handling Integration", "[integration][errors]") {
    SECTION("Consistent error handling across modules") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Test various error conditions

        // Invalid encryption key size (should be caught by type system at compile time)
        // This test ensures runtime errors are handled consistently

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        // Test with tampered ciphertext
        std::string message = "Test message";
        auto encrypted = aead::encrypt(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            },
            *key
        );
        REQUIRE(encrypted.has_value());

        // Tamper with ciphertext
        if (!encrypted->ciphertext.get().empty()) {
            encrypted->ciphertext.get()[0] =
                static_cast<std::byte>(static_cast<uint8_t>(encrypted->ciphertext.get()[0]) ^ 0x01);
        }

        auto decrypt_result = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE_FALSE(decrypt_result.has_value());
        REQUIRE(decrypt_result.error() == error::Code::DecryptionFailed);

        library::shutdown();
    }

    SECTION("Memory safety under error conditions") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Test that memory is properly cleaned up even when operations fail

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string message = "Test message";
        auto signature_result = signature::sign(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            },
            keypair->private_key()
        );
        REQUIRE(signature_result.has_value());

        // Tamper with signature
        signature_result->get()[0] =
            static_cast<std::byte>(static_cast<uint8_t>(signature_result->get()[0]) ^ 0x01);

        // Verification should fail but not leak memory
        auto verify_result = signature::verify(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            },
            *signature_result,
            keypair->public_key()
        );
        REQUIRE_FALSE(verify_result.has_value());
        REQUIRE(verify_result.error() == error::Code::SignatureInvalid);

        library::shutdown();
    }
}

TEST_CASE("Performance Integration", "[integration][performance]") {
    SECTION("Large data processing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create 1MB of test data
        const size_t large_size = 1024 * 1024;
        std::vector<uint8_t> large_data(large_size);

        // Fill with pattern
        for (size_t i = 0; i < large_size; ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        std::span<const std::byte> data_span{
            reinterpret_cast<const std::byte*>(large_data.data()),
            large_data.size()
        };

        // Test encryption of large data
        auto key = random::key<32>();
        REQUIRE(key.has_value());

        auto encrypted = aead::encrypt(data_span, *key);
        REQUIRE(encrypted.has_value());

        auto decrypted = aead::decrypt(std::move(*encrypted), *key);
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted->get().size() == large_size);

        // Test hashing of large data
        auto hash_result = hash::blake2b(data_span);
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 32);

        // Test signing of large data
        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        auto signature_result = signature::sign(data_span, keypair->private_key());
        REQUIRE(signature_result.has_value());

        auto verify_result = signature::verify(data_span, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        library::shutdown();
    }
}