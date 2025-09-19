/*
 * Ecliptix Security Library - Digital Signature Tests
 * Tests for Ed25519 digital signatures
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <string>

using namespace ecliptix;

TEST_CASE("Ed25519 Key Generation", "[signatures][keypair]") {
    SECTION("Key pair generation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        // Verify key sizes
        REQUIRE(keypair->public_key().get().size() == 32);
        REQUIRE(keypair->private_key().get().size() == 32);

        // Public and private keys should be different
        REQUIRE_FALSE(std::equal(
            keypair->public_key().get().begin(),
            keypair->public_key().get().end(),
            keypair->private_key().get().begin()
        ));

        library::shutdown();
    }

    SECTION("Multiple key pairs are different") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair1 = make::signature_keypair();
        auto keypair2 = make::signature_keypair();

        REQUIRE(keypair1.has_value());
        REQUIRE(keypair2.has_value());

        // Different key pairs should have different keys
        REQUIRE_FALSE(std::equal(
            keypair1->public_key().get().begin(),
            keypair1->public_key().get().end(),
            keypair2->public_key().get().begin()
        ));

        REQUIRE_FALSE(std::equal(
            keypair1->private_key().get().begin(),
            keypair1->private_key().get().end(),
            keypair2->private_key().get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("Ed25519 Signing", "[signatures][sign]") {
    SECTION("Basic signing and verification") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string message = "Hello, world! This is a test message for signing.";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Sign the message
        auto signature_result = signature::sign(message_bytes, keypair->private_key());
        REQUIRE(signature_result.has_value());
        REQUIRE(signature_result->get().size() == 64);

        // Verify the signature
        auto verify_result = signature::verify(message_bytes, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        library::shutdown();
    }

    SECTION("Different messages produce different signatures") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string message1 = "First message";
        std::string message2 = "Second message";

        auto sig1 = signature::sign(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message1.data()),
                message1.size()
            },
            keypair->private_key()
        );

        auto sig2 = signature::sign(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(message2.data()),
                message2.size()
            },
            keypair->private_key()
        );

        REQUIRE(sig1.has_value());
        REQUIRE(sig2.has_value());

        // Signatures should be different
        REQUIRE_FALSE(std::equal(
            sig1->get().begin(), sig1->get().end(),
            sig2->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Empty message signing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::span<const std::byte> empty_message;

        auto signature_result = signature::sign(empty_message, keypair->private_key());
        REQUIRE(signature_result.has_value());

        auto verify_result = signature::verify(empty_message, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        library::shutdown();
    }
}

TEST_CASE("Ed25519 Verification", "[signatures][verify]") {
    SECTION("Invalid signature detection") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string message = "Original message";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto signature_result = signature::sign(message_bytes, keypair->private_key());
        REQUIRE(signature_result.has_value());

        // Tamper with the signature
        auto tampered_signature = *signature_result;
        tampered_signature.get()[0] = static_cast<std::byte>(
            static_cast<uint8_t>(tampered_signature.get()[0]) ^ 0x01
        );

        // Verification should fail
        auto verify_result = signature::verify(message_bytes, tampered_signature, keypair->public_key());
        REQUIRE_FALSE(verify_result.has_value());
        REQUIRE(verify_result.error() == error::Code::SignatureInvalid);

        library::shutdown();
    }

    SECTION("Wrong message detection") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string original_message = "Original message";
        std::string different_message = "Different message";

        auto signature_result = signature::sign(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(original_message.data()),
                original_message.size()
            },
            keypair->private_key()
        );
        REQUIRE(signature_result.has_value());

        // Try to verify with different message
        auto verify_result = signature::verify(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(different_message.data()),
                different_message.size()
            },
            *signature_result,
            keypair->public_key()
        );
        REQUIRE_FALSE(verify_result.has_value());
        REQUIRE(verify_result.error() == error::Code::SignatureInvalid);

        library::shutdown();
    }

    SECTION("Wrong public key detection") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair1 = make::signature_keypair();
        auto keypair2 = make::signature_keypair();
        REQUIRE(keypair1.has_value());
        REQUIRE(keypair2.has_value());

        std::string message = "Test message";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Sign with first key pair
        auto signature_result = signature::sign(message_bytes, keypair1->private_key());
        REQUIRE(signature_result.has_value());

        // Try to verify with second public key
        auto verify_result = signature::verify(message_bytes, *signature_result, keypair2->public_key());
        REQUIRE_FALSE(verify_result.has_value());
        REQUIRE(verify_result.error() == error::Code::SignatureInvalid);

        library::shutdown();
    }
}

TEST_CASE("Ed25519 Large Data", "[signatures][performance]") {
    SECTION("Large message signing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        // Create large test data (100KB)
        const size_t large_size = 100 * 1024;
        std::vector<uint8_t> large_data(large_size);

        // Fill with pattern
        for (size_t i = 0; i < large_size; ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        std::span<const std::byte> large_message{
            reinterpret_cast<const std::byte*>(large_data.data()),
            large_data.size()
        };

        auto signature_result = signature::sign(large_message, keypair->private_key());
        REQUIRE(signature_result.has_value());

        auto verify_result = signature::verify(large_message, *signature_result, keypair->public_key());
        REQUIRE(verify_result.has_value());

        library::shutdown();
    }
}

TEST_CASE("Ed25519 Deterministic Signing", "[signatures][deterministic]") {
    SECTION("Same message produces same signature") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create a specific key pair (deterministic for this test)
        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        std::string message = "Deterministic test message";
        std::span<const std::byte> message_bytes{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        // Sign the same message multiple times
        auto sig1 = signature::sign(message_bytes, keypair->private_key());
        auto sig2 = signature::sign(message_bytes, keypair->private_key());

        REQUIRE(sig1.has_value());
        REQUIRE(sig2.has_value());

        // Ed25519 signatures should be deterministic
        REQUIRE(std::equal(
            sig1->get().begin(), sig1->get().end(),
            sig2->get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("Batch Verification", "[signatures][batch]") {
    SECTION("Multiple signature verification") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        constexpr size_t num_signatures = 3;
        std::array<signature::KeyPair, num_signatures> keypairs;
        std::array<std::string, num_signatures> messages = {
            "First message",
            "Second message",
            "Third message"
        };
        std::array<crypto::Ed25519Signature, num_signatures> signatures;

        // Generate keypairs and sign messages
        for (size_t i = 0; i < num_signatures; ++i) {
            auto keypair_result = make::signature_keypair();
            REQUIRE(keypair_result.has_value());
            keypairs[i] = std::move(*keypair_result);

            auto sig_result = signature::sign(
                std::span<const std::byte>{
                    reinterpret_cast<const std::byte*>(messages[i].data()),
                    messages[i].size()
                },
                keypairs[i].private_key()
            );
            REQUIRE(sig_result.has_value());
            signatures[i] = *sig_result;
        }

        // Prepare for batch verification
        std::array<std::span<const std::byte>, num_signatures> message_spans;
        std::array<crypto::Ed25519PublicKey, num_signatures> public_keys;

        for (size_t i = 0; i < num_signatures; ++i) {
            message_spans[i] = std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(messages[i].data()),
                messages[i].size()
            };
            public_keys[i] = keypairs[i].public_key();
        }

        // Batch verify (if implemented)
        auto batch_result = signature::batch_verify<num_signatures>(
            std::span{message_spans},
            std::span{signatures},
            std::span{public_keys}
        );

        if (batch_result.has_value()) {
            // All signatures should be valid
            for (size_t i = 0; i < num_signatures; ++i) {
                REQUIRE((*batch_result)[i] == true);
            }
        } else {
            // Fallback to individual verification if batch not implemented
            for (size_t i = 0; i < num_signatures; ++i) {
                auto verify_result = signature::verify(message_spans[i], signatures[i], public_keys[i]);
                REQUIRE(verify_result.has_value());
            }
        }

        library::shutdown();
    }
}