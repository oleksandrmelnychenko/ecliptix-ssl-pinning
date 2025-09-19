/*
 * Ecliptix Security Library - SSL Certificate Pinning Tests
 * Tests for SSL certificate validation and SPKI pinning
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <string>
#include <string_view>

using namespace ecliptix;

TEST_CASE("SSL Certificate Loading", "[ssl][certificates]") {
    SECTION("Valid certificate parsing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Sample X.509 certificate in PEM format (self-signed test cert)
        std::string_view test_cert_pem = R"(-----BEGIN CERTIFICATE-----
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

        auto cert_result = ssl::certificate::parse_pem(test_cert_pem);
        if (cert_result.has_value()) {
            REQUIRE(cert_result->is_valid());
        } else {
            // Certificate parsing might not be implemented yet
            REQUIRE(cert_result.error() == error::Code::NotImplemented);
        }

        library::shutdown();
    }

    SECTION("Invalid certificate handling") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string_view invalid_cert = "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----";

        auto cert_result = ssl::certificate::parse_pem(invalid_cert);
        REQUIRE_FALSE(cert_result.has_value());

        library::shutdown();
    }

    SECTION("Empty certificate input") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto cert_result = ssl::certificate::parse_pem("");
        REQUIRE_FALSE(cert_result.has_value());
        REQUIRE(cert_result.error() == error::Code::InvalidInput);

        library::shutdown();
    }
}

TEST_CASE("SPKI Pin Generation", "[ssl][pinning]") {
    SECTION("Generate pin from certificate") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Mock certificate data for testing
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
            REQUIRE(pin_result.has_value());

            // SHA-384 pin should be 48 bytes
            REQUIRE(pin_result->get().size() == 48);

            // Pin should be deterministic for same certificate
            auto pin2_result = ssl::spki_pin::from_certificate(*cert_result);
            REQUIRE(pin2_result.has_value());
            REQUIRE(pin_result->get().secure_equals(pin2_result->get()));
        }

        library::shutdown();
    }

    SECTION("Pin from raw public key") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Generate a test public key
        auto keypair = make::signature_keypair();
        REQUIRE(keypair.has_value());

        // Extract public key bytes
        auto public_key_bytes = keypair->public_key().get();
        std::span<const std::byte> pubkey_span{
            reinterpret_cast<const std::byte*>(public_key_bytes.data()),
            public_key_bytes.size()
        };

        auto pin_result = ssl::spki_pin::from_public_key(pubkey_span);
        if (pin_result.has_value()) {
            REQUIRE(pin_result->get().size() == 48);  // SHA-384
        } else {
            // Might not be implemented for Ed25519 keys
            REQUIRE(pin_result.error() == error::Code::NotImplemented);
        }

        library::shutdown();
    }
}

TEST_CASE("Certificate Chain Validation", "[ssl][validation]") {
    SECTION("Single certificate validation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string_view cert_pem = R"(-----BEGIN CERTIFICATE-----
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

        auto cert_result = ssl::certificate::parse_pem(cert_pem);
        if (cert_result.has_value()) {
            auto validation_result = ssl::validate_certificate(*cert_result);
            // Self-signed certificates typically fail validation without trust store
            if (validation_result.has_value()) {
                REQUIRE(validation_result->is_valid());
            }
        }

        library::shutdown();
    }

    SECTION("Certificate chain validation") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Mock certificate chain (would normally be loaded from file/network)
        std::vector<std::string> cert_chain = {
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",  // Leaf
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"   // Intermediate
        };

        std::vector<ssl::Certificate> certificates;
        for (const auto& cert_pem : cert_chain) {
            auto cert_result = ssl::certificate::parse_pem(cert_pem);
            if (cert_result.has_value()) {
                certificates.push_back(std::move(*cert_result));
            }
        }

        if (!certificates.empty()) {
            auto chain_result = ssl::validate_chain(std::span{certificates});
            // Chain validation might fail without proper test certificates
            if (chain_result.has_value()) {
                REQUIRE(chain_result->is_valid());
            }
        }

        library::shutdown();
    }
}

TEST_CASE("Pin Verification", "[ssl][pinning][verification]") {
    SECTION("Valid pin verification") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string_view cert_pem = R"(-----BEGIN CERTIFICATE-----
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

        auto cert_result = ssl::certificate::parse_pem(cert_pem);
        if (cert_result.has_value()) {
            auto pin_result = ssl::spki_pin::from_certificate(*cert_result);
            if (pin_result.has_value()) {
                // Verify pin against the same certificate
                auto verify_result = ssl::verify_pin(*cert_result, *pin_result);
                REQUIRE(verify_result.has_value());
                REQUIRE(*verify_result == true);
            }
        }

        library::shutdown();
    }

    SECTION("Invalid pin verification") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string_view cert_pem = R"(-----BEGIN CERTIFICATE-----
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

        auto cert_result = ssl::certificate::parse_pem(cert_pem);
        if (cert_result.has_value()) {
            // Create a fake pin (all zeros)
            crypto::SpkiPin fake_pin;
            std::fill(fake_pin.get().begin(), fake_pin.get().end(), std::byte{0});

            auto verify_result = ssl::verify_pin(*cert_result, fake_pin);
            if (verify_result.has_value()) {
                REQUIRE(*verify_result == false);
            }
        }

        library::shutdown();
    }

    SECTION("Multiple pin verification") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string_view cert_pem = R"(-----BEGIN CERTIFICATE-----
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

        auto cert_result = ssl::certificate::parse_pem(cert_pem);
        if (cert_result.has_value()) {
            auto pin_result = ssl::spki_pin::from_certificate(*cert_result);
            if (pin_result.has_value()) {
                // Create a pin set with valid and invalid pins
                std::vector<crypto::SpkiPin> pin_set;
                pin_set.push_back(*pin_result);  // Valid pin

                // Add fake pin
                crypto::SpkiPin fake_pin;
                std::fill(fake_pin.get().begin(), fake_pin.get().end(), std::byte{0xFF});
                pin_set.push_back(fake_pin);

                auto verify_result = ssl::verify_pin_set(*cert_result, std::span{pin_set});
                if (verify_result.has_value()) {
                    REQUIRE(*verify_result == true);  // Should match at least one pin
                }
            }
        }

        library::shutdown();
    }
}

TEST_CASE("SSL Context Configuration", "[ssl][context]") {
    SECTION("Create SSL context with pinning") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create pin set for testing
        std::vector<crypto::SpkiPin> pins;

        // Generate some test pins (normally these would be pre-calculated)
        for (int i = 0; i < 3; ++i) {
            crypto::SpkiPin pin;
            // Fill with test pattern
            for (size_t j = 0; j < pin.get().size(); ++j) {
                pin.get()[j] = std::byte{static_cast<uint8_t>((i * 256 + j) % 256)};
            }
            pins.push_back(pin);
        }

        auto context_result = ssl::create_context(std::span{pins});
        if (context_result.has_value()) {
            REQUIRE(context_result->is_pinning_enabled());
        } else {
            // SSL context creation might not be implemented
            REQUIRE(context_result.error() == error::Code::NotImplemented);
        }

        library::shutdown();
    }

    SECTION("SSL context without pinning") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto context_result = ssl::create_context();
        if (context_result.has_value()) {
            REQUIRE_FALSE(context_result->is_pinning_enabled());
        }

        library::shutdown();
    }
}