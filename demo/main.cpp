/*
 * Ecliptix Security Library Demo
 * Demonstrates basic usage of the SSL pinning and crypto library
 */

#include "ecliptix/security.h"
#include "ecliptix/security.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>

// Helper function to print bytes as hex
void print_hex(const uint8_t* data, size_t size, const std::string& label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

// Logging callback
void log_callback(int level, const char* message) {
    const char* level_str = (level == 1) ? "INFO" : "DEBUG";
    std::cout << "[" << level_str << "] " << message << std::endl;
}

// Error callback
void error_callback(const ecliptix_error_info_t* error_info, void* user_data) {
    std::cout << "[ERROR] " << error_info->message << " in " << error_info->function
              << " at line " << error_info->line << std::endl;
}

int main() {
    std::cout << "=== Ecliptix Security Library Demo ===" << std::endl;

    // Test C API
    std::cout << "\n--- Testing C API ---" << std::endl;

    // Initialize library
    ecliptix_result_t result = ecliptix_init_ex(log_callback, error_callback, nullptr);
    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Failed to initialize library: " << ecliptix_result_to_string(result) << std::endl;
        return 1;
    }

    // Get version info
    ecliptix_version_info_t version_info;
    result = ecliptix_get_version(&version_info);
    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "Library version: " << version_info.major << "."
                  << version_info.minor << "." << version_info.patch
                  << " (build " << version_info.build << ")" << std::endl;
        std::cout << "Build date: " << version_info.build_date << std::endl;
    }

    // Self-test
    std::cout << "\nRunning self-test..." << std::endl;
    result = ecliptix_self_test();
    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ Self-test passed" << std::endl;
    } else {
        std::cout << "✗ Self-test failed: " << ecliptix_result_to_string(result) << std::endl;
    }

    // Test random number generation
    std::cout << "\nTesting random number generation..." << std::endl;
    uint8_t random_data[32];
    result = ecliptix_random_bytes(random_data, sizeof(random_data));
    if (result == ECLIPTIX_SUCCESS) {
        print_hex(random_data, sizeof(random_data), "Random bytes");
    } else {
        std::cout << "✗ Random generation failed: " << ecliptix_result_to_string(result) << std::endl;
    }

    // Test AES-GCM encryption
    std::cout << "\nTesting AES-GCM encryption..." << std::endl;
    const char* test_message = "Hello, Ecliptix Security! This is a test message.";
    size_t message_len = std::strlen(test_message);

    uint8_t key[ECLIPTIX_AES_256_KEY_SIZE];
    uint8_t nonce[ECLIPTIX_AES_GCM_IV_SIZE];
    uint8_t tag[ECLIPTIX_AES_GCM_TAG_SIZE];

    // Generate random key
    result = ecliptix_random_bytes(key, sizeof(key));
    if (result != ECLIPTIX_SUCCESS) {
        std::cout << "✗ Key generation failed" << std::endl;
        goto cleanup;
    }

    // Encrypt
    std::vector<uint8_t> ciphertext(message_len);
    size_t ciphertext_size = ciphertext.size();

    result = ecliptix_encrypt_aes_gcm(
        reinterpret_cast<const uint8_t*>(test_message), message_len,
        key, sizeof(key),
        ciphertext.data(), &ciphertext_size,
        nonce, tag,
        nullptr, 0  // No associated data
    );

    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ Encryption successful" << std::endl;
        print_hex(key, sizeof(key), "Key");
        print_hex(nonce, sizeof(nonce), "Nonce");
        print_hex(tag, sizeof(tag), "Tag");
        print_hex(ciphertext.data(), ciphertext_size, "Ciphertext");

        // Decrypt
        std::vector<uint8_t> plaintext(ciphertext_size);
        size_t plaintext_size = plaintext.size();

        result = ecliptix_decrypt_aes_gcm(
            ciphertext.data(), ciphertext_size,
            key, sizeof(key),
            nonce, tag,
            plaintext.data(), &plaintext_size,
            nullptr, 0  // No associated data
        );

        if (result == ECLIPTIX_SUCCESS) {
            std::cout << "✓ Decryption successful" << std::endl;
            std::string decrypted_message(
                reinterpret_cast<const char*>(plaintext.data()),
                plaintext_size
            );
            std::cout << "Original: " << test_message << std::endl;
            std::cout << "Decrypted: " << decrypted_message << std::endl;

            if (decrypted_message == test_message) {
                std::cout << "✓ Message integrity verified" << std::endl;
            } else {
                std::cout << "✗ Message integrity check failed" << std::endl;
            }
        } else {
            std::cout << "✗ Decryption failed: " << ecliptix_result_to_string(result) << std::endl;
        }
    } else {
        std::cout << "✗ Encryption failed: " << ecliptix_result_to_string(result) << std::endl;
    }

    // Test Ed25519 signing
    std::cout << "\nTesting Ed25519 digital signatures..." << std::endl;
    uint8_t signature[ECLIPTIX_ED25519_SIGNATURE_SIZE];

    result = ecliptix_sign_ed25519(
        reinterpret_cast<const uint8_t*>(test_message), message_len,
        signature
    );

    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ Signing successful" << std::endl;
        print_hex(signature, sizeof(signature), "Signature");

        // Verify signature
        result = ecliptix_verify_ed25519(
            reinterpret_cast<const uint8_t*>(test_message), message_len,
            signature,
            nullptr  // Use embedded public key
        );

        if (result == ECLIPTIX_SUCCESS) {
            std::cout << "✓ Signature verification successful" << std::endl;
        } else {
            std::cout << "✗ Signature verification failed: " << ecliptix_result_to_string(result) << std::endl;
        }
    } else {
        std::cout << "✗ Signing failed: " << ecliptix_result_to_string(result) << std::endl;
    }

    // Test C++ API
    std::cout << "\n--- Testing C++ API ---" << std::endl;

    try {
        // Test AES-GCM with C++ API
        std::cout << "Testing C++ AES-GCM..." << std::endl;

        std::span<const uint8_t> message_span(
            reinterpret_cast<const uint8_t*>(test_message), message_len
        );

        auto random_key = ecliptix::utils::random_bytes(32);
        if (random_key.has_value()) {
            auto key_span = std::span<const uint8_t, 32>(random_key.value().data(), 32);

            auto encrypt_result = ecliptix::crypto::AES_GCM::encrypt(message_span, key_span);
            if (encrypt_result.has_value()) {
                std::cout << "✓ C++ Encryption successful" << std::endl;

                auto decrypt_result = ecliptix::crypto::AES_GCM::decrypt(
                    encrypt_result.value().ciphertext.span(),
                    key_span,
                    encrypt_result.value().nonce,
                    encrypt_result.value().tag
                );

                if (decrypt_result.has_value()) {
                    std::cout << "✓ C++ Decryption successful" << std::endl;

                    std::string decrypted_cpp(
                        reinterpret_cast<const char*>(decrypt_result.value().data()),
                        decrypt_result.value().size()
                    );

                    if (decrypted_cpp == test_message) {
                        std::cout << "✓ C++ Message integrity verified" << std::endl;
                    }
                }
            }
        }

        // Test Ed25519 with C++ API
        std::cout << "Testing C++ Ed25519..." << std::endl;

        auto sign_result = ecliptix::crypto::Ed25519::sign(message_span);
        if (sign_result.has_value()) {
            std::cout << "✓ C++ Signing successful" << std::endl;

            auto verify_result = ecliptix::crypto::Ed25519::verify(
                message_span, sign_result.value()
            );

            if (verify_result.has_value() && verify_result.value()) {
                std::cout << "✓ C++ Signature verification successful" << std::endl;
            }
        }

    } catch (const std::exception& e) {
        std::cout << "✗ C++ API test failed: " << e.what() << std::endl;
    }

    // Get performance metrics
    std::cout << "\n--- Performance Metrics ---" << std::endl;
    ecliptix_metrics_t metrics;
    result = ecliptix_get_metrics(&metrics);
    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "Total operations: " << metrics.operations_total << std::endl;
        std::cout << "Successful operations: " << metrics.operations_successful << std::endl;
        std::cout << "Failed operations: " << metrics.operations_failed << std::endl;
        std::cout << "Bytes encrypted: " << metrics.bytes_encrypted << std::endl;
        std::cout << "Bytes decrypted: " << metrics.bytes_decrypted << std::endl;
        std::cout << "Certificates validated: " << metrics.certificates_validated << std::endl;
        std::cout << "Signatures verified: " << metrics.signatures_verified << std::endl;
    }

cleanup:
    // Cleanup
    ecliptix_cleanup();
    std::cout << "\n=== Demo completed ===" << std::endl;

    return 0;
}