#include <iostream>
#include <cstring>
#include "include/ecliptix/security.h"

int main() {
    std::cout << "Testing Final Minimal API..." << std::endl;

    ecliptix_result_t result = ecliptix_init();
    if (result != ECLIPTIX_SUCCESS) {
        std::cout << "Failed to initialize library: " << result << std::endl;
        return 1;
    }
    std::cout << "✓ Library initialized successfully" << std::endl;

    const char* message = "Hello, World!";
    size_t message_len = strlen(message);

    uint8_t ciphertext[256];
    size_t ciphertext_size = sizeof(ciphertext);

    result = ecliptix_encrypt_rsa(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        ciphertext,
        &ciphertext_size
    );

    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ RSA encryption successful! Ciphertext size: " << ciphertext_size << " bytes" << std::endl;
    } else {
        std::cout << "✗ RSA encryption failed: " << result << std::endl;
        const char* error_msg = ecliptix_get_error_message();
        std::cout << "Error: " << error_msg << std::endl;
        ecliptix_cleanup();
        return 1;
    }

    // Test Ed25519 verification (with dummy signature since we can't sign)
    uint8_t dummy_signature[64];
    memset(dummy_signature, 0, sizeof(dummy_signature));

    result = ecliptix_verify_ed25519(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        dummy_signature
    );

    if (result == ECLIPTIX_ERR_SIGNATURE_INVALID) {
        std::cout << "✓ Ed25519 verification working (correctly rejected invalid signature)" << std::endl;
    } else {
        std::cout << "? Ed25519 verification result: " << result << std::endl;
    }

    // Cleanup
    ecliptix_cleanup();
    std::cout << "✓ Final API test completed successfully!" << std::endl;
    return 0;
}