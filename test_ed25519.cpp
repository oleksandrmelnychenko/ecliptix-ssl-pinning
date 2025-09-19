#include <iostream>
#include <cstring>
#include "include/ecliptix/security.h"

int main() {
    std::cout << "Testing Ed25519 signing..." << std::endl;

    // Initialize library
    ecliptix_result_t result = ecliptix_init();
    if (result != ECLIPTIX_SUCCESS) {
        std::cout << "Failed to initialize library: " << result << std::endl;
        return 1;
    }
    std::cout << "✓ Library initialized successfully" << std::endl;

    // Test message
    const char* message = "Hello, World!";
    size_t message_len = strlen(message);

    // Test Ed25519 signing
    uint8_t signature[64]; // Ed25519 signature size

    result = ecliptix_sign_ed25519(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature
    );

    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ Ed25519 signing successful!" << std::endl;

        // Test Ed25519 verification
        result = ecliptix_verify_ed25519(
            reinterpret_cast<const uint8_t*>(message),
            message_len,
            signature
        );

        if (result == ECLIPTIX_SUCCESS) {
            std::cout << "✓ Ed25519 verification successful!" << std::endl;
        } else {
            std::cout << "✗ Ed25519 verification failed: " << result << std::endl;
            const char* error_msg = ecliptix_get_error_message();
            std::cout << "Error: " << error_msg << std::endl;
        }
    } else {
        std::cout << "✗ Ed25519 signing failed: " << result << std::endl;
        const char* error_msg = ecliptix_get_error_message();
        std::cout << "Error: " << error_msg << std::endl;
    }

    // Cleanup
    ecliptix_cleanup();
    return (result == ECLIPTIX_SUCCESS) ? 0 : 1;
}