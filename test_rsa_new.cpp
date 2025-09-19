#include <iostream>
#include <cstring>
#include "include/ecliptix/security.h"

int main() {
    std::cout << "Testing RSA encryption with new RSA certificate..." << std::endl;

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

    // Prepare output buffer
    uint8_t ciphertext[256]; // RSA-2048 output size
    size_t ciphertext_size = sizeof(ciphertext);

    // Test RSA encryption
    result = ecliptix_encrypt_rsa(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        ciphertext,
        &ciphertext_size
    );

    if (result == ECLIPTIX_SUCCESS) {
        std::cout << "✓ RSA encryption successful! Ciphertext size: " << ciphertext_size << " bytes" << std::endl;

        // Print first few bytes of ciphertext
        std::cout << "Ciphertext (first 16 bytes): ";
        for (size_t i = 0; i < std::min(size_t(16), ciphertext_size); i++) {
            printf("%02x ", ciphertext[i]);
        }
        std::cout << std::endl;
    } else {
        std::cout << "✗ RSA encryption failed: " << result << std::endl;

        // Get error message
        const char* error_msg = ecliptix_get_error_message();
        std::cout << "Error: " << error_msg << std::endl;
    }

    // Cleanup
    ecliptix_cleanup();
    return (result == ECLIPTIX_SUCCESS) ? 0 : 1;
}