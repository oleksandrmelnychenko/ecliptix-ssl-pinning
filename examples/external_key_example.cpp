#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

#include "../server/include/ecliptix_server.h"
#include "../client/include/ecliptix_client.h"

std::vector<uint8_t> load_pem_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << std::endl;
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();

    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <server_private_key.pem> <client_private_key.pem>" << std::endl;
        std::cout << "\nExample demonstrating external key loading with Ecliptix Security library." << std::endl;
        std::cout << "This replaces the previous embedded key approach for improved security." << std::endl;
        return 1;
    }

    const std::string server_key_file = argv[1];
    const std::string client_key_file = argv[2];

    std::cout << "=== Ecliptix Security External Key Loading Demo ===" << std::endl;
    std::cout << "Loading server private key from: " << server_key_file << std::endl;
    std::cout << "Loading client private key from: " << client_key_file << std::endl;
    std::cout << std::endl;

    auto server_key_data = load_pem_file(server_key_file);
    auto client_key_data = load_pem_file(client_key_file);

    if (server_key_data.empty()) {
        std::cerr << "Failed to load server private key file" << std::endl;
        return 1;
    }

    if (client_key_data.empty()) {
        std::cerr << "Failed to load client private key file" << std::endl;
        return 1;
    }

    std::cout << "1. Initializing server with external private key..." << std::endl;
    int result = ecliptix_server_init_with_key(server_key_data.data(), server_key_data.size());
    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Server initialization failed: " << ecliptix_server_get_error() << std::endl;
        return 1;
    }
    std::cout << "   ✓ Server initialized successfully" << std::endl;

    std::cout << "2. Initializing client with external private key..." << std::endl;
    result = ecliptix_client_init_with_key(client_key_data.data(), client_key_data.size());
    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Client initialization failed: " << ecliptix_client_get_error() << std::endl;
        ecliptix_server_cleanup();
        return 1;
    }
    std::cout << "   ✓ Client initialized successfully" << std::endl;

    std::cout << "3. Testing encryption/decryption..." << std::endl;
    const char* test_message = "Hello, secure world!";
    size_t message_len = strlen(test_message);

    uint8_t encrypted_buffer[512];
    size_t encrypted_len = sizeof(encrypted_buffer);

    result = ecliptix_server_encrypt(
        reinterpret_cast<const uint8_t*>(test_message),
        message_len,
        encrypted_buffer,
        &encrypted_len
    );

    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Encryption failed: " << ecliptix_server_get_error() << std::endl;
    } else {
        std::cout << "   ✓ Message encrypted successfully (" << encrypted_len << " bytes)" << std::endl;

        uint8_t decrypted_buffer[512];
        size_t decrypted_len = sizeof(decrypted_buffer);

        result = ecliptix_client_decrypt(
            encrypted_buffer,
            encrypted_len,
            decrypted_buffer,
            &decrypted_len
        );

        if (result != ECLIPTIX_SUCCESS) {
            std::cerr << "Decryption failed: " << ecliptix_client_get_error() << std::endl;
        } else {
            decrypted_buffer[decrypted_len] = '\0';
            std::cout << "   ✓ Message decrypted successfully: \"" << reinterpret_cast<char*>(decrypted_buffer) << "\"" << std::endl;
        }
    }

    std::cout << "4. Testing digital signatures..." << std::endl;
    const char* data_to_sign = "Important data requiring authentication";
    size_t data_len = strlen(data_to_sign);

    uint8_t signature_buffer[512];
    size_t signature_len = sizeof(signature_buffer);

    result = ecliptix_server_sign(
        reinterpret_cast<const uint8_t*>(data_to_sign),
        data_len,
        signature_buffer,
        &signature_len
    );

    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Signing failed: " << ecliptix_server_get_error() << std::endl;
    } else {
        std::cout << "   ✓ Data signed successfully (" << signature_len << " bytes)" << std::endl;

        result = ecliptix_client_verify(
            reinterpret_cast<const uint8_t*>(data_to_sign),
            data_len,
            signature_buffer,
            signature_len
        );

        if (result != ECLIPTIX_SUCCESS) {
            std::cerr << "Signature verification failed: " << ecliptix_client_get_error() << std::endl;
        } else {
            std::cout << "   ✓ Signature verified successfully" << std::endl;
        }
    }

    std::cout << "5. Cleaning up..." << std::endl;
    ecliptix_server_cleanup();
    ecliptix_client_cleanup();
    std::cout << "   ✓ Cleanup completed" << std::endl;

    std::cout << std::endl;
    std::cout << "=== Demo completed successfully ===" << std::endl;
    std::cout << "Private keys were loaded externally, providing better security than embedded keys." << std::endl;

    return 0;
}