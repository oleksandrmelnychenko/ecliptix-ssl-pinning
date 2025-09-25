#pragma once

#include "common_types.h"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

int ecliptix_client_init(void);
void ecliptix_client_cleanup(void);
ecliptix_result_t ecliptix_client_verify(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len);
ecliptix_result_t ecliptix_client_encrypt(const uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext, size_t* ciphertext_len);
ecliptix_result_t ecliptix_client_decrypt(const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, size_t* plaintext_len);
ecliptix_result_t ecliptix_client_get_public_key(uint8_t* public_key_der, size_t* public_key_len);
const char* ecliptix_client_get_error(void);

int ecliptix_server_init(void);
int ecliptix_server_init_with_key(const uint8_t* private_key_pem, size_t key_size);
int ecliptix_server_init_with_keys(const uint8_t* server_private_pem, size_t server_key_size,
                                   const uint8_t* client_public_pem, size_t client_pub_size);
void ecliptix_server_cleanup(void);
ecliptix_result_t ecliptix_server_encrypt(const uint8_t* plaintext, size_t plain_len, uint8_t* ciphertext, size_t* cipher_len);
ecliptix_result_t ecliptix_server_decrypt(const uint8_t* ciphertext, size_t cipher_len, uint8_t* plaintext, size_t* plain_len);
ecliptix_result_t ecliptix_server_sign(const uint8_t* data, size_t data_len, uint8_t* signature, size_t* sig_len);
const char* ecliptix_server_get_error(void);

#ifdef __cplusplus
}
#endif

namespace TestHelpers {

    inline std::vector<uint8_t> load_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file " << filename << std::endl;
            return {};
        }

        file.seekg(0, std::ios::end);
        auto file_size = file.tellg();
        file.seekg(0, std::ios::beg);

        size_t size = static_cast<size_t>(file_size);
        std::vector<uint8_t> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
        file.close();

        return buffer;
    }

    // Use embedded keys instead of loading from files
    inline int init_server_with_test_key() {
        // Use the embedded keys compiled into the library
        return ecliptix_server_init();
    }

    inline int init_server_with_matching_keys() {
        // Use the embedded keys compiled into the library
        return ecliptix_server_init();
    }

    inline int init_client_for_testing() {
        return ecliptix_client_init();
    }

    inline void cleanup_all() {
        ecliptix_server_cleanup();
        ecliptix_client_cleanup();
    }

    inline int init_both_for_testing() {
        int server_result = init_server_with_matching_keys();
        if (server_result != ECLIPTIX_SUCCESS) {
            return server_result;
        }

        int client_result = init_client_for_testing();
        if (client_result != ECLIPTIX_SUCCESS) {
            ecliptix_server_cleanup();
            return client_result;
        }

        return ECLIPTIX_SUCCESS;
    }

    class ScopedTestSetup {
    public:
        ScopedTestSetup() {
            server_initialized = (init_server_with_matching_keys() == ECLIPTIX_SUCCESS);
            client_initialized = (init_client_for_testing() == ECLIPTIX_SUCCESS);
        }

        ~ScopedTestSetup() {
            cleanup_all();
        }

        bool is_ready() const {
            return server_initialized && client_initialized;
        }

        bool server_ok() const { return server_initialized; }
        bool client_ok() const { return client_initialized; }

    private:
        bool server_initialized = false;
        bool client_initialized = false;
    };
}

#define REQUIRE_TEST_SETUP() \
    REQUIRE(TestHelpers::init_both_for_testing() == ECLIPTIX_SUCCESS)

#define REQUIRE_SERVER_INIT() \
    REQUIRE(TestHelpers::init_server_with_test_key() == ECLIPTIX_SUCCESS)

#define REQUIRE_CLIENT_INIT() \
    REQUIRE(TestHelpers::init_client_for_testing() == ECLIPTIX_SUCCESS)