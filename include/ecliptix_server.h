#pragma once

#include "ecliptix_common.h"

#ifdef __cplusplus
extern "C" {
#endif

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_init(void);

ECLIPTIX_SERVER_API void ECLIPTIX_CALL ecliptix_server_cleanup(void);

[[nodiscard]] ECLIPTIX_SERVER_API const char* ECLIPTIX_CALL ecliptix_server_get_error_message(void);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* private_key,
    uint8_t* signature_out
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* private_key_pem,
    size_t private_key_size,
    uint8_t* plaintext,
    size_t* plaintext_size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_generate_ed25519_keypair(
    uint8_t* public_key_out,
    uint8_t* private_key_out
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_generate_rsa_keypair(
    uint8_t* public_key_pem,
    size_t* public_key_size,
    uint8_t* private_key_pem,
    size_t* private_key_size,
    int key_bits
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_derive_key_argon2id(
    const uint8_t* password,
    size_t password_size,
    const uint8_t* salt,
    size_t salt_size,
    uint32_t memory_kb,
    uint32_t iterations,
    uint8_t* derived_key,
    size_t key_size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_encrypt_chacha20_poly1305(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* key,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_decrypt_chacha20_poly1305(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* key,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t* plaintext,
    size_t* plaintext_size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_create_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_t* pin_out
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_create_pin_config(
    const char* hostname,
    const uint8_t* primary_cert_der,
    size_t primary_cert_size,
    const uint8_t** backup_certs_der,
    const size_t* backup_cert_sizes,
    uint8_t backup_count,
    ecliptix_pin_config_t* config_out
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_validate_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    const ecliptix_pin_t* expected_pin
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_hash_blake2b(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_size,
    uint8_t* hash_out,
    size_t hash_size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_secure_malloc(
    void** ptr,
    size_t size
);

ECLIPTIX_SERVER_API void ECLIPTIX_CALL ecliptix_server_secure_free(
    void* ptr,
    size_t size
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_constant_time_compare(
    const uint8_t* a,
    const uint8_t* b,
    size_t size,
    int* result
);

[[nodiscard]] ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_get_library_version(
    char* version_buffer,
    size_t buffer_size
);

#ifdef __cplusplus
}
#endif