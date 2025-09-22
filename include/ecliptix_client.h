#pragma once

#include "ecliptix_common.h"

#ifdef __cplusplus
extern "C" {
#endif

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_init(void);

ECLIPTIX_CLIENT_API void ECLIPTIX_CALL ecliptix_client_cleanup(void);

[[nodiscard]] ECLIPTIX_CLIENT_API const char* ECLIPTIX_CALL ecliptix_client_get_error_message(void);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_validate_certificate(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_verify_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    const ecliptix_pin_t* expected_pin
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_get_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_t* pin_out
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_verify_ed25519_signature(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* signature,
    const uint8_t* public_key
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_validate_pin_config(
    const ecliptix_pin_config_t* pin_config
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_hash_sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t* hash_out
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_hash_sha384(
    const uint8_t* data,
    size_t data_size,
    uint8_t* hash_out
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_generate_random(
    uint8_t* buffer,
    size_t buffer_size
);

[[nodiscard]] ECLIPTIX_CLIENT_API int ECLIPTIX_CALL ecliptix_client_is_hostname_trusted(
    const char* hostname
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_constant_time_compare(
    const uint8_t* a,
    const uint8_t* b,
    size_t size,
    int* result
);

[[nodiscard]] ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_get_library_version(
    char* version_buffer,
    size_t buffer_size
);

#ifdef __cplusplus
}
#endif