
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>


#ifdef _WIN32
    #ifdef BUILDING_ECLIPTIX
        #define ECLIPTIX_API __declspec(dllexport)
    #else
        #define ECLIPTIX_API __declspec(dllimport)
    #endif
    #define ECLIPTIX_CALL __cdecl
#else
    #define ECLIPTIX_API __attribute__((visibility("default")))
    #define ECLIPTIX_CALL
#endif


typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERR_NOT_INITIALIZED = -1,
    ECLIPTIX_ERR_INVALID_PARAM = -3,
    ECLIPTIX_ERR_MEMORY_ALLOCATION = -4,
    ECLIPTIX_ERR_CRYPTO_FAILURE = -5,
    ECLIPTIX_ERR_SIGNATURE_INVALID = -11,
    ECLIPTIX_ERR_DECRYPTION_FAILED = -12,
    ECLIPTIX_ERR_BUFFER_TOO_SMALL = -14,
    ECLIPTIX_ERR_UNKNOWN = -99
} ecliptix_result_t;


#define ECLIPTIX_ED25519_SIGNATURE_SIZE 64
#define ECLIPTIX_RSA_MAX_PLAINTEXT_SIZE 214
#define ECLIPTIX_RSA_CIPHERTEXT_SIZE 256


[[nodiscard]] ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init(void);

ECLIPTIX_API void ECLIPTIX_CALL ecliptix_cleanup(void);

[[nodiscard]] ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_get_error_message(void);


[[nodiscard]] ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size
);

[[nodiscard]] ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* private_key_pem,
    size_t private_key_size,
    uint8_t* plaintext,
    size_t* plaintext_size
);


[[nodiscard]] ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_verify_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* signature
);

#ifdef __cplusplus
}
#endif