#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #ifdef ECLIPTIX_SERVER_STATIC
    #define ECLIPTIX_SERVER_API
  #else
    #ifdef ECLIPTIX_SERVER_EXPORTS
      #define ECLIPTIX_SERVER_API __declspec(dllexport)
    #else
      #define ECLIPTIX_SERVER_API __declspec(dllimport)
    #endif
  #endif
#else
  #define ECLIPTIX_SERVER_API __attribute__((visibility("default")))
#endif

typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERROR_INVALID_PARAMS = -1,
    ECLIPTIX_ERROR_CRYPTO_FAILURE = -2,
    ECLIPTIX_ERROR_VERIFICATION_FAILED = -3,
    ECLIPTIX_ERROR_INIT_FAILED = -4
} ecliptix_result_t;

ECLIPTIX_SERVER_API int ecliptix_server_init(void);

ECLIPTIX_SERVER_API int ecliptix_server_init_with_key(const uint8_t* private_key_pem, size_t key_size);

ECLIPTIX_SERVER_API int ecliptix_server_init_with_keys(
    const uint8_t* server_private_pem,
    size_t server_key_size,
    const uint8_t* client_public_pem,
    size_t client_pub_size
);

ECLIPTIX_SERVER_API void ecliptix_server_cleanup(void);

ECLIPTIX_SERVER_API ecliptix_result_t ecliptix_server_encrypt(
    const uint8_t* plaintext,
    size_t plain_len,
    uint8_t* ciphertext,
    size_t* cipher_len
);

ECLIPTIX_SERVER_API ecliptix_result_t ecliptix_server_decrypt(
    const uint8_t* ciphertext,
    size_t cipher_len,
    uint8_t* plaintext,
    size_t* plain_len
);

ECLIPTIX_SERVER_API ecliptix_result_t ecliptix_server_sign(
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* sig_len
);

ECLIPTIX_SERVER_API const char* ecliptix_server_get_error(void);

#ifdef __cplusplus
}
#endif