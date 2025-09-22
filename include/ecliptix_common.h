#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #ifdef BUILDING_ECLIPTIX_CLIENT
        #define ECLIPTIX_CLIENT_API __declspec(dllexport)
    #else
        #define ECLIPTIX_CLIENT_API __declspec(dllimport)
    #endif
    #ifdef BUILDING_ECLIPTIX_SERVER
        #define ECLIPTIX_SERVER_API __declspec(dllexport)
    #else
        #define ECLIPTIX_SERVER_API __declspec(dllimport)
    #endif
    #define ECLIPTIX_CALL __cdecl
#else
    #define ECLIPTIX_CLIENT_API __attribute__((visibility("default")))
    #define ECLIPTIX_SERVER_API __attribute__((visibility("default")))
    #define ECLIPTIX_CALL
#endif

typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERR_NOT_INITIALIZED = -1,
    ECLIPTIX_ERR_INVALID_PARAM = -2,
    ECLIPTIX_ERR_MEMORY_ALLOCATION = -3,
    ECLIPTIX_ERR_CRYPTO_FAILURE = -4,
    ECLIPTIX_ERR_CERTIFICATE_INVALID = -5,
    ECLIPTIX_ERR_CERTIFICATE_EXPIRED = -6,
    ECLIPTIX_ERR_CERTIFICATE_NOT_TRUSTED = -7,
    ECLIPTIX_ERR_PIN_VERIFICATION_FAILED = -8,
    ECLIPTIX_ERR_SIGNATURE_INVALID = -9,
    ECLIPTIX_ERR_ENCRYPTION_FAILED = -10,
    ECLIPTIX_ERR_DECRYPTION_FAILED = -11,
    ECLIPTIX_ERR_KEY_GENERATION_FAILED = -12,
    ECLIPTIX_ERR_BUFFER_TOO_SMALL = -13,
    ECLIPTIX_ERR_UNKNOWN = -99
} ecliptix_result_t;

#define ECLIPTIX_ED25519_PUBLIC_KEY_SIZE 32
#define ECLIPTIX_ED25519_PRIVATE_KEY_SIZE 32
#define ECLIPTIX_ED25519_SIGNATURE_SIZE 64
#define ECLIPTIX_RSA_MAX_PLAINTEXT_SIZE 214
#define ECLIPTIX_RSA_CIPHERTEXT_SIZE 256
#define ECLIPTIX_SHA256_HASH_SIZE 32
#define ECLIPTIX_SHA384_HASH_SIZE 48
#define ECLIPTIX_MAX_HOSTNAME_SIZE 256
#define ECLIPTIX_MAX_ERROR_MESSAGE_SIZE 512

typedef struct {
    uint8_t hash[ECLIPTIX_SHA384_HASH_SIZE];
} ecliptix_pin_t;

typedef struct {
    char hostname[ECLIPTIX_MAX_HOSTNAME_SIZE];
    ecliptix_pin_t primary_pin;
    ecliptix_pin_t backup_pins[3];
    uint8_t backup_pin_count;
} ecliptix_pin_config_t;

#ifdef __cplusplus
}
#endif