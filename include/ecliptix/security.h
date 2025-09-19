/*
 * Ecliptix Security Library - C API Header
 * Minimal C interface for legacy compatibility
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// API Macros
// ============================================================================

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

// ============================================================================
// Error Codes
// ============================================================================

typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERR_NOT_INITIALIZED = -1,
    ECLIPTIX_ERR_ALREADY_INITIALIZED = -2,
    ECLIPTIX_ERR_INVALID_PARAM = -3,
    ECLIPTIX_ERR_MEMORY_ALLOCATION = -4,
    ECLIPTIX_ERR_CRYPTO_FAILURE = -5,
    ECLIPTIX_ERR_CERT_INVALID = -6,
    ECLIPTIX_ERR_CERT_EXPIRED = -7,
    ECLIPTIX_ERR_CERT_NOT_YET_VALID = -8,
    ECLIPTIX_ERR_HOSTNAME_MISMATCH = -9,
    ECLIPTIX_ERR_PIN_MISMATCH = -10,
    ECLIPTIX_ERR_SIGNATURE_INVALID = -11,
    ECLIPTIX_ERR_DECRYPTION_FAILED = -12,
    ECLIPTIX_ERR_TAMPERED = -13,
    ECLIPTIX_ERR_BUFFER_TOO_SMALL = -14,
    ECLIPTIX_ERR_INVALID_CERT = -15,
    ECLIPTIX_ERR_INVALID_CHAIN = -16,
    ECLIPTIX_ERR_OUT_OF_MEMORY = -17,
    ECLIPTIX_ERR_UNSUPPORTED = -18,
    ECLIPTIX_ERR_TIMEOUT = -19,
    ECLIPTIX_ERR_UNKNOWN = -99
} ecliptix_result_t;

// ============================================================================
// Validation Flags
// ============================================================================

typedef enum {
    ECLIPTIX_CERT_VALIDATE_NONE = 0,
    ECLIPTIX_CERT_VALIDATE_TIME = 1 << 0,
    ECLIPTIX_CERT_VALIDATE_HOSTNAME = 1 << 1,
    ECLIPTIX_CERT_VALIDATE_CHAIN = 1 << 2,
    ECLIPTIX_CERT_VALIDATE_PIN = 1 << 3,
    ECLIPTIX_CERT_VALIDATE_ALL = 0xFF
} ecliptix_cert_validation_flags_t;

// ============================================================================
// Pin Mode Flags
// ============================================================================

typedef enum {
    ECLIPTIX_PIN_MODE_STRICT = 0,
    ECLIPTIX_PIN_MODE_BACKUP = 1,
    ECLIPTIX_PIN_MODE_ALLOW_NEW = 2
} ecliptix_pin_mode_t;

// ============================================================================
// Callback Types
// ============================================================================

// Forward declaration
typedef struct ecliptix_error_info_t ecliptix_error_info_t;

typedef void (*ecliptix_log_callback_t)(int level, const char* message);
typedef void (*ecliptix_error_callback_t)(ecliptix_error_info_t* error_info, void* user_data);

// ============================================================================
// Structure Types
// ============================================================================

struct ecliptix_error_info_t {
    int code;
    char message[256];
    const char* function;
    uint32_t line;
    uint64_t timestamp;
    uint32_t thread_id;
};

typedef struct {
    int major;
    int minor;
    int patch;
    int build;
    char version_string[32];
    char build_date[32];
    const char* commit_hash;
    uint64_t build_timestamp;
} ecliptix_version_info_t;

typedef struct {
    uint64_t operations_total;
    uint64_t operations_successful;
    uint64_t operations_failed;
    uint64_t certificates_validated;
    uint64_t pins_checked;
    uint64_t encryptions_performed;
    uint64_t signatures_created;
    uint64_t signatures_verified;
} ecliptix_metrics_t;

// ============================================================================
// Library Management
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init(void);
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init_ex(
    ecliptix_log_callback_t log_callback,
    ecliptix_error_callback_t error_callback,
    void* user_data
);
ECLIPTIX_API void ECLIPTIX_CALL ecliptix_cleanup(void);
ECLIPTIX_API int ECLIPTIX_CALL ecliptix_is_initialized(void);
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_get_version(ecliptix_version_info_t* version_info);
ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_get_error_message(void);
ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_version(void);

// ============================================================================
// Certificate Validation and Pinning
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_validate_certificate(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    ecliptix_cert_validation_flags_t validation_flags
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_check_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const uint8_t* trusted_pins,
    size_t num_pins
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_check_certificate_pin_ex(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_mode_t pin_mode
);

// ============================================================================
// Cryptographic Operations
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_generate_random(uint8_t* buffer, size_t size);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_encrypt_aead(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* associated_data,
    size_t associated_data_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size,
    uint8_t* nonce,
    uint8_t* tag
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_decrypt_aead(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* associated_data,
    size_t associated_data_size,
    const uint8_t* nonce,
    const uint8_t* tag,
    uint8_t* plaintext,
    size_t* plaintext_size
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* private_key,
    uint8_t* signature
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_verify_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* signature,
    const uint8_t* public_key
);

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_hash_blake2b(
    const uint8_t* data,
    size_t data_size,
    uint8_t* hash,
    size_t hash_size
);

// ============================================================================
// Statistics and Diagnostics
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_get_stats(
    uint64_t* operations_total,
    uint64_t* operations_successful,
    uint64_t* operations_failed
);

#ifdef __cplusplus
}
#endif