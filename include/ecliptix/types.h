#pragma once

/*
 * Ecliptix Security Types
 * Common type definitions for the security library
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// API visibility macros
#ifdef _WIN32
    #ifdef ECLIPTIX_SECURITY_EXPORTS
        #define ECLIPTIX_API __declspec(dllexport)
    #else
        #define ECLIPTIX_API __declspec(dllimport)
    #endif
    #define ECLIPTIX_CALL __cdecl
#else
    #ifdef ECLIPTIX_SECURITY_EXPORTS
        #define ECLIPTIX_API __attribute__((visibility("default")))
    #else
        #define ECLIPTIX_API
    #endif
    #define ECLIPTIX_CALL
#endif

// Result codes
typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERR_INVALID_PARAM = -1,
    ECLIPTIX_ERR_INVALID_CERT = -2,
    ECLIPTIX_ERR_INVALID_CHAIN = -3,
    ECLIPTIX_ERR_CERT_EXPIRED = -4,
    ECLIPTIX_ERR_CERT_NOT_YET_VALID = -5,
    ECLIPTIX_ERR_HOSTNAME_MISMATCH = -6,
    ECLIPTIX_ERR_PIN_MISMATCH = -7,
    ECLIPTIX_ERR_CRYPTO_FAILURE = -8,
    ECLIPTIX_ERR_BUFFER_TOO_SMALL = -9,
    ECLIPTIX_ERR_OUT_OF_MEMORY = -10,
    ECLIPTIX_ERR_NOT_INITIALIZED = -11,
    ECLIPTIX_ERR_ALREADY_INITIALIZED = -12,
    ECLIPTIX_ERR_TAMPERED = -13,
    ECLIPTIX_ERR_UNSUPPORTED = -14,
    ECLIPTIX_ERR_TIMEOUT = -15,
    ECLIPTIX_ERR_UNKNOWN = -99
} ecliptix_result_t;

// Encryption algorithms
typedef enum {
    ECLIPTIX_ENCRYPT_AES_256_GCM = 1,
    ECLIPTIX_ENCRYPT_CHACHA20_POLY1305 = 2,
    ECLIPTIX_ENCRYPT_XCHACHA20_POLY1305 = 3
} ecliptix_encryption_algorithm_t;

// Signature algorithms
typedef enum {
    ECLIPTIX_SIGN_ED25519 = 1,
    ECLIPTIX_SIGN_ECDSA_P384 = 2,
    ECLIPTIX_SIGN_RSA_PSS_4096 = 3
} ecliptix_signature_algorithm_t;

// Hash algorithms
typedef enum {
    ECLIPTIX_HASH_SHA256 = 1,
    ECLIPTIX_HASH_SHA384 = 2,
    ECLIPTIX_HASH_SHA512 = 3,
    ECLIPTIX_HASH_BLAKE3 = 4
} ecliptix_hash_algorithm_t;

// SSL pinning validation modes
typedef enum {
    ECLIPTIX_PIN_MODE_STRICT = 1,      // Only accept pinned certificates
    ECLIPTIX_PIN_MODE_BACKUP = 2,      // Accept primary or backup pins
    ECLIPTIX_PIN_MODE_ALLOW_NEW = 3    // Accept new pins (for rotation)
} ecliptix_pin_mode_t;

// Memory protection levels
typedef enum {
    ECLIPTIX_MEMORY_NORMAL = 0,        // Standard allocation
    ECLIPTIX_MEMORY_SECURE = 1,        // Locked, non-swappable
    ECLIPTIX_MEMORY_PROTECTED = 2      // Guarded pages, secure wipe
} ecliptix_memory_protection_t;

// Certificate validation flags
typedef enum {
    ECLIPTIX_CERT_VALIDATE_NONE = 0x00,
    ECLIPTIX_CERT_VALIDATE_TIME = 0x01,
    ECLIPTIX_CERT_VALIDATE_HOSTNAME = 0x02,
    ECLIPTIX_CERT_VALIDATE_CHAIN = 0x04,
    ECLIPTIX_CERT_VALIDATE_PIN = 0x08,
    ECLIPTIX_CERT_VALIDATE_ALL = 0xFF
} ecliptix_cert_validation_flags_t;

// Session context (opaque handle)
typedef struct ecliptix_session ecliptix_session_t;

// Certificate context (opaque handle)
typedef struct ecliptix_certificate ecliptix_certificate_t;

// Crypto context (opaque handle)
typedef struct ecliptix_crypto_context ecliptix_crypto_context_t;

// Buffer structure for safe data passing
typedef struct {
    uint8_t* data;
    size_t size;
    size_t capacity;
    ecliptix_memory_protection_t protection;
} ecliptix_buffer_t;

// Certificate information structure
typedef struct {
    char subject[256];
    char issuer[256];
    char serial_number[64];
    uint64_t not_before;    // Unix timestamp
    uint64_t not_after;     // Unix timestamp
    uint8_t fingerprint_sha256[32];
    uint8_t pin_sha384[48];
} ecliptix_cert_info_t;

// Crypto operation parameters
typedef struct {
    ecliptix_encryption_algorithm_t encryption_algorithm;
    ecliptix_signature_algorithm_t signature_algorithm;
    ecliptix_hash_algorithm_t hash_algorithm;
    uint32_t key_derivation_iterations;
    uint8_t* associated_data;
    size_t associated_data_size;
} ecliptix_crypto_params_t;

// Session parameters
typedef struct {
    uint32_t timeout_seconds;
    ecliptix_pin_mode_t pin_mode;
    ecliptix_cert_validation_flags_t validation_flags;
    const char* trusted_domains[16];  // Null-terminated array
    uint8_t* client_certificate;
    size_t client_certificate_size;
    uint8_t* client_private_key;
    size_t client_private_key_size;
} ecliptix_session_params_t;

// Library version information
typedef struct {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
    uint32_t build;
    const char* build_date;
    const char* commit_hash;
    uint64_t build_timestamp;
} ecliptix_version_info_t;

// Performance metrics
typedef struct {
    uint64_t operations_total;
    uint64_t operations_successful;
    uint64_t operations_failed;
    uint64_t bytes_encrypted;
    uint64_t bytes_decrypted;
    uint64_t certificates_validated;
    uint64_t signatures_verified;
    double average_encryption_time_ms;
    double average_decryption_time_ms;
    double average_validation_time_ms;
} ecliptix_metrics_t;

// Error information structure
typedef struct {
    ecliptix_result_t code;
    const char* message;
    const char* function;
    uint32_t line;
    uint64_t timestamp;
    uint32_t thread_id;
} ecliptix_error_info_t;

// Callback function types
typedef void (*ecliptix_log_callback_t)(int level, const char* message);
typedef int (*ecliptix_cert_callback_t)(const ecliptix_cert_info_t* cert_info, void* user_data);
typedef void (*ecliptix_error_callback_t)(const ecliptix_error_info_t* error_info, void* user_data);

// Constants
#define ECLIPTIX_MAX_HOSTNAME_LEN 256
#define ECLIPTIX_MAX_CERT_SIZE 8192
#define ECLIPTIX_MAX_KEY_SIZE 4096
#define ECLIPTIX_MAX_SIGNATURE_SIZE 256
#define ECLIPTIX_MAX_PLAINTEXT_SIZE (1024 * 1024)  // 1MB
#define ECLIPTIX_MAX_CIPHERTEXT_SIZE (ECLIPTIX_MAX_PLAINTEXT_SIZE + 64)

#define ECLIPTIX_AES_256_KEY_SIZE 32
#define ECLIPTIX_AES_GCM_IV_SIZE 12
#define ECLIPTIX_AES_GCM_TAG_SIZE 16

#define ECLIPTIX_CHACHA20_KEY_SIZE 32
#define ECLIPTIX_CHACHA20_NONCE_SIZE 12
#define ECLIPTIX_CHACHA20_TAG_SIZE 16

#define ECLIPTIX_ED25519_PUBLIC_KEY_SIZE 32
#define ECLIPTIX_ED25519_PRIVATE_KEY_SIZE 32
#define ECLIPTIX_ED25519_SIGNATURE_SIZE 64

#define ECLIPTIX_SHA256_DIGEST_SIZE 32
#define ECLIPTIX_SHA384_DIGEST_SIZE 48
#define ECLIPTIX_SHA512_DIGEST_SIZE 64

#define ECLIPTIX_SSL_PIN_SIZE ECLIPTIX_SHA384_DIGEST_SIZE

// Version macros
#define ECLIPTIX_VERSION_MAJOR 1
#define ECLIPTIX_VERSION_MINOR 0
#define ECLIPTIX_VERSION_PATCH 0

// Utility macros
#define ECLIPTIX_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ECLIPTIX_UNUSED(x) ((void)(x))

// Memory alignment
#define ECLIPTIX_ALIGN(n) __attribute__((aligned(n)))
#define ECLIPTIX_CACHE_ALIGN ECLIPTIX_ALIGN(64)

// Security annotations
#define ECLIPTIX_SENSITIVE __attribute__((annotate("sensitive")))
#define ECLIPTIX_WIPE_ON_RETURN __attribute__((annotate("wipe_on_return")))

#ifdef __cplusplus
}
#endif