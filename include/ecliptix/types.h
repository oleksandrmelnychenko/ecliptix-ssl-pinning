/*
 * Ecliptix Security Library - C Types Header
 * Type definitions for C API compatibility
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Cryptographic Constants
// ============================================================================

#define ECLIPTIX_CHACHA20_KEY_SIZE 32
#define ECLIPTIX_CHACHA20_NONCE_SIZE 12
#define ECLIPTIX_POLY1305_TAG_SIZE 16
#define ECLIPTIX_ED25519_PUBLIC_KEY_SIZE 32
#define ECLIPTIX_ED25519_PRIVATE_KEY_SIZE 32
#define ECLIPTIX_ED25519_SIGNATURE_SIZE 64
#define ECLIPTIX_BLAKE2B_HASH_SIZE 32
#define ECLIPTIX_SHA384_HASH_SIZE 48
#define ECLIPTIX_SPKI_PIN_SIZE 48
#define ECLIPTIX_AES_256_KEY_SIZE 32
#define ECLIPTIX_AES_GCM_IV_SIZE 12
#define ECLIPTIX_AES_GCM_TAG_SIZE 16

// ============================================================================
// Library Version
// ============================================================================

#define ECLIPTIX_VERSION_MAJOR 1
#define ECLIPTIX_VERSION_MINOR 0
#define ECLIPTIX_VERSION_PATCH 0
#define ECLIPTIX_VERSION_STRING "1.0.0"

#ifdef __cplusplus
}
#endif