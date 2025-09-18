#pragma once

/*
 * Ecliptix Security Library - Main C API
 * Provides SSL pinning, encryption, and digital signature functionality
 */

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Library Initialization and Cleanup
// ============================================================================

/**
 * Initialize the Ecliptix security library
 * Must be called before any other functions
 *
 * @return ECLIPTIX_SUCCESS on success, error code otherwise
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_init(void);

/**
 * Initialize with custom parameters
 *
 * @param log_callback Optional logging callback
 * @param error_callback Optional error handling callback
 * @param user_data User data passed to callbacks
 * @return ECLIPTIX_SUCCESS on success, error code otherwise
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_init_ex(ecliptix_log_callback_t log_callback,
                 ecliptix_error_callback_t error_callback,
                 void* user_data);

/**
 * Cleanup the library and free all resources
 * Should be called before program termination
 */
ECLIPTIX_API void ECLIPTIX_CALL
ecliptix_cleanup(void);

/**
 * Check if the library is initialized
 *
 * @return 1 if initialized, 0 otherwise
 */
ECLIPTIX_API int ECLIPTIX_CALL
ecliptix_is_initialized(void);

/**
 * Get library version information
 *
 * @param version_info Pointer to version info structure to fill
 * @return ECLIPTIX_SUCCESS on success, error code otherwise
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_get_version(ecliptix_version_info_t* version_info);

// ============================================================================
// SSL Certificate Validation and Pinning
// ============================================================================

/**
 * Validate a certificate using SSL pinning
 *
 * @param cert_der Certificate in DER format
 * @param cert_size Size of certificate data
 * @param hostname Hostname to validate against
 * @param validation_flags Validation flags (time, hostname, chain, pin)
 * @return ECLIPTIX_SUCCESS if certificate is valid and pinned
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_validate_certificate(const uint8_t* cert_der,
                              size_t cert_size,
                              const char* hostname,
                              ecliptix_cert_validation_flags_t validation_flags);

/**
 * Validate a certificate chain
 *
 * @param certs Array of certificates in DER format
 * @param cert_sizes Array of certificate sizes
 * @param cert_count Number of certificates in chain
 * @param hostname Hostname to validate against
 * @param validation_flags Validation flags
 * @return ECLIPTIX_SUCCESS if chain is valid
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_validate_certificate_chain(const uint8_t** certs,
                                    const size_t* cert_sizes,
                                    size_t cert_count,
                                    const char* hostname,
                                    ecliptix_cert_validation_flags_t validation_flags);

/**
 * Extract certificate information
 *
 * @param cert_der Certificate in DER format
 * @param cert_size Size of certificate data
 * @param cert_info Pointer to structure to fill with certificate info
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_get_certificate_info(const uint8_t* cert_der,
                              size_t cert_size,
                              ecliptix_cert_info_t* cert_info);

/**
 * Check if a certificate matches any of the pinned public keys
 *
 * @param cert_der Certificate in DER format
 * @param cert_size Size of certificate data
 * @param pin_mode Pinning mode (strict, backup, allow_new)
 * @return ECLIPTIX_SUCCESS if certificate is pinned
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_check_certificate_pin(const uint8_t* cert_der,
                               size_t cert_size,
                               ecliptix_pin_mode_t pin_mode);

/**
 * Add a new backup pin (for key rotation)
 *
 * @param pin_sha384 SHA-384 hash of the public key
 * @param pin_index Index of backup pin to replace (0-2)
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_add_backup_pin(const uint8_t pin_sha384[48],
                        uint32_t pin_index);

// ============================================================================
// Symmetric Encryption
// ============================================================================

/**
 * Encrypt data using AES-256-GCM
 *
 * @param plaintext Data to encrypt
 * @param plaintext_size Size of plaintext
 * @param key Encryption key (32 bytes for AES-256)
 * @param key_size Size of encryption key
 * @param ciphertext Buffer for encrypted data
 * @param ciphertext_size Pointer to ciphertext buffer size (in/out)
 * @param nonce Buffer for nonce/IV (12 bytes)
 * @param tag Buffer for authentication tag (16 bytes)
 * @param associated_data Optional associated data for authentication
 * @param associated_data_size Size of associated data
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_encrypt_aes_gcm(const uint8_t* plaintext,
                         size_t plaintext_size,
                         const uint8_t* key,
                         size_t key_size,
                         uint8_t* ciphertext,
                         size_t* ciphertext_size,
                         uint8_t nonce[ECLIPTIX_AES_GCM_IV_SIZE],
                         uint8_t tag[ECLIPTIX_AES_GCM_TAG_SIZE],
                         const uint8_t* associated_data,
                         size_t associated_data_size);

/**
 * Decrypt data using AES-256-GCM
 *
 * @param ciphertext Encrypted data
 * @param ciphertext_size Size of ciphertext
 * @param key Decryption key
 * @param key_size Size of decryption key
 * @param nonce Nonce/IV used for encryption
 * @param tag Authentication tag
 * @param plaintext Buffer for decrypted data
 * @param plaintext_size Pointer to plaintext buffer size (in/out)
 * @param associated_data Associated data for authentication
 * @param associated_data_size Size of associated data
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_decrypt_aes_gcm(const uint8_t* ciphertext,
                         size_t ciphertext_size,
                         const uint8_t* key,
                         size_t key_size,
                         const uint8_t nonce[ECLIPTIX_AES_GCM_IV_SIZE],
                         const uint8_t tag[ECLIPTIX_AES_GCM_TAG_SIZE],
                         uint8_t* plaintext,
                         size_t* plaintext_size,
                         const uint8_t* associated_data,
                         size_t associated_data_size);

/**
 * Encrypt data using ChaCha20-Poly1305
 *
 * @param plaintext Data to encrypt
 * @param plaintext_size Size of plaintext
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param ciphertext Buffer for encrypted data
 * @param ciphertext_size Pointer to ciphertext buffer size (in/out)
 * @param tag Buffer for authentication tag (16 bytes)
 * @param associated_data Optional associated data
 * @param associated_data_size Size of associated data
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_encrypt_chacha20_poly1305(const uint8_t* plaintext,
                                   size_t plaintext_size,
                                   const uint8_t key[ECLIPTIX_CHACHA20_KEY_SIZE],
                                   const uint8_t nonce[ECLIPTIX_CHACHA20_NONCE_SIZE],
                                   uint8_t* ciphertext,
                                   size_t* ciphertext_size,
                                   uint8_t tag[ECLIPTIX_CHACHA20_TAG_SIZE],
                                   const uint8_t* associated_data,
                                   size_t associated_data_size);

/**
 * Decrypt data using ChaCha20-Poly1305
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_decrypt_chacha20_poly1305(const uint8_t* ciphertext,
                                   size_t ciphertext_size,
                                   const uint8_t key[ECLIPTIX_CHACHA20_KEY_SIZE],
                                   const uint8_t nonce[ECLIPTIX_CHACHA20_NONCE_SIZE],
                                   const uint8_t tag[ECLIPTIX_CHACHA20_TAG_SIZE],
                                   uint8_t* plaintext,
                                   size_t* plaintext_size,
                                   const uint8_t* associated_data,
                                   size_t associated_data_size);

// ============================================================================
// Digital Signatures
// ============================================================================

/**
 * Sign data using Ed25519
 *
 * @param message Data to sign
 * @param message_size Size of message
 * @param signature Buffer for signature (64 bytes)
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_sign_ed25519(const uint8_t* message,
                      size_t message_size,
                      uint8_t signature[ECLIPTIX_ED25519_SIGNATURE_SIZE]);

/**
 * Verify Ed25519 signature
 *
 * @param message Original message
 * @param message_size Size of message
 * @param signature Signature to verify
 * @param public_key Public key for verification (optional, uses embedded if NULL)
 * @return ECLIPTIX_SUCCESS if signature is valid
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_verify_ed25519(const uint8_t* message,
                        size_t message_size,
                        const uint8_t signature[ECLIPTIX_ED25519_SIGNATURE_SIZE],
                        const uint8_t* public_key);

/**
 * Sign data using ECDSA P-384
 *
 * @param message Data to sign
 * @param message_size Size of message
 * @param signature Buffer for signature
 * @param signature_size Pointer to signature buffer size (in/out)
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_sign_ecdsa_p384(const uint8_t* message,
                         size_t message_size,
                         uint8_t* signature,
                         size_t* signature_size);

/**
 * Verify ECDSA P-384 signature
 *
 * @param message Original message
 * @param message_size Size of message
 * @param signature Signature to verify
 * @param signature_size Size of signature
 * @param public_key Public key for verification
 * @return ECLIPTIX_SUCCESS if signature is valid
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_verify_ecdsa_p384(const uint8_t* message,
                           size_t message_size,
                           const uint8_t* signature,
                           size_t signature_size,
                           const uint8_t* public_key);

// ============================================================================
// Key Management
// ============================================================================

/**
 * Generate random bytes using secure random number generator
 *
 * @param buffer Buffer to fill with random data
 * @param size Number of random bytes to generate
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_random_bytes(uint8_t* buffer, size_t size);

/**
 * Derive key using HKDF-SHA384
 *
 * @param input_key Input key material
 * @param input_key_size Size of input key
 * @param salt Optional salt (can be NULL)
 * @param salt_size Size of salt
 * @param info Optional context info
 * @param info_size Size of info
 * @param output_key Buffer for derived key
 * @param output_key_size Desired output key size
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_derive_key_hkdf(const uint8_t* input_key,
                         size_t input_key_size,
                         const uint8_t* salt,
                         size_t salt_size,
                         const uint8_t* info,
                         size_t info_size,
                         uint8_t* output_key,
                         size_t output_key_size);

/**
 * Secure memory allocation
 *
 * @param size Size of memory to allocate
 * @param protection Memory protection level
 * @return Pointer to allocated memory, NULL on failure
 */
ECLIPTIX_API void* ECLIPTIX_CALL
ecliptix_secure_alloc(size_t size, ecliptix_memory_protection_t protection);

/**
 * Secure memory deallocation with automatic wiping
 *
 * @param ptr Pointer to memory to free
 * @param size Size of memory block
 */
ECLIPTIX_API void ECLIPTIX_CALL
ecliptix_secure_free(void* ptr, size_t size);

/**
 * Secure memory wipe
 *
 * @param ptr Pointer to memory to wipe
 * @param size Size of memory to wipe
 */
ECLIPTIX_API void ECLIPTIX_CALL
ecliptix_secure_wipe(void* ptr, size_t size);

// ============================================================================
// Session Management
// ============================================================================

/**
 * Create a new session context
 *
 * @param params Session parameters
 * @param session Pointer to session handle (output)
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_session_create(const ecliptix_session_params_t* params,
                        ecliptix_session_t** session);

/**
 * Destroy a session and free resources
 *
 * @param session Session handle to destroy
 */
ECLIPTIX_API void ECLIPTIX_CALL
ecliptix_session_destroy(ecliptix_session_t* session);

/**
 * Set session timeout
 *
 * @param session Session handle
 * @param timeout_seconds Timeout in seconds
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_session_set_timeout(ecliptix_session_t* session,
                             uint32_t timeout_seconds);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get the last error message
 *
 * @return Pointer to error message string
 */
ECLIPTIX_API const char* ECLIPTIX_CALL
ecliptix_get_error_message(void);

/**
 * Get performance metrics
 *
 * @param metrics Pointer to metrics structure to fill
 * @return ECLIPTIX_SUCCESS on success
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_get_metrics(ecliptix_metrics_t* metrics);

/**
 * Reset performance metrics
 */
ECLIPTIX_API void ECLIPTIX_CALL
ecliptix_reset_metrics(void);

/**
 * Self-test the library integrity
 *
 * @return ECLIPTIX_SUCCESS if all tests pass
 */
ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL
ecliptix_self_test(void);

/**
 * Convert result code to human-readable string
 *
 * @param result Result code
 * @return Pointer to string description
 */
ECLIPTIX_API const char* ECLIPTIX_CALL
ecliptix_result_to_string(ecliptix_result_t result);

#ifdef __cplusplus
}
#endif