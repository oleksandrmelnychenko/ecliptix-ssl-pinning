#pragma once
/*
 * Ecliptix Cryptographic Constants
 * Auto-generated cryptographic definitions
 */

#include <cstdint>

namespace ecliptix::crypto {

// Algorithm identifiers
enum class EncryptionAlgorithm : uint8_t {
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2,
    XCHACHA20_POLY1305 = 3
};

enum class SignatureAlgorithm : uint8_t {
    ED25519 = 1,
    ECDSA_P384 = 2,
    RSA_PSS_4096 = 3
};

enum class HashAlgorithm : uint8_t {
    SHA256 = 1,
    SHA384 = 2,
    SHA512 = 3,
    BLAKE3 = 4
};

// Key sizes (in bytes)
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

constexpr size_t CHACHA20_KEY_SIZE = 32;
constexpr size_t CHACHA20_NONCE_SIZE = 12;
constexpr size_t CHACHA20_TAG_SIZE = 16;

constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

constexpr size_t ECDSA_P384_PUBLIC_KEY_SIZE = 97;  // Uncompressed
constexpr size_t ECDSA_P384_PRIVATE_KEY_SIZE = 48;
constexpr size_t ECDSA_P384_SIGNATURE_SIZE = 96;   // r + s

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA384_DIGEST_SIZE = 48;
constexpr size_t SHA512_DIGEST_SIZE = 64;

// SSL/TLS constants
constexpr size_t SSL_PIN_SIZE = SHA384_DIGEST_SIZE;
constexpr size_t SSL_CERT_MAX_SIZE = 8192;
constexpr size_t SSL_CHAIN_MAX_CERTS = 10;

// Security limits
constexpr size_t MAX_PLAINTEXT_SIZE = 1024 * 1024;  // 1MB
constexpr size_t MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 64;  // + overhead
constexpr size_t MAX_SIGNATURE_SIZE = 256;

// Default algorithms for new operations
constexpr EncryptionAlgorithm DEFAULT_ENCRYPTION = EncryptionAlgorithm::AES_256_GCM;
constexpr SignatureAlgorithm DEFAULT_SIGNATURE = SignatureAlgorithm::ED25519;
constexpr HashAlgorithm DEFAULT_HASH = HashAlgorithm::SHA384;

} // namespace ecliptix::crypto
