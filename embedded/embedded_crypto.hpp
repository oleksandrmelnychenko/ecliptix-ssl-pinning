#pragma once

#include <cstdint>

namespace ecliptix::crypto {

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

constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

constexpr size_t CHACHA20_KEY_SIZE = 32;
constexpr size_t CHACHA20_NONCE_SIZE = 12;
constexpr size_t CHACHA20_TAG_SIZE = 16;

constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

constexpr size_t ECDSA_P384_PUBLIC_KEY_SIZE = 97;
constexpr size_t ECDSA_P384_PRIVATE_KEY_SIZE = 48;
constexpr size_t ECDSA_P384_SIGNATURE_SIZE = 96;

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA384_DIGEST_SIZE = 48;
constexpr size_t SHA512_DIGEST_SIZE = 64;

constexpr size_t SSL_PIN_SIZE = SHA384_DIGEST_SIZE;
constexpr size_t SSL_CERT_MAX_SIZE = 8192;
constexpr size_t SSL_CHAIN_MAX_CERTS = 10;

constexpr size_t MAX_PLAINTEXT_SIZE = 1024 * 1024;
constexpr size_t MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 64;
constexpr size_t MAX_SIGNATURE_SIZE = 256;

constexpr EncryptionAlgorithm DEFAULT_ENCRYPTION = EncryptionAlgorithm::AES_256_GCM;
constexpr SignatureAlgorithm DEFAULT_SIGNATURE = SignatureAlgorithm::ED25519;
constexpr HashAlgorithm DEFAULT_HASH = HashAlgorithm::SHA384;

}
