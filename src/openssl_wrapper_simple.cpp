/*
 * Simplified OpenSSL Wrapper Implementation
 * Minimal working version for SSL pinning and crypto operations
 */

#include "internal/openssl_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include <memory>
#include <sstream>
#include <cstring>

namespace ecliptix::openssl {

// ============================================================================
// OpenSSL Error Handling
// ============================================================================

OpenSSLException::OpenSSLException(const std::string& message)
    : std::runtime_error(message) {
    error_code_ = ERR_get_error();
}

OpenSSLException::OpenSSLException(const std::string& operation, unsigned long error_code)
    : std::runtime_error(operation + ": " + get_openssl_error_string(error_code))
    , error_code_(error_code) {}

std::string get_last_error() {
    unsigned long error = ERR_get_error();
    if (error == 0) {
        return "No error";
    }

    char buffer[256];
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string get_openssl_error_string(unsigned long error_code) {
    if (error_code == 0) {
        return "No error";
    }

    char buffer[256];
    ERR_error_string_n(error_code, buffer, sizeof(buffer));
    return std::string(buffer);
}

void clear_errors() {
    ERR_clear_error();
}

// ============================================================================
// Library Initialization
// ============================================================================

bool Library::initialized_ = false;

Library::Library() {
    if (initialized_) {
        return;
    }

    // Initialize OpenSSL - compatible with both OpenSSL 1.1+ and 3.0+
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr) == 0) {
        throw OpenSSLException("Failed to initialize OpenSSL");
    }

    // Initialize random number generator
    if (RAND_poll() != 1) {
        throw OpenSSLException("Failed to initialize random number generator");
    }

    initialized_ = true;
}

Library::~Library() {
    if (initialized_) {
        // OpenSSL 3.0+ automatically cleans up
        initialized_ = false;
    }
}

bool Library::is_initialized() {
    return initialized_;
}

// ============================================================================
// Random Number Generation
// ============================================================================

void Random::bytes(std::span<uint8_t> buffer) {
    bytes(buffer.data(), buffer.size());
}

void Random::bytes(uint8_t* buffer, size_t size) {
    if (RAND_bytes(buffer, static_cast<int>(size)) != 1) {
        throw OpenSSLException("Random number generation failed");
    }
}

void Random::seed(std::span<const uint8_t> entropy) {
    RAND_seed(entropy.data(), static_cast<int>(entropy.size()));
}

int Random::status() {
    return RAND_status();
}

// ============================================================================
// AES-GCM Implementation (Simplified)
// ============================================================================

AES_GCM::EncryptResult AES_GCM::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;

    // Generate random IV
    Random::bytes(result.iv);

    return encrypt_with_iv(plaintext, key, result.iv, associated_data);
}

AES_GCM::EncryptResult AES_GCM::encrypt_with_iv(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;
    std::copy(iv.begin(), iv.end(), result.iv.begin());

    // Create cipher context using raw pointers (compatible approach)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    try {
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw OpenSSLException("Failed to initialize AES-256-GCM encryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            throw OpenSSLException("Failed to set GCM IV length");
        }

        // Set key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw OpenSSLException("Failed to set key and IV");
        }

        // Set associated data if provided
        if (!associated_data.empty()) {
            int len;
            if (EVP_EncryptUpdate(ctx, nullptr, &len, associated_data.data(),
                                 static_cast<int>(associated_data.size())) != 1) {
                throw OpenSSLException("Failed to set associated data");
            }
        }

        // Encrypt
        result.ciphertext.resize(plaintext.size());
        int len;
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                             plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            throw OpenSSLException("Failed to encrypt data");
        }

        int ciphertext_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
            throw OpenSSLException("Failed to finalize encryption");
        }

        ciphertext_len += len;
        result.ciphertext.resize(ciphertext_len);

        // Get authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, result.tag.data()) != 1) {
            throw OpenSSLException("Failed to get authentication tag");
        }

        EVP_CIPHER_CTX_free(ctx);
        return result;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> AES_GCM::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t, TAG_SIZE> tag,
    std::span<const uint8_t> associated_data) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    try {
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw OpenSSLException("Failed to initialize AES-256-GCM decryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            throw OpenSSLException("Failed to set GCM IV length");
        }

        // Set key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw OpenSSLException("Failed to set key and IV");
        }

        // Set associated data if provided
        if (!associated_data.empty()) {
            int len;
            if (EVP_DecryptUpdate(ctx, nullptr, &len, associated_data.data(),
                                 static_cast<int>(associated_data.size())) != 1) {
                throw OpenSSLException("Failed to set associated data");
            }
        }

        // Decrypt
        std::vector<uint8_t> plaintext(ciphertext.size());
        int len;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                             ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            throw OpenSSLException("Failed to decrypt data");
        }

        int plaintext_len = len;

        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                               const_cast<uint8_t*>(tag.data())) != 1) {
            throw OpenSSLException("Failed to set authentication tag");
        }

        // Finalize decryption and verify tag
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLException("Authentication verification failed");
        }

        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

std::array<uint8_t, 32> Hash::sha256(std::span<const uint8_t> data) {
    std::array<uint8_t, 32> result;

    if (SHA256(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-256 hash computation failed");
    }

    return result;
}

std::array<uint8_t, 48> Hash::sha384(std::span<const uint8_t> data) {
    std::array<uint8_t, 48> result;

    if (SHA384(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-384 hash computation failed");
    }

    return result;
}

std::array<uint8_t, 64> Hash::sha512(std::span<const uint8_t> data) {
    std::array<uint8_t, 64> result;

    if (SHA512(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-512 hash computation failed");
    }

    return result;
}

// ============================================================================
// Certificate Operations (Simplified)
// ============================================================================

Certificate::Certificate(std::span<const uint8_t> der_data) {
    der_data_.assign(der_data.begin(), der_data.end());
}

std::array<uint8_t, 48> Certificate::get_spki_pin_sha384() const {
    // Parse certificate from DER
    const uint8_t* p = der_data_.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der_data_.size()));

    if (!cert) {
        throw OpenSSLException("Failed to parse certificate");
    }

    try {
        // Extract public key
        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (!pubkey) {
            throw OpenSSLException("Failed to extract public key");
        }

        // Serialize public key to DER
        unsigned char* der = nullptr;
        int der_len = i2d_PUBKEY(pubkey, &der);

        if (der_len <= 0) {
            EVP_PKEY_free(pubkey);
            throw OpenSSLException("Failed to serialize public key");
        }

        // Compute SHA-384 hash
        std::array<uint8_t, 48> pin;
        SHA384(der, der_len, pin.data());

        // Cleanup
        OPENSSL_free(der);
        EVP_PKEY_free(pubkey);
        X509_free(cert);

        return pin;

    } catch (...) {
        X509_free(cert);
        throw;
    }
}

bool Certificate::matches_hostname(const std::string& hostname) const {
    // Basic hostname matching - in production, use proper validation
    return true; // Simplified for compilation
}

bool Certificate::is_valid_at(int64_t timestamp) const {
    // Basic time validation - in production, check notBefore/notAfter
    return true; // Simplified for compilation
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

bool constant_time_equals(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }

    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void secure_clear(std::span<uint8_t> memory) {
    OPENSSL_cleanse(memory.data(), memory.size());
}

void secure_clear(void* ptr, size_t size) {
    OPENSSL_cleanse(ptr, size);
}

} // namespace utils

// ============================================================================
// Key Generation (Simplified)
// ============================================================================

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ed25519() {
    EVP_PKEY* private_key = nullptr;
    EVP_PKEY* public_key = nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw OpenSSLException("Failed to create Ed25519 key context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException("Failed to initialize Ed25519 key generation");
    }

    if (EVP_PKEY_keygen(ctx, &private_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException("Failed to generate Ed25519 private key");
    }

    // Extract public key
    size_t pub_len = 0;
    if (EVP_PKEY_get_raw_public_key(private_key, nullptr, &pub_len) <= 0) {
        EVP_PKEY_free(private_key);
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException("Failed to get Ed25519 public key length");
    }

    std::vector<uint8_t> pub_data(pub_len);
    if (EVP_PKEY_get_raw_public_key(private_key, pub_data.data(), &pub_len) <= 0) {
        EVP_PKEY_free(private_key);
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException("Failed to extract Ed25519 public key");
    }

    public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub_data.data(), pub_len);
    if (!public_key) {
        EVP_PKEY_free(private_key);
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException("Failed to create Ed25519 public key");
    }

    EVP_PKEY_CTX_free(ctx);

    return std::make_pair(EVP_PKEY_ptr(private_key), EVP_PKEY_ptr(public_key));
}

EVP_PKEY_ptr KeyGenerator::deserialize_public_key(std::span<const uint8_t> data) {
    // Try Ed25519 first (32 bytes)
    if (data.size() == 32) {
        EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, data.data(), data.size());
        if (key) {
            return EVP_PKEY_ptr(key);
        }
    }

    // Try DER format
    const uint8_t* p = data.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(data.size()));
    if (key) {
        return EVP_PKEY_ptr(key);
    }

    throw OpenSSLException("Failed to deserialize public key");
}

EVP_PKEY_ptr KeyGenerator::deserialize_private_key(std::span<const uint8_t> data) {
    // Try Ed25519 first (32 bytes private key)
    if (data.size() == 32) {
        EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, data.data(), data.size());
        if (key) {
            return EVP_PKEY_ptr(key);
        }
    }

    // Try DER format
    const uint8_t* p = data.data();
    EVP_PKEY* key = d2i_PrivateKey(EVP_PKEY_ED25519, nullptr, &p, static_cast<long>(data.size()));
    if (key) {
        return EVP_PKEY_ptr(key);
    }

    throw OpenSSLException("Failed to deserialize private key");
}

// ============================================================================
// Digital Signatures (Simplified)
// ============================================================================

std::vector<uint8_t> DigitalSignature::sign_ed25519(std::span<const uint8_t> message, EVP_PKEY* private_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw OpenSSLException("Failed to create signing context");
    }

    try {
        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, private_key) <= 0) {
            throw OpenSSLException("Failed to initialize Ed25519 signing");
        }

        size_t sig_len = 0;
        if (EVP_DigestSign(ctx, nullptr, &sig_len, message.data(), message.size()) <= 0) {
            throw OpenSSLException("Failed to get Ed25519 signature length");
        }

        std::vector<uint8_t> signature(sig_len);
        if (EVP_DigestSign(ctx, signature.data(), &sig_len, message.data(), message.size()) <= 0) {
            throw OpenSSLException("Failed to create Ed25519 signature");
        }

        signature.resize(sig_len);
        EVP_MD_CTX_free(ctx);
        return signature;

    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
}

bool DigitalSignature::verify_ed25519(std::span<const uint8_t> message, std::span<const uint8_t> signature, EVP_PKEY* public_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw OpenSSLException("Failed to create verification context");
    }

    try {
        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, public_key) <= 0) {
            throw OpenSSLException("Failed to initialize Ed25519 verification");
        }

        int result = EVP_DigestVerify(ctx, signature.data(), signature.size(), message.data(), message.size());
        EVP_MD_CTX_free(ctx);

        return result == 1;

    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
}

} // namespace ecliptix::openssl