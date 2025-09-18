/*
 * OpenSSL Wrapper Implementation
 * Safe C++ wrapper around OpenSSL functions with RAII management
 */

#include "internal/openssl_wrapper.hpp"
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace ecliptix::openssl {

// Smart pointer type aliases for implementation
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

// Forward declarations
std::string get_error_string(unsigned long error_code);

// ============================================================================
// OpenSSL Error Handling
// ============================================================================

OpenSSLException::OpenSSLException(const std::string& message)
    : std::runtime_error(message) {
    error_code_ = ERR_get_error();
}

OpenSSLException::OpenSSLException(const std::string& operation, unsigned long error_code)
    : std::runtime_error(operation + ": " + get_error_string(error_code))
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

std::string get_error_string(unsigned long error_code) {
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

std::string get_error_string(unsigned long error_code) {
    if (error_code == 0) {
        return "No error";
    }

    char buffer[256];
    ERR_error_string_n(error_code, buffer, sizeof(buffer));
    return std::string(buffer);
}

// ============================================================================
// Library Initialization
// ============================================================================

bool Library::initialized_ = false;

Library::Library() {
    if (initialized_) {
        return;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Initialize random number generator
    if (RAND_poll() != 1) {
        throw OpenSSLException("Failed to initialize random number generator");
    }

    initialized_ = true;
}

Library::~Library() {
    if (initialized_) {
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
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
// Key Generation
// ============================================================================

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ed25519() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    if (!ctx) {
        throw OpenSSLException("Failed to create Ed25519 key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 key generation");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate Ed25519 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    // Extract public key
    size_t public_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(private_key.get(), nullptr, &public_key_len) != 1) {
        throw OpenSSLException("Failed to get Ed25519 public key length");
    }

    std::vector<uint8_t> public_key_raw(public_key_len);
    if (EVP_PKEY_get_raw_public_key(private_key.get(), public_key_raw.data(), &public_key_len) != 1) {
        throw OpenSSLException("Failed to extract Ed25519 public key");
    }

    EVP_PKEY_ptr public_key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key_raw.data(), public_key_len
    ));

    if (!public_key) {
        throw OpenSSLException("Failed to create Ed25519 public key object");
    }

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ecdsa_p384() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx) {
        throw OpenSSLException("Failed to create ECDSA key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize ECDSA key generation");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) != 1) {
        throw OpenSSLException("Failed to set ECDSA curve to P-384");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate ECDSA P-384 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    // Extract public key by serializing and deserializing
    std::vector<uint8_t> public_key_der = serialize_public_key(private_key.get());
    EVP_PKEY_ptr public_key = deserialize_public_key(public_key_der);

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_rsa(int bits) {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        throw OpenSSLException("Failed to create RSA key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize RSA key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) {
        throw OpenSSLException("Failed to set RSA key size");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate RSA key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    // Extract public key
    std::vector<uint8_t> public_key_der = serialize_public_key(private_key.get());
    EVP_PKEY_ptr public_key = deserialize_public_key(public_key_der);

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ecdh_x25519() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx) {
        throw OpenSSLException("Failed to create X25519 key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize X25519 key generation");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate X25519 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    // Extract public key
    size_t public_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(private_key.get(), nullptr, &public_key_len) != 1) {
        throw OpenSSLException("Failed to get X25519 public key length");
    }

    std::vector<uint8_t> public_key_raw(public_key_len);
    if (EVP_PKEY_get_raw_public_key(private_key.get(), public_key_raw.data(), &public_key_len) != 1) {
        throw OpenSSLException("Failed to extract X25519 public key");
    }

    EVP_PKEY_ptr public_key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, public_key_raw.data(), public_key_len
    ));

    if (!public_key) {
        throw OpenSSLException("Failed to create X25519 public key object");
    }

    return {std::move(private_key), std::move(public_key)};
}

std::vector<uint8_t> KeyGenerator::serialize_public_key(EVP_PKEY* key) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    if (i2d_PUBKEY_bio(bio.get(), key) != 1) {
        throw OpenSSLException("Failed to serialize public key");
    }

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer->data),
        reinterpret_cast<const uint8_t*>(buffer->data) + buffer->length
    );
}

std::vector<uint8_t> KeyGenerator::serialize_private_key(EVP_PKEY* key) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    if (i2d_PrivateKey_bio(bio.get(), key) != 1) {
        throw OpenSSLException("Failed to serialize private key");
    }

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer->data),
        reinterpret_cast<const uint8_t*>(buffer->data) + buffer->length
    );
}

EVP_PKEY_ptr KeyGenerator::deserialize_public_key(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    EVP_PKEY* key = d2i_PUBKEY_bio(bio.get(), nullptr);
    if (!key) {
        throw OpenSSLException("Failed to deserialize public key");
    }

    return EVP_PKEY_ptr(key);
}

EVP_PKEY_ptr KeyGenerator::deserialize_private_key(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    EVP_PKEY* key = d2i_PrivateKey_bio(bio.get(), nullptr);
    if (!key) {
        throw OpenSSLException("Failed to deserialize private key");
    }

    return EVP_PKEY_ptr(key);
}

// ============================================================================
// AES-GCM Implementation
// ============================================================================

AES_GCM::EncryptResult AES_GCM::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;

    // Generate random IV
    Random::bytes(result.iv);

    result = encrypt_with_iv(plaintext, key, result.iv, associated_data);
    return result;
}

AES_GCM::EncryptResult AES_GCM::encrypt_with_iv(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;
    std::copy(iv.begin(), iv.end(), result.iv.begin());

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize AES-256-GCM encryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        throw OpenSSLException("Failed to set GCM IV length");
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw OpenSSLException("Failed to set key and IV");
    }

    // Set associated data if provided
    if (!associated_data.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, associated_data.data(),
                             static_cast<int>(associated_data.size())) != 1) {
            throw OpenSSLException("Failed to set associated data");
        }
    }

    // Encrypt
    result.ciphertext.resize(plaintext.size());
    int len;
    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len,
                         plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw OpenSSLException("Failed to encrypt data");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + len, &len) != 1) {
        throw OpenSSLException("Failed to finalize encryption");
    }

    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, result.tag.data()) != 1) {
        throw OpenSSLException("Failed to get authentication tag");
    }

    return result;
}

std::vector<uint8_t> AES_GCM::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t, TAG_SIZE> tag,
    std::span<const uint8_t> associated_data) {

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize AES-256-GCM decryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        throw OpenSSLException("Failed to set GCM IV length");
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw OpenSSLException("Failed to set key and IV");
    }

    // Set associated data if provided
    if (!associated_data.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, associated_data.data(),
                             static_cast<int>(associated_data.size())) != 1) {
            throw OpenSSLException("Failed to set associated data");
        }
    }

    // Decrypt
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw OpenSSLException("Failed to decrypt data");
    }

    int plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                           const_cast<uint8_t*>(tag.data())) != 1) {
        throw OpenSSLException("Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw OpenSSLException("Authentication verification failed");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext;
}

// ============================================================================
// Digital Signatures
// ============================================================================

std::vector<uint8_t> DigitalSignature::sign_ed25519(
    std::span<const uint8_t> message,
    EVP_PKEY* private_key) {

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create signing context");
    }

    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, private_key) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 signing");
    }

    // Get signature length
    size_t signature_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &signature_len, message.data(), message.size()) != 1) {
        throw OpenSSLException("Failed to get Ed25519 signature length");
    }

    // Create signature
    std::vector<uint8_t> signature(signature_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &signature_len,
                      message.data(), message.size()) != 1) {
        throw OpenSSLException("Failed to create Ed25519 signature");
    }

    signature.resize(signature_len);
    return signature;
}

bool DigitalSignature::verify_ed25519(
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature,
    EVP_PKEY* public_key) {

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create verification context");
    }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, public_key) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 verification");
    }

    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                 message.data(), message.size());

    if (result == 1) {
        return true;  // Signature valid
    } else if (result == 0) {
        return false; // Signature invalid
    } else {
        throw OpenSSLException("Ed25519 signature verification failed");
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

Hash::Context::Context(const EVP_MD* algorithm)
    : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) {
        throw OpenSSLException("Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx_.get(), algorithm, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize hash context");
    }
}

void Hash::Context::update(std::span<const uint8_t> data) {
    if (EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) != 1) {
        throw OpenSSLException("Failed to update hash context");
    }
}

std::vector<uint8_t> Hash::Context::finalize() {
    unsigned int digest_len = 0;
    std::vector<uint8_t> digest(EVP_MD_size(EVP_MD_CTX_md(ctx_.get())));

    if (EVP_DigestFinal_ex(ctx_.get(), digest.data(), &digest_len) != 1) {
        throw OpenSSLException("Failed to finalize hash");
    }

    digest.resize(digest_len);
    return digest;
}

// ============================================================================
// Key Derivation
// ============================================================================

std::vector<uint8_t> KeyDerivation::hkdf_sha384(
    std::span<const uint8_t> input_key,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_length) {

    EVP_KDF_CTX_ptr ctx(EVP_KDF_CTX_new(EVP_KDF_fetch(nullptr, "HKDF", nullptr)));
    if (!ctx) {
        throw OpenSSLException("Failed to create HKDF context");
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA384"), 0),
        OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t*>(input_key.data()), input_key.size()),
        OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string("info", const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_CTX_set_params(ctx.get(), params) != 1) {
        throw OpenSSLException("Failed to set HKDF parameters");
    }

    std::vector<uint8_t> output(output_length);
    if (EVP_KDF_derive(ctx.get(), output.data(), output.size(), nullptr) != 1) {
        throw OpenSSLException("HKDF key derivation failed");
    }

    return output;
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

std::string base64_encode(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    BIO_ptr b64(BIO_new(BIO_f_base64()));

    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    bio.reset(BIO_push(b64.release(), bio.release()));

    BIO_write(bio.get(), data.data(), static_cast<int>(data.size()));
    BIO_flush(bio.get());

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::string(buffer->data, buffer->length);
}

} // namespace utils

} // namespace ecliptix::openssl