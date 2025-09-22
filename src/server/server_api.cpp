#include "ecliptix_server.h"
#include "ecliptix/core/secure_memory.hpp"
#include "internal/cryptographic_provider.hpp"
#include "internal/sodium_wrapper.hpp"

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <cstring>
#include <chrono>

#include <sodium.h>

namespace {

std::atomic<bool> g_server_initialized{false};
std::unique_ptr<ecliptix::openssl::Library> g_openssl_lib;
std::mutex g_server_init_mutex;

thread_local std::string g_server_last_error;

void set_server_error(ecliptix_result_t code, const std::string& message) {
    g_server_last_error = "[" + std::to_string(static_cast<int>(code)) + "] " + message;
}

[[nodiscard]] ecliptix_result_t handle_server_exception(const std::exception& e, const char* operation) {
    std::string message = std::string(operation) + ": " + e.what();

    if (dynamic_cast<const ecliptix::openssl::OpenSSLException*>(&e)) {
        set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, message);
        return ECLIPTIX_ERR_CRYPTO_FAILURE;
    }

    set_server_error(ECLIPTIX_ERR_UNKNOWN, message);
    return ECLIPTIX_ERR_UNKNOWN;
}

class PKeyContext {
public:
    explicit PKeyContext(EVP_PKEY* key)
        : ctx_(EVP_PKEY_CTX_new(key, nullptr)) {
        if (!ctx_) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        }
    }

    ~PKeyContext() {
        if (ctx_) {
            EVP_PKEY_CTX_free(ctx_);
        }
    }

    PKeyContext(const PKeyContext&) = delete;
    PKeyContext& operator=(const PKeyContext&) = delete;

    PKeyContext(PKeyContext&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    PKeyContext& operator=(PKeyContext&& other) noexcept {
        if (this != &other) {
            if (ctx_) {
                EVP_PKEY_CTX_free(ctx_);
            }
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] EVP_PKEY_CTX* get() const noexcept { return ctx_; }
    [[nodiscard]] operator EVP_PKEY_CTX*() const noexcept { return ctx_; }

private:
    EVP_PKEY_CTX* ctx_;
};

}

extern "C" {

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_init(void) {
    std::lock_guard<std::mutex> lock(g_server_init_mutex);

    if (g_server_initialized.load()) {
        return ECLIPTIX_SUCCESS;
    }

    try {
        g_openssl_lib = std::make_unique<ecliptix::openssl::Library>();

        if (sodium_init() < 0) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Failed to initialize libsodium");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        g_server_initialized.store(true);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Server library initialization");
    }
}

ECLIPTIX_SERVER_API void ECLIPTIX_CALL ecliptix_server_cleanup(void) {
    std::lock_guard<std::mutex> lock(g_server_init_mutex);

    if (!g_server_initialized.load()) {
        return;
    }

    g_openssl_lib.reset();
    g_server_initialized.store(false);
}

ECLIPTIX_SERVER_API const char* ECLIPTIX_CALL ecliptix_server_get_error_message(void) {
    return g_server_last_error.c_str();
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* private_key,
    uint8_t* signature_out) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !private_key || !signature_out) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid Ed25519 signing parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        if (crypto_sign_detached(signature_out, nullptr, message, message_size, private_key) != 0) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Ed25519 signing failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Ed25519 signing");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* private_key_pem,
    size_t private_key_size,
    uint8_t* plaintext,
    size_t* plaintext_size) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!ciphertext || ciphertext_size == 0 || !private_key_pem || private_key_size == 0 ||
        !plaintext || !plaintext_size) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA decryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto private_key = ecliptix::openssl::KeyGenerator::deserialize_private_key(
            std::span<const uint8_t>(private_key_pem, private_key_size)
        );

        PKeyContext ctx(private_key.get());

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            throw std::runtime_error("Failed to initialize RSA decryption");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("Failed to set RSA OAEP padding");
        }

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext, ciphertext_size) <= 0) {
            throw std::runtime_error("Failed to determine RSA output size");
        }

        ecliptix::core::memory::SecureVector<uint8_t> decrypted(outlen);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, ciphertext, ciphertext_size) <= 0) {
            set_server_error(ECLIPTIX_ERR_DECRYPTION_FAILED, "RSA decryption failed");
            return ECLIPTIX_ERR_DECRYPTION_FAILED;
        }

        decrypted.resize(outlen);

        if (decrypted.size() > *plaintext_size) {
            set_server_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(decrypted.begin(), decrypted.end(), plaintext);
        *plaintext_size = decrypted.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "RSA decryption");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_generate_ed25519_keypair(
    uint8_t* public_key_out,
    uint8_t* private_key_out) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!public_key_out || !private_key_out) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid Ed25519 key generation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        if (crypto_sign_keypair(public_key_out, private_key_out) != 0) {
            set_server_error(ECLIPTIX_ERR_KEY_GENERATION_FAILED, "Ed25519 key generation failed");
            return ECLIPTIX_ERR_KEY_GENERATION_FAILED;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Ed25519 key generation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_generate_rsa_keypair(
    uint8_t* public_key_pem,
    size_t* public_key_size,
    uint8_t* private_key_pem,
    size_t* private_key_size,
    int key_bits) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!public_key_pem || !public_key_size || !private_key_pem || !private_key_size) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA key generation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (key_bits < 2048 || key_bits > 4096) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA key size (must be 2048-4096 bits)");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto keypair = ecliptix::openssl::KeyGenerator::generate_rsa(key_bits);

        auto public_pem = ecliptix::openssl::KeyGenerator::serialize_public_key(keypair.first.get());
        auto private_pem = ecliptix::openssl::KeyGenerator::serialize_private_key(keypair.second.get());

        if (public_pem.size() > *public_key_size || private_pem.size() > *private_key_size) {
            *public_key_size = public_pem.size();
            *private_key_size = private_pem.size();
            set_server_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Key buffers too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(public_pem.begin(), public_pem.end(), public_key_pem);
        std::copy(private_pem.begin(), private_pem.end(), private_key_pem);

        *public_key_size = public_pem.size();
        *private_key_size = private_pem.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "RSA key generation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_derive_key_argon2id(
    const uint8_t* password,
    size_t password_size,
    const uint8_t* salt,
    size_t salt_size,
    uint32_t memory_kb,
    uint32_t iterations,
    uint8_t* derived_key,
    size_t key_size) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!password || password_size == 0 || !salt || salt_size < 16 ||
        !derived_key || key_size == 0) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid Argon2id parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (memory_kb < 1024 || iterations < 1) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Insufficient Argon2id security parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        if (crypto_pwhash(derived_key, key_size,
                         reinterpret_cast<const char*>(password), password_size,
                         salt, iterations, memory_kb * 1024,
                         crypto_pwhash_ALG_DEFAULT) != 0) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Argon2id key derivation failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Argon2id key derivation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_encrypt_chacha20_poly1305(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* key,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!plaintext || plaintext_size == 0 || !key || !ciphertext || !ciphertext_size) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid ChaCha20-Poly1305 encryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    size_t required_size = plaintext_size + crypto_aead_chacha20poly1305_ABYTES + crypto_aead_chacha20poly1305_NPUBBYTES;
    if (*ciphertext_size < required_size) {
        *ciphertext_size = required_size;
        set_server_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    try {
        uint8_t* nonce = ciphertext;
        uint8_t* encrypted_data = ciphertext + crypto_aead_chacha20poly1305_NPUBBYTES;

        randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

        unsigned long long encrypted_len;
        if (crypto_aead_chacha20poly1305_encrypt(
                encrypted_data, &encrypted_len,
                plaintext, plaintext_size,
                additional_data, additional_data_size,
                nullptr, nonce, key) != 0) {
            set_server_error(ECLIPTIX_ERR_ENCRYPTION_FAILED, "ChaCha20-Poly1305 encryption failed");
            return ECLIPTIX_ERR_ENCRYPTION_FAILED;
        }

        *ciphertext_size = crypto_aead_chacha20poly1305_NPUBBYTES + encrypted_len;
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "ChaCha20-Poly1305 encryption");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_decrypt_chacha20_poly1305(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* key,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t* plaintext,
    size_t* plaintext_size) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!ciphertext || ciphertext_size <= crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES ||
        !key || !plaintext || !plaintext_size) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid ChaCha20-Poly1305 decryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        const uint8_t* nonce = ciphertext;
        const uint8_t* encrypted_data = ciphertext + crypto_aead_chacha20poly1305_NPUBBYTES;
        size_t encrypted_len = ciphertext_size - crypto_aead_chacha20poly1305_NPUBBYTES;

        unsigned long long decrypted_len;
        if (crypto_aead_chacha20poly1305_decrypt(
                plaintext, &decrypted_len,
                nullptr,
                encrypted_data, encrypted_len,
                additional_data, additional_data_size,
                nonce, key) != 0) {
            set_server_error(ECLIPTIX_ERR_DECRYPTION_FAILED, "ChaCha20-Poly1305 decryption failed");
            return ECLIPTIX_ERR_DECRYPTION_FAILED;
        }

        if (decrypted_len > *plaintext_size) {
            *plaintext_size = decrypted_len;
            set_server_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Plaintext buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        *plaintext_size = decrypted_len;
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "ChaCha20-Poly1305 decryption");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_create_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_t* pin_out) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0 || !pin_out) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid pin creation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der, cert_size)
        );

        auto pin_sha384 = cert.get_spki_pin_sha384();
        std::copy(pin_sha384.begin(), pin_sha384.end(), pin_out->hash);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Certificate pin creation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_create_pin_config(
    const char* hostname,
    const uint8_t* primary_cert_der,
    size_t primary_cert_size,
    const uint8_t** backup_certs_der,
    const size_t* backup_cert_sizes,
    uint8_t backup_count,
    ecliptix_pin_config_t* config_out) {

    if (!hostname || !primary_cert_der || primary_cert_size == 0 || !config_out) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid pin config creation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (backup_count > 3) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Too many backup certificates");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (strlen(hostname) >= ECLIPTIX_MAX_HOSTNAME_SIZE) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Hostname too long");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        strncpy(config_out->hostname, hostname, ECLIPTIX_MAX_HOSTNAME_SIZE - 1);
        config_out->hostname[ECLIPTIX_MAX_HOSTNAME_SIZE - 1] = '\0';

        auto result = ecliptix_server_create_certificate_pin(
            primary_cert_der, primary_cert_size, &config_out->primary_pin);
        if (result != ECLIPTIX_SUCCESS) {
            return result;
        }

        config_out->backup_pin_count = backup_count;
        for (uint8_t i = 0; i < backup_count; ++i) {
            if (!backup_certs_der[i] || backup_cert_sizes[i] == 0) {
                set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid backup certificate");
                return ECLIPTIX_ERR_INVALID_PARAM;
            }

            result = ecliptix_server_create_certificate_pin(
                backup_certs_der[i], backup_cert_sizes[i], &config_out->backup_pins[i]);
            if (result != ECLIPTIX_SUCCESS) {
                return result;
            }
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Pin config creation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_hash_blake2b(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_size,
    uint8_t* hash_out,
    size_t hash_size) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!data || data_size == 0 || !hash_out || hash_size == 0) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid Blake2b parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (hash_size > crypto_generichash_BYTES_MAX) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Blake2b hash size too large");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        if (crypto_generichash(hash_out, hash_size, data, data_size, key, key_size) != 0) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Blake2b hashing failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Blake2b hashing");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_secure_malloc(
    void** ptr,
    size_t size) {

    if (!ptr || size == 0) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid secure malloc parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        *ptr = sodium_malloc(size);
        if (!*ptr) {
            set_server_error(ECLIPTIX_ERR_MEMORY_ALLOCATION, "Secure memory allocation failed");
            return ECLIPTIX_ERR_MEMORY_ALLOCATION;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Secure memory allocation");
    }
}

ECLIPTIX_SERVER_API void ECLIPTIX_CALL ecliptix_server_secure_free(
    void* ptr,
    size_t size) {

    if (ptr) {
        sodium_munlock(ptr, size);
        sodium_free(ptr);
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_constant_time_compare(
    const uint8_t* a,
    const uint8_t* b,
    size_t size,
    int* result) {

    if (!a || !b || size == 0 || !result) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid constant-time comparison parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    *result = (sodium_memcmp(a, b, size) == 0) ? 1 : 0;
    return ECLIPTIX_SUCCESS;
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_validate_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    const ecliptix_pin_t* expected_pin) {

    if (!g_server_initialized.load()) {
        set_server_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0 || !hostname || !expected_pin) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid certificate pin validation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der, cert_size)
        );

        auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (!cert.is_valid_at(current_time)) {
            set_server_error(ECLIPTIX_ERR_CERTIFICATE_INVALID, "Certificate is not valid at current time");
            return ECLIPTIX_ERR_CERTIFICATE_INVALID;
        }

        if (!cert.matches_hostname(std::string(hostname))) {
            set_server_error(ECLIPTIX_ERR_CERTIFICATE_INVALID, "Certificate hostname verification failed");
            return ECLIPTIX_ERR_CERTIFICATE_INVALID;
        }

        auto actual_pin = cert.get_spki_pin_sha384();

        if (actual_pin.empty() || actual_pin.size() != ECLIPTIX_SHA384_HASH_SIZE) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Invalid SHA-384 hash size from certificate");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        if (sizeof(expected_pin->hash) != ECLIPTIX_SHA384_HASH_SIZE) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Expected pin hash size mismatch");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        int pin_comparison_result;
        ecliptix_result_t compare_result = ecliptix_server_constant_time_compare(
            actual_pin.data(), expected_pin->hash, ECLIPTIX_SHA384_HASH_SIZE, &pin_comparison_result);

        if (compare_result != ECLIPTIX_SUCCESS) {
            set_server_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Pin comparison failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        if (pin_comparison_result != 1) {
            set_server_error(ECLIPTIX_ERR_PIN_VERIFICATION_FAILED, "Certificate pin validation failed");
            return ECLIPTIX_ERR_PIN_VERIFICATION_FAILED;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_server_exception(e, "Certificate pin validation");
    }
}

ECLIPTIX_SERVER_API ecliptix_result_t ECLIPTIX_CALL ecliptix_server_get_library_version(
    char* version_buffer,
    size_t buffer_size) {

    if (!version_buffer || buffer_size == 0) {
        set_server_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid version buffer parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    const char* version = "1.0.0-server";
    size_t version_len = strlen(version);

    if (buffer_size <= version_len) {
        set_server_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Version buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    strcpy(version_buffer, version);
    return ECLIPTIX_SUCCESS;
}

}