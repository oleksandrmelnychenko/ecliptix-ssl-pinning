#include "ecliptix_client.h"
#include "ecliptix/core/secure_memory.hpp"
#include "internal/cryptographic_provider.hpp"
#include "client/client_keys.hpp"

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <cstring>
#include <chrono>

namespace {

std::atomic<bool> g_client_initialized{false};
std::unique_ptr<ecliptix::openssl::Library> g_openssl_lib;
std::mutex g_client_init_mutex;

thread_local std::string g_client_last_error;

void set_client_error(ecliptix_result_t code, const std::string& message) {
    g_client_last_error = "[" + std::to_string(static_cast<int>(code)) + "] " + message;
}

[[nodiscard]] ecliptix_result_t handle_client_exception(const std::exception& e, const char* operation) {
    std::string message = std::string(operation) + ": " + e.what();

    if (dynamic_cast<const ecliptix::openssl::OpenSSLException*>(&e)) {
        set_client_error(ECLIPTIX_ERR_CRYPTO_FAILURE, message);
        return ECLIPTIX_ERR_CRYPTO_FAILURE;
    }

    set_client_error(ECLIPTIX_ERR_UNKNOWN, message);
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

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_init(void) {
    std::lock_guard<std::mutex> lock(g_client_init_mutex);

    if (g_client_initialized.load()) {
        return ECLIPTIX_SUCCESS;
    }

    try {
        g_openssl_lib = std::make_unique<ecliptix::openssl::Library>();
        g_client_initialized.store(true);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Client library initialization");
    }
}

ECLIPTIX_CLIENT_API void ECLIPTIX_CALL ecliptix_client_cleanup(void) {
    std::lock_guard<std::mutex> lock(g_client_init_mutex);

    if (!g_client_initialized.load()) {
        return;
    }

    g_openssl_lib.reset();
    g_client_initialized.store(false);
}

ECLIPTIX_CLIENT_API const char* ECLIPTIX_CALL ecliptix_client_get_error_message(void) {
    return g_client_last_error.c_str();
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_validate_certificate(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname) {

    if (!g_client_initialized.load()) {
        set_client_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Client library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0 || !hostname) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid certificate validation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der, cert_size)
        );

        auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (!cert.is_valid_at(current_time)) {
            set_client_error(ECLIPTIX_ERR_CERTIFICATE_INVALID, "Certificate is not valid at current time");
            return ECLIPTIX_ERR_CERTIFICATE_INVALID;
        }

        if (!cert.matches_hostname(std::string(hostname))) {
            set_client_error(ECLIPTIX_ERR_CERTIFICATE_INVALID, "Certificate hostname verification failed");
            return ECLIPTIX_ERR_CERTIFICATE_INVALID;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Certificate validation");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_verify_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    const ecliptix_pin_t* expected_pin) {

    if (!g_client_initialized.load()) {
        set_client_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Client library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0 || !hostname || !expected_pin) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid pin verification parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der, cert_size)
        );

        ecliptix_pin_t actual_pin;
        auto result = ecliptix_client_get_certificate_pin(cert_der, cert_size, &actual_pin);
        if (result != ECLIPTIX_SUCCESS) {
            return result;
        }

        if (sizeof(actual_pin.hash) != ECLIPTIX_SHA384_HASH_SIZE || sizeof(expected_pin->hash) != ECLIPTIX_SHA384_HASH_SIZE) {
            set_client_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Pin hash size mismatch");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        int pin_comparison_result;
        ecliptix_result_t compare_result = ecliptix_client_constant_time_compare(
            actual_pin.hash, expected_pin->hash, ECLIPTIX_SHA384_HASH_SIZE, &pin_comparison_result);

        if (compare_result != ECLIPTIX_SUCCESS) {
            set_client_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Pin comparison failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        if (pin_comparison_result == 1) {
            return ECLIPTIX_SUCCESS;
        }

        set_client_error(ECLIPTIX_ERR_PIN_VERIFICATION_FAILED, "Certificate pin verification failed");
        return ECLIPTIX_ERR_PIN_VERIFICATION_FAILED;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Pin verification");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_get_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_t* pin_out) {

    if (!g_client_initialized.load()) {
        set_client_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Client library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0 || !pin_out) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid pin generation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der, cert_size)
        );

        auto pin_sha384 = cert.get_spki_pin_sha384();

        if (pin_sha384.empty() || pin_sha384.size() != ECLIPTIX_SHA384_HASH_SIZE) {
            set_client_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Invalid SHA-384 hash size");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        std::copy(pin_sha384.begin(), pin_sha384.end(), pin_out->hash);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Pin generation");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_verify_ed25519_signature(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* signature,
    const uint8_t* public_key) {

    if (!g_client_initialized.load()) {
        set_client_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Client library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !signature || !public_key) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid Ed25519 verification parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto pub_key = ecliptix::openssl::KeyGenerator::deserialize_public_key(
            std::span<const uint8_t>(public_key, ECLIPTIX_ED25519_PUBLIC_KEY_SIZE)
        );

        std::span<const uint8_t> message_span(message, message_size);
        std::span<const uint8_t> sig_span(signature, ECLIPTIX_ED25519_SIGNATURE_SIZE);

        bool valid = ecliptix::openssl::DigitalSignature::verify_ed25519(
            message_span, sig_span, pub_key.get()
        );

        return valid ? ECLIPTIX_SUCCESS : ECLIPTIX_ERR_SIGNATURE_INVALID;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Ed25519 verification");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size) {

    if (!g_client_initialized.load()) {
        set_client_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Client library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!plaintext || plaintext_size == 0 || !ciphertext || !ciphertext_size) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA encryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (plaintext_size > ECLIPTIX_RSA_MAX_PLAINTEXT_SIZE) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Plaintext too large for RSA encryption");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (*ciphertext_size < ECLIPTIX_RSA_CIPHERTEXT_SIZE) {
        set_client_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    try {
        auto cert_der = ecliptix::client::SERVER_CERT_DER;
        ecliptix::client::deobfuscate_data(cert_der, ecliptix::client::CERT_XOR_KEY);

        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der.data(), cert_der.size())
        );

        auto public_key = cert.get_public_key();
        PKeyContext ctx(public_key.get());

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            throw std::runtime_error("Failed to initialize RSA encryption");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("Failed to set RSA OAEP padding");
        }

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, plaintext_size) <= 0) {
            throw std::runtime_error("Failed to determine RSA output size");
        }

        ecliptix::core::memory::SecureVector<uint8_t> encrypted(outlen);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, plaintext, plaintext_size) <= 0) {
            throw std::runtime_error("RSA encryption failed");
        }

        encrypted.resize(outlen);

        if (encrypted.size() > *ciphertext_size) {
            set_client_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(encrypted.begin(), encrypted.end(), ciphertext);
        *ciphertext_size = encrypted.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "RSA encryption");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_validate_pin_config(
    const ecliptix_pin_config_t* pin_config) {

    if (!pin_config) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Pin configuration is null");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (strlen(pin_config->hostname) == 0 || strlen(pin_config->hostname) >= ECLIPTIX_MAX_HOSTNAME_SIZE) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid hostname in pin configuration");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (pin_config->backup_pin_count > 3) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Too many backup pins");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    return ECLIPTIX_SUCCESS;
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_hash_sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t* hash_out) {

    if (!data || data_size == 0 || !hash_out) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid SHA-256 parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto hash = ecliptix::openssl::Hash::sha256(
            std::span<const uint8_t>(data, data_size)
        );

        std::copy(hash.begin(), hash.end(), hash_out);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "SHA-256 hashing");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_hash_sha384(
    const uint8_t* data,
    size_t data_size,
    uint8_t* hash_out) {

    if (!data || data_size == 0 || !hash_out) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid SHA-384 parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto hash = ecliptix::openssl::Hash::sha384(
            std::span<const uint8_t>(data, data_size)
        );

        std::copy(hash.begin(), hash.end(), hash_out);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "SHA-384 hashing");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_generate_random(
    uint8_t* buffer,
    size_t buffer_size) {

    if (!buffer || buffer_size == 0) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid random generation parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        if (RAND_bytes(buffer, static_cast<int>(buffer_size)) != 1) {
            set_client_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Random generation failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Random generation");
    }
}

ECLIPTIX_CLIENT_API int ECLIPTIX_CALL ecliptix_client_is_hostname_trusted(
    const char* hostname) {

    if (!hostname) {
        return 0;
    }

    for (const char* const* domain = ecliptix::client::TRUSTED_DOMAINS; *domain != nullptr; ++domain) {
        if (strcmp(hostname, *domain) == 0) {
            return 1;
        }

        if ((*domain)[0] == '*' && strlen(*domain) > 2) {
            const char* suffix = *domain + 2;
            size_t hostname_len = strlen(hostname);
            size_t suffix_len = strlen(suffix);

            if (hostname_len >= suffix_len &&
                strcmp(hostname + hostname_len - suffix_len, suffix) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_constant_time_compare(
    const uint8_t* a,
    const uint8_t* b,
    size_t size,
    int* result) {

    if (!a || !b || size == 0 || !result) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid constant-time comparison parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        *result = ecliptix::core::memory::constant_time_equals(a, b, size) ? 1 : 0;
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_client_exception(e, "Constant-time comparison");
    }
}

ECLIPTIX_CLIENT_API ecliptix_result_t ECLIPTIX_CALL ecliptix_client_get_library_version(
    char* version_buffer,
    size_t buffer_size) {

    if (!version_buffer || buffer_size == 0) {
        set_client_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid version buffer parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    const char* version = "1.0.0-client";
    size_t version_len = strlen(version);

    if (buffer_size <= version_len) {
        set_client_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Version buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    strcpy(version_buffer, version);
    return ECLIPTIX_SUCCESS;
}

}