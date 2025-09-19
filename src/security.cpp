
#include "ecliptix/security.h"
#include "ecliptix/types.h"
#include "internal/openssl_wrapper.hpp"
#include "embedded_keys.hpp"
#include "embedded_pins.hpp"

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <cstring>


namespace {

std::atomic<bool> g_initialized{false};
std::unique_ptr<ecliptix::openssl::Library> g_openssl_lib;
std::mutex g_init_mutex;

thread_local std::string g_last_error;

void set_error(ecliptix_result_t code, const std::string& message) {
    g_last_error = message;
}

ecliptix_result_t handle_exception(const std::exception& e, const char* operation) {
    std::string message = std::string(operation) + ": " + e.what();

    if (auto* ssl_ex = dynamic_cast<const ecliptix::openssl::OpenSSLException*>(&e)) {
        (void)ssl_ex;
        set_error(ECLIPTIX_ERR_CRYPTO_FAILURE, message);
        return ECLIPTIX_ERR_CRYPTO_FAILURE;
    }

    set_error(ECLIPTIX_ERR_UNKNOWN, message);
    return ECLIPTIX_ERR_UNKNOWN;
}

}


extern "C" {

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init(void) {
    std::lock_guard<std::mutex> lock(g_init_mutex);

    if (g_initialized.load()) {
        return ECLIPTIX_SUCCESS;
    }

    try {
        g_openssl_lib = std::make_unique<ecliptix::openssl::Library>();
        g_initialized.store(true);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "Library initialization");
    }
}

ECLIPTIX_API void ECLIPTIX_CALL ecliptix_cleanup(void) {
    std::lock_guard<std::mutex> lock(g_init_mutex);

    if (!g_initialized.load()) {
        return;
    }

    g_openssl_lib.reset();
    g_initialized.store(false);
}

ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_get_error_message(void) {
    return g_last_error.c_str();
}


ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_verify_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* signature) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !signature) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid verification parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto public_key_pem = ecliptix::embedded::ED25519_PUBLIC_KEY_PEM;
        ecliptix::embedded::deobfuscate_data(public_key_pem, ecliptix::embedded::ED25519_XOR_KEY);

        auto pub_key = ecliptix::openssl::KeyGenerator::deserialize_public_key(
            std::span<const uint8_t>(public_key_pem.data(), public_key_pem.size())
        );

        std::span<const uint8_t> message_span(message, message_size);
        std::span<const uint8_t> sig_span(signature, ECLIPTIX_ED25519_SIGNATURE_SIZE);

        bool valid = ecliptix::openssl::DigitalSignature::verify_ed25519(
            message_span, sig_span, pub_key.get()
        );

        return valid ? ECLIPTIX_SUCCESS : ECLIPTIX_ERR_SIGNATURE_INVALID;

    } catch (const std::exception& e) {
        return handle_exception(e, "Ed25519 verification");
    }
}


ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!plaintext || plaintext_size == 0 || !ciphertext || !ciphertext_size) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA encryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (plaintext_size > ECLIPTIX_RSA_MAX_PLAINTEXT_SIZE) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Plaintext too large for RSA encryption");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (*ciphertext_size < ECLIPTIX_RSA_CIPHERTEXT_SIZE) {
        set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    try {
        auto cert_der = ecliptix::embedded::SERVER_CERT_DER;
        ecliptix::embedded::deobfuscate_data(cert_der, ecliptix::embedded::CERT_XOR_KEY);

        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der.data(), cert_der.size())
        );

        auto public_key = cert.get_public_key();

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key.get(), nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create RSA encryption context");
        }

        std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_ptr(ctx, EVP_PKEY_CTX_free);

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

        std::vector<uint8_t> encrypted(outlen);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, plaintext, plaintext_size) <= 0) {
            throw std::runtime_error("RSA encryption failed");
        }

        encrypted.resize(outlen);

        if (encrypted.size() > *ciphertext_size) {
            set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(encrypted.begin(), encrypted.end(), ciphertext);
        *ciphertext_size = encrypted.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "RSA encryption");
    }
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* private_key_pem,
    size_t private_key_size,
    uint8_t* plaintext,
    size_t* plaintext_size) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!ciphertext || ciphertext_size == 0 || !private_key_pem || private_key_size == 0 ||
        !plaintext || !plaintext_size) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid RSA decryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        auto private_key = ecliptix::openssl::KeyGenerator::deserialize_private_key(
            std::span<const uint8_t>(private_key_pem, private_key_size)
        );

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key.get(), nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create RSA decryption context");
        }

        std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_ptr(ctx, EVP_PKEY_CTX_free);

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

        std::vector<uint8_t> decrypted(outlen);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, ciphertext, ciphertext_size) <= 0) {
            set_error(ECLIPTIX_ERR_DECRYPTION_FAILED, "RSA decryption failed");
            return ECLIPTIX_ERR_DECRYPTION_FAILED;
        }

        decrypted.resize(outlen);

        if (decrypted.size() > *plaintext_size) {
            set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(decrypted.begin(), decrypted.end(), plaintext);
        *plaintext_size = decrypted.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "RSA decryption");
    }
}

}