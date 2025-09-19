/*
 * Ecliptix Security Library - Main C API Implementation
 * Public interface for SSL pinning, encryption, and digital signatures
 */

#include "ecliptix/security.h"
#include "ecliptix/types.h"
#include "internal/openssl_wrapper.hpp"
#include "embedded_keys.hpp"
#include "embedded_pins.hpp"

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>

// ============================================================================
// Global State Management
// ============================================================================

namespace {

std::atomic<bool> g_initialized{false};
std::unique_ptr<ecliptix::openssl::Library> g_openssl_lib;
std::mutex g_init_mutex;

// Performance metrics
std::atomic<uint64_t> g_operations_total{0};
std::atomic<uint64_t> g_operations_successful{0};
std::atomic<uint64_t> g_operations_failed{0};
std::atomic<uint64_t> g_bytes_encrypted{0};
std::atomic<uint64_t> g_bytes_decrypted{0};
std::atomic<uint64_t> g_certificates_validated{0};
std::atomic<uint64_t> g_signatures_verified{0};

// Error handling
thread_local std::string g_last_error;

// Callbacks
ecliptix_log_callback_t g_log_callback = nullptr;
ecliptix_error_callback_t g_error_callback = nullptr;
void* g_callback_user_data = nullptr;

// Helper functions
void log_message(int level, const std::string& message) {
    if (g_log_callback) {
        g_log_callback(level, message.c_str());
    }
}

void set_error(ecliptix_result_t code, const std::string& message,
               const char* function = __builtin_FUNCTION(), uint32_t line = __builtin_LINE()) {
    g_last_error = message;

    if (g_error_callback) {
        ecliptix_error_info_t error_info = {
            .code = code,
            .function = function,
            .line = static_cast<uint32_t>(line),
            .timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            ),
            .thread_id = static_cast<uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()))
        };

        strncpy(error_info.message, message.c_str(), sizeof(error_info.message) - 1);
        error_info.message[sizeof(error_info.message) - 1] = '\0';

        g_error_callback(&error_info, g_callback_user_data);
    }
}

ecliptix_result_t handle_exception(const std::exception& e, const char* operation) {
    std::string message = std::string(operation) + ": " + e.what();

    if (auto* ssl_ex = dynamic_cast<const ecliptix::openssl::OpenSSLException*>(&e)) {
        (void)ssl_ex; // Suppress unused variable warning
        set_error(ECLIPTIX_ERR_CRYPTO_FAILURE, message);
        return ECLIPTIX_ERR_CRYPTO_FAILURE;
    }

    set_error(ECLIPTIX_ERR_UNKNOWN, message);
    return ECLIPTIX_ERR_UNKNOWN;
}

bool verify_library_integrity() {
    try {
        // Verify embedded keys integrity
        if (!ecliptix::embedded::verify_build_integrity()) {
            set_error(ECLIPTIX_ERR_TAMPERED, "Library integrity check failed");
            return false;
        }

        // Additional runtime checks can be added here
        return true;
    } catch (const std::exception& e) {
        set_error(ECLIPTIX_ERR_TAMPERED, "Integrity verification error: " + std::string(e.what()));
        return false;
    }
}

} // anonymous namespace

// ============================================================================
// Library Initialization and Cleanup
// ============================================================================

extern "C" {

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init(void) {
    return ecliptix_init_ex(nullptr, nullptr, nullptr);
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_init_ex(
    ecliptix_log_callback_t log_callback,
    ecliptix_error_callback_t error_callback,
    void* user_data) {

    std::lock_guard<std::mutex> lock(g_init_mutex);

    if (g_initialized.load()) {
        return ECLIPTIX_ERR_ALREADY_INITIALIZED;
    }

    try {
        // Set callbacks first
        g_log_callback = log_callback;
        g_error_callback = error_callback;
        g_callback_user_data = user_data;

        log_message(1, "Initializing Ecliptix Security Library");

        // Verify library integrity
        if (!verify_library_integrity()) {
            return ECLIPTIX_ERR_TAMPERED;
        }

        // Initialize OpenSSL
        g_openssl_lib = std::make_unique<ecliptix::openssl::Library>();

        log_message(1, "Ecliptix Security Library initialized successfully");
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

    log_message(1, "Cleaning up Ecliptix Security Library");

    g_openssl_lib.reset();
    g_initialized.store(false);

    // Clear callbacks
    g_log_callback = nullptr;
    g_error_callback = nullptr;
    g_callback_user_data = nullptr;

    log_message(1, "Ecliptix Security Library cleanup complete");
}

ECLIPTIX_API int ECLIPTIX_CALL ecliptix_is_initialized(void) {
    return g_initialized.load() ? 1 : 0;
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_get_version(ecliptix_version_info_t* version_info) {
    if (!version_info) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Version info pointer is null");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    version_info->major = ECLIPTIX_VERSION_MAJOR;
    version_info->minor = ECLIPTIX_VERSION_MINOR;
    version_info->patch = ECLIPTIX_VERSION_PATCH;
    version_info->build = 1;
    strncpy(version_info->build_date, __DATE__ " " __TIME__, sizeof(version_info->build_date) - 1);
    version_info->build_date[sizeof(version_info->build_date) - 1] = '\0';
    strncpy(version_info->version_string, ECLIPTIX_VERSION_STRING, sizeof(version_info->version_string) - 1);
    version_info->version_string[sizeof(version_info->version_string) - 1] = '\0';
    version_info->commit_hash = "dev";
    version_info->build_timestamp = ecliptix::embedded::BUILD_TIMESTAMP;

    return ECLIPTIX_SUCCESS;
}

// ============================================================================
// SSL Certificate Validation and Pinning
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_validate_certificate(
    const uint8_t* cert_der,
    size_t cert_size,
    const char* hostname,
    ecliptix_cert_validation_flags_t validation_flags) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid certificate data");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (!hostname) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Hostname is null");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    g_operations_total++;

    try {
        // Parse certificate
        std::span<const uint8_t> cert_span(cert_der, cert_size);
        ecliptix::openssl::Certificate cert(cert_span);

        // Validate time if requested
        if (validation_flags & ECLIPTIX_CERT_VALIDATE_TIME) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            if (!cert.is_valid_at(now)) {
                set_error(ECLIPTIX_ERR_CERT_EXPIRED, "Certificate is not valid at current time");
                g_operations_failed++;
                return ECLIPTIX_ERR_CERT_EXPIRED;
            }
        }

        // Validate hostname if requested
        if (validation_flags & ECLIPTIX_CERT_VALIDATE_HOSTNAME) {
            if (!cert.matches_hostname(hostname)) {
                set_error(ECLIPTIX_ERR_HOSTNAME_MISMATCH, "Certificate hostname does not match");
                g_operations_failed++;
                return ECLIPTIX_ERR_HOSTNAME_MISMATCH;
            }
        }

        // Validate pin if requested
        if (validation_flags & ECLIPTIX_CERT_VALIDATE_PIN) {
            auto pin = cert.get_spki_pin_sha384();

            // Check against primary pin
            auto primary_pin = ecliptix::embedded::PRIMARY_PIN_SHA384;
            auto primary_pin_copy = primary_pin;
            ecliptix::embedded::deobfuscate_data(primary_pin_copy, ecliptix::embedded::PIN_XOR_KEY);

            if (!ecliptix::openssl::utils::constant_time_equals(pin, primary_pin_copy)) {
                // Check against backup pins
                bool pin_found = false;
                for (const auto& backup_pin_obfuscated : ecliptix::embedded::BACKUP_PINS_SHA384) {
                    auto backup_pin_copy = backup_pin_obfuscated;
                    ecliptix::embedded::deobfuscate_data(backup_pin_copy, ecliptix::embedded::PIN_XOR_KEY);

                    if (ecliptix::openssl::utils::constant_time_equals(pin, backup_pin_copy)) {
                        pin_found = true;
                        break;
                    }
                }

                if (!pin_found) {
                    set_error(ECLIPTIX_ERR_PIN_MISMATCH, "Certificate pin does not match any trusted pins");
                    g_operations_failed++;
                    return ECLIPTIX_ERR_PIN_MISMATCH;
                }
            }
        }

        g_operations_successful++;
        g_certificates_validated++;

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "Certificate validation");
    }
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_check_certificate_pin_ex(
    const uint8_t* cert_der,
    size_t cert_size,
    ecliptix_pin_mode_t pin_mode) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!cert_der || cert_size == 0) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid certificate data");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    g_operations_total++;

    try {
        std::span<const uint8_t> cert_span(cert_der, cert_size);
        ecliptix::openssl::Certificate cert(cert_span);

        auto pin = cert.get_spki_pin_sha384();

        // Check primary pin
        auto primary_pin = ecliptix::embedded::PRIMARY_PIN_SHA384;
        auto primary_pin_copy = primary_pin;
        ecliptix::embedded::deobfuscate_data(primary_pin_copy, ecliptix::embedded::PIN_XOR_KEY);

        if (ecliptix::openssl::utils::constant_time_equals(pin, primary_pin_copy)) {
            g_operations_successful++;
            return ECLIPTIX_SUCCESS;
        }

        // Check backup pins if allowed
        if (pin_mode == ECLIPTIX_PIN_MODE_BACKUP || pin_mode == ECLIPTIX_PIN_MODE_ALLOW_NEW) {
            for (const auto& backup_pin_obfuscated : ecliptix::embedded::BACKUP_PINS_SHA384) {
                auto backup_pin_copy = backup_pin_obfuscated;
                ecliptix::embedded::deobfuscate_data(backup_pin_copy, ecliptix::embedded::PIN_XOR_KEY);

                if (ecliptix::openssl::utils::constant_time_equals(pin, backup_pin_copy)) {
                    g_operations_successful++;
                    return ECLIPTIX_SUCCESS;
                }
            }
        }

        set_error(ECLIPTIX_ERR_PIN_MISMATCH, "Certificate pin does not match any trusted pins");
        g_operations_failed++;
        return ECLIPTIX_ERR_PIN_MISMATCH;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "Certificate pin check");
    }
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_check_certificate_pin(
    const uint8_t* cert_der,
    size_t cert_size,
    const uint8_t* /* trusted_pins */,
    size_t /* num_pins */) {

    // Simple wrapper that calls the extended function with strict mode
    return ecliptix_check_certificate_pin_ex(cert_der, cert_size, ECLIPTIX_PIN_MODE_STRICT);
}

// ============================================================================
// Symmetric Encryption
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_encrypt_aead(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* associated_data,
    size_t associated_data_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size,
    uint8_t* nonce,
    uint8_t* tag) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!plaintext || plaintext_size == 0 || !key || key_size != ECLIPTIX_AES_256_KEY_SIZE ||
        !ciphertext || !ciphertext_size || !nonce || !tag) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid encryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (*ciphertext_size < plaintext_size) {
        set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    g_operations_total++;

    try {
        std::span<const uint8_t> plaintext_span(plaintext, plaintext_size);
        std::span<const uint8_t, 32> key_span(key, key_size);
        std::span<const uint8_t> aad_span(associated_data, associated_data_size);

        auto result = ecliptix::openssl::AES_GCM::encrypt(plaintext_span, key_span, aad_span);

        // Copy results
        std::copy(result.ciphertext.begin(), result.ciphertext.end(), ciphertext);
        std::copy(result.iv.begin(), result.iv.end(), nonce);
        std::copy(result.tag.begin(), result.tag.end(), tag);

        *ciphertext_size = result.ciphertext.size();

        g_operations_successful++;
        g_bytes_encrypted += plaintext_size;

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "AES-GCM encryption");
    }
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_decrypt_aes_gcm(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    const uint8_t* key,
    size_t key_size,
    const uint8_t nonce[ECLIPTIX_AES_GCM_IV_SIZE],
    const uint8_t tag[ECLIPTIX_AES_GCM_TAG_SIZE],
    uint8_t* plaintext,
    size_t* plaintext_size,
    const uint8_t* associated_data,
    size_t associated_data_size) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!ciphertext || ciphertext_size == 0 || !key || key_size != ECLIPTIX_AES_256_KEY_SIZE ||
        !nonce || !tag || !plaintext || !plaintext_size) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid decryption parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (*plaintext_size < ciphertext_size) {
        set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Plaintext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    g_operations_total++;

    try {
        std::span<const uint8_t> ciphertext_span(ciphertext, ciphertext_size);
        std::span<const uint8_t, 32> key_span(key, key_size);
        std::span<const uint8_t, 12> nonce_span(nonce, ECLIPTIX_AES_GCM_IV_SIZE);
        std::span<const uint8_t, 16> tag_span(tag, ECLIPTIX_AES_GCM_TAG_SIZE);
        std::span<const uint8_t> aad_span(associated_data, associated_data_size);

        auto result = ecliptix::openssl::AES_GCM::decrypt(
            ciphertext_span, key_span, nonce_span, tag_span, aad_span
        );

        // Copy result
        std::copy(result.begin(), result.end(), plaintext);
        *plaintext_size = result.size();

        g_operations_successful++;
        g_bytes_decrypted += result.size();

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "AES-GCM decryption");
    }
}

// ============================================================================
// Digital Signatures
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t* /* private_key */,
    uint8_t* signature) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !signature) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid signing parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    g_operations_total++;

    try {
        // Deobfuscate embedded private key
        auto private_key_pem = ecliptix::embedded::ED25519_PRIVATE_KEY_PEM;
        ecliptix::embedded::deobfuscate_data(private_key_pem, ecliptix::embedded::ED25519_XOR_KEY);

        // Load private key
        auto private_key = ecliptix::openssl::KeyGenerator::deserialize_private_key(
            std::span<const uint8_t>(private_key_pem.data(), private_key_pem.size())
        );

        std::span<const uint8_t> message_span(message, message_size);
        auto sig_result = ecliptix::openssl::DigitalSignature::sign_ed25519(message_span, private_key.get());

        if (sig_result.size() != ECLIPTIX_ED25519_SIGNATURE_SIZE) {
            set_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Invalid signature size");
            g_operations_failed++;
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        std::copy(sig_result.begin(), sig_result.end(), signature);

        g_operations_successful++;
        g_signatures_verified++;

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "Ed25519 signing");
    }
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_verify_ed25519(
    const uint8_t* message,
    size_t message_size,
    const uint8_t signature[ECLIPTIX_ED25519_SIGNATURE_SIZE]) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !signature) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid verification parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    g_operations_total++;

    try {
        // Always use embedded public key for security
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

        g_operations_successful++;

        return valid ? ECLIPTIX_SUCCESS : ECLIPTIX_ERR_CRYPTO_FAILURE;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "Ed25519 verification");
    }
}

// ============================================================================
// RSA Encryption/Decryption (Asymmetric)
// ============================================================================

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

    // RSA can only encrypt data smaller than key size minus padding
    constexpr size_t RSA_KEY_SIZE = 256; // 2048-bit RSA
    constexpr size_t RSA_OAEP_PADDING = 42; // OAEP padding overhead
    constexpr size_t MAX_PLAINTEXT_SIZE = RSA_KEY_SIZE - RSA_OAEP_PADDING;

    if (plaintext_size > MAX_PLAINTEXT_SIZE) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Plaintext too large for RSA encryption");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    if (*ciphertext_size < RSA_KEY_SIZE) {
        set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
    }

    g_operations_total++;

    try {
        // Extract RSA public key from embedded server certificate
        auto cert_der = ecliptix::embedded::SERVER_CERT_DER;
        ecliptix::embedded::deobfuscate_data(cert_der, ecliptix::embedded::CERT_XOR_KEY);

        // Parse certificate to extract public key
        auto cert = ecliptix::openssl::Certificate(
            std::span<const uint8_t>(cert_der.data(), cert_der.size())
        );

        auto public_key = cert.get_public_key();

        // Perform RSA-OAEP encryption using EVP high-level API
        std::span<const uint8_t> plaintext_span(plaintext, plaintext_size);

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

        g_operations_successful++;
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
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

    g_operations_total++;

    try {
        // Load private key from PEM
        auto private_key = ecliptix::openssl::KeyGenerator::deserialize_private_key(
            std::span<const uint8_t>(private_key_pem, private_key_size)
        );

        // Perform RSA-OAEP decryption using EVP high-level API
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
            throw std::runtime_error("RSA decryption failed");
        }

        decrypted.resize(outlen);

        if (decrypted.size() > *plaintext_size) {
            set_error(ECLIPTIX_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(decrypted.begin(), decrypted.end(), plaintext);
        *plaintext_size = decrypted.size();

        g_operations_successful++;
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        g_operations_failed++;
        return handle_exception(e, "RSA decryption");
    }
}

// ============================================================================
// Key Management
// ============================================================================

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_random_bytes(uint8_t* buffer, size_t size) {
    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    if (!buffer || size == 0) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Invalid random bytes parameters");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    try {
        ecliptix::openssl::Random::bytes(buffer, size);
        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "Random bytes generation");
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_get_error_message(void) {
    return g_last_error.c_str();
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_get_metrics(ecliptix_metrics_t* metrics) {
    if (!metrics) {
        set_error(ECLIPTIX_ERR_INVALID_PARAM, "Metrics pointer is null");
        return ECLIPTIX_ERR_INVALID_PARAM;
    }

    metrics->operations_total = g_operations_total.load();
    metrics->operations_successful = g_operations_successful.load();
    metrics->operations_failed = g_operations_failed.load();
    metrics->certificates_validated = 0; // TODO: implement counter
    metrics->pins_checked = 0; // TODO: implement counter
    metrics->encryptions_performed = 0; // TODO: implement counter
    metrics->signatures_created = 0; // TODO: implement counter
    metrics->signatures_verified = 0; // TODO: implement counter

    return ECLIPTIX_SUCCESS;
}

ECLIPTIX_API void ECLIPTIX_CALL ecliptix_reset_metrics(void) {
    g_operations_total = 0;
    g_operations_successful = 0;
    g_operations_failed = 0;
    g_bytes_encrypted = 0;
    g_bytes_decrypted = 0;
    g_certificates_validated = 0;
    g_signatures_verified = 0;
}

ECLIPTIX_API ecliptix_result_t ECLIPTIX_CALL ecliptix_self_test(void) {
    if (!g_initialized.load()) {
        set_error(ECLIPTIX_ERR_NOT_INITIALIZED, "Library not initialized");
        return ECLIPTIX_ERR_NOT_INITIALIZED;
    }

    try {
        // Test random number generation
        uint8_t random_data[32];
        ecliptix::openssl::Random::bytes(random_data, sizeof(random_data));

        // Test AES-GCM encryption/decryption
        const char* test_message = "Hello, Ecliptix Security!";
        std::span<const uint8_t> message_span(
            reinterpret_cast<const uint8_t*>(test_message),
            std::strlen(test_message)
        );

        auto key = ecliptix::openssl::Random::bytes<32>();
        auto encrypt_result = ecliptix::openssl::AES_GCM::encrypt(message_span, key);

        auto decrypt_result = ecliptix::openssl::AES_GCM::decrypt(
            encrypt_result.ciphertext, key, encrypt_result.iv, encrypt_result.tag
        );

        // Verify decryption
        if (decrypt_result.size() != message_span.size() ||
            !std::equal(decrypt_result.begin(), decrypt_result.end(), message_span.begin())) {
            set_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "AES-GCM self-test failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        // Test Ed25519 signing
        auto [ed_private, ed_public] = ecliptix::openssl::KeyGenerator::generate_ed25519();
        auto signature = ecliptix::openssl::DigitalSignature::sign_ed25519(message_span, ed_private.get());
        bool sig_valid = ecliptix::openssl::DigitalSignature::verify_ed25519(
            message_span, signature, ed_public.get()
        );

        if (!sig_valid) {
            set_error(ECLIPTIX_ERR_CRYPTO_FAILURE, "Ed25519 self-test failed");
            return ECLIPTIX_ERR_CRYPTO_FAILURE;
        }

        return ECLIPTIX_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "Self-test");
    }
}

ECLIPTIX_API const char* ECLIPTIX_CALL ecliptix_result_to_string(ecliptix_result_t result) {
    switch (result) {
        case ECLIPTIX_SUCCESS: return "Success";
        case ECLIPTIX_ERR_INVALID_PARAM: return "Invalid parameter";
        case ECLIPTIX_ERR_INVALID_CERT: return "Invalid certificate";
        case ECLIPTIX_ERR_INVALID_CHAIN: return "Invalid certificate chain";
        case ECLIPTIX_ERR_CERT_EXPIRED: return "Certificate expired";
        case ECLIPTIX_ERR_CERT_NOT_YET_VALID: return "Certificate not yet valid";
        case ECLIPTIX_ERR_HOSTNAME_MISMATCH: return "Hostname mismatch";
        case ECLIPTIX_ERR_PIN_MISMATCH: return "Pin mismatch";
        case ECLIPTIX_ERR_CRYPTO_FAILURE: return "Cryptographic operation failed";
        case ECLIPTIX_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
        case ECLIPTIX_ERR_OUT_OF_MEMORY: return "Out of memory";
        case ECLIPTIX_ERR_NOT_INITIALIZED: return "Library not initialized";
        case ECLIPTIX_ERR_ALREADY_INITIALIZED: return "Library already initialized";
        case ECLIPTIX_ERR_TAMPERED: return "Library integrity compromised";
        case ECLIPTIX_ERR_UNSUPPORTED: return "Operation not supported";
        case ECLIPTIX_ERR_TIMEOUT: return "Operation timed out";
        case ECLIPTIX_ERR_UNKNOWN: return "Unknown error";
        default: return "Invalid error code";
    }
}

} // extern "C"