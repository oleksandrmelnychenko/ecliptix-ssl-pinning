#pragma once

/*
 * Ecliptix Security Library - C++ API
 * Modern C++ wrapper around the C API
 */

#include "security.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <span>
#include <array>
#include <chrono>
#include <functional>
#include <stdexcept>

namespace ecliptix {

// ============================================================================
// Exception Classes
// ============================================================================

class SecurityException : public std::runtime_error {
public:
    explicit SecurityException(ecliptix_result_t code, const std::string& message = "")
        : std::runtime_error(message.empty() ? ecliptix_result_to_string(code) : message)
        , code_(code) {}

    ecliptix_result_t code() const noexcept { return code_; }

private:
    ecliptix_result_t code_;
};

class CertificateException : public SecurityException {
public:
    explicit CertificateException(ecliptix_result_t code, const std::string& message = "")
        : SecurityException(code, message) {}
};

class CryptoException : public SecurityException {
public:
    explicit CryptoException(ecliptix_result_t code, const std::string& message = "")
        : SecurityException(code, message) {}
};

// ============================================================================
// RAII Wrappers and Smart Pointers
// ============================================================================

namespace detail {

struct SessionDeleter {
    void operator()(ecliptix_session_t* session) const {
        if (session) {
            ecliptix_session_destroy(session);
        }
    }
};

} // namespace detail

using SessionPtr = std::unique_ptr<ecliptix_session_t, detail::SessionDeleter>;

// ============================================================================
// Secure Memory Management
// ============================================================================

template<typename T>
class SecureVector {
public:
    SecureVector() = default;

    explicit SecureVector(size_t size) {
        resize(size);
    }

    SecureVector(std::initializer_list<T> init) {
        resize(init.size());
        std::copy(init.begin(), init.end(), data());
    }

    ~SecureVector() {
        clear();
    }

    // Move-only semantics for security
    SecureVector(const SecureVector&) = delete;
    SecureVector& operator=(const SecureVector&) = delete;

    SecureVector(SecureVector&& other) noexcept
        : data_(std::exchange(other.data_, nullptr))
        , size_(std::exchange(other.size_, 0))
        , capacity_(std::exchange(other.capacity_, 0)) {}

    SecureVector& operator=(SecureVector&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::exchange(other.data_, nullptr);
            size_ = std::exchange(other.size_, 0);
            capacity_ = std::exchange(other.capacity_, 0);
        }
        return *this;
    }

    void resize(size_t new_size) {
        if (new_size > capacity_) {
            reserve(new_size);
        }
        size_ = new_size;
    }

    void reserve(size_t new_capacity) {
        if (new_capacity <= capacity_) return;

        T* new_data = static_cast<T*>(
            ecliptix_secure_alloc(new_capacity * sizeof(T), ECLIPTIX_MEMORY_SECURE)
        );

        if (!new_data) {
            throw std::bad_alloc();
        }

        if (data_ && size_ > 0) {
            std::memcpy(new_data, data_, size_ * sizeof(T));
        }

        clear();
        data_ = new_data;
        capacity_ = new_capacity;
    }

    void clear() {
        if (data_) {
            ecliptix_secure_free(data_, capacity_ * sizeof(T));
            data_ = nullptr;
        }
        size_ = 0;
        capacity_ = 0;
    }

    // Accessors
    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size_ == 0; }

    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }

    T& at(size_t index) {
        if (index >= size_) throw std::out_of_range("SecureVector index out of range");
        return data_[index];
    }

    const T& at(size_t index) const {
        if (index >= size_) throw std::out_of_range("SecureVector index out of range");
        return data_[index];
    }

    std::span<T> span() { return {data_, size_}; }
    std::span<const T> span() const { return {data_, size_}; }

private:
    T* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

using SecureBytes = SecureVector<uint8_t>;

// ============================================================================
// Result Wrapper
// ============================================================================

template<typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), has_value_(true) {}
    Result(ecliptix_result_t error) : error_(error), has_value_(false) {}

    bool has_value() const noexcept { return has_value_; }
    bool has_error() const noexcept { return !has_value_; }

    const T& value() const& {
        if (!has_value_) {
            throw SecurityException(error_);
        }
        return value_;
    }

    T value() && {
        if (!has_value_) {
            throw SecurityException(error_);
        }
        return std::move(value_);
    }

    ecliptix_result_t error() const {
        return has_value_ ? ECLIPTIX_SUCCESS : error_;
    }

    T value_or(const T& default_value) const {
        return has_value_ ? value_ : default_value;
    }

    template<typename F>
    auto map(F&& func) const {
        using ReturnType = std::invoke_result_t<F, const T&>;
        if (has_value_) {
            return Result<ReturnType>(func(value_));
        } else {
            return Result<ReturnType>(error_);
        }
    }

private:
    union {
        T value_;
        ecliptix_result_t error_;
    };
    bool has_value_;
};

// ============================================================================
// Certificate Management
// ============================================================================

struct CertificateInfo {
    std::string subject;
    std::string issuer;
    std::string serial_number;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::array<uint8_t, 32> fingerprint_sha256;
    std::array<uint8_t, 48> pin_sha384;

    static CertificateInfo from_c_struct(const ecliptix_cert_info_t& info) {
        return CertificateInfo{
            .subject = info.subject,
            .issuer = info.issuer,
            .serial_number = info.serial_number,
            .not_before = std::chrono::system_clock::from_time_t(info.not_before),
            .not_after = std::chrono::system_clock::from_time_t(info.not_after),
            .fingerprint_sha256 = [&info]() {
                std::array<uint8_t, 32> arr;
                std::memcpy(arr.data(), info.fingerprint_sha256, 32);
                return arr;
            }(),
            .pin_sha384 = [&info]() {
                std::array<uint8_t, 48> arr;
                std::memcpy(arr.data(), info.pin_sha384, 48);
                return arr;
            }()
        };
    }
};

class Certificate {
public:
    Certificate(std::span<const uint8_t> der_data)
        : der_data_(der_data.begin(), der_data.end()) {}

    Result<CertificateInfo> get_info() const {
        ecliptix_cert_info_t info;
        auto result = ecliptix_get_certificate_info(
            der_data_.data(), der_data_.size(), &info
        );

        if (result != ECLIPTIX_SUCCESS) {
            return Result<CertificateInfo>(result);
        }

        return Result<CertificateInfo>(CertificateInfo::from_c_struct(info));
    }

    Result<void> validate(const std::string& hostname,
                         ecliptix_cert_validation_flags_t flags = ECLIPTIX_CERT_VALIDATE_ALL) const {
        auto result = ecliptix_validate_certificate(
            der_data_.data(), der_data_.size(), hostname.c_str(), flags
        );

        return result == ECLIPTIX_SUCCESS ?
            Result<void>(monostate{}) : Result<void>(result);
    }

    Result<void> check_pin(ecliptix_pin_mode_t mode = ECLIPTIX_PIN_MODE_STRICT) const {
        auto result = ecliptix_check_certificate_pin(
            der_data_.data(), der_data_.size(), mode
        );

        return result == ECLIPTIX_SUCCESS ?
            Result<void>(monostate{}) : Result<void>(result);
    }

    std::span<const uint8_t> der_data() const { return der_data_; }

private:
    std::vector<uint8_t> der_data_;
    struct monostate {};
};

// ============================================================================
// Cryptographic Operations
// ============================================================================

namespace crypto {

class AES_GCM {
public:
    static constexpr size_t KEY_SIZE = ECLIPTIX_AES_256_KEY_SIZE;
    static constexpr size_t IV_SIZE = ECLIPTIX_AES_GCM_IV_SIZE;
    static constexpr size_t TAG_SIZE = ECLIPTIX_AES_GCM_TAG_SIZE;

    struct EncryptResult {
        SecureBytes ciphertext;
        std::array<uint8_t, IV_SIZE> nonce;
        std::array<uint8_t, TAG_SIZE> tag;
    };

    static Result<EncryptResult> encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t> associated_data = {}) {

        EncryptResult result;
        result.ciphertext.resize(plaintext.size());

        // Generate random nonce
        auto nonce_result = ecliptix_random_bytes(result.nonce.data(), IV_SIZE);
        if (nonce_result != ECLIPTIX_SUCCESS) {
            return Result<EncryptResult>(nonce_result);
        }

        size_t ciphertext_size = result.ciphertext.size();
        auto encrypt_result = ecliptix_encrypt_aes_gcm(
            plaintext.data(), plaintext.size(),
            key.data(), key.size(),
            result.ciphertext.data(), &ciphertext_size,
            result.nonce.data(), result.tag.data(),
            associated_data.data(), associated_data.size()
        );

        if (encrypt_result != ECLIPTIX_SUCCESS) {
            return Result<EncryptResult>(encrypt_result);
        }

        result.ciphertext.resize(ciphertext_size);
        return Result<EncryptResult>(std::move(result));
    }

    static Result<SecureBytes> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, IV_SIZE> nonce,
        std::span<const uint8_t, TAG_SIZE> tag,
        std::span<const uint8_t> associated_data = {}) {

        SecureBytes plaintext(ciphertext.size());
        size_t plaintext_size = plaintext.size();

        auto result = ecliptix_decrypt_aes_gcm(
            ciphertext.data(), ciphertext.size(),
            key.data(), key.size(),
            nonce.data(), tag.data(),
            plaintext.data(), &plaintext_size,
            associated_data.data(), associated_data.size()
        );

        if (result != ECLIPTIX_SUCCESS) {
            return Result<SecureBytes>(result);
        }

        plaintext.resize(plaintext_size);
        return Result<SecureBytes>(std::move(plaintext));
    }
};

class Ed25519 {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = ECLIPTIX_ED25519_PUBLIC_KEY_SIZE;
    static constexpr size_t PRIVATE_KEY_SIZE = ECLIPTIX_ED25519_PRIVATE_KEY_SIZE;
    static constexpr size_t SIGNATURE_SIZE = ECLIPTIX_ED25519_SIGNATURE_SIZE;

    static Result<std::array<uint8_t, SIGNATURE_SIZE>> sign(
        std::span<const uint8_t> message) {

        std::array<uint8_t, SIGNATURE_SIZE> signature;
        auto result = ecliptix_sign_ed25519(
            message.data(), message.size(), signature.data()
        );

        if (result != ECLIPTIX_SUCCESS) {
            return Result<std::array<uint8_t, SIGNATURE_SIZE>>(result);
        }

        return Result<std::array<uint8_t, SIGNATURE_SIZE>>(signature);
    }

    static Result<bool> verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t, SIGNATURE_SIZE> signature,
        std::span<const uint8_t, PUBLIC_KEY_SIZE> public_key = {}) {

        auto result = ecliptix_verify_ed25519(
            message.data(), message.size(),
            signature.data(),
            public_key.empty() ? nullptr : public_key.data()
        );

        if (result == ECLIPTIX_SUCCESS) {
            return Result<bool>(true);
        } else if (result == ECLIPTIX_ERR_CRYPTO_FAILURE) {
            return Result<bool>(false);
        } else {
            return Result<bool>(result);
        }
    }
};

} // namespace crypto

// ============================================================================
// Library Management
// ============================================================================

class Library {
public:
    Library() {
        auto result = ecliptix_init();
        if (result != ECLIPTIX_SUCCESS) {
            throw SecurityException(result, "Failed to initialize Ecliptix library");
        }
        initialized_ = true;
    }

    ~Library() {
        if (initialized_) {
            ecliptix_cleanup();
        }
    }

    // Non-copyable, non-movable
    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;
    Library(Library&&) = delete;
    Library& operator=(Library&&) = delete;

    static bool is_initialized() {
        return ecliptix_is_initialized() != 0;
    }

    static std::string version_string() {
        ecliptix_version_info_t info;
        auto result = ecliptix_get_version(&info);
        if (result != ECLIPTIX_SUCCESS) {
            return "Unknown";
        }

        return std::to_string(info.major) + "." +
               std::to_string(info.minor) + "." +
               std::to_string(info.patch);
    }

    static Result<void> self_test() {
        auto result = ecliptix_self_test();
        return result == ECLIPTIX_SUCCESS ?
            Result<void>(monostate{}) : Result<void>(result);
    }

private:
    bool initialized_ = false;
    struct monostate {};
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

Result<SecureBytes> random_bytes(size_t count) {
    SecureBytes bytes(count);
    auto result = ecliptix_random_bytes(bytes.data(), count);

    if (result != ECLIPTIX_SUCCESS) {
        return Result<SecureBytes>(result);
    }

    return Result<SecureBytes>(std::move(bytes));
}

Result<SecureBytes> derive_key_hkdf(
    std::span<const uint8_t> input_key,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_size) {

    SecureBytes output(output_size);
    auto result = ecliptix_derive_key_hkdf(
        input_key.data(), input_key.size(),
        salt.data(), salt.size(),
        info.data(), info.size(),
        output.data(), output.size()
    );

    if (result != ECLIPTIX_SUCCESS) {
        return Result<SecureBytes>(result);
    }

    return Result<SecureBytes>(std::move(output));
}

} // namespace utils

} // namespace ecliptix