#pragma once

/*
 * Ecliptix Security Library - Core Type System
 * World-class C++23 implementation with strong type safety
 *
 * Design Principles:
 * - Make invalid states unrepresentable
 * - Zero-cost abstractions with optimal codegen
 * - Guaranteed memory security that cannot be optimized away
 * - Minimal, orthogonal, composable API surface
 */

#include <array>
#include <span>
#include <string_view>
#include <concepts>
#include <type_traits>
#include <cstdint>
#include <bit>
#if __cpp_lib_expected >= 202202L
#include <expected>
#endif

namespace ecliptix::core {

// ============================================================================
// Strong Type System - Prevent Category Errors
// ============================================================================

namespace detail {
    template<typename T, typename Tag, typename = void>
    struct strong_type {
        using value_type = T;
        using tag_type = Tag;

        constexpr strong_type() noexcept = default;
        constexpr explicit strong_type(T value) noexcept : value_(std::move(value)) {}

        constexpr const T& get() const noexcept { return value_; }
        constexpr T& get() noexcept { return value_; }

        constexpr operator const T&() const noexcept { return value_; }

        // Only allow explicit conversion to prevent accidents
        constexpr explicit operator T() const noexcept requires(!std::same_as<T, bool>) {
            return value_;
        }

        constexpr auto operator<=>(const strong_type&) const = default;

    private:
        T value_{};
    };
}

// Cryptographic type tags for type safety
struct key_tag {};
struct nonce_tag {};
struct signature_tag {};
struct hash_tag {};
struct pin_tag {};
struct plaintext_tag {};
struct ciphertext_tag {};

// Strong types prevent mixing up different byte arrays
template<size_t N>
using Key = detail::strong_type<std::array<std::byte, N>, key_tag>;

template<size_t N>
using Nonce = detail::strong_type<std::array<std::byte, N>, nonce_tag>;

template<size_t N>
using Signature = detail::strong_type<std::array<std::byte, N>, signature_tag>;

template<size_t N>
using Hash = detail::strong_type<std::array<std::byte, N>, hash_tag>;

template<size_t N>
using Pin = detail::strong_type<std::array<std::byte, N>, pin_tag>;

// Dynamic size secure containers
class SecureBytes;  // Forward declaration

using Plaintext = detail::strong_type<SecureBytes, plaintext_tag>;
using Ciphertext = detail::strong_type<SecureBytes, ciphertext_tag>;

// ============================================================================
// Cryptographic Constants - Compile Time Verified
// ============================================================================

namespace crypto {
    // ChaCha20-Poly1305 (recommended AEAD)
    inline constexpr size_t CHACHA20_KEY_SIZE = 32;
    inline constexpr size_t CHACHA20_NONCE_SIZE = 12;
    inline constexpr size_t CHACHA20_TAG_SIZE = 16;

    // Ed25519 Digital Signatures
    inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
    inline constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
    inline constexpr size_t ED25519_SIGNATURE_SIZE = 64;

    // Blake2b Hashing
    inline constexpr size_t BLAKE2B_DEFAULT_SIZE = 32;
    inline constexpr size_t BLAKE2B_MIN_SIZE = 16;
    inline constexpr size_t BLAKE2B_MAX_SIZE = 64;

    // SSL Certificate Pinning
    inline constexpr size_t SSL_PIN_SIZE = 48;  // SHA-384

    // Type aliases for common sizes
    using ChaCha20Key = Key<CHACHA20_KEY_SIZE>;
    using ChaCha20Nonce = Nonce<CHACHA20_NONCE_SIZE>;

    using Ed25519PublicKey = Key<ED25519_PUBLIC_KEY_SIZE>;
    using Ed25519PrivateKey = Key<ED25519_PRIVATE_KEY_SIZE>;
    using Ed25519Signature = Signature<ED25519_SIGNATURE_SIZE>;

    using Blake2bHash = Hash<BLAKE2B_DEFAULT_SIZE>;
    using SslPin = Pin<SSL_PIN_SIZE>;
}

// ============================================================================
// Concepts for Template Constraints
// ============================================================================

template<typename T>
concept ByteLike = std::same_as<T, std::byte> ||
                   std::same_as<T, uint8_t> ||
                   std::same_as<T, char> ||
                   std::same_as<T, unsigned char>;

template<typename T>
concept ByteSpanLike = requires(T t) {
    std::span{t};
    requires ByteLike<typename std::span<T>::element_type>;
};

template<typename T>
concept CryptographicKey = requires {
    typename T::tag_type;
    requires std::same_as<typename T::tag_type, key_tag>;
};

template<typename T>
concept CryptographicNonce = requires {
    typename T::tag_type;
    requires std::same_as<typename T::tag_type, nonce_tag>;
};

template<typename T>
concept CryptographicSignature = requires {
    typename T::tag_type;
    requires std::same_as<typename T::tag_type, signature_tag>;
};

template<typename T>
concept CryptographicHash = requires {
    typename T::tag_type;
    requires std::same_as<typename T::tag_type, hash_tag>;
};

// ============================================================================
// Error Handling - std::expected Style (C++23)
// ============================================================================

namespace error {
    enum class Code : int32_t {
        Success = 0,

        // Input validation errors
        InvalidParameter = -1,
        BufferTooSmall = -2,
        InvalidSize = -3,

        // Cryptographic errors
        DecryptionFailed = -10,
        SignatureInvalid = -11,
        KeyDerivationFailed = -12,
        RandomGenerationFailed = -13,

        // SSL/Certificate errors
        CertificateInvalid = -20,
        CertificateExpired = -21,
        HostnameMismatch = -22,
        PinMismatch = -23,

        // Library state errors
        NotInitialized = -30,
        AlreadyInitialized = -31,
        LibraryTampered = -32,

        // Memory/System errors
        OutOfMemory = -40,
        MemoryLockFailed = -41,

        // Generic errors
        InternalError = -90,
        Unknown = -99
    };

    constexpr std::string_view to_string(Code code) noexcept {
        switch (code) {
            case Code::Success: return "Success";
            case Code::InvalidParameter: return "Invalid parameter";
            case Code::BufferTooSmall: return "Buffer too small";
            case Code::InvalidSize: return "Invalid size";
            case Code::DecryptionFailed: return "Decryption failed";
            case Code::SignatureInvalid: return "Signature invalid";
            case Code::KeyDerivationFailed: return "Key derivation failed";
            case Code::RandomGenerationFailed: return "Random generation failed";
            case Code::CertificateInvalid: return "Certificate invalid";
            case Code::CertificateExpired: return "Certificate expired";
            case Code::HostnameMismatch: return "Hostname mismatch";
            case Code::PinMismatch: return "Pin mismatch";
            case Code::NotInitialized: return "Library not initialized";
            case Code::AlreadyInitialized: return "Library already initialized";
            case Code::LibraryTampered: return "Library integrity compromised";
            case Code::OutOfMemory: return "Out of memory";
            case Code::MemoryLockFailed: return "Memory lock failed";
            case Code::InternalError: return "Internal error";
            case Code::Unknown: return "Unknown error";
        }
        return "Invalid error code";
    }
}

// Modern error handling without exceptions
#if __cpp_lib_expected >= 202202L
template<typename T>
using Result = std::expected<T, error::Code>;

using Success = std::expected<void, error::Code>;
#else
// Fallback implementation for pre-C++23 compilers
#include <optional>

template<typename T>
class Result {
private:
    std::optional<T> value_;
    error::Code error_code_;
    bool has_error_;

public:
    constexpr Result(T value) : value_(std::move(value)), has_error_(false) {}
    constexpr Result(unexpected<error::Code> error) : error_code_(error.value()), has_error_(true) {}
    constexpr Result(error::Code error) : error_code_(error), has_error_(true) {}

    constexpr bool has_value() const noexcept { return !has_error_; }
    constexpr T& value() & { return *value_; }
    constexpr const T& value() const& { return *value_; }
    constexpr T&& value() && { return std::move(*value_); }
    constexpr error::Code error() const noexcept { return error_code_; }
};

// Specialization for void
template<>
class Result<void> {
private:
    error::Code error_code_;
    bool has_error_;

public:
    constexpr Result() : has_error_(false) {}
    constexpr Result(unexpected<error::Code> error) : error_code_(error.value()), has_error_(true) {}
    constexpr Result(error::Code error) : error_code_(error), has_error_(true) {}

    constexpr bool has_value() const noexcept { return !has_error_; }
    constexpr error::Code error() const noexcept { return error_code_; }
};

using Success = Result<void>;
#endif

// Helper for creating unexpected results (available in both cases)
template<typename E>
struct unexpected {
    E value_;
    constexpr explicit unexpected(E e) : value_(e) {}
    constexpr E value() const { return value_; }
};

// ============================================================================
// Secure Memory Management Foundation
// ============================================================================

namespace memory {
    // Memory protection levels
    enum class Protection : uint8_t {
        None = 0,           // Standard allocation
        Locked = 1,         // Prevent swapping to disk
        Guarded = 2         // Guard pages to detect buffer overruns
    };

    // Secure memory allocation traits
    struct SecureTraits {
        static constexpr Protection default_protection = Protection::Locked;
        static constexpr bool auto_wipe = true;
        static constexpr bool constant_time_ops = true;
    };
}

// ============================================================================
// Compile-Time Utilities
// ============================================================================

namespace detail {
    // Compile-time string hashing for type safety
    template<size_t N>
    consteval uint64_t hash_string(const char (&str)[N]) noexcept {
        uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
        for (size_t i = 0; i < N - 1; ++i) {
            hash ^= static_cast<uint64_t>(str[i]);
            hash *= 1099511628211ULL;  // FNV prime
        }
        return hash;
    }

    // Compile-time size validation
    template<size_t Size>
    consteval bool validate_crypto_size() noexcept {
        return Size > 0 && Size <= 8192 && (Size & (Size - 1)) == 0;  // Power of 2, reasonable size
    }
}

// ============================================================================
// Type Traits and Metaprogramming
// ============================================================================

template<typename T>
struct is_strong_type : std::false_type {};

template<typename T, typename Tag>
struct is_strong_type<detail::strong_type<T, Tag>> : std::true_type {};

template<typename T>
inline constexpr bool is_strong_type_v = is_strong_type<T>::value;

template<typename T>
concept StrongType = is_strong_type_v<T>;

// Size extraction for strong types
template<StrongType T>
constexpr size_t size_v = std::tuple_size_v<typename T::value_type>;

template<StrongType T>
using element_type_t = typename T::value_type::value_type;

} // namespace ecliptix::core