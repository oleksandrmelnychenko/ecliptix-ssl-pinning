#pragma once

/*
 * Ecliptix Security Library - Minimal API
 * World-class design: Minimal, orthogonal, type-safe, high-performance
 *
 * Design Principles:
 * - Each function does exactly one thing
 * - Strong types prevent misuse
 * - Zero-cost abstractions with optimal codegen
 * - Perfect error handling with std::expected
 * - Move semantics and perfect forwarding throughout
 * - Composable operations for complex workflows
 */

#include "core/types.hpp"
#include "core/secure_memory.hpp"
#include <span>
#include <string_view>

namespace ecliptix {

// Bring core types into main namespace for convenience
using namespace core;
using namespace core::crypto;
using namespace core::memory;

// ============================================================================
// Random Number Generation - Foundation of all crypto
// ============================================================================

namespace random {
    /**
     * Generate cryptographically secure random bytes
     * Zero allocations, optimal performance
     */
    template<size_t N>
    [[nodiscard]] Result<std::array<std::byte, N>> bytes() noexcept;

    /**
     * Fill existing container with random bytes
     * Works with any contiguous container
     */
    template<ByteSpanLike Container>
    Result<void> fill(Container&& container) noexcept;

    /**
     * Generate random integer in range [0, upper_bound)
     * Uniform distribution, no bias
     */
    [[nodiscard]] Result<uint32_t> uniform(uint32_t upper_bound) noexcept;

    /**
     * Generate secure random key of specified size
     * Returns strongly-typed key to prevent misuse
     */
    template<size_t N>
    [[nodiscard]] Result<Key<N>> key() noexcept {
        auto result = bytes<N>();
        if (!result) return std::unexpected(result.error());
        return Key<N>{result.value()};
    }

    /**
     * Generate secure random nonce of specified size
     * Returns strongly-typed nonce to prevent reuse
     */
    template<size_t N>
    [[nodiscard]] Result<Nonce<N>> nonce() noexcept {
        auto result = bytes<N>();
        if (!result) return std::unexpected(result.error());
        return Nonce<N>{result.value()};
    }
}

// ============================================================================
// Key Derivation - Secure key management
// ============================================================================

namespace kdf {
    /**
     * Derive key from password using Argon2id
     * Recommended for password-based encryption
     */
    template<size_t KeySize>
    [[nodiscard]] Result<Key<KeySize>> from_password(
        std::span<const std::byte> password,
        std::span<const std::byte> salt,
        uint32_t ops_limit = 3,      // Interactive default
        size_t mem_limit = 67108864  // 64MB default
    ) noexcept;

    /**
     * Derive key from existing key material using HKDF
     * Recommended for key stretching and domain separation
     */
    template<size_t KeySize>
    [[nodiscard]] Result<Key<KeySize>> from_key(
        std::span<const std::byte> input_key,
        std::span<const std::byte> salt,
        std::span<const std::byte> info
    ) noexcept;

    /**
     * Derive multiple keys from single input
     * Atomic operation - either all succeed or all fail
     */
    template<size_t... KeySizes>
    [[nodiscard]] Result<std::tuple<Key<KeySizes>...>> derive_multiple(
        std::span<const std::byte> input_key,
        std::span<const std::byte> salt,
        std::span<const std::byte> info
    ) noexcept;
}

// ============================================================================
// Authenticated Encryption - Confidentiality + Authenticity
// ============================================================================

namespace aead {
    /**
     * Encryption result with nonce
     * Designed for optimal move semantics
     */
    struct EncryptionResult {
        Ciphertext ciphertext;
        ChaCha20Nonce nonce;

        // Move-only type for performance
        EncryptionResult() = default;
        EncryptionResult(const EncryptionResult&) = delete;
        EncryptionResult& operator=(const EncryptionResult&) = delete;
        EncryptionResult(EncryptionResult&&) = default;
        EncryptionResult& operator=(EncryptionResult&&) = default;
    };

    /**
     * Encrypt data with automatic nonce generation
     * ChaCha20-Poly1305 - fastest, most secure AEAD
     */
    [[nodiscard]] Result<EncryptionResult> encrypt(
        std::span<const std::byte> plaintext,
        const ChaCha20Key& key,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    /**
     * Encrypt data with explicit nonce (advanced usage)
     * Use only when you have secure nonce management
     */
    [[nodiscard]] Result<Ciphertext> encrypt_with_nonce(
        std::span<const std::byte> plaintext,
        const ChaCha20Key& key,
        const ChaCha20Nonce& nonce,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    /**
     * Decrypt data and verify authenticity
     * Constant-time operation to prevent timing attacks
     */
    [[nodiscard]] Result<Plaintext> decrypt(
        const Ciphertext& ciphertext,
        const ChaCha20Key& key,
        const ChaCha20Nonce& nonce,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    /**
     * Decrypt from EncryptionResult (convenience)
     * Zero-copy when possible
     */
    [[nodiscard]] Result<Plaintext> decrypt(
        EncryptionResult&& encrypted,
        const ChaCha20Key& key,
        std::span<const std::byte> associated_data = {}
    ) noexcept;
}

// ============================================================================
// Digital Signatures - Authentication and Non-repudiation
// ============================================================================

namespace signature {
    /**
     * Ed25519 key pair with secure private key storage
     * Private key automatically wiped on destruction
     */
    class KeyPair {
    public:
        KeyPair() noexcept;  // Generate new key pair
        ~KeyPair() = default;

        // Move-only for security
        KeyPair(const KeyPair&) = delete;
        KeyPair& operator=(const KeyPair&) = delete;
        KeyPair(KeyPair&&) = default;
        KeyPair& operator=(KeyPair&&) = default;

        [[nodiscard]] const Ed25519PublicKey& public_key() const noexcept { return public_key_; }
        [[nodiscard]] const Ed25519PrivateKey& private_key() const noexcept { return private_key_; }

    private:
        Ed25519PublicKey public_key_;
        Ed25519PrivateKey private_key_;
    };

    /**
     * Sign data with Ed25519 private key
     * Deterministic, fast, secure
     */
    [[nodiscard]] Result<Ed25519Signature> sign(
        std::span<const std::byte> message,
        const Ed25519PrivateKey& private_key
    ) noexcept;

    /**
     * Verify Ed25519 signature
     * Constant-time operation, batch-verifiable
     */
    [[nodiscard]] Result<void> verify(
        std::span<const std::byte> message,
        const Ed25519Signature& signature,
        const Ed25519PublicKey& public_key
    ) noexcept;

    /**
     * Batch verify multiple signatures (performance optimization)
     * Faster than individual verification for multiple signatures
     */
    template<size_t N>
    [[nodiscard]] Result<std::array<bool, N>> batch_verify(
        std::span<const std::span<const std::byte>, N> messages,
        std::span<const Ed25519Signature, N> signatures,
        std::span<const Ed25519PublicKey, N> public_keys
    ) noexcept;
}

// ============================================================================
// Cryptographic Hashing - Integrity and Fingerprinting
// ============================================================================

namespace hash {
    /**
     * Blake2b hash - faster and more secure than SHA-2
     * Configurable output size for different use cases
     */
    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    [[nodiscard]] Result<Hash<DigestSize>> blake2b(
        std::span<const std::byte> data
    ) noexcept requires(DigestSize >= BLAKE2B_MIN_SIZE && DigestSize <= BLAKE2B_MAX_SIZE);

    /**
     * Keyed Blake2b hash (MAC) - message authentication
     * Preferred over HMAC for new applications
     */
    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    [[nodiscard]] Result<Hash<DigestSize>> blake2b_keyed(
        std::span<const std::byte> data,
        std::span<const std::byte> key
    ) noexcept requires(DigestSize >= BLAKE2B_MIN_SIZE && DigestSize <= BLAKE2B_MAX_SIZE);

    /**
     * Incremental hashing for large data
     * Memory-efficient for streaming data
     */
    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    class IncrementalHasher {
    public:
        IncrementalHasher() noexcept;
        explicit IncrementalHasher(std::span<const std::byte> key) noexcept;

        Result<void> update(std::span<const std::byte> data) noexcept;
        [[nodiscard]] Result<Hash<DigestSize>> finalize() noexcept;

        // Move-only
        IncrementalHasher(const IncrementalHasher&) = delete;
        IncrementalHasher& operator=(const IncrementalHasher&) = delete;
        IncrementalHasher(IncrementalHasher&&) = default;
        IncrementalHasher& operator=(IncrementalHasher&&) = default;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}

// ============================================================================
// SSL Certificate Validation - Transport Security
// ============================================================================

namespace ssl {
    /**
     * Certificate validation result
     * Provides detailed information about validation
     */
    struct ValidationResult {
        bool valid;
        bool hostname_matches;
        bool pin_matches;
        bool time_valid;
        std::string_view error_message;
    };

    /**
     * Validate SSL certificate with pinning
     * Complete validation including hostname, time, and pinning
     */
    [[nodiscard]] Result<ValidationResult> validate_certificate(
        std::span<const std::byte> certificate_der,
        std::string_view hostname
    ) noexcept;

    /**
     * Check certificate against pinned public keys
     * Fast pin-only validation for performance-critical paths
     */
    [[nodiscard]] Result<bool> check_pin(
        std::span<const std::byte> certificate_der
    ) noexcept;

    /**
     * Update certificate pin with authentication
     * Secure pin rotation mechanism
     */
    [[nodiscard]] Result<void> update_pin(
        const SslPin& new_pin,
        const Ed25519Signature& update_signature
    ) noexcept;

    /**
     * Extract public key pin from certificate
     * For manual pin management
     */
    [[nodiscard]] Result<SslPin> extract_pin(
        std::span<const std::byte> certificate_der
    ) noexcept;
}

// ============================================================================
// Utility Functions - Encoding and Conversion
// ============================================================================

namespace util {
    /**
     * Encode binary data to hexadecimal
     * Fast, allocation-free when possible
     */
    template<size_t N>
    [[nodiscard]] constexpr std::array<char, N * 2> to_hex(
        std::span<const std::byte, N> data
    ) noexcept;

    /**
     * Decode hexadecimal to binary data
     * Validates input format
     */
    template<size_t N>
    [[nodiscard]] Result<std::array<std::byte, N>> from_hex(
        std::string_view hex
    ) noexcept;

    /**
     * Encode binary data to Base64
     * Standard Base64 encoding
     */
    [[nodiscard]] Result<std::string> to_base64(
        std::span<const std::byte> data
    ) noexcept;

    /**
     * Decode Base64 to binary data
     * Validates input format and padding
     */
    [[nodiscard]] Result<SecureBytes> from_base64(
        std::string_view base64
    ) noexcept;

    /**
     * Constant-time string comparison
     * Prevents timing attacks on secret comparison
     */
    [[nodiscard]] bool constant_time_equals(
        std::span<const std::byte> a,
        std::span<const std::byte> b
    ) noexcept;
}

// ============================================================================
// Library Management - Initialization and Configuration
// ============================================================================

namespace library {
    /**
     * Library initialization
     * Must be called before any other operations
     */
    [[nodiscard]] Result<void> initialize() noexcept;

    /**
     * Library cleanup
     * Automatically called at program exit if not called explicitly
     */
    void shutdown() noexcept;

    /**
     * Self-test to verify library integrity
     * Comprehensive test of all cryptographic operations
     */
    [[nodiscard]] Result<void> self_test() noexcept;

    /**
     * Get library version information
     * For compatibility checking
     */
    struct VersionInfo {
        uint16_t major;
        uint16_t minor;
        uint16_t patch;
        std::string_view build_date;
        std::string_view commit_hash;
    };

    [[nodiscard]] VersionInfo version() noexcept;

    /**
     * RAII library management
     * Automatic initialization and cleanup
     */
    class Manager {
    public:
        Manager();
        ~Manager();

        // Non-copyable, non-movable
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = delete;
        Manager& operator=(Manager&&) = delete;

        void self_test();

    private:
        bool initialized_;
    };
}

// ============================================================================
// Convenience Aliases and Factory Functions
// ============================================================================

// Common key types
using AESKey = Key<32>;
using EncryptionKey = ChaCha20Key;  // Preferred
using MACKey = Key<32>;

// Factory functions for common operations
namespace make {
    /**
     * Create encryption key pair (key + nonce)
     * For one-time use encryption
     */
    [[nodiscard]] inline Result<std::pair<EncryptionKey, ChaCha20Nonce>> encryption_pair() noexcept {
        auto key_result = random::key<CHACHA20_KEY_SIZE>();
        if (!key_result) return std::unexpected(key_result.error());

        auto nonce_result = random::nonce<CHACHA20_NONCE_SIZE>();
        if (!nonce_result) return std::unexpected(nonce_result.error());

        return std::make_pair(std::move(key_result.value()), std::move(nonce_result.value()));
    }

    /**
     * Create signature key pair
     * For digital signatures
     */
    [[nodiscard]] inline Result<signature::KeyPair> signature_keypair() noexcept {
        return signature::KeyPair{};
    }
}

} // namespace ecliptix