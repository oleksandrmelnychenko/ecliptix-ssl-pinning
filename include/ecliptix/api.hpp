#pragma once


#include "core/types.hpp"
#include "core/secure_memory.hpp"
#include <span>
#include <string_view>

namespace ecliptix {

using namespace core;
using namespace core::crypto;
using namespace core::memory;


namespace random {
    template<size_t N>
    [[nodiscard]] Result<std::array<std::byte, N>> bytes() noexcept;

    template<ByteSpanLike Container>
    Result<void> fill(Container&& container) noexcept;

    [[nodiscard]] Result<uint32_t> uniform(uint32_t upper_bound) noexcept;

    template<size_t N>
    [[nodiscard]] Result<Key<N>> key() noexcept {
        auto result = bytes<N>();
        if (!result) return std::unexpected(result.error());
        return Key<N>{result.value()};
    }

    template<size_t N>
    [[nodiscard]] Result<Nonce<N>> nonce() noexcept {
        auto result = bytes<N>();
        if (!result) return std::unexpected(result.error());
        return Nonce<N>{result.value()};
    }
}


namespace kdf {
    template<size_t KeySize>
    [[nodiscard]] Result<Key<KeySize>> from_password(
        std::span<const std::byte> password,
        std::span<const std::byte> salt,
        uint32_t ops_limit = 3,
        size_t mem_limit = 67108864
    ) noexcept;

    template<size_t KeySize>
    [[nodiscard]] Result<Key<KeySize>> from_key(
        std::span<const std::byte> input_key,
        std::span<const std::byte> salt,
        std::span<const std::byte> info
    ) noexcept;

    template<size_t... KeySizes>
    [[nodiscard]] Result<std::tuple<Key<KeySizes>...>> derive_multiple(
        std::span<const std::byte> input_key,
        std::span<const std::byte> salt,
        std::span<const std::byte> info
    ) noexcept;
}


namespace aead {
    struct EncryptionResult {
        Ciphertext ciphertext;
        ChaCha20Nonce nonce;

        EncryptionResult() = default;
        EncryptionResult(const EncryptionResult&) = delete;
        EncryptionResult& operator=(const EncryptionResult&) = delete;
        EncryptionResult(EncryptionResult&&) = default;
        EncryptionResult& operator=(EncryptionResult&&) = default;
    };

    [[nodiscard]] Result<EncryptionResult> encrypt(
        std::span<const std::byte> plaintext,
        const ChaCha20Key& key,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    [[nodiscard]] Result<Ciphertext> encrypt_with_nonce(
        std::span<const std::byte> plaintext,
        const ChaCha20Key& key,
        const ChaCha20Nonce& nonce,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    [[nodiscard]] Result<Plaintext> decrypt(
        const Ciphertext& ciphertext,
        const ChaCha20Key& key,
        const ChaCha20Nonce& nonce,
        std::span<const std::byte> associated_data = {}
    ) noexcept;

    [[nodiscard]] Result<Plaintext> decrypt(
        EncryptionResult&& encrypted,
        const ChaCha20Key& key,
        std::span<const std::byte> associated_data = {}
    ) noexcept;
}


namespace signature {
    class KeyPair {
    public:
        KeyPair() noexcept;
        ~KeyPair() = default;

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

    [[nodiscard]] Result<Ed25519Signature> sign(
        std::span<const std::byte> message,
        const Ed25519PrivateKey& private_key
    ) noexcept;

    [[nodiscard]] Result<void> verify(
        std::span<const std::byte> message,
        const Ed25519Signature& signature,
        const Ed25519PublicKey& public_key
    ) noexcept;

    template<size_t N>
    [[nodiscard]] Result<std::array<bool, N>> batch_verify(
        std::span<const std::span<const std::byte>, N> messages,
        std::span<const Ed25519Signature, N> signatures,
        std::span<const Ed25519PublicKey, N> public_keys
    ) noexcept;
}


namespace hash {
    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    [[nodiscard]] Result<Hash<DigestSize>> blake2b(
        std::span<const std::byte> data
    ) noexcept requires(DigestSize >= BLAKE2B_MIN_SIZE && DigestSize <= BLAKE2B_MAX_SIZE);

    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    [[nodiscard]] Result<Hash<DigestSize>> blake2b_keyed(
        std::span<const std::byte> data,
        std::span<const std::byte> key
    ) noexcept requires(DigestSize >= BLAKE2B_MIN_SIZE && DigestSize <= BLAKE2B_MAX_SIZE);

    template<size_t DigestSize = BLAKE2B_DEFAULT_SIZE>
    class IncrementalHasher {
    public:
        IncrementalHasher() noexcept;
        explicit IncrementalHasher(std::span<const std::byte> key) noexcept;

        Result<void> update(std::span<const std::byte> data) noexcept;
        [[nodiscard]] Result<Hash<DigestSize>> finalize() noexcept;

        IncrementalHasher(const IncrementalHasher&) = delete;
        IncrementalHasher& operator=(const IncrementalHasher&) = delete;
        IncrementalHasher(IncrementalHasher&&) = default;
        IncrementalHasher& operator=(IncrementalHasher&&) = default;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}


namespace ssl {
    struct ValidationResult {
        bool valid;
        bool hostname_matches;
        bool pin_matches;
        bool time_valid;
        std::string_view error_message;
    };

    [[nodiscard]] Result<ValidationResult> validate_certificate(
        std::span<const std::byte> certificate_der,
        std::string_view hostname
    ) noexcept;

    [[nodiscard]] Result<bool> check_pin(
        std::span<const std::byte> certificate_der
    ) noexcept;

    [[nodiscard]] Result<void> update_pin(
        const SslPin& new_pin,
        const Ed25519Signature& update_signature
    ) noexcept;

    [[nodiscard]] Result<SslPin> extract_pin(
        std::span<const std::byte> certificate_der
    ) noexcept;
}


namespace util {
    template<size_t N>
    [[nodiscard]] constexpr std::array<char, N * 2> to_hex(
        std::span<const std::byte, N> data
    ) noexcept;

    template<size_t N>
    [[nodiscard]] Result<std::array<std::byte, N>> from_hex(
        std::string_view hex
    ) noexcept;

    [[nodiscard]] Result<std::string> to_base64(
        std::span<const std::byte> data
    ) noexcept;

    [[nodiscard]] Result<SecureBytes> from_base64(
        std::string_view base64
    ) noexcept;

    [[nodiscard]] bool constant_time_equals(
        std::span<const std::byte> a,
        std::span<const std::byte> b
    ) noexcept;
}


namespace library {
    [[nodiscard]] Result<void> initialize() noexcept;

    void shutdown() noexcept;

    [[nodiscard]] Result<void> self_test() noexcept;

    struct VersionInfo {
        uint16_t major;
        uint16_t minor;
        uint16_t patch;
        std::string_view build_date;
        std::string_view commit_hash;
    };

    [[nodiscard]] VersionInfo version() noexcept;

    class Manager {
    public:
        Manager();
        ~Manager();

        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = delete;
        Manager& operator=(Manager&&) = delete;

        void self_test();

    private:
        bool initialized_;
    };
}


using AESKey = Key<32>;
using EncryptionKey = ChaCha20Key;
using MACKey = Key<32>;

namespace make {
    [[nodiscard]] inline Result<std::pair<EncryptionKey, ChaCha20Nonce>> encryption_pair() noexcept {
        auto key_result = random::key<CHACHA20_KEY_SIZE>();
        if (!key_result) return std::unexpected(key_result.error());

        auto nonce_result = random::nonce<CHACHA20_NONCE_SIZE>();
        if (!nonce_result) return std::unexpected(nonce_result.error());

        return std::make_pair(std::move(key_result.value()), std::move(nonce_result.value()));
    }

    [[nodiscard]] inline Result<signature::KeyPair> signature_keypair() noexcept {
        return signature::KeyPair{};
    }
}

}