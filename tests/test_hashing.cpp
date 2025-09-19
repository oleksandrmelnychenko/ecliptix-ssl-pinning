/*
 * Ecliptix Security Library - Hashing Tests
 * Tests for Blake2b cryptographic hashing
 */

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/api.hpp"
#include <string>

using namespace ecliptix;

TEST_CASE("Blake2b Basic Hashing", "[hashing][blake2b]") {
    SECTION("Default size hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string message = "Hello, world!";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto hash_result = hash::blake2b(data);
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 32);  // Default size

        library::shutdown();
    }

    SECTION("Different hash sizes") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string message = "Test message";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto hash16 = hash::blake2b<16>(data);
        auto hash32 = hash::blake2b<32>(data);
        auto hash64 = hash::blake2b<64>(data);

        REQUIRE(hash16.has_value());
        REQUIRE(hash32.has_value());
        REQUIRE(hash64.has_value());

        REQUIRE(hash16->get().size() == 16);
        REQUIRE(hash32->get().size() == 32);
        REQUIRE(hash64->get().size() == 64);

        // Different sizes should produce different hashes
        REQUIRE_FALSE(std::equal(
            hash16->get().begin(), hash16->get().end(),
            hash32->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Empty input hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::span<const std::byte> empty_data;

        auto hash_result = hash::blake2b(empty_data);
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 32);

        // Hash should not be all zeros
        bool has_nonzero = false;
        for (auto byte : hash_result->get()) {
            if (byte != std::byte{0}) {
                has_nonzero = true;
                break;
            }
        }
        REQUIRE(has_nonzero);

        library::shutdown();
    }

    SECTION("Deterministic hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string message = "Deterministic test";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto hash1 = hash::blake2b(data);
        auto hash2 = hash::blake2b(data);

        REQUIRE(hash1.has_value());
        REQUIRE(hash2.has_value());

        // Same input should produce same hash
        REQUIRE(std::equal(
            hash1->get().begin(), hash1->get().end(),
            hash2->get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("Blake2b Keyed Hashing (MAC)", "[hashing][mac]") {
    SECTION("Basic keyed hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Message to authenticate";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };
        std::span<const std::byte> key_bytes{
            reinterpret_cast<const std::byte*>(key->get().data()),
            key->get().size()
        };

        auto mac_result = hash::blake2b_keyed(data, key_bytes);
        REQUIRE(mac_result.has_value());
        REQUIRE(mac_result->get().size() == 32);

        library::shutdown();
    }

    SECTION("Different keys produce different MACs") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key1 = random::key<32>();
        auto key2 = random::key<32>();
        REQUIRE(key1.has_value());
        REQUIRE(key2.has_value());

        std::string message = "Same message";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto mac1 = hash::blake2b_keyed(data,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(key1->get().data()),
                key1->get().size()
            });

        auto mac2 = hash::blake2b_keyed(data,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(key2->get().data()),
                key2->get().size()
            });

        REQUIRE(mac1.has_value());
        REQUIRE(mac2.has_value());

        // Different keys should produce different MACs
        REQUIRE_FALSE(std::equal(
            mac1->get().begin(), mac1->get().end(),
            mac2->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Keyed vs unkeyed hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::string message = "Test message";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto unkeyed_hash = hash::blake2b(data);
        auto keyed_hash = hash::blake2b_keyed(data,
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(key->get().data()),
                key->get().size()
            });

        REQUIRE(unkeyed_hash.has_value());
        REQUIRE(keyed_hash.has_value());

        // Keyed and unkeyed hashes should be different
        REQUIRE_FALSE(std::equal(
            unkeyed_hash->get().begin(), unkeyed_hash->get().end(),
            keyed_hash->get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("Blake2b Incremental Hashing", "[hashing][incremental]") {
    SECTION("Basic incremental hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string part1 = "Hello, ";
        std::string part2 = "world!";
        std::string combined = part1 + part2;

        // Hash in parts
        auto hasher = hash::IncrementalHasher<32>{};

        auto update1_result = hasher.update(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(part1.data()),
            part1.size()
        });
        REQUIRE(update1_result.has_value());

        auto update2_result = hasher.update(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(part2.data()),
            part2.size()
        });
        REQUIRE(update2_result.has_value());

        auto incremental_hash = hasher.finalize();
        REQUIRE(incremental_hash.has_value());

        // Hash all at once
        auto direct_hash = hash::blake2b(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(combined.data()),
            combined.size()
        });
        REQUIRE(direct_hash.has_value());

        // Results should be the same
        REQUIRE(std::equal(
            incremental_hash->get().begin(), incremental_hash->get().end(),
            direct_hash->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Incremental keyed hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        auto key = random::key<32>();
        REQUIRE(key.has_value());

        std::span<const std::byte> key_bytes{
            reinterpret_cast<const std::byte*>(key->get().data()),
            key->get().size()
        };

        std::string part1 = "First part";
        std::string part2 = "Second part";
        std::string combined = part1 + part2;

        // Incremental keyed hashing
        auto hasher = hash::IncrementalHasher<32>{key_bytes};

        hasher.update(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(part1.data()),
            part1.size()
        });

        hasher.update(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(part2.data()),
            part2.size()
        });

        auto incremental_mac = hasher.finalize();
        REQUIRE(incremental_mac.has_value());

        // Direct keyed hashing
        auto direct_mac = hash::blake2b_keyed(
            std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(combined.data()),
                combined.size()
            },
            key_bytes
        );
        REQUIRE(direct_mac.has_value());

        // Results should be the same
        REQUIRE(std::equal(
            incremental_mac->get().begin(), incremental_mac->get().end(),
            direct_mac->get().begin()
        ));

        library::shutdown();
    }

    SECTION("Large data incremental hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        // Create large test data
        const size_t chunk_size = 1024;
        const size_t num_chunks = 100;
        std::vector<uint8_t> large_data(chunk_size * num_chunks);

        // Fill with pattern
        for (size_t i = 0; i < large_data.size(); ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Hash incrementally
        auto hasher = hash::IncrementalHasher<32>{};

        for (size_t i = 0; i < num_chunks; ++i) {
            std::span<const std::byte> chunk{
                reinterpret_cast<const std::byte*>(&large_data[i * chunk_size]),
                chunk_size
            };
            auto result = hasher.update(chunk);
            REQUIRE(result.has_value());
        }

        auto incremental_hash = hasher.finalize();
        REQUIRE(incremental_hash.has_value());

        // Hash all at once
        auto direct_hash = hash::blake2b(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(large_data.data()),
            large_data.size()
        });
        REQUIRE(direct_hash.has_value());

        // Results should be the same
        REQUIRE(std::equal(
            incremental_hash->get().begin(), incremental_hash->get().end(),
            direct_hash->get().begin()
        ));

        library::shutdown();
    }
}

TEST_CASE("Blake2b Edge Cases", "[hashing][edge]") {
    SECTION("Single byte hashing") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        uint8_t single_byte = 0x42;
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(&single_byte),
            1
        };

        auto hash_result = hash::blake2b(data);
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 32);

        library::shutdown();
    }

    SECTION("Maximum size hash") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string message = "Max size test";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto hash_result = hash::blake2b<64>(data);  // Maximum Blake2b output size
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 64);

        library::shutdown();
    }

    SECTION("Minimum size hash") {
        auto lib_result = library::initialize();
        REQUIRE(lib_result.has_value());

        std::string message = "Min size test";
        std::span<const std::byte> data{
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        };

        auto hash_result = hash::blake2b<16>(data);  // Minimum Blake2b output size
        REQUIRE(hash_result.has_value());
        REQUIRE(hash_result->get().size() == 16);

        library::shutdown();
    }
}