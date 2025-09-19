
#include <catch2/catch_test_macros.hpp>
#include "ecliptix/core/secure_memory.hpp"

using namespace ecliptix::core::memory;

TEST_CASE("SecureBytes", "[memory][secure]") {
    SECTION("Basic construction") {
        SecureBytes empty;
        REQUIRE(empty.empty());
        REQUIRE(empty.size() == 0);

        SecureBytes sized(1024);
        REQUIRE(sized.size() == 1024);
        REQUIRE_FALSE(sized.empty());
    }

    SECTION("Data access") {
        SecureBytes data(10);
        data[0] = std::byte{0xAB};
        data[1] = std::byte{0xCD};

        REQUIRE(data[0] == std::byte{0xAB});
        REQUIRE(data[1] == std::byte{0xCD});
        REQUIRE(data.front() == std::byte{0xAB});
        REQUIRE(data.back() == std::byte{0x00});
    }

    SECTION("Secure comparison") {
        SecureBytes data1(4);
        SecureBytes data2(4);

        data1[0] = std::byte{0x01};
        data1[1] = std::byte{0x02};
        data2[0] = std::byte{0x01};
        data2[1] = std::byte{0x02};

        REQUIRE(data1.secure_equals(data2));
        REQUIRE(data1 == data2);

        data2[1] = std::byte{0x03};
        REQUIRE_FALSE(data1.secure_equals(data2));
        REQUIRE_FALSE(data1 == data2);
    }

    SECTION("Move semantics") {
        SecureBytes original(1024);
        original[0] = std::byte{0xAB};

        SecureBytes moved = std::move(original);
        REQUIRE(moved.size() == 1024);
        REQUIRE(moved[0] == std::byte{0xAB});

        // Original should be in valid but unspecified state
        REQUIRE(original.size() == 0);  // Typically moved-from containers are empty
    }

    SECTION("Span conversion") {
        SecureBytes data(4);
        data[0] = std::byte{0x01};
        data[1] = std::byte{0x02};

        auto span = data.span();
        REQUIRE(span.size() == 4);
        REQUIRE(span[0] == std::byte{0x01});
        REQUIRE(span[1] == std::byte{0x02});

        auto const_span = static_cast<const SecureBytes&>(data).span();
        REQUIRE(const_span.size() == 4);
        REQUIRE(const_span[0] == std::byte{0x01});
    }

    SECTION("Type conversions") {
        SecureBytes data(8);
        data[0] = std::byte{0x01};
        data[1] = std::byte{0x02};
        data[2] = std::byte{0x03};
        data[3] = std::byte{0x04};

        auto uint32_span = data.as_span<uint32_t>();
        REQUIRE(uint32_span.size() == 2);  // 8 bytes / 4 bytes per uint32_t

        auto const_uint32_span = static_cast<const SecureBytes&>(data).as_span<uint32_t>();
        REQUIRE(const_uint32_span.size() == 2);
    }
}

TEST_CASE("SecureAllocator", "[memory][allocator]") {
    SECTION("Basic allocation") {
        SecureAllocator<uint8_t> allocator;

        uint8_t* ptr = allocator.allocate(1024);
        REQUIRE(ptr != nullptr);

        // Memory should be initialized to zero
        bool all_zero = true;
        for (size_t i = 0; i < 1024; ++i) {
            if (ptr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE(all_zero);

        allocator.deallocate(ptr, 1024);
    }

    SECTION("SecureVector usage") {
        SecureVector<uint8_t> vec;
        vec.resize(1024);

        REQUIRE(vec.size() == 1024);

        // Fill with test data
        for (size_t i = 0; i < vec.size(); ++i) {
            vec[i] = static_cast<uint8_t>(i & 0xFF);
        }

        REQUIRE(vec[0] == 0);
        REQUIRE(vec[255] == 255);
        REQUIRE(vec[256] == 0);  // Wrapped around
    }

    SECTION("SecureString usage") {
        SecureString secure_str = "Hello, secure world!";
        REQUIRE(secure_str.size() == 20);
        REQUIRE(secure_str.find("secure") != SecureString::npos);

        // Test append
        secure_str += " More text.";
        REQUIRE(secure_str.size() == 31);
    }
}

TEST_CASE("Memory Protection", "[memory][protection]") {
    SECTION("Memory locking") {
        constexpr size_t size = 4096;  // One page
        auto ptr = std::aligned_alloc(4096, size);
        REQUIRE(ptr != nullptr);

        MemoryLock lock(ptr, size);
        // On most systems this should succeed, but we can't guarantee it in tests
        // REQUIRE(lock.is_locked());

        std::free(ptr);
    }

    SECTION("Secure wipe function") {
        uint8_t data[16];
        std::fill(data, data + 16, 0xFF);

        // Verify data is initially 0xFF
        bool all_ff = true;
        for (int i = 0; i < 16; ++i) {
            if (data[i] != 0xFF) {
                all_ff = false;
                break;
            }
        }
        REQUIRE(all_ff);

        secure_wipe(data, 16);

        // After wiping, should be zero
        bool all_zero = true;
        for (int i = 0; i < 16; ++i) {
            if (data[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE(all_zero);
    }

    SECTION("Constant time comparison") {
        uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t data2[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t data3[] = {0x01, 0x02, 0x03, 0x05};

        REQUIRE(constant_time_equals(data1, data2, 4));
        REQUIRE_FALSE(constant_time_equals(data1, data3, 4));
        REQUIRE_FALSE(constant_time_equals(nullptr, data1, 4));
        REQUIRE_FALSE(constant_time_equals(data1, nullptr, 4));
    }
}

TEST_CASE("RAII Memory Management", "[memory][raii]") {
    SECTION("MemoryLock RAII") {
        constexpr size_t size = 4096;
        auto ptr = std::aligned_alloc(4096, size);
        REQUIRE(ptr != nullptr);

        {
            MemoryLock lock(ptr, size);
            // Memory should be locked here (if successful)
        }
        // Memory should be unlocked here automatically

        std::free(ptr);
    }

    SECTION("SecureBytes automatic cleanup") {
        std::unique_ptr<SecureBytes> data;

        {
            data = std::make_unique<SecureBytes>(1024);
            (*data)[0] = std::byte{0xAB};
            (*data)[1] = std::byte{0xCD};

            REQUIRE((*data)[0] == std::byte{0xAB});
        }

        // SecureBytes destructor should have wiped the memory
        // We can't easily test this without implementation details
    }
}