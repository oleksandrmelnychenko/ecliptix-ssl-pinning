#pragma once


#include "types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <new>
#include <atomic>

#ifdef _WIN32
    #include <windows.h>
    #include <memoryapi.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

namespace ecliptix::core::memory {


namespace detail {
    inline void secure_wipe_impl(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;

#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
        explicit_bzero(ptr, size);
#elif defined(_WIN32)
        SecureZeroMemory(ptr, size);
#else
        volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            vptr[i] = 0;
        }

        std::atomic_thread_fence(std::memory_order_release);

        asm volatile("" : : "r"(ptr) : "memory");
#endif
    }

    [[nodiscard]] inline bool lock_memory_impl(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return false;

#ifdef _WIN32
        return VirtualLock(ptr, size) != 0;
#else
        return mlock(ptr, size) == 0;
#endif
    }

    inline bool unlock_memory_impl(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return true;

#ifdef _WIN32
        return VirtualUnlock(ptr, size) != 0;
#else
        return munlock(ptr, size) == 0;
#endif
    }

    inline size_t get_page_size() noexcept {
        static const size_t page_size = []() {
#ifdef _WIN32
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            return static_cast<size_t>(si.dwPageSize);
#else
            return static_cast<size_t>(getpagesize());
#endif
        }();
        return page_size;
    }

    constexpr size_t align_to_page(size_t size) noexcept {
        const size_t page_size = 4096;
        return (size + page_size - 1) & ~(page_size - 1);
    }

    inline constexpr size_t cache_line_size = std::hardware_destructive_interference_size;
}


template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    constexpr SecureAllocator() noexcept = default;

    template<typename U>
    constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(size_type n) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }

        const size_type bytes = n * sizeof(T);
        const size_type aligned_bytes = detail::align_to_page(bytes);

        void* ptr = std::aligned_alloc(detail::cache_line_size, aligned_bytes);
        if (!ptr) {
            throw std::bad_alloc();
        }

        if (!detail::lock_memory_impl(ptr, aligned_bytes)) {
            std::free(ptr);
            throw std::bad_alloc();
        }

        detail::secure_wipe_impl(ptr, aligned_bytes);

        return static_cast<T*>(ptr);
    }

    void deallocate(T* ptr, size_type n) noexcept {
        if (!ptr) return;

        const size_type bytes = n * sizeof(T);
        const size_type aligned_bytes = detail::align_to_page(bytes);

        detail::secure_wipe_impl(ptr, aligned_bytes);

        detail::unlock_memory_impl(ptr, aligned_bytes);

        std::free(ptr);
    }

    template<typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template<typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};


template<typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;


class SecureBytes {
public:
    using value_type = std::byte;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = std::byte&;
    using const_reference = const std::byte&;
    using pointer = std::byte*;
    using const_pointer = const std::byte*;
    using iterator = typename SecureVector<std::byte>::iterator;
    using const_iterator = typename SecureVector<std::byte>::const_iterator;

    SecureBytes() = default;

    explicit SecureBytes(size_type count) : data_(count) {}

    SecureBytes(size_type count, const std::byte& value) : data_(count, value) {}

    template<typename InputIt>
    SecureBytes(InputIt first, InputIt last) : data_(first, last) {}

    SecureBytes(std::initializer_list<std::byte> init) : data_(init) {}

    template<ByteSpanLike T>
    explicit SecureBytes(T&& container) {
        auto span = std::span{container};
        data_.reserve(span.size());
        std::transform(span.begin(), span.end(), std::back_inserter(data_),
                      [](auto byte) { return std::byte{static_cast<unsigned char>(byte)}; });
    }

    SecureBytes(const SecureBytes& other) : data_(other.data_) {}

    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {}

    ~SecureBytes() {
        secure_wipe();
    }

    SecureBytes& operator=(const SecureBytes& other) {
        if (this != &other) {
            secure_wipe();
            data_ = other.data_;
        }
        return *this;
    }

    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            secure_wipe();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] size_type size() const noexcept { return data_.size(); }
    [[nodiscard]] size_type capacity() const noexcept { return data_.capacity(); }
    [[nodiscard]] size_type max_size() const noexcept { return data_.max_size(); }

    void reserve(size_type new_cap) { data_.reserve(new_cap); }
    void shrink_to_fit() { data_.shrink_to_fit(); }

    [[nodiscard]] reference at(size_type pos) { return data_.at(pos); }
    [[nodiscard]] const_reference at(size_type pos) const { return data_.at(pos); }

    [[nodiscard]] reference operator[](size_type pos) noexcept { return data_[pos]; }
    [[nodiscard]] const_reference operator[](size_type pos) const noexcept { return data_[pos]; }

    [[nodiscard]] reference front() noexcept { return data_.front(); }
    [[nodiscard]] const_reference front() const noexcept { return data_.front(); }

    [[nodiscard]] reference back() noexcept { return data_.back(); }
    [[nodiscard]] const_reference back() const noexcept { return data_.back(); }

    [[nodiscard]] pointer data() noexcept { return data_.data(); }
    [[nodiscard]] const_pointer data() const noexcept { return data_.data(); }

    [[nodiscard]] iterator begin() noexcept { return data_.begin(); }
    [[nodiscard]] const_iterator begin() const noexcept { return data_.begin(); }
    [[nodiscard]] const_iterator cbegin() const noexcept { return data_.cbegin(); }

    [[nodiscard]] iterator end() noexcept { return data_.end(); }
    [[nodiscard]] const_iterator end() const noexcept { return data_.end(); }
    [[nodiscard]] const_iterator cend() const noexcept { return data_.cend(); }

    void clear() noexcept {
        secure_wipe();
        data_.clear();
    }

    void resize(size_type count) {
        data_.resize(count);
    }

    void resize(size_type count, const std::byte& value) {
        data_.resize(count, value);
    }

    void push_back(const std::byte& value) {
        data_.push_back(value);
    }

    void pop_back() noexcept {
        data_.pop_back();
    }

    template<typename... Args>
    reference emplace_back(Args&&... args) {
        return data_.emplace_back(std::forward<Args>(args)...);
    }

    void secure_wipe() noexcept {
        if (!data_.empty()) {
            detail::secure_wipe_impl(data_.data(), data_.size());
        }
    }

    [[nodiscard]] bool secure_equals(const SecureBytes& other) const noexcept {
        if (size() != other.size()) {
            return false;
        }

        volatile unsigned char result = 0;
        const auto* a = reinterpret_cast<const volatile unsigned char*>(data());
        const auto* b = reinterpret_cast<const volatile unsigned char*>(other.data());

        for (size_type i = 0; i < size(); ++i) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }

    [[nodiscard]] std::span<std::byte> span() noexcept {
        return {data_.data(), data_.size()};
    }

    [[nodiscard]] std::span<const std::byte> span() const noexcept {
        return {data_.data(), data_.size()};
    }

    template<typename T>
    [[nodiscard]] std::span<T> as_span() noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        return {reinterpret_cast<T*>(data_.data()), size() / sizeof(T)};
    }

    template<typename T>
    [[nodiscard]] std::span<const T> as_span() const noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        return {reinterpret_cast<const T*>(data_.data()), size() / sizeof(T)};
    }

    bool operator==(const SecureBytes& other) const noexcept {
        return secure_equals(other);
    }

    bool operator!=(const SecureBytes& other) const noexcept {
        return !secure_equals(other);
    }

private:
    SecureVector<std::byte> data_;
};


class MemoryLock {
public:
    explicit MemoryLock(void* ptr, size_t size) noexcept
        : ptr_(ptr), size_(size), locked_(false) {
        if (ptr_ && size_ > 0) {
            locked_ = detail::lock_memory_impl(ptr_, size_);
        }
    }

    ~MemoryLock() noexcept {
        if (locked_) {
            detail::unlock_memory_impl(ptr_, size_);
        }
    }

    MemoryLock(const MemoryLock&) = delete;
    MemoryLock& operator=(const MemoryLock&) = delete;

    MemoryLock(MemoryLock&& other) noexcept
        : ptr_(other.ptr_), size_(other.size_), locked_(other.locked_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
        other.locked_ = false;
    }

    MemoryLock& operator=(MemoryLock&& other) noexcept {
        if (this != &other) {
            if (locked_) {
                detail::unlock_memory_impl(ptr_, size_);
            }
            ptr_ = other.ptr_;
            size_ = other.size_;
            locked_ = other.locked_;
            other.ptr_ = nullptr;
            other.size_ = 0;
            other.locked_ = false;
        }
        return *this;
    }

    [[nodiscard]] bool is_locked() const noexcept { return locked_; }

private:
    void* ptr_;
    size_t size_;
    bool locked_;
};

inline void secure_wipe(void* ptr, size_t size) noexcept {
    detail::secure_wipe_impl(ptr, size);
}

inline bool constant_time_equals(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) return false;

    volatile unsigned char result = 0;
    const auto* va = static_cast<const volatile unsigned char*>(a);
    const auto* vb = static_cast<const volatile unsigned char*>(b);

    for (size_t i = 0; i < size; ++i) {
        result |= va[i] ^ vb[i];
    }

    return result == 0;
}

}