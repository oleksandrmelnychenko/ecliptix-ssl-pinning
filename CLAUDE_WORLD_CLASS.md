# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Ecliptix Security Library** is a world-class C++23 cryptographic library designed with security-first principles. It provides SSL certificate pinning, authenticated encryption, digital signatures, and secure hashing with **guaranteed memory security** and **zero-cost abstractions**.

## 🚀 **World-Class Architecture (New)**

### Core Design Principles

1. **Type Safety First**: Strong types make invalid states unrepresentable
2. **Zero-Cost Abstractions**: Every abstraction compiles to optimal code
3. **Guaranteed Memory Security**: Compiler-proof memory wiping, locked pages
4. **Perfect Error Handling**: std::expected throughout, no exceptions mixing
5. **Modern C++23**: Concepts, ranges, constexpr, perfect forwarding
6. **Minimal API Surface**: Orthogonal, composable operations

### Development Commands

```bash
# Build with C++23 support (requires GCC 13+ or Clang 16+)
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=g++-13 .. && make -j4

# Run world-class demo
./bin/ecliptix_world_class_demo

# Run legacy demo (for compatibility)
./bin/ecliptix_demo
```

### Key Dependencies

- **C++23 Compiler**: GCC 13+, Clang 16+, or MSVC 2022 17.8+
- **libsodium**: Memory-safe cryptographic operations
- **OpenSSL**: SSL/TLS certificate handling (legacy support)
- **CMake 3.20+**: Build system

## 🎯 **New API Architecture**

### Core Type System (`include/ecliptix/core/types.hpp`)

**Strong Types Prevent Misuse:**
```cpp
// These are different types - cannot be mixed up
ChaCha20Key encryption_key = random::key<32>().value();
ChaCha20Nonce nonce = random::nonce<12>().value();
Ed25519Signature signature = sign(message, private_key).value();

// Compilation errors prevent mistakes:
// aead::encrypt(plaintext, nonce, key);  // ERROR: Wrong parameter order
// signature::verify(message, encryption_key, public_key);  // ERROR: Wrong key type
```

**Template Concepts for Safety:**
```cpp
template<CryptographicKey KeyType>
auto encrypt_with_key(std::span<const std::byte> data, const KeyType& key);

template<ByteSpanLike Container>
auto hash_container(Container&& container);
```

### Secure Memory Management (`include/ecliptix/core/secure_memory.hpp`)

**Guaranteed Memory Erasure:**
```cpp
SecureBytes sensitive_data(1024);  // Automatically locked in memory
// Data is guaranteed to be wiped on destruction - cannot be optimized away

SecureAllocator<uint8_t> allocator;  // For standard containers
SecureVector<uint8_t> secure_vector;  // Secure std::vector equivalent
```

**Memory Protection:**
```cpp
MemoryLock lock(ptr, size);  // RAII memory locking
secure_wipe(ptr, size);      // Compiler-proof wiping
constant_time_equals(a, b, size);  // Timing-attack resistant comparison
```

### Minimal API (`include/ecliptix/api.hpp`)

**Perfect Encryption (ChaCha20-Poly1305):**
```cpp
// Generate key and encrypt (move semantics, zero-copy)
auto key = random::key<32>().value();
auto encrypted = aead::encrypt(plaintext, key, associated_data).value();

// Decrypt with automatic verification
auto decrypted = aead::decrypt(std::move(encrypted), key, associated_data).value();
```

**Digital Signatures (Ed25519):**
```cpp
// Generate key pair (private key stored securely)
auto keypair = signature::KeyPair{};

// Sign and verify
auto signature = signature::sign(message, keypair.private_key()).value();
auto valid = signature::verify(message, signature, keypair.public_key());
```

**High-Performance Hashing (Blake2b):**
```cpp
// Fast, secure hashing
auto hash = hash::blake2b<32>(data).value();

// Keyed MAC
auto mac = hash::blake2b_keyed<32>(data, key).value();

// Incremental hashing for large data
auto hasher = hash::IncrementalHasher<32>{};
hasher.update(chunk1).value();
hasher.update(chunk2).value();
auto final_hash = hasher.finalize().value();
```

**Key Derivation:**
```cpp
// From password (Argon2id)
auto key = kdf::from_password<32>(password, salt).value();

// From existing key (HKDF)
auto derived = kdf::from_key<32>(input_key, salt, info).value();

// Multiple keys atomically
auto [key1, key2, key3] = kdf::derive_multiple<32, 16, 64>(input, salt, info).value();
```

## 🔒 **Security Features**

### Cryptographic Algorithms

- **ChaCha20-Poly1305**: Authenticated encryption (recommended)
- **Ed25519**: Digital signatures (fastest, most secure)
- **Blake2b**: Cryptographic hashing (faster than SHA-2)
- **Argon2id**: Password-based key derivation
- **HKDF**: Key stretching and domain separation

### Memory Security

- **Guaranteed Erasure**: Compiler cannot optimize away memory wiping
- **Page Locking**: Prevents swapping to disk (`mlock`/`VirtualLock`)
- **Constant-Time Operations**: Prevents timing attacks
- **Secure Allocation**: Cache-aligned, automatically wiped
- **RAII Patterns**: Automatic cleanup, exception-safe

### Type Safety

- **Strong Types**: Prevent parameter confusion at compile time
- **Concepts**: Template constraints for additional safety
- **Impossible States**: Invalid operations caught at compile time
- **Zero-Cost**: No runtime overhead for type safety

## 📁 **File Structure**

```
include/ecliptix/
├── core/
│   ├── types.hpp           # Strong type system, concepts, error handling
│   └── secure_memory.hpp   # Guaranteed secure memory management
├── api.hpp                 # Main world-class API (use this!)
├── security.h              # Legacy C API (compatibility)
├── security.hpp            # Legacy C++ API (compatibility)
└── public_api.h            # Simplified legacy API (compatibility)

examples/
├── world_class_demo.cpp    # Comprehensive demo of new API
└── simple_usage.cpp       # Basic usage examples (legacy)

src/
├── security.cpp            # Legacy implementation
└── openssl_wrapper.cpp    # SSL/TLS certificate handling
```

## 🎯 **Usage Patterns**

### Recommended (World-Class API)

```cpp
#include "ecliptix/api.hpp"

// Initialize library (RAII)
ecliptix::library::Manager lib;

// Generate secure key
auto key = ecliptix::random::key<32>().value();

// Encrypt data
auto encrypted = ecliptix::aead::encrypt(plaintext, key).value();

// Decrypt data
auto decrypted = ecliptix::aead::decrypt(std::move(encrypted), key).value();
```

### Legacy (Compatibility)

```cpp
#include "ecliptix/security.h"

// C-style API (for FFI/P/Invoke)
ecliptix_init();
ecliptix_encrypt_aes_gcm(/*...*/);
ecliptix_cleanup();
```

## ⚡ **Performance Characteristics**

- **Zero-Cost Abstractions**: Strong types compile to same code as raw pointers
- **Move Semantics**: Minimal copying, optimal memory usage
- **Cache-Friendly**: Aligned allocations, sequential memory access
- **SIMD-Ready**: Data structures compatible with vectorization
- **Compile-Time Optimization**: Extensive use of constexpr and consteval

## 🧪 **Testing Strategy**

```bash
# Run comprehensive self-test
./bin/ecliptix_world_class_demo

# Verify all cryptographic operations
ecliptix::library::Manager lib;
lib.self_test();  // Throws on failure
```

## 🔧 **Integration Patterns**

### .NET P/Invoke Integration

The legacy C API (`include/ecliptix/security.h`) provides a stable ABI for .NET integration:

```csharp
[DllImport("ecliptix_security")]
public static extern int ecliptix_encrypt_aes_gcm(/*...*/);
```

### Modern C++ Applications

Use the world-class API for new C++ applications:

```cpp
#include "ecliptix/api.hpp"
using namespace ecliptix;

// Type-safe, high-performance operations
auto result = aead::encrypt(data, key, aad).value();
```

## 🛡️ **Security Guidelines**

1. **Use the new API**: Prefer `ecliptix/api.hpp` for maximum security
2. **Never embed private keys**: Generate keys at runtime or load from secure storage
3. **Use strong types**: Let the compiler prevent mistakes
4. **Lock sensitive memory**: Use `SecureBytes` for all sensitive data
5. **Verify certificates**: Always use SSL pinning for network communications
6. **Rotate keys regularly**: Use authenticated pin updates for certificate rotation
7. **Enable all warnings**: Compile with `-Wall -Wextra -Werror`

The library follows modern C++ security best practices and should only be used for legitimate security applications.