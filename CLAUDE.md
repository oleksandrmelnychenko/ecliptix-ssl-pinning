# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ecliptix Security SSL Pinning Library is a C++ security library that provides SSL certificate pinning, cryptographic operations, and digital signatures with both C and C++ APIs. The library is designed for defensive security applications with hardened anti-tampering features.

## Development Commands

### Building the Library
```bash
# Full build with key generation
mkdir build && cd build
cmake .. && make -j4

# Or use existing cmake-build-debug directory
cd cmake-build-debug
make -j4
```

### Key Generation and PKI Setup
```bash
# Generate PKI infrastructure and embed keys (automatically done during build)
cd keys
bash generate_pki.sh
python3 embed_keys.py
```

### Running Demo
```bash
# After building
./cmake-build-debug/bin/ecliptix_demo
```

### Testing and Validation
```bash
# Self-test functionality is built into the library
# Use ecliptix_self_test() function or demo application
```

## Architecture Overview

### Core Components

1. **Public API Layer** (`include/ecliptix/public_api.h`, `include/ecliptix/ecliptix.hpp`)
   - Clean, comprehensive C API for all platforms
   - Modern C++ RAII wrapper for safe usage
   - Essential crypto operations: encrypt, decrypt, sign, verify, hash
   - SSL certificate validation with pinning
   - Secure key derivation and random generation

2. **Legacy API Layer** (`include/ecliptix/security.h`, `src/security.cpp`)
   - Extended C API with advanced features
   - Performance metrics and detailed error handling
   - Compatibility functions for complex scenarios

3. **Libsodium Integration** (`include/internal/sodium_wrapper.hpp`)
   - Memory-safe cryptographic operations
   - ChaCha20-Poly1305, Ed25519, Blake2b, Argon2id
   - Constant-time operations and secure memory management

4. **OpenSSL Integration** (`include/internal/openssl_wrapper.hpp`, `src/openssl_wrapper.cpp`)
   - SSL/TLS certificate parsing and validation
   - Legacy cryptographic algorithm support
   - Certificate chain verification

5. **Embedded Security** (`embedded/embedded_keys.hpp`)
   - XOR-obfuscated certificate pins (no private keys)
   - Runtime integrity verification
   - Anti-tampering mechanisms

6. **PKI Infrastructure** (`keys/`)
   - Certificate authority chain generation for testing
   - Pin generation and embedding automation
   - Key rotation support

### Key Security Features

- **SSL Pinning**: SHA-384 SPKI pinning with backup pin support
- **Key Obfuscation**: XOR obfuscation of embedded certificates and keys
- **Memory Protection**: Secure allocation and automatic wiping
- **Integrity Verification**: Runtime library tampering detection
- **Performance Monitoring**: Built-in metrics for all operations

### Build System Architecture

The CMake build system automatically:
1. Generates a complete PKI infrastructure (Root CA → Intermediate CA → Server certificates)
2. Creates Ed25519 signing keys with backups
3. Obfuscates and embeds all certificates/keys into the library
4. Compiles both shared (`ecliptix_security`) and static (`ecliptix_security_static`) variants
5. Applies security hardening compiler flags

### Integration Patterns

The library is designed for integration with .NET applications via P/Invoke, providing:
- Complete C API for cross-platform interop
- Thread-safe operations with proper error handling
- Session management for stateful operations
- Performance metrics for monitoring

### Key Files and Locations

- `include/ecliptix/security.h` - Main C API declarations
- `include/ecliptix/types.h` - Type definitions and constants
- `src/security.cpp` - Main C API implementation
- `keys/generate_pki.sh` - PKI generation script
- `keys/embed_keys.py` - Key embedding automation
- `demo/main.cpp` - Example usage and testing

### Dependencies

- OpenSSL (automatically detected by CMake)
- C++20 compiler support
- CMake 3.20 or higher
- Python 3 (for key embedding)
- Bash (for PKI generation)

## Security Improvements & Best Practices

### ✅ Critical Security Fixes Applied

1. **Removed Embedded Private Keys**
   - Eliminated Ed25519 private keys from binary
   - Signing now requires external key provision
   - Prevents key extraction from reverse engineering

2. **Enhanced Cryptographic Implementation**
   - Integrated libsodium for memory-safe operations
   - Added ChaCha20-Poly1305 with automatic nonce generation
   - Implemented Blake2b hashing (faster than SHA-2)
   - Added Argon2id for secure password-based key derivation

3. **Improved Memory Security**
   - Secure memory allocation with automatic wiping
   - Memory locking to prevent swapping to disk
   - Constant-time comparisons to prevent timing attacks
   - RAII patterns for guaranteed cleanup

4. **Dynamic Pin Management**
   - Pin versioning and expiration support
   - Authenticated pin updates via signatures
   - Multiple backup pins for key rotation

### 🎯 Recommended Usage Patterns

**For Encryption:**
```cpp
// Use the clean public API
auto key = ecliptix::random_bytes<32>();
auto encrypted = ecliptix::encrypt(plaintext, key, associated_data);
auto decrypted = ecliptix::decrypt(encrypted, key, associated_data);
```

**For Digital Signatures:**
```cpp
// Generate keys on secure server, distribute public keys only
ecliptix::KeyPair server_keypair;  // Server-side only
auto signature = ecliptix::sign(message, server_keypair.private_key());
bool valid = ecliptix::verify(message, signature, public_key);  // Client-side
```

**For SSL Pinning:**
```cpp
// Certificate validation with embedded pins
ecliptix::validate_certificate(cert_der, hostname);
```

### 🔒 Security Guidelines

- **Never embed private keys** in client applications
- **Use libsodium functions** for new implementations (memory-safe)
- **Lock sensitive memory** with `ecliptix_secure_malloc()`
- **Verify all certificates** against pinned public keys
- **Rotate pins periodically** using authenticated updates
- **Use Argon2id** for password-based key derivation
- **Implement rate limiting** for cryptographic operations

The library follows defensive security practices and should only be used for legitimate security applications.