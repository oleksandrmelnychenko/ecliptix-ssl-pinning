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

1. **C API Layer** (`include/ecliptix/security.h`, `src/security.cpp`)
   - Main public interface with comprehensive C API
   - SSL certificate validation and pinning
   - AES-256-GCM and ChaCha20-Poly1305 encryption
   - Ed25519 and ECDSA P-384 digital signatures
   - Performance metrics and error handling

2. **C++ Wrapper Layer** (`include/ecliptix/security.hpp`)
   - Modern C++20 RAII-based interface
   - Exception-safe error handling
   - Type-safe cryptographic operations

3. **OpenSSL Integration** (`include/internal/openssl_wrapper.hpp`, `src/openssl_wrapper.cpp`)
   - High-level C++ wrappers around OpenSSL
   - Certificate parsing and validation
   - Cryptographic primitives implementation

4. **Embedded Security** (`embedded/embedded_keys.hpp`)
   - XOR-obfuscated certificate pins and keys
   - Runtime integrity verification
   - Anti-tampering mechanisms

5. **PKI Infrastructure** (`keys/`)
   - Complete certificate authority chain generation
   - Ed25519 and ECDSA key pair generation
   - Automated key embedding system

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

The library follows defensive security practices and should only be used for legitimate security applications.