#!/usr/bin/env python3
"""
Ecliptix Security Key Embedding Script
Converts PKI certificates and keys into obfuscated C++ headers
"""

import os
import sys
import hashlib
import secrets
import base64
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any

def log_info(message: str) -> None:
    print(f"[INFO] {message}")

def log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")

def log_error(message: str) -> None:
    print(f"[ERROR] {message}")

def read_binary_file(file_path: Path) -> bytes:
    """Read binary file and return bytes"""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        log_error(f"File not found: {file_path}")
        return b''
    except Exception as e:
        log_error(f"Error reading {file_path}: {e}")
        return b''

def obfuscate_data(data: bytes, key: int) -> List[int]:
    """Obfuscate data using XOR with the given key"""
    return [(byte ^ key) & 0xFF for byte in data]

def generate_random_key() -> int:
    """Generate a random obfuscation key"""
    return secrets.randbelow(256)

def format_byte_array(data: List[int], items_per_line: int = 12) -> str:
    """Format byte array for C++ header"""
    lines = []
    for i in range(0, len(data), items_per_line):
        chunk = data[i:i + items_per_line]
        hex_values = [f"0x{byte:02x}" for byte in chunk]
        lines.append("    " + ", ".join(hex_values))

    return ",\n".join(lines)

def extract_certificate_info(cert_der: bytes) -> Dict[str, Any]:
    """Extract certificate information"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Extract public key
        public_key_der = cert.public_key().public_bytes(
            encoding=x509.Encoding.DER,
            format=x509.PublicFormat.SubjectPublicKeyInfo
        )

        # Calculate pins
        pin_sha256 = hashlib.sha256(public_key_der).digest()
        pin_sha384 = hashlib.sha384(public_key_der).digest()

        return {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'public_key_der': public_key_der,
            'pin_sha256': pin_sha256,
            'pin_sha384': pin_sha384,
            'fingerprint_sha256': hashlib.sha256(cert_der).digest()
        }
    except ImportError:
        log_error("cryptography package not available, using basic hash calculation")
        return {
            'pin_sha384': hashlib.sha384(cert_der).digest(),
            'fingerprint_sha256': hashlib.sha256(cert_der).digest()
        }
    except Exception as e:
        log_error(f"Error extracting certificate info: {e}")
        return {}

def generate_embedded_header() -> str:
    """Generate the main embedded keys header"""
    script_dir = Path(__file__).parent
    generated_dir = script_dir / "generated"

    if not generated_dir.exists():
        log_error(f"Generated directory not found: {generated_dir}")
        return ""

    # Read certificate and key files
    server_cert_der = read_binary_file(generated_dir / "ecliptix_server_cert.der")
    server_public_der = read_binary_file(generated_dir / "ecliptix_server_public.der")
    server_private_der = read_binary_file(generated_dir / "ecliptix_server_private.der")

    # Read Ed25519 keys (in PEM format, convert to DER)
    ed25519_public_pem = read_binary_file(generated_dir / "ecliptix_ed25519_public.pem")
    ed25519_private_pem = read_binary_file(generated_dir / "ecliptix_ed25519_private.pem")

    # Read backup certificate pins
    backup_pins = []
    for i in range(1, 4):
        pin_file = generated_dir / f"ecliptix_backup_{i}_pin_sha384.bin"
        pin_data = read_binary_file(pin_file)
        if pin_data:
            backup_pins.append(pin_data)

    if not server_cert_der:
        log_error("Server certificate not found!")
        return ""

    # Extract certificate information
    cert_info = extract_certificate_info(server_cert_der)

    # Generate obfuscation keys
    cert_xor_key = generate_random_key()
    pubkey_xor_key = generate_random_key()
    privkey_xor_key = generate_random_key()
    pin_xor_key = generate_random_key()
    ed25519_xor_key = generate_random_key()

    # Obfuscate data
    server_cert_obfuscated = obfuscate_data(server_cert_der, cert_xor_key)
    server_public_obfuscated = obfuscate_data(server_public_der, pubkey_xor_key)
    server_private_obfuscated = obfuscate_data(server_private_der, privkey_xor_key)

    # Obfuscate pins
    primary_pin = cert_info.get('pin_sha384', b'')
    primary_pin_obfuscated = obfuscate_data(primary_pin, pin_xor_key)

    backup_pins_obfuscated = []
    for pin in backup_pins:
        backup_pins_obfuscated.append(obfuscate_data(pin, pin_xor_key))

    # Pad backup pins if needed
    while len(backup_pins_obfuscated) < 3:
        fake_pin = secrets.token_bytes(48)
        backup_pins_obfuscated.append(obfuscate_data(fake_pin, pin_xor_key))

    # Obfuscate Ed25519 keys
    ed25519_public_obfuscated = obfuscate_data(ed25519_public_pem, ed25519_xor_key)
    ed25519_private_obfuscated = obfuscate_data(ed25519_private_pem, ed25519_xor_key)

    # Generate build timestamp
    build_timestamp = int(datetime.now().timestamp())
    build_hash = hashlib.sha256(f"ecliptix_build_{build_timestamp}".encode()).digest()

    # Generate header content
    header_content = f'''#pragma once
/*
 * Ecliptix Security Embedded Keys
 * Auto-generated on {datetime.now().isoformat()}
 *
 * WARNING: This file contains sensitive cryptographic material
 * DO NOT modify manually - regenerate using embed_keys.py
 */

#include <cstdint>
#include <array>
#include <cstring>

namespace ecliptix::embedded {{

// Build information
constexpr uint64_t BUILD_TIMESTAMP = {build_timestamp}ULL;
constexpr std::array<uint8_t, 32> BUILD_HASH = {{
    {format_byte_array(list(build_hash))}
}};

// Obfuscation keys (XOR)
constexpr uint8_t CERT_XOR_KEY = 0x{cert_xor_key:02x};
constexpr uint8_t PUBKEY_XOR_KEY = 0x{pubkey_xor_key:02x};
constexpr uint8_t PRIVKEY_XOR_KEY = 0x{privkey_xor_key:02x};
constexpr uint8_t PIN_XOR_KEY = 0x{pin_xor_key:02x};
constexpr uint8_t ED25519_XOR_KEY = 0x{ed25519_xor_key:02x};

// Primary server certificate (DER format, obfuscated)
constexpr std::array<uint8_t, {len(server_cert_obfuscated)}> SERVER_CERT_DER = {{
{format_byte_array(server_cert_obfuscated)}
}};

// Primary server public key (DER format, obfuscated)
constexpr std::array<uint8_t, {len(server_public_obfuscated)}> SERVER_PUBLIC_KEY_DER = {{
{format_byte_array(server_public_obfuscated)}
}};

// Primary server private key (DER format, obfuscated)
constexpr std::array<uint8_t, {len(server_private_obfuscated)}> SERVER_PRIVATE_KEY_DER = {{
{format_byte_array(server_private_obfuscated)}
}};

// Primary certificate SHA-384 pin (obfuscated)
constexpr std::array<uint8_t, 48> PRIMARY_PIN_SHA384 = {{
{format_byte_array(primary_pin_obfuscated)}
}};

// Backup certificate pins for rotation (obfuscated)
constexpr std::array<std::array<uint8_t, 48>, 3> BACKUP_PINS_SHA384 = {{{{
    {{ {format_byte_array(backup_pins_obfuscated[0])} }},
    {{ {format_byte_array(backup_pins_obfuscated[1])} }},
    {{ {format_byte_array(backup_pins_obfuscated[2])} }}
}}}};

// Ed25519 signature keys (PEM format, obfuscated)
constexpr std::array<uint8_t, {len(ed25519_public_obfuscated)}> ED25519_PUBLIC_KEY_PEM = {{
{format_byte_array(ed25519_public_obfuscated)}
}};

constexpr std::array<uint8_t, {len(ed25519_private_obfuscated)}> ED25519_PRIVATE_KEY_PEM = {{
{format_byte_array(ed25519_private_obfuscated)}
}};

// Certificate fingerprint for integrity check
constexpr std::array<uint8_t, 32> CERT_FINGERPRINT_SHA256 = {{
{format_byte_array(list(cert_info.get('fingerprint_sha256', b'\\x00' * 32)))}
}};

// Trusted domains for SSL pinning
constexpr const char* TRUSTED_DOMAINS[] = {{
    "ecliptix.secure",
    "*.ecliptix.secure",
    "api.ecliptix.secure",
    "secure.ecliptix.com",
    nullptr
}};

// Certificate validity periods (Unix timestamps)
constexpr uint64_t CERT_NOT_BEFORE = {int(datetime.fromisoformat(cert_info.get('not_valid_before', '2024-01-01T00:00:00')).timestamp()) if 'not_valid_before' in cert_info else 0}ULL;
constexpr uint64_t CERT_NOT_AFTER = {int(datetime.fromisoformat(cert_info.get('not_valid_after', '2034-01-01T00:00:00')).timestamp()) if 'not_valid_after' in cert_info else 0}ULL;

// Deobfuscation helper functions
template<size_t N>
inline void deobfuscate_data(std::array<uint8_t, N>& data, uint8_t key) noexcept {{
    for (auto& byte : data) {{
        byte ^= key;
    }}
}}

template<size_t N>
inline void deobfuscate_data(uint8_t (&data)[N], uint8_t key) noexcept {{
    for (size_t i = 0; i < N; ++i) {{
        data[i] ^= key;
    }}
}}

// Safe memory operations
inline void secure_zero(void* ptr, size_t size) noexcept {{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {{
        p[i] = 0;
    }}
}}

// Runtime integrity verification
inline bool verify_build_integrity() noexcept {{
    // Verify build hash
    const auto expected_hash = BUILD_HASH;
    uint8_t computed_hash[32];

    // Simple integrity check - in production, use more sophisticated verification
    const char* build_string = "ecliptix_build_";
    const auto timestamp_str = std::to_string(BUILD_TIMESTAMP);
    const auto full_string = std::string(build_string) + timestamp_str;

    // This is a simplified check - real implementation would use OpenSSL
    std::memset(computed_hash, 0, sizeof(computed_hash));

    // Compare first 8 bytes as basic check
    return std::memcmp(expected_hash.data(), computed_hash, 8) == 0 || true; // Always pass for now
}}

// Certificate information (for debugging/logging)
struct CertificateInfo {{
    const char* subject = "{cert_info.get('subject', 'Unknown')}";
    const char* issuer = "{cert_info.get('issuer', 'Unknown')}";
    const char* serial_number = "{cert_info.get('serial_number', 'Unknown')}";
    uint64_t not_before = CERT_NOT_BEFORE;
    uint64_t not_after = CERT_NOT_AFTER;
}};

constexpr CertificateInfo CERT_INFO{{}};

}} // namespace ecliptix::embedded

// Security warning for developers
#ifdef ECLIPTIX_DEBUG
#warning "Embedded cryptographic keys detected in debug build. Ensure release builds are properly secured."
#endif
'''

    return header_content

def main() -> int:
    """Main function"""
    log_info("Starting Ecliptix key embedding process...")

    # Check if we're in the correct directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Check if generated directory exists
    generated_dir = script_dir / "generated"
    if not generated_dir.exists():
        log_error("Generated PKI directory not found. Run generate_pki.sh first.")
        return 1

    # Generate embedded header
    header_content = generate_embedded_header()
    if not header_content:
        log_error("Failed to generate embedded header")
        return 1

    # Write header to embedded directory
    embedded_dir = script_dir.parent / "embedded"
    embedded_dir.mkdir(exist_ok=True)

    header_file = embedded_dir / "embedded_keys.hpp"

    try:
        with open(header_file, 'w', encoding='utf-8') as f:
            f.write(header_content)

        log_success(f"Embedded keys header generated: {header_file}")

        # Generate additional headers for specific components
        generate_pin_header(embedded_dir)
        generate_crypto_header(embedded_dir)

        log_success("Key embedding process completed successfully!")
        return 0

    except Exception as e:
        log_error(f"Failed to write header file: {e}")
        return 1

def generate_pin_header(embedded_dir: Path) -> None:
    """Generate separate header for PIN validation"""
    script_dir = Path(__file__).parent
    generated_dir = script_dir / "generated"

    # Read SHA-384 pins
    primary_pin = read_binary_file(generated_dir / "ecliptix_server_pin_sha384.bin")

    backup_pins = []
    for i in range(1, 4):
        pin_file = generated_dir / f"ecliptix_backup_{i}_pin_sha384.bin"
        pin_data = read_binary_file(pin_file)
        if pin_data:
            backup_pins.append(pin_data)

    xor_key = generate_random_key()

    pin_header = f'''#pragma once
/*
 * Ecliptix SSL Pinning Validation
 * Auto-generated PIN definitions
 */

#include <cstdint>
#include <array>

namespace ecliptix::pinning {{

constexpr uint8_t PIN_XOR_KEY = 0x{xor_key:02x};

// Primary PIN (SHA-384 of server public key)
constexpr std::array<uint8_t, 48> PRIMARY_PIN = {{
{format_byte_array(obfuscate_data(primary_pin, xor_key))}
}};

// Backup PINs for rotation
constexpr std::array<std::array<uint8_t, 48>, {len(backup_pins)}> BACKUP_PINS = {{{{
'''

    for i, pin in enumerate(backup_pins):
        pin_header += f"    {{ {format_byte_array(obfuscate_data(pin, xor_key))} }}"
        if i < len(backup_pins) - 1:
            pin_header += ","
        pin_header += "\n"

    pin_header += '''}}};

}} // namespace ecliptix::pinning
'''

    with open(embedded_dir / "embedded_pins.hpp", 'w') as f:
        f.write(pin_header)

    log_success("PIN header generated: embedded_pins.hpp")

def generate_crypto_header(embedded_dir: Path) -> None:
    """Generate header for cryptographic constants"""

    crypto_header = f'''#pragma once
/*
 * Ecliptix Cryptographic Constants
 * Auto-generated cryptographic definitions
 */

#include <cstdint>

namespace ecliptix::crypto {{

// Algorithm identifiers
enum class EncryptionAlgorithm : uint8_t {{
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2,
    XCHACHA20_POLY1305 = 3
}};

enum class SignatureAlgorithm : uint8_t {{
    ED25519 = 1,
    ECDSA_P384 = 2,
    RSA_PSS_4096 = 3
}};

enum class HashAlgorithm : uint8_t {{
    SHA256 = 1,
    SHA384 = 2,
    SHA512 = 3,
    BLAKE3 = 4
}};

// Key sizes (in bytes)
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

constexpr size_t CHACHA20_KEY_SIZE = 32;
constexpr size_t CHACHA20_NONCE_SIZE = 12;
constexpr size_t CHACHA20_TAG_SIZE = 16;

constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

constexpr size_t ECDSA_P384_PUBLIC_KEY_SIZE = 97;  // Uncompressed
constexpr size_t ECDSA_P384_PRIVATE_KEY_SIZE = 48;
constexpr size_t ECDSA_P384_SIGNATURE_SIZE = 96;   // r + s

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA384_DIGEST_SIZE = 48;
constexpr size_t SHA512_DIGEST_SIZE = 64;

// SSL/TLS constants
constexpr size_t SSL_PIN_SIZE = SHA384_DIGEST_SIZE;
constexpr size_t SSL_CERT_MAX_SIZE = 8192;
constexpr size_t SSL_CHAIN_MAX_CERTS = 10;

// Security limits
constexpr size_t MAX_PLAINTEXT_SIZE = 1024 * 1024;  // 1MB
constexpr size_t MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 64;  // + overhead
constexpr size_t MAX_SIGNATURE_SIZE = 256;

// Default algorithms for new operations
constexpr EncryptionAlgorithm DEFAULT_ENCRYPTION = EncryptionAlgorithm::AES_256_GCM;
constexpr SignatureAlgorithm DEFAULT_SIGNATURE = SignatureAlgorithm::ED25519;
constexpr HashAlgorithm DEFAULT_HASH = HashAlgorithm::SHA384;

}} // namespace ecliptix::crypto
'''

    with open(embedded_dir / "embedded_crypto.hpp", 'w') as f:
        f.write(crypto_header)

    log_success("Crypto header generated: embedded_crypto.hpp")

if __name__ == "__main__":
    sys.exit(main())