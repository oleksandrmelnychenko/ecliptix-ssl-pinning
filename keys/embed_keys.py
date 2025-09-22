#!/usr/bin/env python3
import os
import sys
from pathlib import Path

def read_pem_as_bytes(filepath):
    """Read PEM file and return as byte array"""
    with open(filepath, 'rb') as f:
        return f.read()

def bytes_to_c_array(data, name):
    """Convert bytes to C array format"""
    hex_data = ', '.join(f'0x{b:02x}' for b in data)
    return f"static const unsigned char {name}[] = {{\n    {hex_data}\n}};\nstatic const size_t {name}_size = {len(data)};"

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 embed_keys.py <project_root>")
        print("Note: This script only embeds PUBLIC keys for security. Private keys must be loaded externally.")
        sys.exit(1)

    project_root = Path(sys.argv[1])
    keys_dir = project_root / "keys"

    # Read public keys only (NEVER embed private keys for security)
    client_public_path = keys_dir / "client_public.pem"
    server_public_path = keys_dir / "server_public.pem"

    if not all(p.exists() for p in [client_public_path, server_public_path]):
        print("Error: Public keys not found. Run generate_keys.sh first.")
        sys.exit(1)

    print("Reading PUBLIC keys only (private keys are loaded externally for security)...")
    client_public_data = read_pem_as_bytes(client_public_path)
    server_public_data = read_pem_as_bytes(server_public_path)

    # Create client header (server public key for verification only)
    client_header = f"""#pragma once

// SECURITY NOTE: Private keys are NO LONGER embedded for security reasons.
// Use ecliptix_client_init_with_key() to provide private keys externally at runtime.

// Server RSA public key (for signature verification)
{bytes_to_c_array(server_public_data, 'SERVER_PUBLIC_KEY_PEM')}
#define SERVER_PUBLIC_KEY_SIZE SERVER_PUBLIC_KEY_PEM_size
"""

    # Create server header (client public key for encryption only)
    server_header = f"""#pragma once

// SECURITY NOTE: Private keys are NO LONGER embedded for security reasons.
// Use ecliptix_server_init_with_key() to provide private keys externally at runtime.

// Client RSA public key (for encryption)
{bytes_to_c_array(client_public_data, 'CLIENT_PUBLIC_KEY_PEM')}
#define CLIENT_PUBLIC_KEY_SIZE CLIENT_PUBLIC_KEY_PEM_size
"""

    # Write client header
    client_header_path = project_root / "client" / "embedded" / "keys.h"
    with open(client_header_path, 'w') as f:
        f.write(client_header)
    print(f"Created: {client_header_path}")

    # Write server header
    server_header_path = project_root / "server" / "embedded" / "keys.h"
    with open(server_header_path, 'w') as f:
        f.write(server_header)
    print(f"Created: {server_header_path}")

    print("Public key embedding completed successfully!")
    print(f"Client public key size: {len(client_public_data)} bytes")
    print(f"Server public key size: {len(server_public_data)} bytes")
    print("")
    print("SECURITY NOTE: Private keys are NOT embedded and must be provided externally.")
    print("Use ecliptix_*_init_with_key() functions to load private keys at runtime.")

if __name__ == "__main__":
    main()