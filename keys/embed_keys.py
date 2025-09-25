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
        print("Note: This script embeds ALL keys as requested.")
        sys.exit(1)

    project_root = Path(sys.argv[1])
    keys_dir = project_root / "keys"

    # Read all keys as requested
    client_private_path = keys_dir / "client_private.pem"
    client_public_path = keys_dir / "client_public.pem"
    server_private_path = keys_dir / "server_private.pem"
    server_public_path = keys_dir / "server_public.pem"

    if not all(p.exists() for p in [client_private_path, client_public_path, server_private_path, server_public_path]):
        print("Error: Keys not found. Run generate_keys.sh first.")
        sys.exit(1)

    print("Reading ALL keys as requested...")
    client_private_data = read_pem_as_bytes(client_private_path)
    client_public_data = read_pem_as_bytes(client_public_path)
    server_private_data = read_pem_as_bytes(server_private_path)
    server_public_data = read_pem_as_bytes(server_public_path)

    # Create client header with all necessary keys
    client_header = f"""#pragma once

// Certificate Pinning Keys - All keys embedded for SSL pinning functionality

// Server RSA public key (for client-to-server encryption)
{bytes_to_c_array(server_public_data, 'SERVER_PUBLIC_KEY_PEM')}
#define SERVER_PUBLIC_KEY_SIZE SERVER_PUBLIC_KEY_PEM_size

// Client RSA public key (for server-to-client encryption)
{bytes_to_c_array(client_public_data, 'CLIENT_PUBLIC_KEY_PEM')}
#define CLIENT_PUBLIC_KEY_SIZE CLIENT_PUBLIC_KEY_PEM_size

// Client RSA private key (for decrypting server responses)
{bytes_to_c_array(client_private_data, 'CLIENT_PRIVATE_KEY_PEM')}
#define CLIENT_PRIVATE_KEY_SIZE CLIENT_PRIVATE_KEY_PEM_size
"""

    # Create server header with all necessary keys
    server_header = f"""#pragma once

// Certificate Pinning Keys - All keys embedded for SSL pinning functionality

// Client RSA public key (for server-to-client encryption)
{bytes_to_c_array(client_public_data, 'CLIENT_PUBLIC_KEY_PEM')}
#define CLIENT_PUBLIC_KEY_SIZE CLIENT_PUBLIC_KEY_PEM_size

// Server RSA private key (for decrypting client requests)
{bytes_to_c_array(server_private_data, 'SERVER_PRIVATE_KEY_PEM')}
#define SERVER_PRIVATE_KEY_SIZE SERVER_PRIVATE_KEY_PEM_size

// Server RSA public key (for server-to-client encryption verification)
{bytes_to_c_array(server_public_data, 'SERVER_PUBLIC_KEY_PEM')}
#define SERVER_PUBLIC_KEY_SIZE SERVER_PUBLIC_KEY_PEM_size
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

    print("All key embedding completed successfully!")
    print(f"Client private key size: {len(client_private_data)} bytes")
    print(f"Client public key size: {len(client_public_data)} bytes")
    print(f"Server private key size: {len(server_private_data)} bytes")
    print(f"Server public key size: {len(server_public_data)} bytes")
    print("")
    print("All keys are now embedded in the libraries as requested.")

if __name__ == "__main__":
    main()