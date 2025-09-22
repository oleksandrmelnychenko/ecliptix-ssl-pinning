#!/bin/bash

# Script to generate test RSA key pairs for external key loading examples
# This replaces the embedded keys for security testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/test_keys"

echo "=== Generating Test RSA Key Pairs ==="
echo "Output directory: $KEYS_DIR"

# Create keys directory
mkdir -p "$KEYS_DIR"

# Generate server key pair (2048-bit RSA)
echo "1. Generating server RSA key pair..."
openssl genrsa -out "$KEYS_DIR/server_private_key.pem" 2048
openssl rsa -in "$KEYS_DIR/server_private_key.pem" -pubout -out "$KEYS_DIR/server_public_key.pem"
echo "   ✓ Server keys generated"

# Generate client key pair (2048-bit RSA)
echo "2. Generating client RSA key pair..."
openssl genrsa -out "$KEYS_DIR/client_private_key.pem" 2048
openssl rsa -in "$KEYS_DIR/client_private_key.pem" -pubout -out "$KEYS_DIR/client_public_key.pem"
echo "   ✓ Client keys generated"

# Set secure permissions on private keys
echo "3. Setting secure permissions..."
chmod 600 "$KEYS_DIR"/*_private_key.pem
chmod 644 "$KEYS_DIR"/*_public_key.pem
echo "   ✓ Permissions set (private keys: 600, public keys: 644)"

echo ""
echo "=== Key Generation Completed ==="
echo "Generated files:"
echo "  Server private key: $KEYS_DIR/server_private_key.pem"
echo "  Server public key:  $KEYS_DIR/server_public_key.pem"
echo "  Client private key: $KEYS_DIR/client_private_key.pem"
echo "  Client public key:  $KEYS_DIR/client_public_key.pem"
echo ""
echo "To run the external key example:"
echo "  cd examples"
echo "  ./external_key_example test_keys/server_private_key.pem test_keys/client_private_key.pem"
echo ""
echo "Security Note: These are test keys only. Never use these in production!"