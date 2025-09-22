#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix RSA Key Generation (Testing/Examples)"
echo "=========================================="
echo "SECURITY NOTE: Generated keys are for testing/examples only."
echo "Private keys are NOT embedded in libraries for security."

KEYS_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$KEYS_DIR")"

echo "Keys directory: $KEYS_DIR"
echo "Project root: $PROJECT_ROOT"

# Clean previous keys
rm -f client_private.pem client_public.pem server_private.pem server_public.pem

echo "Generating client 2048-bit RSA keypair..."
openssl genrsa -out client_private.pem 2048
openssl rsa -in client_private.pem -pubout -out client_public.pem

echo "Generating server 2048-bit RSA keypair..."
openssl genrsa -out server_private.pem 2048
openssl rsa -in server_private.pem -pubout -out server_public.pem

echo "Keys generated successfully:"
echo "  Client private: client_private.pem"
echo "  Client public: client_public.pem"
echo "  Server private: server_private.pem"
echo "  Server public: server_public.pem"

echo "Embedding PUBLIC keys into header files (private keys remain external)..."
python3 "$KEYS_DIR/embed_keys.py" "$PROJECT_ROOT"

echo "RSA key generation complete!"
echo "IMPORTANT: Use ecliptix_*_init_with_key() functions to load private keys at runtime."