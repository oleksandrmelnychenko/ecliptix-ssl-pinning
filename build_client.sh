#!/bin/bash
set -e

echo "=========================================="
echo "Building Ecliptix Client Library"
echo "=========================================="

# Generate keys for testing/examples if they don't exist (NOT embedded for security)
if [ ! -f "keys/rsa_private.pem" ] || [ ! -f "keys/rsa_public.pem" ]; then
    echo "Generating RSA keys for testing/examples..."
    echo "Note: Private keys are NOT embedded and must be loaded externally"
    cd keys
    ./generate_keys.sh
    cd ..
fi

# Build client library
echo "Building client library..."
cd client
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "Client library built successfully!"
echo "Output: $(pwd)/lib/ecliptix_client.*"