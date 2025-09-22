#!/bin/bash
set -e

echo "=========================================="
echo "Building Both Ecliptix Libraries"
echo "=========================================="

# Generate keys for testing and examples (NOT embedded in libraries for security)
echo "Step 1: Generating RSA keys for testing/examples..."
echo "Note: Private keys are NOT embedded and must be loaded externally"
cd keys
./generate_keys.sh
cd ..

# Build client library
echo "Step 2: Building client library..."
./build_client.sh

# Build server library
echo "Step 3: Building server library..."
./build_server.sh

echo ""
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo "Client library: client/build/lib/ecliptix_client.*"
echo "Server library: server/build/lib/ecliptix_server.*"
echo ""
echo "Usage:"
echo "  Client: Link with client/build/lib/ecliptix_client and include client/include/ecliptix_client.h"
echo "  Server: Link with server/build/lib/ecliptix_server and include server/include/ecliptix_server.h"