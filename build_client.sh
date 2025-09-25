#!/bin/bash
set -e

echo "=========================================="
echo "Building Ecliptix Client Library"
echo "=========================================="

# Build client library
echo "Building client library..."
cd client
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "Client library built successfully!"
echo "Output: $(pwd)/lib/ecliptix_client.*"