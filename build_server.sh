#!/bin/bash
set -e

echo "=========================================="
echo "Building Ecliptix Server Library"
echo "=========================================="

# Build server library
echo "Building server library..."
cd server
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "Server library built successfully!"
echo "Output: $(pwd)/lib/ecliptix_server.*"