#!/bin/bash
set -e

echo "========================================="
echo "Building Ecliptix Linux Libraries"
echo "========================================="

# Navigate to project root
cd "$(dirname "$0")/.."

echo "🐧 Building Linux libraries via Docker..."

# Simple Docker compilation without toolchain
docker run --rm \
    -v "$(pwd):/workspace" \
    -w /workspace \
    ubuntu:22.04 \
    bash -c "
        apt update -q
        apt install -y build-essential cmake libssl-dev libsodium-dev pkg-config git

        # Clean and create build directory
        rm -rf build-linux
        mkdir build-linux
        cd build-linux

        # Configure with Release
        cmake .. -DCMAKE_BUILD_TYPE=Release

        # Build libraries
        make -j\$(nproc)

        echo '✅ Linux libraries built successfully!'
        echo '📍 Output location:'
        ls -la lib/libcertificate.pinning.*
    "

echo "✅ Linux build completed!"
echo "📍 Libraries in: $(pwd)/build-linux/lib/"