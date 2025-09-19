#!/bin/bash
set -e

# Ecliptix Security Library - Linux x64 Build Script
# Compiles for Linux using Docker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/builds/linux"

echo "======================================="
echo "Ecliptix Security - Linux x64 Build"
echo "======================================="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Docker image
echo "Building Linux compilation environment..."
docker build -f "$PROJECT_ROOT/docker/Dockerfile.linux" \
             -t ecliptix-build-linux "$PROJECT_ROOT"

# Run compilation
echo "Compiling for Linux x64..."
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v "$OUTPUT_DIR:/output" \
    -w /workspace \
    ecliptix-build-linux \
    bash -c "
        mkdir -p build-linux
        cd build-linux

        cmake -DCMAKE_BUILD_TYPE=Release \
              -DECLIPTIX_BUILD_TESTS=ON \
              -DCMAKE_TOOLCHAIN_FILE=/workspace/cmake/linux-toolchain.cmake \
              -DCMAKE_INSTALL_PREFIX=/output \
              ..

        make -j\$(nproc)
        make install

        # Copy Linux shared library
        cp lib/ecliptix_security.so /output/ || true

        echo '✅ Linux x64 build completed'
    "

echo ""
echo "Linux build artifacts:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "✅ Linux x64 library ready: $OUTPUT_DIR/ecliptix_security.so"