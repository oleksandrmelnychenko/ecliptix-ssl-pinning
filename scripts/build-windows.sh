#!/bin/bash
set -e

# Ecliptix Security Library - Windows x64 Build Script
# Cross-compiles for Windows using MinGW-w64 in Docker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/builds/windows"

echo "======================================="
echo "Ecliptix Security - Windows x64 Build"
echo "======================================="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Docker image
echo "Building Windows cross-compilation environment..."
docker build -f "$PROJECT_ROOT/docker/Dockerfile.windows" \
             -t ecliptix-build-windows "$PROJECT_ROOT"

# Run cross-compilation
echo "Cross-compiling for Windows x64..."
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v "$OUTPUT_DIR:/output" \
    -w /workspace \
    ecliptix-build-windows \
    bash -c "
        mkdir -p build-windows
        cd build-windows

        cmake -DCMAKE_BUILD_TYPE=Release \
              -DECLIPTIX_BUILD_TESTS=ON \
              -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/windows-toolchain.cmake \
              -DCMAKE_INSTALL_PREFIX=/output \
              ..

        make -j\$(nproc)
        make install

        # Copy Windows DLL
        cp lib/ecliptix_security.dll /output/ || cp lib/ecliptix_security.exe /output/ || true

        echo '✅ Windows x64 build completed'
    "

echo ""
echo "Windows build artifacts:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "✅ Windows x64 library ready: $OUTPUT_DIR/ecliptix_security.dll"