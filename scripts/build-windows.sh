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

# Backup and use simplified Docker config
if [ -f ~/.docker/config.json ]; then
    cp ~/.docker/config.json ~/.docker/config_backup.json
    cp ~/.docker/config_temp.json ~/.docker/config.json
fi

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

        echo '🔧 Running CMake configuration...'
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DECLIPTIX_BUILD_TESTS=OFF \
              -DECLIPTIX_BUILD_CLIENT=ON \
              -DECLIPTIX_BUILD_SERVER=ON \
              -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/windows-toolchain.cmake \
              -DCMAKE_INSTALL_PREFIX=/output \
              .. || exit 1

        echo '🔨 Building libraries...'
        make -j\$(nproc) || exit 1

        echo '📦 Installing...'
        make install || exit 1

        echo '📋 Build directory contents:'
        find . -name '*.dll' -o -name '*.exe' | head -20

        echo '📋 Lib directory contents:'
        ls -la lib/ || echo 'No lib directory found'

        # Copy Windows DLLs for both client and server
        cp lib/ecliptix.client.dll /output/ 2>/dev/null || echo 'No client DLL found'
        cp lib/ecliptix.server.dll /output/ 2>/dev/null || echo 'No server DLL found'

        echo '✅ Windows x64 build completed'
    "

# Restore original Docker config
if [ -f ~/.docker/config_backup.json ]; then
    mv ~/.docker/config_backup.json ~/.docker/config.json
fi

echo ""
echo "Windows build artifacts:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "✅ Windows x64 libraries ready:"
echo "  Client: $OUTPUT_DIR/ecliptix.client.dll"
echo "  Server: $OUTPUT_DIR/ecliptix.server.dll"