#!/bin/bash
set -e

# Ecliptix Security Library - Minimal Windows x64 Build Script
# Creates small DLLs with only RSA + SHA256 operations (no libsodium)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/builds/windows-minimal"

echo "======================================="
echo "Ecliptix Security - Minimal Windows x64"
echo "======================================="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Backup and use simplified Docker config
if [ -f ~/.docker/config.json ]; then
    cp ~/.docker/config.json ~/.docker/config_backup_minimal.json
    cp ~/.docker/config_temp.json ~/.docker/config.json
fi

# Build Docker image
echo "Building minimal Windows cross-compilation environment..."
docker build -f "$PROJECT_ROOT/docker/Dockerfile.windows-minimal" \
             -t ecliptix-build-windows-minimal "$PROJECT_ROOT"

# Run cross-compilation
echo "Cross-compiling minimal version for Windows x64..."
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v "$OUTPUT_DIR:/output" \
    -w /workspace \
    ecliptix-build-windows-minimal \
    bash -c "
        mkdir -p build-windows-minimal
        cd build-windows-minimal

        echo '🔧 Running minimal CMake configuration...'
        cmake -DCMAKE_BUILD_TYPE=MinSizeRel \
              -DECLIPTIX_BUILD_TESTS=OFF \
              -DECLIPTIX_BUILD_CLIENT=ON \
              -DECLIPTIX_BUILD_SERVER=OFF \
              -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/windows-toolchain-minimal.cmake \
              -DCMAKE_INSTALL_PREFIX=/output \
              .. || exit 1

        echo '🔨 Building minimal libraries...'
        make ecliptix_client -j\$(nproc) || exit 1

        echo '📋 Build directory contents:'
        find . -name '*.dll' -o -name '*.exe' | head -20

        echo '📋 Lib directory contents:'
        ls -la lib/ || echo 'No lib directory found'

        # Copy minimal Windows DLL
        cp bin/ecliptix.client.dll /output/ecliptix.client-minimal.dll 2>/dev/null || echo 'No client DLL found'

        echo '✅ Minimal Windows x64 build completed'
    "

# Restore original Docker config
if [ -f ~/.docker/config_backup_minimal.json ]; then
    mv ~/.docker/config_backup_minimal.json ~/.docker/config.json
fi

echo ""
echo "Minimal Windows build artifacts:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "✅ Minimal Windows x64 library ready:"
echo "  Client (minimal): $OUTPUT_DIR/ecliptix.client-minimal.dll"