#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix Client Build Script - Linux"
echo "For Avalonia Desktop Applications"
echo "=========================================="

# Build configuration
BUILD_TYPE=${1:-Release}
BUILD_DIR="build-client-linux"

echo "Build type: $BUILD_TYPE"
echo "Target: Client library only"
echo "Platform: Linux (x86_64)"

# Check dependencies
if ! command -v cmake &> /dev/null; then
    echo "❌ CMake not found. Install with: sudo apt install cmake"
    exit 1
fi

if ! command -v g++ &> /dev/null; then
    echo "❌ g++ not found. Install with: sudo apt install build-essential"
    exit 1
fi

if ! pkg-config --exists openssl; then
    echo "❌ OpenSSL not found. Install with: sudo apt install libssl-dev"
    exit 1
fi

# Clean previous build
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning previous build..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
echo "Configuring CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DECLIPTIX_BUILD_CLIENT=ON \
    -DECLIPTIX_BUILD_SERVER=OFF \
    -DECLIPTIX_BUILD_TESTS=OFF \
    -DECLIPTIX_MAXIMUM_OBFUSCATION=ON

# Build
echo "Building client library..."
make -j$(nproc)

# Verify build
if [ -f "lib/libecliptix.client.so" ]; then
    echo "✅ Success! Client library built:"
    echo "   📦 lib/libecliptix.client.so"

    # Show library info
    echo ""
    echo "Library information:"
    ldd lib/libecliptix.client.so
    echo ""
    echo "Size:"
    ls -lh lib/libecliptix.client.so
    echo ""
    echo "Symbols (should be minimal with obfuscation):"
    nm -D lib/libecliptix.client.so | wc -l

    echo ""
    echo "🎯 Ready for .NET Avalonia integration!"
    echo "Copy lib/libecliptix.client.so to your .NET project"
    echo "Use P/Invoke with: [DllImport(\"libecliptix.client\")]"
else
    echo "❌ Build failed!"
    exit 1
fi

echo "=========================================="