#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix Server Build Script - Linux"
echo "For ASP.NET Core Applications"
echo "=========================================="

# Build configuration
BUILD_TYPE=${1:-Release}
BUILD_DIR="build-server-linux"

echo "Build type: $BUILD_TYPE"
echo "Target: Server library only"
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

if ! command -v pkg-config &> /dev/null; then
    echo "❌ pkg-config not found. Install with: sudo apt install pkg-config"
    exit 1
fi

if ! pkg-config --exists openssl; then
    echo "❌ OpenSSL not found. Install with: sudo apt install libssl-dev"
    exit 1
fi

if ! pkg-config --exists libsodium; then
    echo "❌ libsodium not found. Install with: sudo apt install libsodium-dev"
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
    -DECLIPTIX_BUILD_CLIENT=OFF \
    -DECLIPTIX_BUILD_SERVER=ON \
    -DECLIPTIX_BUILD_TESTS=OFF \
    -DECLIPTIX_MAXIMUM_OBFUSCATION=ON

# Build
echo "Building server library..."
make -j$(nproc)

# Verify build
if [ -f "lib/libecliptix.server.so" ]; then
    echo "✅ Success! Server library built:"
    echo "   📦 lib/libecliptix.server.so"

    # Show library info
    echo ""
    echo "Library information:"
    ldd lib/libecliptix.server.so
    echo ""
    echo "Size:"
    ls -lh lib/libecliptix.server.so
    echo ""
    echo "Symbols (should be minimal with obfuscation):"
    nm -D lib/libecliptix.server.so | wc -l

    echo ""
    echo "🎯 Ready for ASP.NET Core integration!"
    echo "Copy lib/libecliptix.server.so to your ASP.NET Core project"
    echo "Use P/Invoke with: [DllImport(\"libecliptix.server\")]"
else
    echo "❌ Build failed!"
    exit 1
fi

echo "=========================================="