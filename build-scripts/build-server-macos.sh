#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix Server Build Script - macOS"
echo "For ASP.NET Core Applications"
echo "=========================================="

# Build configuration
BUILD_TYPE=${1:-Release}
BUILD_DIR="build-server-macos"

echo "Build type: $BUILD_TYPE"
echo "Target: Server library only"
echo "Platform: macOS (Apple Silicon & Intel)"

# Check dependencies
if ! command -v pkg-config &> /dev/null; then
    echo "❌ pkg-config not found. Install with: brew install pkg-config"
    exit 1
fi

if ! pkg-config --exists libsodium; then
    echo "❌ libsodium not found. Install with: brew install libsodium"
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
    -DECLIPTIX_MAXIMUM_OBFUSCATION=ON \
    -DCMAKE_OSX_ARCHITECTURES="$(uname -m)"

# Build
echo "Building server library..."
make -j$(sysctl -n hw.ncpu)

# Verify build
if [ -f "lib/libecliptix.server.dylib" ]; then
    echo "✅ Success! Server library built:"
    echo "   📦 lib/libecliptix.server.dylib"

    # Show library info
    echo ""
    echo "Library information:"
    otool -L lib/libecliptix.server.dylib
    echo ""
    echo "Architectures:"
    lipo -info lib/libecliptix.server.dylib
    echo ""
    echo "Size:"
    ls -lh lib/libecliptix.server.dylib

    echo ""
    echo "🎯 Ready for ASP.NET Core integration!"
    echo "Copy lib/libecliptix.server.dylib to your ASP.NET Core project"
    echo "Use P/Invoke with: [DllImport(\"libecliptix.server\")]"
else
    echo "❌ Build failed!"
    exit 1
fi

echo "=========================================="