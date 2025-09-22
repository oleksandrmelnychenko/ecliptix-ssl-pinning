#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix Client Build Script - macOS"
echo "For Avalonia Desktop Applications"
echo "=========================================="

# Build configuration
BUILD_TYPE=${1:-Release}
BUILD_DIR="build-client-macos"

echo "Build type: $BUILD_TYPE"
echo "Target: Client library only"
echo "Platform: macOS (Apple Silicon & Intel)"

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
    -DECLIPTIX_MAXIMUM_OBFUSCATION=ON \
    -DCMAKE_OSX_ARCHITECTURES="$(uname -m)"

# Build
echo "Building client library..."
make -j$(sysctl -n hw.ncpu)

# Verify build
if [ -f "lib/libecliptix.client.dylib" ]; then
    echo "✅ Success! Client library built:"
    echo "   📦 lib/libecliptix.client.dylib"

    # Show library info
    echo ""
    echo "Library information:"
    otool -L lib/libecliptix.client.dylib
    echo ""
    echo "Architectures:"
    lipo -info lib/libecliptix.client.dylib
    echo ""
    echo "Size:"
    ls -lh lib/libecliptix.client.dylib

    echo ""
    echo "🎯 Ready for .NET Avalonia integration!"
    echo "Copy lib/libecliptix.client.dylib to your .NET project"
    echo "Use P/Invoke with: [DllImport(\"libecliptix.client\")]"
else
    echo "❌ Build failed!"
    exit 1
fi

echo "=========================================="