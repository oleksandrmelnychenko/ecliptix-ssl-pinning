#!/bin/bash
set -e

echo "========================================="
echo "Building Ecliptix Linux Release Libraries"
echo "========================================="

# Navigate to project root
cd "$(dirname "$0")/.."

echo "🐧 Building Linux Release libraries via Docker..."

# Build Linux Release libraries
docker run --rm \
    -v "$(pwd):/workspace" \
    -w /workspace \
    ubuntu:22.04 \
    bash -c '
        set -e

        echo "📦 Installing dependencies..."
        apt update -q >/dev/null 2>&1
        apt install -y build-essential cmake libssl-dev libsodium-dev pkg-config git >/dev/null 2>&1

        echo "🧹 Cleaning previous builds..."
        rm -rf build-linux
        mkdir build-linux
        cd build-linux

        echo "🔧 Configuring CMake for Release..."
        cmake .. -DCMAKE_BUILD_TYPE=Release -DECLIPTIX_BUILD_TESTS=OFF

        echo "🔨 Building libraries..."
        make -j$(nproc) ecliptix_server ecliptix_client

        echo "✅ Linux Release libraries built successfully!"
        echo "📍 Libraries created:"
        ls -la lib/libcertificate.pinning.* 2>/dev/null || echo "⚠️ Libraries not found in expected location"

        # Show all built libraries for debugging
        find . -name "*.so" -o -name "*.a" | head -10
    '

# Check what was actually built
echo ""
echo "📂 Checking Linux build results..."
if [ -d "build-linux/lib" ]; then
    echo "✅ Build directory exists:"
    ls -la build-linux/lib/ 2>/dev/null || echo "❌ No lib directory found"
else
    echo "❌ Build directory not found"
fi

echo ""
echo "🔍 Searching for any .so files..."
find build-linux -name "*.so" 2>/dev/null | head -5 || echo "❌ No .so files found"

echo ""
echo "✅ Linux Release build completed!"