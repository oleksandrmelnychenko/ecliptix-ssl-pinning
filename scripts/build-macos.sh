#!/bin/bash
set -e

echo "========================================="
echo "Building Ecliptix macOS Libraries"
echo "========================================="

# Navigate to project root
cd "$(dirname "$0")/.."

# Clean and create build directory
echo "🧹 Cleaning previous builds..."
rm -rf build-macos
mkdir build-macos
cd build-macos

# Configure with Release
echo "🔧 Running CMake configuration..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build libraries
echo "🔨 Building libraries..."
make -j$(sysctl -n hw.ncpu)

echo "✅ macOS libraries built successfully!"
echo "📍 Output location: $(pwd)/lib/"
ls -la lib/libcertificate.pinning.*