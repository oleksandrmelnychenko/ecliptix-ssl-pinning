#!/bin/bash
set -e

# Ecliptix Security Library - Cross-Platform Build Script
# Builds for macOS, Windows (x64), and Linux (x64)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/builds"

echo "======================================="
echo "Ecliptix Security - Cross-Platform Build"
echo "======================================="
echo "Project Root: $PROJECT_ROOT"
echo "Build Directory: $BUILD_DIR"
echo ""

# Create build directory structure
mkdir -p "$BUILD_DIR"/{macos,windows,linux}

# Function to build for a specific platform
build_platform() {
    local platform=$1
    local dockerfile=$2
    local toolchain=$3
    local output_dir="$BUILD_DIR/$platform"

    echo "Building for $platform..."
    echo "Output directory: $output_dir"

    if [ "$platform" = "macos" ]; then
        # Native macOS build
        cd "$PROJECT_ROOT"
        mkdir -p build-macos
        cd build-macos

        cmake -DCMAKE_BUILD_TYPE=Release \
              -DECLIPTIX_BUILD_TESTS=ON \
              -DCMAKE_INSTALL_PREFIX="$output_dir" \
              ..

        make -j$(sysctl -n hw.ncpu)
        make install

        # Copy native library to output
        cp lib/ecliptix_security.dylib "$output_dir/"

        echo "✅ macOS build completed successfully"

    else
        # Docker-based cross-compilation
        local image_name="ecliptix-build-$platform"

        echo "Building Docker image: $image_name"
        docker build -f "$PROJECT_ROOT/docker/Dockerfile.$platform" \
                     -t "$image_name" "$PROJECT_ROOT"

        echo "Running cross-compilation in Docker container..."
        docker run --rm \
            -v "$PROJECT_ROOT:/workspace" \
            -v "$output_dir:/output" \
            -w /workspace \
            "$image_name" \
            bash -c "
                mkdir -p build-$platform
                cd build-$platform

                cmake -DCMAKE_BUILD_TYPE=Release \
                      -DECLIPTIX_BUILD_TESTS=ON \
                      -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/windows-toolchain.cmake \
                      -DCMAKE_INSTALL_PREFIX=/output \
                      ..

                make -j\$(nproc)
                make install

                # Copy platform-specific library
                if [ '$platform' = 'windows' ]; then
                    cp lib/ecliptix_security.dll /output/ || true
                elif [ '$platform' = 'linux' ]; then
                    cp lib/ecliptix_security.so /output/ || true
                fi

                echo '✅ $platform build completed successfully'
            "
    fi

    echo "Build artifacts for $platform:"
    ls -la "$output_dir/"
    echo ""
}

# Build for all platforms
echo "Starting cross-platform builds..."
echo ""

# Build for macOS (native)
build_platform "macos" "" ""

# Build for Windows (cross-compile)
build_platform "windows" "Dockerfile.windows" "windows-toolchain.cmake"

# Build for Linux (cross-compile)
build_platform "linux" "Dockerfile.linux" "linux-toolchain.cmake"

echo "======================================="
echo "All builds completed successfully!"
echo "======================================="
echo ""
echo "Build artifacts:"
echo "  macOS:   $BUILD_DIR/macos/"
echo "  Windows: $BUILD_DIR/windows/"
echo "  Linux:   $BUILD_DIR/linux/"
echo ""
echo "Libraries generated:"
find "$BUILD_DIR" -name "ecliptix_security*" -type f
echo ""