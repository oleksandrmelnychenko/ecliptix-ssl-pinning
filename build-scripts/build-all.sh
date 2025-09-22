#!/bin/bash
set -e

echo "=========================================="
echo "Ecliptix .NET Integration Build Script"
echo "Build all platforms and configurations"
echo "=========================================="

# Configuration
BUILD_TYPE=${1:-Release}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Build type: $BUILD_TYPE"
echo "Project root: $PROJECT_ROOT"
echo ""

# Detect platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
else
    echo "❌ Unsupported platform: $OSTYPE"
    echo "Use platform-specific scripts manually"
    exit 1
fi

echo "Detected platform: $PLATFORM"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Build configurations
CONFIGS=("client" "server")

for config in "${CONFIGS[@]}"; do
    echo "=========================================="
    echo "Building $config library for $PLATFORM..."
    echo "=========================================="

    script_name="build-${config}-${PLATFORM}.sh"
    script_path="$SCRIPT_DIR/$script_name"

    if [ -f "$script_path" ]; then
        echo "Running: $script_name"
        bash "$script_path" "$BUILD_TYPE"
        echo ""
    else
        echo "❌ Script not found: $script_name"
        echo "Available scripts:"
        ls "$SCRIPT_DIR"/build-*.sh
        exit 1
    fi
done

echo "=========================================="
echo "✅ All builds completed successfully!"
echo "=========================================="
echo ""
echo "Libraries built:"
if [ -f "build-client-$PLATFORM/lib/libecliptix.client.dylib" ] || [ -f "build-client-$PLATFORM/lib/libecliptix.client.so" ]; then
    echo "  📦 Client library: build-client-$PLATFORM/lib/"
fi
if [ -f "build-server-$PLATFORM/lib/libecliptix.server.dylib" ] || [ -f "build-server-$PLATFORM/lib/libecliptix.server.so" ]; then
    echo "  📦 Server library: build-server-$PLATFORM/lib/"
fi

echo ""
echo "🎯 Ready for .NET integration!"
echo ""
echo "Next steps:"
echo "1. Copy client library to your Avalonia project"
echo "2. Copy server library to your ASP.NET Core project"
echo "3. Use P/Invoke with appropriate DllImport attributes"
echo ""
echo "For Windows builds, use PowerShell scripts:"
echo "  .\build-scripts\build-client-win.ps1"
echo "  .\build-scripts\build-server-win.ps1"
echo "=========================================="