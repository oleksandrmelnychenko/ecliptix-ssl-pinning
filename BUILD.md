# Cross-Platform Build Guide

This document describes how to build the Ecliptix Security SSL Pinning Library for multiple platforms.

## Supported Platforms

- **macOS** (arm64/x64) - Native build
- **Windows** (x64) - Cross-compilation using MinGW-w64
- **Linux** (x64) - Docker-based compilation

## Prerequisites

### General Requirements
- CMake 3.20 or higher
- Docker (for cross-platform builds)
- Python 3 (for key embedding)
- Bash shell

### macOS Native Build
- Xcode Command Line Tools
- Homebrew packages:
  ```bash
  brew install cmake openssl libsodium
  ```

## Quick Start

### Build All Platforms
```bash
# Build for macOS, Windows, and Linux
./scripts/build-all-platforms.sh
```

### Build Individual Platforms
```bash
# Windows x64 only
./scripts/build-windows.sh

# Linux x64 only
./scripts/build-linux.sh

# macOS native (no script needed)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DECLIPTIX_BUILD_TESTS=ON ..
make -j$(sysctl -n hw.ncpu)
```

## Build Outputs

All builds generate the following structure:
```
builds/
├── macos/
│   ├── ecliptix_security.dylib    # macOS shared library
│   ├── include/                   # Header files
│   └── lib/                       # Additional libraries
├── windows/
│   ├── ecliptix_security.dll      # Windows DLL
│   ├── include/                   # Header files
│   └── lib/                       # Import libraries
└── linux/
    ├── ecliptix_security.so       # Linux shared object
    ├── include/                   # Header files
    └── lib/                       # Additional libraries
```

## Library Files for C# Integration

After building, use these files for P/Invoke integration:

### Windows
- **Runtime**: `builds/windows/ecliptix_security.dll`
- **Headers**: `builds/windows/include/ecliptix/`

### Linux
- **Runtime**: `builds/linux/ecliptix_security.so`
- **Headers**: `builds/linux/include/ecliptix/`

### macOS
- **Runtime**: `builds/macos/ecliptix_security.dylib`
- **Headers**: `builds/macos/include/ecliptix/`

## C# NativeLibrary Loading

Update your C# project to load the appropriate library:

```csharp
// In NativeSslPinningService.cs
private static string GetLibraryName()
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        return "ecliptix_security.dll";
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        return "ecliptix_security.so";
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        return "ecliptix_security.dylib";
    else
        throw new PlatformNotSupportedException();
}
```

## Advanced Configuration

### Build Options
```bash
# Static library instead of shared
cmake -DECLIPTIX_STATIC_LIBRARY=ON ..

# Enable address sanitizer (debug builds)
cmake -DECLIPTIX_ENABLE_ASAN=ON ..

# Disable tests
cmake -DECLIPTIX_BUILD_TESTS=OFF ..
```

### Docker Configuration

The Docker-based builds use:
- **Windows**: Ubuntu 22.04 + MinGW-w64 cross-compiler
- **Linux**: Ubuntu 22.04 + GCC native compiler

Both environments include:
- OpenSSL 3.2.0 (compiled for target platform)
- libsodium 1.0.19 (compiled for target platform)
- CMake 3.20+

## Troubleshooting

### Docker Issues
```bash
# Clean Docker images
docker system prune -a

# Rebuild images
docker build --no-cache -f docker/Dockerfile.windows -t ecliptix-build-windows .
```

### Dependencies Not Found
```bash
# macOS - reinstall dependencies
brew reinstall openssl libsodium

# Verify CMake can find dependencies
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

### Permission Issues
```bash
# Make scripts executable
chmod +x scripts/*.sh
```

## Security Notes

- All builds include embedded certificate pins (no private keys)
- Libraries are compiled with security hardening flags
- Memory protection and secure allocation enabled
- Static linking preferred for distribution

## Integration Testing

After building, test the libraries:

```bash
# Run C API tests (if built)
./build/bin/ecliptix_c_api_test

# Test C# integration
cd /path/to/ecliptix-desktop
dotnet build
dotnet run -- --help  # Should show SSL initialization logs
```

## Deployment

Copy the appropriate library files to your C# project's runtime directory:

```
Ecliptix.Security.SSL.Native/
├── runtimes/
│   ├── win-x64/native/ecliptix_security.dll
│   ├── linux-x64/native/ecliptix_security.so
│   └── osx-x64/native/ecliptix_security.dylib
```

This ensures automatic platform detection and loading in .NET applications.