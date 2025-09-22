# Ecliptix Server Build Script - Windows
# For ASP.NET Core Applications

param(
    [string]$BuildType = "Release"
)

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Ecliptix Server Build Script - Windows" -ForegroundColor Cyan
Write-Host "For ASP.NET Core Applications" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

$BuildDir = "build-server-windows"

Write-Host "Build type: $BuildType" -ForegroundColor Yellow
Write-Host "Target: Server library only" -ForegroundColor Yellow
Write-Host "Platform: Windows (x64)" -ForegroundColor Yellow

# Check dependencies
if (-not (Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ CMake not found. Please install CMake and add it to PATH" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "pkg-config" -ErrorAction SilentlyContinue)) {
    Write-Host "⚠️  pkg-config not found. You may need to install vcpkg or use manual dependency paths" -ForegroundColor Yellow
    Write-Host "   Install vcpkg: https://github.com/Microsoft/vcpkg" -ForegroundColor Yellow
    Write-Host "   Then: vcpkg install libsodium:x64-windows" -ForegroundColor Yellow
}

# Clean previous build
if (Test-Path $BuildDir) {
    Write-Host "Cleaning previous build..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

# Create build directory
New-Item -ItemType Directory -Path $BuildDir | Out-Null
Set-Location $BuildDir

try {
    # Configure with CMake
    Write-Host "Configuring CMake..." -ForegroundColor Green
    cmake .. `
        -DCMAKE_BUILD_TYPE=$BuildType `
        -DECLIPTIX_BUILD_CLIENT=OFF `
        -DECLIPTIX_BUILD_SERVER=ON `
        -DECLIPTIX_BUILD_TESTS=OFF `
        -DECLIPTIX_MAXIMUM_OBFUSCATION=ON `
        -A x64

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    # Build
    Write-Host "Building server library..." -ForegroundColor Green
    cmake --build . --config $BuildType --parallel

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    # Verify build
    $LibPath = "bin\$BuildType\ecliptix.server.dll"
    if (Test-Path $LibPath) {
        Write-Host "✅ Success! Server library built:" -ForegroundColor Green
        Write-Host "   📦 $LibPath" -ForegroundColor White

        # Show library info
        Write-Host ""
        Write-Host "Library information:" -ForegroundColor Cyan
        Get-Item $LibPath | Format-Table Name, Length, LastWriteTime -AutoSize

        Write-Host ""
        Write-Host "🎯 Ready for ASP.NET Core integration!" -ForegroundColor Green
        Write-Host "Copy $LibPath to your ASP.NET Core project bin directory" -ForegroundColor White
        Write-Host "Use P/Invoke with: [DllImport(`"ecliptix.server`")]" -ForegroundColor White
    } else {
        throw "Library file not found at expected location"
    }
}
catch {
    Write-Host "❌ Build failed: $_" -ForegroundColor Red
    exit 1
}
finally {
    Set-Location ..
}

Write-Host "===========================================" -ForegroundColor Cyan