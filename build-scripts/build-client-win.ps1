# Ecliptix Client Build Script - Windows
# For Avalonia Desktop Applications

param(
    [string]$BuildType = "Release"
)

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Ecliptix Client Build Script - Windows" -ForegroundColor Cyan
Write-Host "For Avalonia Desktop Applications" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

$BuildDir = "build-client-windows"

Write-Host "Build type: $BuildType" -ForegroundColor Yellow
Write-Host "Target: Client library only" -ForegroundColor Yellow
Write-Host "Platform: Windows (x64)" -ForegroundColor Yellow

# Check if Visual Studio is available
if (-not (Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ CMake not found. Please install CMake and add it to PATH" -ForegroundColor Red
    exit 1
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
        -DECLIPTIX_BUILD_CLIENT=ON `
        -DECLIPTIX_BUILD_SERVER=OFF `
        -DECLIPTIX_BUILD_TESTS=OFF `
        -DECLIPTIX_MAXIMUM_OBFUSCATION=ON `
        -A x64

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    # Build
    Write-Host "Building client library..." -ForegroundColor Green
    cmake --build . --config $BuildType --parallel

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    # Verify build
    $LibPath = "bin\$BuildType\ecliptix.client.dll"
    if (Test-Path $LibPath) {
        Write-Host "✅ Success! Client library built:" -ForegroundColor Green
        Write-Host "   📦 $LibPath" -ForegroundColor White

        # Show library info
        Write-Host ""
        Write-Host "Library information:" -ForegroundColor Cyan
        Get-Item $LibPath | Format-Table Name, Length, LastWriteTime -AutoSize

        Write-Host ""
        Write-Host "🎯 Ready for .NET Avalonia integration!" -ForegroundColor Green
        Write-Host "Copy $LibPath to your .NET project bin directory" -ForegroundColor White
        Write-Host "Use P/Invoke with: [DllImport(`"ecliptix.client`")]" -ForegroundColor White
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