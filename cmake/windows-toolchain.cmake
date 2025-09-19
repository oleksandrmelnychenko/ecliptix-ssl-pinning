# CMake toolchain file for Windows cross-compilation using MinGW-w64
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the cross compiler
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Where to look for the target environment
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Set OpenSSL paths for Windows cross-compilation
set(OPENSSL_ROOT_DIR /usr/x86_64-w64-mingw32)
set(OPENSSL_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(OPENSSL_CRYPTO_LIBRARY /usr/x86_64-w64-mingw32/lib/libcrypto.a)
set(OPENSSL_SSL_LIBRARY /usr/x86_64-w64-mingw32/lib/libssl.a)

# Set libsodium paths for Windows cross-compilation
set(SODIUM_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(SODIUM_LIBRARY /usr/x86_64-w64-mingw32/lib/libsodium.a)

# Additional Windows-specific flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++")

# Windows-specific library extensions
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")
set(CMAKE_EXECUTABLE_SUFFIX ".exe")