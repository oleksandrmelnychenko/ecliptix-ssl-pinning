# Windows x64 Cross-Compilation Toolchain for MinGW-w64
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the cross compiler
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Where to look for the target environment
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Search programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Windows-specific settings
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")

# OpenSSL paths for Windows cross-compilation
set(OPENSSL_ROOT_DIR /usr/x86_64-w64-mingw32)
set(OPENSSL_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(OPENSSL_CRYPTO_LIBRARY /usr/x86_64-w64-mingw32/lib64/libcrypto.a)
set(OPENSSL_SSL_LIBRARY /usr/x86_64-w64-mingw32/lib64/libssl.a)
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
set(OPENSSL_FOUND TRUE)

# libsodium paths for Windows cross-compilation
set(SODIUM_ROOT_DIR /usr/x86_64-w64-mingw32)
set(SODIUM_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(SODIUM_LIBRARY /usr/x86_64-w64-mingw32/lib/libsodium.a)
set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
set(SODIUM_FOUND TRUE)

# Windows system libraries - complete networking and crypto support
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -lws2_32 -lcrypt32 -lssp -ladvapi32 -luser32 -lwininet")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -lws2_32 -lcrypt32 -lssp -ladvapi32 -luser32 -lwininet")

# Disable problematic security features for Windows cross-compilation
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")