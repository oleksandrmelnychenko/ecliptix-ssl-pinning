# Minimal Windows x64 Cross-Compilation Toolchain
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

# Minimal OpenSSL paths for Windows cross-compilation
set(OPENSSL_ROOT_DIR /usr/x86_64-w64-mingw32)
set(OPENSSL_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(OPENSSL_CRYPTO_LIBRARY /usr/x86_64-w64-mingw32/lib64/libcrypto.a)
set(OPENSSL_SSL_LIBRARY /usr/x86_64-w64-mingw32/lib64/libssl.a)
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
set(OPENSSL_FOUND TRUE)

# Disable libsodium for minimal build - use OpenSSL crypto only
set(SODIUM_FOUND FALSE)
set(SODIUM_LIBRARIES "")
set(SODIUM_INCLUDE_DIRS "")

# Windows system libraries - complete set for OpenSSL + stack protection
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -lws2_32 -lcrypt32 -lbcrypt -ladvapi32 -luser32 -lwininet -lssp")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -lws2_32 -lcrypt32 -lbcrypt -ladvapi32 -luser32 -lwininet -lssp")

# Disable problematic security features for Windows cross-compilation
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -Os")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector -Os")