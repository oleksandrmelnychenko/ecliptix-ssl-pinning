set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i686)

set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
set(CMAKE_RC_COMPILER i686-w64-mingw32-windres)

set(CMAKE_FIND_ROOT_PATH /usr/i686-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Set Windows-specific libraries
set(OPENSSL_ROOT_DIR /usr/i686-w64-mingw32)
set(OPENSSL_CRYPTO_LIBRARY /usr/i686-w64-mingw32/lib/libcrypto.a)
set(OPENSSL_SSL_LIBRARY /usr/i686-w64-mingw32/lib/libssl.a)

# Link Windows system libraries
set(CMAKE_CXX_STANDARD_LIBRARIES "-lws2_32 -lcrypt32 -ladvapi32 ${CMAKE_CXX_STANDARD_LIBRARIES}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")