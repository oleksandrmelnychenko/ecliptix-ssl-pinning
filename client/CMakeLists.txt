cmake_minimum_required(VERSION 3.15)
project(sslpinning VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

add_library(sslpinning SHARED
    src/client.cpp
)

target_include_directories(sslpinning
    PUBLIC include
)

target_link_libraries(sslpinning
    PRIVATE OpenSSL::Crypto
)

target_compile_definitions(sslpinning
    PRIVATE ECLIPTIX_CLIENT_EXPORTS
)

target_compile_options(sslpinning PRIVATE
    -fstack-protector-strong
    -fPIE
    -O3
    -fvisibility=hidden
    -Wall
    -Wextra
)

target_link_options(sslpinning PRIVATE
    -Wl,-dead_strip
    -Wl,-x
)

set_target_properties(sslpinning PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "sslpinning"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

if(WIN32)
    set_target_properties(sslpinning PROPERTIES
        OUTPUT_NAME "sslpinning"
        SUFFIX ".dll"
    )
elseif(APPLE)
    set_target_properties(sslpinning PROPERTIES
        OUTPUT_NAME "sslpinning"
        SUFFIX ".dylib"
    )
else()
    set_target_properties(sslpinning PROPERTIES
        OUTPUT_NAME "sslpinning"
        SUFFIX ".so"
    )
endif()

install(TARGETS sslpinning
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/ecliptix_client.h
    DESTINATION include
)