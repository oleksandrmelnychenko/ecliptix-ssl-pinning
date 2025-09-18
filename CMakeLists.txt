cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Security_SSL_Pinning VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags for security and optimization
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")

# Release-specific optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -flto -s")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    add_compile_definitions(NDEBUG)
endif()

# Debug flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")
    add_compile_definitions(ECLIPTIX_DEBUG)
endif()

# Source files
set(ECLIPTIX_SOURCES
    src/security.cpp
    src/openssl_wrapper_simple.cpp
)

# Headers
set(ECLIPTIX_HEADERS
    include/ecliptix/security.h
    include/ecliptix/security.hpp
    include/ecliptix/types.h
    include/internal/openssl_wrapper.hpp
)

# Generate embedded keys header (will be created)
set(EMBEDDED_KEYS_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/embedded/embedded_keys.hpp)

# Main library
add_library(ecliptix_security SHARED ${ECLIPTIX_SOURCES} ${ECLIPTIX_HEADERS})

target_include_directories(ecliptix_security
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/embedded
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(ecliptix_security
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Static library variant
add_library(ecliptix_security_static STATIC ${ECLIPTIX_SOURCES} ${ECLIPTIX_HEADERS})

target_include_directories(ecliptix_security_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/embedded
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(ecliptix_security_static
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Set library properties
set_target_properties(ecliptix_security PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${ECLIPTIX_HEADERS}"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

set_target_properties(ecliptix_security_static PROPERTIES
    OUTPUT_NAME ecliptix_security_static
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Generate PKI and embedded keys at build time
add_custom_command(
    OUTPUT ${EMBEDDED_KEYS_HEADER}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/embedded
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/keys/generated
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/keys/generate_pki.sh
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/keys/embed_keys.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/keys
    COMMENT "Generating PKI keys and embedding certificates"
    VERBATIM
)

add_custom_target(generate_keys DEPENDS ${EMBEDDED_KEYS_HEADER})
add_dependencies(ecliptix_security generate_keys)
add_dependencies(ecliptix_security_static generate_keys)

# Demo executable
add_executable(ecliptix_demo demo/main.cpp)
target_link_libraries(ecliptix_demo PRIVATE ecliptix_security)

# Tests disabled for now

# Installation
install(TARGETS ecliptix_security ecliptix_security_static
    EXPORT EcliptixSecurityTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/ecliptix
)

install(DIRECTORY include/ecliptix/ DESTINATION include/ecliptix)

# Export configuration
install(EXPORT EcliptixSecurityTargets
    FILE EcliptixSecurityTargets.cmake
    NAMESPACE Ecliptix::
    DESTINATION lib/cmake/EcliptixSecurity
)

# Package config
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "EcliptixSecurityConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    "EcliptixSecurityConfigVersion.cmake"
    DESTINATION lib/cmake/EcliptixSecurity
)