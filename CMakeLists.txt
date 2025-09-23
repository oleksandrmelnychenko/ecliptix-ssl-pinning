cmake_minimum_required(VERSION 3.20)
project(EcliptixSecurity VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Compiler Configuration
# ============================================================================

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Cross-platform library output naming
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# Build Options
# ============================================================================

option(ECLIPTIX_BUILD_CLIENT "Build client library for .NET desktop/mobile apps" ON)
option(ECLIPTIX_BUILD_SERVER "Build server library for ASP.NET Core apps" ON)
option(ECLIPTIX_BUILD_TESTS "Build unit tests (enabled by default for quality assurance)" ON)
option(ECLIPTIX_STATIC_LIBRARY "Build static library instead of shared" OFF)
option(ECLIPTIX_ENABLE_ASAN "Enable AddressSanitizer for debugging" OFF)
option(ECLIPTIX_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ECLIPTIX_MAXIMUM_OBFUSCATION "Enable maximum obfuscation and hardening" OFF)

# ============================================================================
# Dependencies
# ============================================================================

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM libsodium)

# Always use find_library for reliable linking
find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    HINTS
        ${SODIUM_LIBRARY_DIRS}
        /opt/homebrew/lib
        /usr/local/lib
        /usr/lib
    REQUIRED
)

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    HINTS
        ${SODIUM_INCLUDE_DIRS}
        /opt/homebrew/include
        /usr/local/include
        /usr/include
    REQUIRED
)

if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
    set(SODIUM_FOUND TRUE)
    message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
else()
    message(FATAL_ERROR "libsodium not found. Please install: apt install libsodium-dev / brew install libsodium / pacman -S libsodium")
endif()

# ============================================================================
# Compiler Flags for Security and Performance
# ============================================================================

# Security hardening flags
set(SECURITY_FLAGS
    -fstack-protector-strong
    -fPIE
    -fvisibility=hidden
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
    -Wno-deprecated-declarations
)

# Maximum obfuscation flags (Clang-compatible)
set(OBFUSCATION_FLAGS
    -O3
    -flto
    -ffunction-sections
    -fdata-sections
    -fno-ident
    -fno-asynchronous-unwind-tables
    -fmerge-all-constants
    -fvisibility-inlines-hidden
    -fomit-frame-pointer
    -finline-functions
    -fno-common
    -fno-keep-static-consts
    -g0
    -s
)

# Binary hardening flags (platform-specific)
if(APPLE)
    set(HARDENING_FLAGS
        -Wl,-dead_strip
        -Wl,-x
        -Wl,-S
        -Wl,-no_compact_unwind
    )
else()
    set(HARDENING_FLAGS
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
        -Wl,-z,separate-code
        -Wl,--gc-sections
        -Wl,--strip-all
        -Wl,--no-undefined
        -Wl,--disable-new-dtags
    )
endif()

# Performance and warning flags
set(WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wcast-qual
    -Wcast-align
    -Wshadow
    -Wnull-dereference
    -Wdouble-promotion
    -Wmissing-include-dirs
)

# Sanitizer flags (debug builds only)
if(ECLIPTIX_ENABLE_ASAN)
    list(APPEND WARNING_FLAGS -fsanitize=address -fno-omit-frame-pointer)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
endif()

if(ECLIPTIX_ENABLE_UBSAN)
    list(APPEND WARNING_FLAGS -fsanitize=undefined)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=undefined")
endif()

# Apply flags based on configuration
if(ECLIPTIX_MAXIMUM_OBFUSCATION)
    add_compile_options(${SECURITY_FLAGS} ${OBFUSCATION_FLAGS} ${WARNING_FLAGS})
    add_link_options(${HARDENING_FLAGS})
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    message(STATUS "Maximum obfuscation enabled - binary will be heavily optimized and stripped")
else()
    add_compile_options(${SECURITY_FLAGS} ${WARNING_FLAGS})
endif()

# Release-specific optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NOT ECLIPTIX_MAXIMUM_OBFUSCATION)
        add_compile_options(-O3 -flto -DNDEBUG)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
    add_compile_definitions(NDEBUG)

    # Force tests to be enabled for release builds (disabled for obfuscated builds)
    if(NOT ECLIPTIX_BUILD_TESTS AND NOT ECLIPTIX_MAXIMUM_OBFUSCATION)
        message(STATUS "Release build detected - enabling tests automatically")
        set(ECLIPTIX_BUILD_TESTS ON CACHE BOOL "Build unit tests (required for release)" FORCE)
    endif()
endif()

# Debug flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -DDEBUG -DECLIPTIX_DEBUG)
endif()

# ============================================================================
# Source Files
# ============================================================================

# Client implementation sources (secure client operations only)
set(ECLIPTIX_CLIENT_SOURCES
    client/src/client.cpp
)

# Server implementation sources (full server operations)
set(ECLIPTIX_SERVER_SOURCES
    server/src/server.cpp
)

# Client API Headers
set(ECLIPTIX_CLIENT_HEADERS
    client/include/ecliptix_client.h
)

# Server API Headers
set(ECLIPTIX_SERVER_HEADERS
    server/include/ecliptix_server.h
)

# Common headers for both client and server
set(ECLIPTIX_COMMON_HEADERS
)

# ============================================================================
# Embedded Keys Generation - Disabled for now
# ============================================================================

# ============================================================================
# Client Library Target (.NET Desktop/Mobile)
# ============================================================================

if(ECLIPTIX_BUILD_CLIENT)
    if(ECLIPTIX_STATIC_LIBRARY)
        add_library(ecliptix_client STATIC ${ECLIPTIX_CLIENT_SOURCES} ${ECLIPTIX_CLIENT_HEADERS} ${ECLIPTIX_COMMON_HEADERS})
        set_target_properties(ecliptix_client PROPERTIES OUTPUT_NAME ecliptix.client_static)
    else()
        add_library(ecliptix_client SHARED ${ECLIPTIX_CLIENT_SOURCES} ${ECLIPTIX_CLIENT_HEADERS} ${ECLIPTIX_COMMON_HEADERS})
    endif()

    # Client compile definitions
    target_compile_definitions(ecliptix_client PRIVATE
        ECLIPTIX_CLIENT_BUILD
        BUILDING_ECLIPTIX_CLIENT
    )

    # Include directories for client
    target_include_directories(ecliptix_client
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/client/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/client/embedded
            ${CMAKE_CURRENT_SOURCE_DIR}/embedded
            ${OPENSSL_INCLUDE_DIR}
    )

    # Link libraries for client (no libsodium - client doesn't need it)
    target_link_libraries(ecliptix_client
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
    )

    # Client library properties
    set_target_properties(ecliptix_client PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        PUBLIC_HEADER "${ECLIPTIX_CLIENT_HEADERS}"
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        PREFIX ""
    )

    # Platform-specific client library naming
    if(WIN32)
        set_target_properties(ecliptix_client PROPERTIES
            OUTPUT_NAME "ecliptix.client"
            SUFFIX ".dll"
        )
    elseif(APPLE)
        set_target_properties(ecliptix_client PROPERTIES
            OUTPUT_NAME "libecliptix.client"
            SUFFIX ".dylib"
        )
    else()
        set_target_properties(ecliptix_client PROPERTIES
            OUTPUT_NAME "libecliptix.client"
            SUFFIX ".so"
        )
    endif()


    message(STATUS "Client library configured for .NET desktop/mobile applications")
endif()

# ============================================================================
# Server Library Target (ASP.NET Core)
# ============================================================================

if(ECLIPTIX_BUILD_SERVER)
    if(ECLIPTIX_STATIC_LIBRARY)
        add_library(ecliptix_server STATIC ${ECLIPTIX_SERVER_SOURCES} ${ECLIPTIX_SERVER_HEADERS} ${ECLIPTIX_COMMON_HEADERS})
        set_target_properties(ecliptix_server PROPERTIES OUTPUT_NAME ecliptix.server_static)
    else()
        add_library(ecliptix_server SHARED ${ECLIPTIX_SERVER_SOURCES} ${ECLIPTIX_SERVER_HEADERS} ${ECLIPTIX_COMMON_HEADERS})
    endif()

    # Server compile definitions
    target_compile_definitions(ecliptix_server PRIVATE
        ECLIPTIX_SERVER_BUILD
        BUILDING_ECLIPTIX_SERVER
    )

    # Include directories for server
    target_include_directories(ecliptix_server
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/server/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/server/embedded
            ${CMAKE_CURRENT_SOURCE_DIR}/embedded
            ${OPENSSL_INCLUDE_DIR}
            ${SODIUM_INCLUDE_DIRS}
    )

    # Link libraries for server (full crypto suite)
    target_link_libraries(ecliptix_server
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
            ${SODIUM_LIBRARIES}
    )

    # Server library properties
    set_target_properties(ecliptix_server PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        PUBLIC_HEADER "${ECLIPTIX_SERVER_HEADERS}"
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        PREFIX ""
    )

    # Platform-specific server library naming
    if(WIN32)
        set_target_properties(ecliptix_server PROPERTIES
            OUTPUT_NAME "ecliptix.server"
            SUFFIX ".dll"
        )
    elseif(APPLE)
        set_target_properties(ecliptix_server PROPERTIES
            OUTPUT_NAME "libecliptix.server"
            SUFFIX ".dylib"
        )
    else()
        set_target_properties(ecliptix_server PROPERTIES
            OUTPUT_NAME "libecliptix.server"
            SUFFIX ".so"
        )
    endif()


    message(STATUS "Server library configured for ASP.NET Core applications")
endif()

# ============================================================================
# Post-Build Symbol Stripping for Maximum Obfuscation
# ============================================================================

if(ECLIPTIX_MAXIMUM_OBFUSCATION)
    # Platform-specific symbol stripping for client
    if(ECLIPTIX_BUILD_CLIENT)
        if(APPLE)
            add_custom_command(TARGET ecliptix_client POST_BUILD
                COMMAND ${CMAKE_STRIP} -S -x $<TARGET_FILE:ecliptix_client>
                COMMENT "Stripping client symbols for maximum obfuscation (macOS)"
                VERBATIM
            )
        else()
            add_custom_command(TARGET ecliptix_client POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all --strip-debug --strip-unneeded
                        $<TARGET_FILE:ecliptix_client>
                COMMENT "Stripping client symbols for maximum obfuscation (Linux)"
                VERBATIM
            )
        endif()

        # Remove client build artifacts
        add_custom_command(TARGET ecliptix_client POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E remove -f
                    ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ecliptix_client.dir/src/*.o
            COMMENT "Cleaning client object files"
            VERBATIM
        )
    endif()

    # Platform-specific symbol stripping for server
    if(ECLIPTIX_BUILD_SERVER)
        if(APPLE)
            add_custom_command(TARGET ecliptix_server POST_BUILD
                COMMAND ${CMAKE_STRIP} -S -x $<TARGET_FILE:ecliptix_server>
                COMMENT "Stripping server symbols for maximum obfuscation (macOS)"
                VERBATIM
            )
        else()
            add_custom_command(TARGET ecliptix_server POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all --strip-debug --strip-unneeded
                        $<TARGET_FILE:ecliptix_server>
                COMMENT "Stripping server symbols for maximum obfuscation (Linux)"
                VERBATIM
            )
        endif()

        # Remove server build artifacts
        add_custom_command(TARGET ecliptix_server POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E remove -f
                    ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ecliptix_server.dir/src/*.o
            COMMENT "Cleaning server object files"
            VERBATIM
        )
    endif()
endif()

# ============================================================================
# Export Definitions for Client/Server DLLs
# ============================================================================

# Generate export headers for cross-platform DLL exports
include(GenerateExportHeader)

if(ECLIPTIX_BUILD_CLIENT)
    generate_export_header(ecliptix_client
        BASE_NAME ECLIPTIX_CLIENT
        EXPORT_MACRO_NAME ECLIPTIX_CLIENT_API
        EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/ecliptix/client_exports.h
    )

    target_include_directories(ecliptix_client PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    )
endif()

if(ECLIPTIX_BUILD_SERVER)
    generate_export_header(ecliptix_server
        BASE_NAME ECLIPTIX_SERVER
        EXPORT_MACRO_NAME ECLIPTIX_SERVER_API
        EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/ecliptix/server_exports.h
    )

    target_include_directories(ecliptix_server PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    )
endif()

# ============================================================================
# Testing (Optional)
# ============================================================================

if(ECLIPTIX_BUILD_TESTS)
    enable_testing()

    # Find or build test framework
    find_package(Catch2 3 QUIET)
    if(NOT Catch2_FOUND)
        message(STATUS "Catch2 not found, downloading...")
        include(FetchContent)
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.4.0
        )
        FetchContent_MakeAvailable(Catch2)
    endif()

    # C API Test (temporarily disabled - file not found)
    # add_executable(ecliptix_c_api_test test_c_api.cpp)

    # target_link_libraries(ecliptix_c_api_test
    #     PRIVATE
    #         ecliptix_security
    # )

    # target_include_directories(ecliptix_c_api_test PRIVATE
    #     ${CMAKE_CURRENT_SOURCE_DIR}/include
    # )

    # C++ Test sources - Comprehensive test suite
    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_types.cpp
        tests/test_memory.cpp
        tests/test_random.cpp
        tests/test_encryption.cpp
        tests/test_signatures.cpp
        tests/test_hashing.cpp
        tests/test_ssl.cpp
        tests/test_api_integration.cpp
    )

    # Build comprehensive C++ test suite
    if(ECLIPTIX_BUILD_CLIENT AND ECLIPTIX_BUILD_SERVER)
        add_executable(ecliptix_test_suite ${TEST_SOURCES})
        target_link_libraries(ecliptix_test_suite
            PRIVATE
                ecliptix_client
                ecliptix_server
                Catch2::Catch2WithMain
        )
    elseif(ECLIPTIX_BUILD_CLIENT)
        add_executable(ecliptix_client_test_suite ${TEST_SOURCES})
        target_link_libraries(ecliptix_client_test_suite
            PRIVATE
                ecliptix_client
                Catch2::Catch2WithMain
        )
    elseif(ECLIPTIX_BUILD_SERVER)
        add_executable(ecliptix_server_test_suite ${TEST_SOURCES})
        target_link_libraries(ecliptix_server_test_suite
            PRIVATE
                ecliptix_server
                Catch2::Catch2WithMain
        )
    endif()
    target_include_directories(ecliptix_test_suite PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/embedded
    )

    # Add tests to CTest
    # add_test(NAME EcliptixC_API_Tests COMMAND ecliptix_c_api_test)
    add_test(NAME EcliptixCPP_Test_Suite COMMAND ecliptix_test_suite)

    # World-class engineering: Optional pre-build testing
    # Note: To run tests before each build, use: make test_all && make
    add_custom_target(run_tests_before_build
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS ecliptix_test_suite
        COMMENT "Running unit tests for quality assurance (manual trigger)"
    )

    # Optional: Uncomment to make library depend on tests (creates circular dependency)
    # add_dependencies(ecliptix_security run_tests_before_build)

    # Enable CTest integration
    include(CTest)

    # Set environment for tests to find the library
    set_tests_properties(EcliptixCPP_Test_Suite PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
    )

    # Custom targets for manual testing
    # add_custom_target(test_c_api
    #     COMMAND ${CMAKE_CTEST_COMMAND} --verbose --tests-regex "EcliptixC_API_Tests"
    #     DEPENDS ecliptix_c_api_test
    #     COMMENT "Running C API tests manually"
    # )

    add_custom_target(test_cpp
        COMMAND ${CMAKE_CTEST_COMMAND} --verbose --tests-regex "EcliptixCPP_Test_Suite"
        DEPENDS ecliptix_test_suite
        COMMENT "Running C++ test suite manually"
    )

    add_custom_target(test_all
        COMMAND ${CMAKE_CTEST_COMMAND} --verbose --output-on-failure
        DEPENDS ecliptix_test_suite
        COMMENT "Running complete test suite manually"
    )

    # Release build test enforcement
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        # Create a post-build test target that runs after library is built
        add_custom_target(validate_release
            COMMAND ${CMAKE_CTEST_COMMAND} --verbose --tests-regex "c_api_test" --output-on-failure
            DEPENDS ecliptix_security ecliptix_c_api_test
            COMMENT "Validating release build with mandatory tests"
        )

        # Create an all-inclusive release target that builds and tests
        add_custom_target(release_build_with_tests
            DEPENDS validate_release
            COMMENT "Complete release build with automatic testing"
        )

        message(STATUS "Release mode: Use 'make release_build_with_tests' for full release build with testing")
        message(STATUS "Standard build: 'make' (library only), Manual tests: 'make test_c_api'")
    else()
        message(STATUS "Debug mode: Unit tests enabled. Run with: make test_c_api OR make test_all")
    endif()
else()
    message(STATUS "Unit tests disabled. Enable with: -DECLIPTIX_BUILD_TESTS=ON")
endif()

# ============================================================================
# Installation
# ============================================================================

# Install client and server libraries
if(ECLIPTIX_BUILD_CLIENT)
    install(TARGETS ecliptix_client
        EXPORT EcliptixSecurityTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        PUBLIC_HEADER DESTINATION include
    )
endif()

if(ECLIPTIX_BUILD_SERVER)
    install(TARGETS ecliptix_server
        EXPORT EcliptixSecurityTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        PUBLIC_HEADER DESTINATION include
    )
endif()

# Install all headers with proper structure
install(DIRECTORY include/ecliptix/
    DESTINATION include/ecliptix
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/ecliptix/exports.h
    DESTINATION include/ecliptix
)

# Export configuration
install(EXPORT EcliptixSecurityTargets
    FILE EcliptixSecurityTargets.cmake
    NAMESPACE Ecliptix::
    DESTINATION lib/cmake/EcliptixSecurity
)

# Package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/EcliptixSecurityConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/EcliptixSecurityConfig.cmake
    INSTALL_DESTINATION lib/cmake/EcliptixSecurity
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/EcliptixSecurityConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/EcliptixSecurityConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/EcliptixSecurityConfigVersion.cmake
    DESTINATION lib/cmake/EcliptixSecurity
)

# ============================================================================
# Package Creation
# ============================================================================

set(CPACK_PACKAGE_NAME "EcliptixSecurity")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "World-class cryptographic security library")
set(CPACK_PACKAGE_VENDOR "Ecliptix")
set(CPACK_PACKAGE_CONTACT "security@ecliptix.com")

# Platform-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
elseif(APPLE)
    set(CPACK_GENERATOR "ZIP;DragNDrop")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# ============================================================================
# Status Summary
# ============================================================================

message(STATUS "")
message(STATUS "======================================")
message(STATUS "Ecliptix Security .NET Integration")
message(STATUS "======================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
if(ECLIPTIX_STATIC_LIBRARY)
    message(STATUS "Library type: STATIC")
else()
    message(STATUS "Library type: SHARED")
endif()

if(ECLIPTIX_BUILD_CLIENT)
    message(STATUS "Client library: ENABLED (Avalonia Desktop/Mobile)")
else()
    message(STATUS "Client library: DISABLED")
endif()

if(ECLIPTIX_BUILD_SERVER)
    message(STATUS "Server library: ENABLED (ASP.NET Core)")
else()
    message(STATUS "Server library: DISABLED")
endif()

if(ECLIPTIX_BUILD_TESTS)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(STATUS "Unit tests: ENABLED (Use 'make release_build_with_tests')")
    else()
        message(STATUS "Unit tests: ENABLED")
    endif()
else()
    message(STATUS "Unit tests: DISABLED")
endif()
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
if(SODIUM_FOUND)
    message(STATUS "libsodium: FOUND (Server library only)")
else()
    message(STATUS "libsodium: NOT FOUND (Required for server library)")
endif()
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "======================================")
message(STATUS "Build Commands:")
if(ECLIPTIX_BUILD_CLIENT)
    message(STATUS "  Client only: cmake .. -DECLIPTIX_BUILD_SERVER=OFF")
endif()
if(ECLIPTIX_BUILD_SERVER)
    message(STATUS "  Server only: cmake .. -DECLIPTIX_BUILD_CLIENT=OFF")
endif()
message(STATUS "  Both: cmake .. (default)")
message(STATUS "======================================")
message(STATUS "")