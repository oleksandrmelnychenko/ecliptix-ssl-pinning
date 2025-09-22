cmake_minimum_required(VERSION 3.15)
project(sslpinning_server VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

add_library(sslpinning_server SHARED
    src/server.cpp
)

target_include_directories(sslpinning_server
    PUBLIC include
)

target_link_libraries(sslpinning_server
    PRIVATE OpenSSL::Crypto
)

target_compile_definitions(sslpinning_server
    PRIVATE ECLIPTIX_SERVER_EXPORTS
)

target_compile_options(sslpinning_server PRIVATE
    -fstack-protector-strong
    -fPIE
    -O3
    -fvisibility=hidden
    -Wall
    -Wextra
)

target_link_options(sslpinning_server PRIVATE
    -Wl,-dead_strip
    -Wl,-x
)

set_target_properties(sslpinning_server PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "sslpinning_server"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

if(WIN32)
    set_target_properties(sslpinning_server PROPERTIES
        OUTPUT_NAME "sslpinning_server"
        SUFFIX ".dll"
    )
elseif(APPLE)
    set_target_properties(sslpinning_server PROPERTIES
        OUTPUT_NAME "sslpinning_server"
        SUFFIX ".dylib"
    )
else()
    set_target_properties(sslpinning_server PROPERTIES
        OUTPUT_NAME "sslpinning_server"
        SUFFIX ".so"
    )
endif()

install(TARGETS sslpinning_server
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/ecliptix_server.h
    DESTINATION include
)