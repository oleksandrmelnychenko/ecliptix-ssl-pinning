/*
 * Ecliptix Security Library - Test Main
 * Comprehensive test suite using Catch2
 */

#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

// Test configuration and global setup
int main(int argc, char* argv[]) {
    return Catch::Session().run(argc, argv);
}