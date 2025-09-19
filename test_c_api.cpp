/*
 * Simple C API Test
 * Test basic functionality of the C API
 */

#include "ecliptix/security.h"
#include "ecliptix/types.h"
#include <iostream>
#include <cstring>

int main() {
    std::cout << "Testing Ecliptix Security Library C API..." << std::endl;

    // Test library initialization
    std::cout << "1. Testing library initialization..." << std::endl;
    ecliptix_result_t result = ecliptix_init();
    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Failed to initialize library: " << result << std::endl;
        return 1;
    }
    std::cout << "   ✓ Library initialized successfully" << std::endl;

    // Test if library is initialized
    std::cout << "2. Testing library status..." << std::endl;
    int is_init = ecliptix_is_initialized();
    if (!is_init) {
        std::cerr << "Library reports as not initialized" << std::endl;
        return 1;
    }
    std::cout << "   ✓ Library status check working" << std::endl;

    // Test version information
    std::cout << "3. Testing version information..." << std::endl;
    ecliptix_version_info_t version_info;
    result = ecliptix_get_version(&version_info);
    if (result != ECLIPTIX_SUCCESS) {
        std::cerr << "Failed to get version: " << result << std::endl;
        return 1;
    }
    std::cout << "   ✓ Version: " << version_info.major << "."
              << version_info.minor << "." << version_info.patch
              << " (build " << version_info.build << ")" << std::endl;
    std::cout << "   ✓ Build date: " << version_info.build_date << std::endl;

    // Test error message retrieval
    std::cout << "4. Testing error handling..." << std::endl;
    const char* error_msg = ecliptix_get_error_message();
    if (!error_msg) {
        std::cerr << "Failed to get error message" << std::endl;
        return 1;
    }
    std::cout << "   ✓ Error message retrieval working" << std::endl;

    // Test library cleanup
    std::cout << "5. Testing library cleanup..." << std::endl;
    ecliptix_cleanup();
    std::cout << "   ✓ Library cleaned up successfully" << std::endl;

    std::cout << std::endl << "All tests passed! ✓" << std::endl;
    return 0;
}