
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was EcliptixSecurityConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

# Ecliptix Security Library Configuration File
#
# This file allows other projects to find and use the Ecliptix Security Library
# through CMake's find_package() mechanism.
#
# Usage example:
#   find_package(EcliptixSecurity REQUIRED)
#   target_link_libraries(your_target Ecliptix::ecliptix_security)

include(CMakeFindDependencyMacro)

# Find required dependencies
find_dependency(OpenSSL REQUIRED)
find_dependency(Threads REQUIRED)

# Find libsodium (try pkg-config first, then direct search)
find_dependency(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM libsodium)
endif()

if(NOT SODIUM_FOUND)
    find_library(SODIUM_LIBRARY sodium)
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        set(SODIUM_FOUND TRUE)
    else()
        message(FATAL_ERROR "Required dependency libsodium not found")
    endif()
endif()

# Include the exported targets
include("${CMAKE_CURRENT_LIST_DIR}/EcliptixSecurityTargets.cmake")

# Provide information about the library
set(EcliptixSecurity_VERSION "1.0.0")
set(EcliptixSecurity_VERSION_MAJOR "1")
set(EcliptixSecurity_VERSION_MINOR "0")
set(EcliptixSecurity_VERSION_PATCH "0")

# Check if all required components are available
check_required_components(EcliptixSecurity)

# Set variables for backwards compatibility
if(TARGET Ecliptix::ecliptix_security)
    set(EcliptixSecurity_FOUND TRUE)
    set(ECLIPTIX_SECURITY_FOUND TRUE)

    # Get target properties for legacy variables
    get_target_property(EcliptixSecurity_INCLUDE_DIRS Ecliptix::ecliptix_security INTERFACE_INCLUDE_DIRECTORIES)
    set(EcliptixSecurity_LIBRARIES Ecliptix::ecliptix_security)
    set(ECLIPTIX_SECURITY_LIBRARIES ${EcliptixSecurity_LIBRARIES})
    set(ECLIPTIX_SECURITY_INCLUDE_DIRS ${EcliptixSecurity_INCLUDE_DIRS})
else()
    set(EcliptixSecurity_FOUND FALSE)
    set(ECLIPTIX_SECURITY_FOUND FALSE)
endif()

# Provide usage hints
if(EcliptixSecurity_FOUND AND NOT EcliptixSecurity_FIND_QUIETLY)
    message(STATUS "Found Ecliptix Security Library v${EcliptixSecurity_VERSION}")
    message(STATUS "  Include dirs: ${EcliptixSecurity_INCLUDE_DIRS}")
    message(STATUS "  Libraries: ${EcliptixSecurity_LIBRARIES}")
    message(STATUS "")
    message(STATUS "Usage example:")
    message(STATUS "  target_link_libraries(your_target Ecliptix::ecliptix_security)")
    message(STATUS "  #include \"ecliptix/api.hpp\"")
endif()
