cmake_minimum_required(VERSION 3.16)
project(MultivariateAdaptorSignatures VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    set(PLATFORM_NAME "Windows")
    set(LIBRARY_EXTENSION ".dll")
    set(STATIC_LIBRARY_EXTENSION ".lib")
elseif(APPLE)
    set(PLATFORM_NAME "macOS")
    set(LIBRARY_EXTENSION ".dylib")
    set(STATIC_LIBRARY_EXTENSION ".a")
elseif(UNIX)
    set(PLATFORM_NAME "Linux")
    set(LIBRARY_EXTENSION ".so")
    set(STATIC_LIBRARY_EXTENSION ".a")
else()
    set(PLATFORM_NAME "Unknown")
    set(LIBRARY_EXTENSION ".so")
    set(STATIC_LIBRARY_EXTENSION ".a")
endif()

message(STATUS "Building for ${PLATFORM_NAME}")

# Compiler flags
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /O2")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D_DEBUG")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Find liboqs
find_path(LIBOQS_INCLUDE_DIR
    NAMES oqs/oqs.h
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/liboqs/build/include
        ${CMAKE_CURRENT_SOURCE_DIR}/liboqs/include
        /usr/local/include
        /usr/include
)

find_library(LIBOQS_LIBRARY
    NAMES oqs
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/liboqs/build/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/liboqs/lib
        /usr/local/lib
        /usr/lib
)

if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found. Please build liboqs first.")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/interfaces
    ${CMAKE_CURRENT_SOURCE_DIR}/src/implementations
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
    ${LIBOQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(ADAPTOR_SOURCES
    src/implementations/multivariate_adaptor.c
    src/utils/csv_utils.c
)

set(ADAPTOR_HEADERS
    src/interfaces/multivariate_adaptor.h
    src/utils/csv_utils.h
)

# Create library
add_library(adaptor_signatures STATIC ${ADAPTOR_SOURCES} ${ADAPTOR_HEADERS})

# Link libraries
target_link_libraries(adaptor_signatures
    ${LIBOQS_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Test executables - organized by category
set(UNIT_TEST_SOURCES
    "tests/Unit Tests/test_core.c"
    "tests/Unit Tests/test_validation.c"
    "tests/Unit Tests/test_sizing.c"
    "tests/Unit Tests/test_witness.c"
    "tests/Unit Tests/test_utility.c"
    "tests/Unit Tests/test_boundary.c"
)

set(INTEGRATION_TEST_SOURCES
    "tests/Integration Tests/test_integration.c"
)

set(PERFORMANCE_TEST_SOURCES
    "tests/Performance Tests/test_performance.c"
    "tests/Performance Tests/test_bench.c"
)

set(ROBUSTNESS_TEST_SOURCES
    "tests/Robustness Tests/test_negative.c"
    "tests/Robustness Tests/test_stress.c"
)

# Combine all test sources
set(TEST_SOURCES
    ${UNIT_TEST_SOURCES}
    ${INTEGRATION_TEST_SOURCES}
    ${PERFORMANCE_TEST_SOURCES}
    ${ROBUSTNESS_TEST_SOURCES}
)

# Create organized test directories
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Unit_Tests)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Integration_Tests)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Performance_Tests)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Robustness_Tests)

# Build Unit Tests
foreach(test_source ${UNIT_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name}
        adaptor_signatures
        ${LIBOQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Unit_Tests
    )
endforeach()

# Build Integration Tests
foreach(test_source ${INTEGRATION_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name}
        adaptor_signatures
        ${LIBOQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Integration_Tests
    )
endforeach()

# Build Performance Tests
foreach(test_source ${PERFORMANCE_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name}
        adaptor_signatures
        ${LIBOQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        m
        pthread
    )
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Performance_Tests
    )
endforeach()

# Build Robustness Tests
foreach(test_source ${ROBUSTNESS_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name}
        adaptor_signatures
        ${LIBOQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/Robustness_Tests
    )
endforeach()

# Create organized results directories in project root
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/results/unit)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/results/integration)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/results/performance)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/results/robustness)

# Results directories are now created dynamically by test files

# Installation
install(TARGETS adaptor_signatures
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${ADAPTOR_HEADERS}
    DESTINATION include
)

# Test targets by category
add_custom_target(run_unit_tests
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_core --scheme UOV --level 128
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_validation --csv
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_sizing --csv
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_witness --csv
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_utility --csv
    COMMAND ${CMAKE_BINARY_DIR}/bin/Unit_Tests/test_boundary --csv
    DEPENDS test_core test_validation test_sizing test_witness test_utility test_boundary
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running unit tests"
)

add_custom_target(run_integration_tests
    COMMAND ${CMAKE_BINARY_DIR}/bin/Integration_Tests/test_integration --csv
    DEPENDS test_integration
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running integration tests"
)

add_custom_target(run_performance_tests
    COMMAND ${CMAKE_BINARY_DIR}/bin/Performance_Tests/test_performance --csv
    COMMAND ${CMAKE_BINARY_DIR}/bin/Performance_Tests/test_bench --iterations 10 --csv
    DEPENDS test_performance test_bench
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running performance tests"
)

add_custom_target(run_robustness_tests
    COMMAND ${CMAKE_BINARY_DIR}/bin/Robustness_Tests/test_negative --scheme UOV --level 128
    COMMAND ${CMAKE_BINARY_DIR}/bin/Robustness_Tests/test_stress --csv
    DEPENDS test_negative test_stress
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running robustness tests"
)

# All tests target
add_custom_target(run_tests
    DEPENDS run_unit_tests run_integration_tests run_performance_tests run_robustness_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running all test categories"
)

# Package configuration
include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Platform: ${PLATFORM_NAME}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  liboqs Include: ${LIBOQS_INCLUDE_DIR}")
message(STATUS "  liboqs Library: ${LIBOQS_LIBRARY}")
message(STATUS "  OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "")
