# LMS/HSS Test Suite CMakeLists.txt

cmake_minimum_required(VERSION 3.14)

project(test_suite_sdv_eal_lms_hss)

# Add include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/crypto/lms_hss/include
    ${CMAKE_SOURCE_DIR}/crypto/lms_hss/src
    ${CMAKE_SOURCE_DIR}/testcode/framework
    ${CMAKE_SOURCE_DIR}/testcode/framework/include
    ${CMAKE_SOURCE_DIR}/testcode/include
)

# Add library directory
link_directories(${CMAKE_SOURCE_DIR}/lib)

# Create test executable
add_executable(test_suite_sdv_eal_lms_hss test_suite_sdv_eal_lms_hss.c)

# Link libraries
target_link_libraries(test_suite_sdv_eal_lms_hss
    hitls_crypto
    hitls_bsl
    m
    pthread
)

# Set output directory
set_target_properties(test_suite_sdv_eal_lms_hss PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/testcase/crypto/lms_hss
)