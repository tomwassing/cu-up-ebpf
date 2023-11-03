cmake_minimum_required(VERSION 3.14)
project(XDP_Program)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include the GoogleTest library
include(GoogleTest)

# Add the XDP program source file
add_executable(XDP_Program ./rx/xdp_pdcp_rx.c)
add_executable(XDP_Test ./rx/rx_test.cpp)

find_package(GTest REQUIRED)
target_link_libraries(XDP_Test GTest::gtest_main)

# Include the GoogleTest library
include(GoogleTest)

# Add a test target
gtest_discover_tests(XDP_Test)