cmake_minimum_required(VERSION 3.16)
project(thinlto_test CXX)

set(HELPER_FACTOR 3 CACHE STRING "Value helper() multiplies by")

add_library(helper STATIC helper.cpp)
target_compile_definitions(helper PRIVATE HELPER_FACTOR=${HELPER_FACTOR})

add_executable(app main.cpp)
target_link_libraries(app helper)
