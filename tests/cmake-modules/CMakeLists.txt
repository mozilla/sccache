cmake_minimum_required(VERSION 3.28)

project(myproject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_library(mymodule OBJECT)
target_sources(mymodule PUBLIC FILE_SET MODULES_SOURCE_FILES FILES mymodule.cppm)

add_library(myproject OBJECT main.cpp)
target_link_libraries(myproject PRIVATE mymodule)