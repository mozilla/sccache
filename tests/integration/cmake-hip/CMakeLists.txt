cmake_minimum_required(VERSION 3.10)

project(myproject LANGUAGES CXX HIP)

add_library(vectoradd_hip vectoradd_hip.cpp)
set_source_files_properties(vectoradd_hip.cpp PROPERTIES LANGUAGE HIP)
