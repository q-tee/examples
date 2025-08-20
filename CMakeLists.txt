cmake_minimum_required(VERSION 3.10)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build/$<CONFIG>")

project(examples)
add_subdirectory(smbios-dump)