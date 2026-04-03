cmake_minimum_required(VERSION 3.28.3)

project(logger)

add_executable(logger src/main.c)

target_include_directories(logger PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(logger PRIVATE ${CMAKE_SOURCE_DIR}/../../include)

find_library(EBPF_PROBE_LIB ebpf_probe PATHS ${CMAKE_SOURCE_DIR}/../../build REQUIRED)

target_link_libraries(logger PRIVATE ${EBPF_PROBE_LIB})

target_compile_options(logger PRIVATE -Wall -Werror -O3)