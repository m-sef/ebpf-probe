cmake_minimum_required(VERSION 3.28.3)

project(xdp_probe)

add_executable(xdp_probe src/main.c)

target_include_directories(xdp_probe PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(xdp_probe PRIVATE ${CMAKE_SOURCE_DIR}/../../include)

find_library(EBPF_PROBE_LIB ebpf_probe PATHS ${CMAKE_SOURCE_DIR}/../../build REQUIRED)

target_link_libraries(xdp_probe PRIVATE ${EBPF_PROBE_LIB})

target_compile_options(xdp_probe PRIVATE -Wall -Werror -O3)