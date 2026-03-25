cmake_minimum_required(VERSION 3.28.3)

project(perf_event)

add_executable(perf_event src/main.c)

target_include_directories(perf_event PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(perf_event PRIVATE ${CMAKE_SOURCE_DIR}/../../include)

find_library(EBPF_PROBE_LIB ebpf_probe PATHS ${CMAKE_SOURCE_DIR}/../../build REQUIRED)

target_link_libraries(perf_event PRIVATE ${EBPF_PROBE_LIB})

target_compile_options(perf_event PRIVATE -Wall -Werror -O3)