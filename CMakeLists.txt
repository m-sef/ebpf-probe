cmake_minimum_required(VERSION 3.28.3)

project(packet_counter)

set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/xdp_prog.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog.bpf.o)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I/usr/include
        -I/usr/include/x86_64-linux-gnu
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
)

add_custom_target(bpf_program ALL DEPENDS ${BPF_OBJECT})

add_executable(packet_counter src/main.c)
target_include_directories(packet_counter PRIVATE ${CMAKE_SOURCE_DIR}/include)
