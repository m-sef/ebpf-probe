cmake_minimum_required(VERSION 3.28.3)

project(packet_counter)

set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/xdp_prog.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog.bpf.o)
set(BPF_SKELETON ${CMAKE_CURRENT_SOURCE_DIR}/include/xdp_prog.skel.h)

#==============================================================================
# Generate object file from src/xdp_prog.bpf.c using clang compiler
#==============================================================================
add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I/usr/include/
        -I/usr/include/x86_64-linux-gnu
		-I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
)

add_custom_target(bpf_program ALL DEPENDS ${BPF_OBJECT})

#==============================================================================
# Generate skeleton header file from xdp_prog.bpf.o using bpftool
#==============================================================================
add_custom_command(
    OUTPUT ${BPF_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}
    DEPENDS ${BPF_OBJECT}
)

add_custom_target(bpf_skeleton ALL DEPENDS ${BPF_SKELETON})

#==============================================================================
# Compile userspace program
#==============================================================================
add_executable(packet_counter src/main.c)
target_include_directories(packet_counter PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(packet_counter PRIVATE bpf)
target_compile_options(packet_counter PRIVATE -Wall -Werror -O3)

add_dependencies(packet_counter bpf_skeleton)
