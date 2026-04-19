cmake_minimum_required(VERSION 3.28.3)
project(ebpf_probe)

set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/src/ebpf_probe.bpf.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/ebpf_probe.bpf.o)
set(BPF_SKELETON ${CMAKE_SOURCE_DIR}/include/ebpf_probe.skel.h)
set(VMLINUX_HEADER ${CMAKE_SOURCE_DIR}/include/vmlinux.h)

#------------------------------------------------------------------------------
# Generate vmlinux.h using bpftool
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    COMMAND bpftool
        btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}
    DEPENDS /sys/kernel/btf/vmlinux
)

#------------------------------------------------------------------------------
# Generate object file from src/probe.bpf.c using clang compiler
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
)

add_custom_target(bpf_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_OBJECT})

#------------------------------------------------------------------------------
# Generate skeleton header file from probe.bpf.o using bpftool
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}
    DEPENDS ${BPF_OBJECT}
)

add_custom_target(bpf_skeleton ALL DEPENDS ${BPF_SKELETON})

#------------------------------------------------------------------------------
# Compile src/kernel_module.c
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Compile as shared object
#------------------------------------------------------------------------------
add_executable(
    ebpf_probe
    src/main.cpp
    src/ebpf_probe.cpp)
target_include_directories(ebpf_probe PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ebpf_probe PRIVATE bpf)
target_compile_options(ebpf_probe PRIVATE -O3 -Wall -Werror)

add_dependencies(bpf_skeleton bpf_object)
add_dependencies(ebpf_probe bpf_skeleton)
