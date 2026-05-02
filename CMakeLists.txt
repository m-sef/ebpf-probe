cmake_minimum_required(VERSION 3.28.3)
project(ebpf_probe)

set(VMLINUX_HEADER ${CMAKE_SOURCE_DIR}/include/vmlinux.h)

set(BPF_DATA_SOURCE ${CMAKE_SOURCE_DIR}/src/ebpf_probe_data.bpf.c)
set(BPF_DATA_OBJECT ${CMAKE_BINARY_DIR}/ebpf_probe_data.bpf.o)
set(BPF_DATA_SKELETON ${CMAKE_SOURCE_DIR}/include/ebpf_probe_data.skel.h)

set(BPF_ITER_SOURCE ${CMAKE_SOURCE_DIR}/src/ebpf_probe_iter.bpf.c)
set(BPF_ITER_OBJECT ${CMAKE_BINARY_DIR}/ebpf_probe_iter.bpf.o)
set(BPF_ITER_SKELETON ${CMAKE_SOURCE_DIR}/include/ebpf_probe_iter.skel.h)

#------------------------------------------------------------------------------
# Generate 'include/vmlinux.h' using bpftool
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    COMMAND bpftool
        btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}
    DEPENDS /sys/kernel/btf/vmlinux
)

#------------------------------------------------------------------------------
# Compile 'src/ebpf_probe_data.bpf.c' and 'src/ebpf_probe_iter.bpf.c'
# using clang compiler
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_DATA_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_DATA_SOURCE}
        -o ${BPF_DATA_OBJECT}
    DEPENDS ${BPF_DATA_SOURCE}
)

add_custom_command(
    OUTPUT ${BPF_ITER_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_ITER_SOURCE}
        -o ${BPF_ITER_OBJECT}
    DEPENDS ${BPF_ITER_SOURCE}
)

add_custom_target(bpf_data_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_DATA_OBJECT})
add_custom_target(bpf_iter_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_ITER_OBJECT})

#------------------------------------------------------------------------------
# Generate skeleton header file from ebpf_probe.bpf.o using bpftool
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_DATA_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_DATA_OBJECT} > ${BPF_DATA_SKELETON}
    DEPENDS ${BPF_DATA_OBJECT}
)

add_custom_command(
    OUTPUT ${BPF_ITER_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_ITER_OBJECT} > ${BPF_ITER_SKELETON}
    DEPENDS ${BPF_ITER_OBJECT}
)

add_custom_target(bpf_data_skeleton ALL DEPENDS ${BPF_DATA_SKELETON})
add_dependencies(bpf_data_skeleton bpf_data_object)

add_custom_target(bpf_iter_skeleton ALL DEPENDS ${BPF_ITER_SKELETON})
add_dependencies(bpf_iter_skeleton bpf_iter_object)

#------------------------------------------------------------------------------
# Compile userspace loader
#------------------------------------------------------------------------------
add_executable(
    ebpf_probe
    src/main.cpp
    src/userspace_loader.cpp)
target_include_directories(ebpf_probe PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ebpf_probe PRIVATE bpf)
target_compile_options(ebpf_probe PRIVATE -O3 -Wall -Werror)

add_dependencies(ebpf_probe bpf_data_skeleton bpf_iter_skeleton)
