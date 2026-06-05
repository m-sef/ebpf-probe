cmake_minimum_required(VERSION 3.28.3)
project(ebpf_probe)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VMLINUX_HEADER ${CMAKE_SOURCE_DIR}/include/generated/vmlinux.h)

set(BPF_DATA_SOURCE   ${CMAKE_SOURCE_DIR}/src/bpf/data.bpf.c)
set(BPF_DATA_OBJECT   ${CMAKE_BINARY_DIR}/data.bpf.o)
set(BPF_DATA_SKELETON ${CMAKE_SOURCE_DIR}/include/generated/data.skel.h)

set(BPF_CORE_ITER_SOURCE   ${CMAKE_SOURCE_DIR}/src/bpf/core_iterator.bpf.c)
set(BPF_CORE_ITER_OBJECT   ${CMAKE_BINARY_DIR}/core_iterator.bpf.o)
set(BPF_CORE_ITER_SKELETON ${CMAKE_SOURCE_DIR}/include/generated/core_iterator.skel.h)

set(BPF_RAPL_ITER_SOURCE   ${CMAKE_SOURCE_DIR}/src/bpf/rapl_iterator.bpf.c)
set(BPF_RAPL_ITER_OBJECT   ${CMAKE_BINARY_DIR}/rapl_iterator.bpf.o)
set(BPF_RAPL_ITER_SKELETON ${CMAKE_SOURCE_DIR}/include/generated/rapl_iterator.skel.h)

set(BPF_INTERFACE_ITER_SOURCE   ${CMAKE_SOURCE_DIR}/src/bpf/interface_iterator.bpf.c)
set(BPF_INTERFACE_ITER_OBJECT   ${CMAKE_BINARY_DIR}/interface_iterator.bpf.o)
set(BPF_INTERFACE_ITER_SKELETON ${CMAKE_SOURCE_DIR}/include/generated/interface_iterator.skel.h)

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
# Compile bpf source to objects using clang compiler
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_DATA_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_DATA_SOURCE}
        -o ${BPF_DATA_OBJECT}
    DEPENDS ${BPF_DATA_SOURCE} ${VMLINUX_HEADER}
)

add_custom_command(
    OUTPUT ${BPF_CORE_ITER_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_CORE_ITER_SOURCE}
        -o ${BPF_CORE_ITER_OBJECT}
    DEPENDS ${BPF_CORE_ITER_SOURCE} ${VMLINUX_HEADER}
)

add_custom_command(
    OUTPUT ${BPF_RAPL_ITER_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_RAPL_ITER_SOURCE}
        -o ${BPF_RAPL_ITER_OBJECT}
    DEPENDS ${BPF_RAPL_ITER_SOURCE} ${VMLINUX_HEADER}
)

add_custom_command(
    OUTPUT ${BPF_INTERFACE_ITER_OBJECT}
    COMMAND clang
        -g -O2
        -target bpf
        -I${CMAKE_SOURCE_DIR}/include
        -c ${BPF_INTERFACE_ITER_SOURCE}
        -o ${BPF_INTERFACE_ITER_OBJECT}
    DEPENDS ${BPF_INTERFACE_ITER_SOURCE} ${VMLINUX_HEADER}
)

add_custom_target(bpf_data_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_DATA_OBJECT})
add_custom_target(bpf_core_iter_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_CORE_ITER_OBJECT})
add_custom_target(bpf_rapl_iter_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_RAPL_ITER_OBJECT})
add_custom_target(bpf_interface_iter_object ALL DEPENDS ${VMLINUX_HEADER} ${BPF_INTERFACE_ITER_OBJECT})

#------------------------------------------------------------------------------
# Generate skeleton header files
#------------------------------------------------------------------------------
add_custom_command(
    OUTPUT ${BPF_DATA_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_DATA_OBJECT} > ${BPF_DATA_SKELETON}
    DEPENDS ${BPF_DATA_OBJECT}
)

add_custom_command(
    OUTPUT ${BPF_CORE_ITER_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_CORE_ITER_OBJECT} > ${BPF_CORE_ITER_SKELETON}
    DEPENDS ${BPF_CORE_ITER_OBJECT}
)

add_custom_command(
    OUTPUT ${BPF_RAPL_ITER_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_RAPL_ITER_OBJECT} > ${BPF_RAPL_ITER_SKELETON}
    DEPENDS ${BPF_RAPL_ITER_OBJECT}
)

add_custom_command(
    OUTPUT ${BPF_INTERFACE_ITER_SKELETON}
    COMMAND bpftool
        gen skeleton ${BPF_INTERFACE_ITER_OBJECT} > ${BPF_INTERFACE_ITER_SKELETON}
    DEPENDS ${BPF_INTERFACE_ITER_OBJECT}
)

add_custom_target(bpf_data_skeleton ALL DEPENDS ${BPF_DATA_SKELETON})
add_dependencies(bpf_data_skeleton bpf_data_object)

add_custom_target(bpf_core_iter_skeleton ALL DEPENDS ${BPF_CORE_ITER_SKELETON})
add_dependencies(bpf_core_iter_skeleton bpf_core_iter_object)

add_custom_target(bpf_rapl_iter_skeleton ALL DEPENDS ${BPF_RAPL_ITER_SKELETON})
add_dependencies(bpf_rapl_iter_skeleton bpf_rapl_iter_object)

add_custom_target(bpf_interface_iter_skeleton ALL DEPENDS ${BPF_INTERFACE_ITER_SKELETON})
add_dependencies(bpf_interface_iter_skeleton bpf_interface_iter_object)

#------------------------------------------------------------------------------
# Compile userspace loader
#------------------------------------------------------------------------------
add_executable(
    ebpf_probe
    src/main.cpp
    src/userspace_loader.cpp
    src/data_bpf.cpp
    src/core_iterator_bpf.cpp
    src/rapl_iterator_bpf.cpp
    src/interface_iterator_bpf.cpp)
target_include_directories(ebpf_probe PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ebpf_probe PRIVATE bpf)
target_compile_options(ebpf_probe PRIVATE -O3 -Wall -Werror)

add_dependencies(ebpf_probe bpf_data_skeleton bpf_core_iter_skeleton bpf_rapl_iter_skeleton)
