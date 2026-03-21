cmake_minimum_required(VERSION 3.28.3)

project(packet_counter)

set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/src/probe.bpf.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/probe.bpf.o)
set(BPF_SKELETON ${CMAKE_SOURCE_DIR}/include/probe.skel.h)
set(VMLINUX_HEADER ${CMAKE_SOURCE_DIR}/include/vmlinux.h)

#==============================================================================
# Generate vmlinux.h using bpftool
#==============================================================================
add_custom_command(
	OUTPUT ${VMLINUX_HEADER}
	COMMAND bpftool
		btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}
	DEPENDS /sys/kernel/btf/vmlinux
)

#==============================================================================
# Generate object file from src/probe.bpf.c using clang compiler
#==============================================================================
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

#==============================================================================
# Generate skeleton header file from probe.bpf.o using bpftool
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
add_executable(packet_counter src/main.c src/probe.c)
target_include_directories(packet_counter PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(packet_counter PRIVATE bpf)
target_compile_options(packet_counter PRIVATE -Wall -Werror -O3)

#==============================================================================
# Compile ebpf_probe.c as library
#==============================================================================
add_library(ebpf_probe SHARED src/probe.c)
target_include_directories(ebpf_probe PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ebpf_probe PRIVATE bpf)

add_dependencies(bpf_skeleton bpf_object)
add_dependencies(packet_counter bpf_skeleton)
add_dependencies(ebpf_probe bpf_skeleton)
