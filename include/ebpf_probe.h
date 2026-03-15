#ifndef EBPF_PROBE_H
#define EBPF_PROBE_H

#include "shared.h"

struct ebpf_probe;
typedef int (*packet_info_ring_buffer_callback_t)(void* context, void* data, size_t size);

struct ebpf_probe* ebpf_probe__init(
	const char* interface_name,
	packet_info_ring_buffer_callback_t callback,
	void* context);

void ebpf_probe__destroy(
	struct ebpf_probe* ebpf_probe);

void ebpf_probe__flush_packet_info_ring_buffer(
	struct ebpf_probe* ebpf_probe);

#endif
