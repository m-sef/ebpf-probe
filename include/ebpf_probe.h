#ifndef EBPF_PROBE_H
#define EBPF_PROBE_H

#include "shared.h"

struct ebpf_probe;

struct ebpf_probe* ebpf_probe_init(
	const char* interface_name);

void ebpf_probe_destroy(
	struct ebpf_probe* ebpf_probe);

void ebpf_probe_read_from_packet_info_ring_buffer(
	struct ebpf_probe* ebpf_probe);

void ebpf_probe_flush_packet_info_ring_buffer(
	struct ebpf_probe* ebpf_probe,
	struct packet_info_t* buffer,
	size_t* buffer_size);

#endif
