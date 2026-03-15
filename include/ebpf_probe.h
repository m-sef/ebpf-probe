#ifndef EBPF_PROBE_H
#define EBPF_PROBE_H

#include "shared.h"

struct ebpf_probe;

struct ebpf_probe* ebpf_probe__init(
	const char* interface_name);

void ebpf_probe__destroy(
	struct ebpf_probe* ebpf_probe);

void ebpf_probe__flush_packet_info_ring_buffer(
	struct ebpf_probe* ebpf_probe);

#endif
