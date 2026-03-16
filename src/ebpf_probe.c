#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_prog.skel.h"

#include "ebpf_probe.h"

struct ebpf_probe {
	struct xdp_prog_bpf* skeleton;
	struct ring_buffer* packet_info_ring_buffer;
	packet_info_ring_buffer_callback_t callback;
	void* context;
};

struct ebpf_probe* ebpf_probe__init(
	const char* interface_name,
	packet_info_ring_buffer_callback_t callback,
	void* context)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "Program must be run as root\n");
		return NULL;
	}
	
	unsigned int interface_index = if_nametoindex(interface_name);
	if (!interface_index)
	{
		fprintf(stderr, "Could not find interface \"%s\"\n", interface_name);
		return NULL;
	}
	
	struct xdp_prog_bpf* skeleton = xdp_prog_bpf__open_and_load();
	if (!skeleton)
	{
		fprintf(stderr, "Failed to open and/or load BPF object\n");
		xdp_prog_bpf__destroy(skeleton);
		return NULL;
	}

	skeleton->links.xdp_prog = bpf_program__attach_xdp(skeleton->progs.xdp_prog, interface_index);
	if (!skeleton->links.xdp_prog)
	{
		fprintf(stderr, "Failed to attach XDP program\n");
		xdp_prog_bpf__destroy(skeleton);
		return NULL;
	}

	struct ring_buffer* packet_info_ring_buffer = ring_buffer__new(
		bpf_map__fd(skeleton->maps.packet_info_ring_buffer),
		callback, context, NULL);

	struct ebpf_probe* ebpf_probe = (struct ebpf_probe*) malloc(sizeof(struct ebpf_probe));

	ebpf_probe->skeleton = skeleton;
	ebpf_probe->packet_info_ring_buffer = packet_info_ring_buffer;
	ebpf_probe->callback = callback;
	ebpf_probe->context = context;

	return ebpf_probe;
}

void ebpf_probe__destroy(
	struct ebpf_probe* ebpf_probe)
{
	ring_buffer__free(ebpf_probe->packet_info_ring_buffer);
	xdp_prog_bpf__destroy(ebpf_probe->skeleton);
	free(ebpf_probe);
}

void ebpf_probe__flush_buffer(
	struct ebpf_probe* ebpf_probe)
{
	if (!ring_buffer__consume(ebpf_probe->packet_info_ring_buffer))
		usleep(1000); // Sleep for 1ms if no data was consumed, as to not max out CPU usage
}
