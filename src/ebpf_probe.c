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
};

static int handle_record(void* context, void* data, size_t size)
{
    struct packet_info_t* info = data;

    printf("%03u.%03u.%03u.%03u:%-5u->%03u.%03u.%03u.%03u:%-5u rx_queue_index: %-9u protocol: %-3u size: %lu\n",
        (info->source_ipv4_address)            & 0xFF,
        (info->source_ipv4_address >> 8)       & 0xFF,
        (info->source_ipv4_address >> 16)      & 0xFF,
        (info->source_ipv4_address >> 24)      & 0xFF,
        info->source_port,
        (info->destination_ipv4_address)       & 0xFF,
        (info->destination_ipv4_address >> 8)  & 0xFF,
        (info->destination_ipv4_address >> 16) & 0xFF,
        (info->destination_ipv4_address >> 24) & 0xFF,
        info->destination_port,
		info->rx_queue_index,
        info->protocol,
		info->size);

    return 0;
}

struct ebpf_probe* ebpf_probe_init(
	const char* interface_name)
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
	
	struct xdp_prog_bpf* skeleton = xdp_prog_bpf__open();
	if (!skeleton)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return NULL;
	}

	int error = xdp_prog_bpf__load(skeleton);
	if (error)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
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
		handle_record, NULL, NULL);

	struct ebpf_probe* ebpf_probe = (struct ebpf_probe*) malloc(sizeof(struct ebpf_probe));

	ebpf_probe->skeleton = skeleton;
	ebpf_probe->packet_info_ring_buffer = packet_info_ring_buffer;

	return ebpf_probe;
}

void ebpf_probe_destroy(
	struct ebpf_probe* ebpf_probe)
{
	ring_buffer__free(ebpf_probe->packet_info_ring_buffer);
	xdp_prog_bpf__destroy(ebpf_probe->skeleton);
	free(ebpf_probe);
}

void ebpf_probe_read_from_packet_info_ring_buffer(
	struct ebpf_probe* ebpf_probe)
{
	ring_buffer__poll(ebpf_probe->packet_info_ring_buffer, 100);
}
