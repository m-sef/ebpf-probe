#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "probe.skel.h"

#include "probe.h"

typedef struct probe {
	struct probe_bpf* skeleton;
	struct ring_buffer* buffer;
} probe_t;

probe_t* probe__init()
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "Program must be run as root\n");
		return NULL;
	}
	
	struct probe_bpf* skeleton = probe_bpf__open_and_load();
	if (!skeleton)
	{
		fprintf(stderr, "Failed to open and/or load BPF object\n");
		probe_bpf__destroy(skeleton);
		return NULL;
	}

	probe_t* probe = (probe_t*) malloc(sizeof(probe_t));

	probe->skeleton = skeleton;
	probe->buffer = NULL;

	return probe;
}

void probe__destroy(
		probe_t* probe)
{
	probe_bpf__destroy(probe->skeleton);
	free(probe);
}

void probe__attach_xdp(
		probe_t* probe,
		const char* interface_name)
{
	unsigned int interface_index = if_nametoindex(interface_name);
	if (!interface_index)
	{
		fprintf(stderr, "Could not find interface \"%s\"\n", interface_name);
		return;
	}

	probe->skeleton->links.xdp_prog = bpf_program__attach_xdp(probe->skeleton->progs.xdp_prog, interface_index);
	if (!probe->skeleton->links.xdp_prog)
	{
		fprintf(stderr, "Failed to attach XDP program\n");
		return;
	}
}

void probe__init_buffer(
		probe_t* probe,
		buffer_callback_t callback,
		void* context)
{
	struct ring_buffer* buffer = ring_buffer__new(
		bpf_map__fd(probe->skeleton->maps.packet_info_ring_buffer),
		callback, context, NULL);
	
	probe->buffer = buffer;
}

void probe__flush_buffer(
		probe_t* probe)
{
	size_t entries_consumed = ring_buffer__consume(probe->buffer);

	// Sleep for 1ms if no data was consumed, so to not max out CPU usage
	if (entries_consumed == 0)
		usleep(1000);
}

void probe__destroy_buffer(
		probe_t* probe)
{
	ring_buffer__free(probe->buffer);
}

size_t probe__available_buffer_size(
		probe_t* probe)
{
	return ring__avail_data_size(ring_buffer__ring(probe->buffer, 0));
}
