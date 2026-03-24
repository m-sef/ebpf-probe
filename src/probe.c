#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <err.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#include "probe.skel.h"
#include "probe.h"

typedef long file_descriptor_t;

typedef struct probe {
	struct probe_bpf* skeleton;
	struct ring_buffer* buffer;
	struct { uint64_t key; file_descriptor_t value; }* perf_event_map;
} probe_t;

typedef struct probe_config {
	struct { uint32_t key; void* value; }* rx_queue_whitelist;
	struct { uint32_t key; void* value; }* source_ipv4_address_whitelist;
	struct { uint16_t key; void* value; }* source_port_whitelist;
	struct { uint32_t key; void* value; }* destination_ipv4_address_whitelist;
	struct { uint16_t key; void* value; }* destination_port_whitelist;
	struct { uint8_t  key; void* value; }* protocol_whitelist;
} probe_config_t;

static file_descriptor_t perf_event_open(
		struct perf_event_attr* hw_event,
		pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

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

	probe->skeleton->links.xdp_probe = bpf_program__attach_xdp(probe->skeleton->progs.xdp_probe, interface_index);
	if (!probe->skeleton->links.xdp_probe)
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

void probe__init_perf_event(
		probe_t* probe)
{
	struct perf_event_attr perf_event_attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(perf_event_attr),
		.config = PERF_COUNT_HW_INSTRUCTIONS
	};

	file_descriptor_t file_descriptor = perf_event_open(&perf_event_attr, -1, 0, -1, 0);
	if (file_descriptor == -1)
		err(EXIT_FAILURE, "Error opening leader %llx\n", perf_event_attr.config);
	
	if (ioctl(file_descriptor, PERF_EVENT_IOC_RESET, 0) == -1)
		err(EXIT_FAILURE, "PERF_EVENT_IOC_RESET");
	if (ioctl(file_descriptor, PERF_EVENT_IOC_ENABLE, 0) == -1)
		err(EXIT_FAILURE, "PERF_EVENT_IOC_ENABLE");
	
	hmput(probe->perf_event_map, PERF_COUNT_HW_INSTRUCTIONS, file_descriptor);
}

uint64_t probe__read_perf_event(
		probe_t* probe)
{
	file_descriptor_t file_descriptor = hmget(probe->perf_event_map, PERF_COUNT_HW_INSTRUCTIONS);
	uint64_t value;

	if (ioctl(file_descriptor, PERF_EVENT_IOC_DISABLE, 0) == -1)
		err(EXIT_FAILURE, "PERF_EVENT_IOC_DISABLE");
	if (read(file_descriptor, &value, sizeof(value)) != sizeof(value))
		err(EXIT_FAILURE, "read");
	if (ioctl(file_descriptor, PERF_EVENT_IOC_ENABLE, 0) == -1)
		err(EXIT_FAILURE, "PERF_EVENT_IOC_ENABLE");
	
	return value;
}
