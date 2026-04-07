/**
 * @file xdp_probe.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#include "xdp_probe.skel.h"
#include "xdp_probe.h"

static struct {
	struct xdp_probe_bpf* skeleton;
	struct ring_buffer* buffer;
} xdp_probe;

void xdp_probe__init()
{
	if (geteuid() != 0)
		err(EXIT_FAILURE, "Program must be run as root\n");
	
	struct xdp_probe_bpf* skeleton = xdp_probe_bpf__open_and_load();
	if (!skeleton)
	{
		xdp_probe_bpf__destroy(skeleton);
		err(EXIT_FAILURE, "Failed to open and/or load BPF object\n");
	}

	xdp_probe.skeleton = skeleton;
	xdp_probe.buffer = NULL;
}

void xdp_probe__destroy()
{
	xdp_probe_bpf__destroy(xdp_probe.skeleton);
}

void xdp_probe__attach(
		const char* interface_name)
{
	unsigned int interface_index = if_nametoindex(interface_name);
	if (!interface_index)
		err(EXIT_FAILURE, "Could not find interface \"%s\"\n", interface_name);

	xdp_probe.skeleton->links.xdp_probe = bpf_program__attach_xdp(xdp_probe.skeleton->progs.xdp_probe, interface_index);
	if (!xdp_probe.skeleton->links.xdp_probe)
		err(EXIT_FAILURE, "Failed to attach XDP program\n");
}

size_t xdp_probe__get_total_packets_received()
{
	size_t cpu_count = libbpf_num_possible_cpus();
	__u32 key = 0;
	__u64 sum = 0;
	struct counters counters[cpu_count];
	int ret;
	int fd = bpf_map__fd(xdp_probe.skeleton->maps.counters_map);

	ret = bpf_map_lookup_elem(fd, &key, &counters);
	assert(ret >= 0);

	for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
	{
		sum += counters[cpu_idx].total_packets_received;
	}

	return sum;
}

size_t xdp_probe__get_total_rx_bytes_received()
{
	size_t cpu_count = libbpf_num_possible_cpus();
	__u32 key = 0;
	__u64 sum = 0;
	struct counters counters[cpu_count];
	int ret;
	int fd = bpf_map__fd(xdp_probe.skeleton->maps.counters_map);

	ret = bpf_map_lookup_elem(fd, &key, &counters);
	assert(ret >= 0);

	for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
	{
		sum += counters[cpu_idx].total_rx_bytes_received;
	}

	return sum;
}
