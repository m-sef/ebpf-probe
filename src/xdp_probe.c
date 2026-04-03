/**
 * @file xdp_probe.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
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

typedef struct probe_config {
	struct { uint32_t key; void* value; }* rx_queue_whitelist;
	struct { uint32_t key; void* value; }* source_ipv4_address_whitelist;
	struct { uint16_t key; void* value; }* source_port_whitelist;
	struct { uint32_t key; void* value; }* destination_ipv4_address_whitelist;
	struct { uint16_t key; void* value; }* destination_port_whitelist;
	struct { uint8_t  key; void* value; }* protocol_whitelist;
} probe_config_t;

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

void xdp_probe__init_buffer(
		buffer_callback_t callback,
		void* context)
{
	struct ring_buffer* buffer = ring_buffer__new(
		bpf_map__fd(xdp_probe.skeleton->maps.packet_info_ring_buffer),
		callback, context, NULL);
	
	xdp_probe.buffer = buffer;
}

void xdp_probe__flush_buffer()
{
	size_t entries_consumed = ring_buffer__consume(xdp_probe.buffer);

	// Sleep for 1ms if no data was consumed, so to not max out CPU usage
	if (entries_consumed == 0)
		usleep(1000);
}

void xdp_probe__destroy_buffer()
{
	ring_buffer__free(xdp_probe.buffer);
}

size_t xdp_probe__available_buffer_size()
{
	return ring__avail_data_size(ring_buffer__ring(xdp_probe.buffer, 0));
}

size_t xdp_probe__get_total_packets_received()
{
	return xdp_probe.skeleton->bss->total_packets_received;
}

size_t xdp_probe__get_total_rx_bytes_received()
{
	return xdp_probe.skeleton->bss->total_rx_bytes_received;
}
