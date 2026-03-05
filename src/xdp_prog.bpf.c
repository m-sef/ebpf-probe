#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum direction_t { SOURCE, DESTINATION };

struct key_t {
	union {
		__u16 source_port;
		__u16 destination_port;
	};
	__u16 queue;
	__u8 protocol;
	__u8 direction;
};

struct value_t {
	__u64 total_packets_recieved;
	__u64 total_bytes_recieved;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct value_t);
	/* I'm totally expecting this to blow up in my face later... */
	__uint(max_entries, 65536);
} throughput_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md* context)
{
	void* data     = (void*)(long)context->data;
	void* data_end = (void*)(long)context->data_end;

	struct ethhdr* ethernet_header = data;
	if ((void*)ethernet_header + sizeof(*ethernet_header) > data_end)
		return XDP_PASS;

	/* Only handling IPv4 packets */
	if (ethernet_header->h_proto != bpf_ntohs(0x0800))
		return XDP_PASS;

	struct iphdr* ipv4_header = data + sizeof(*ethernet_header);
	if ((void*)ipv4_header + sizeof(*ipv4_header) > data_end)
		return XDP_PASS;

	if (ipv4_header->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	struct key_t temp_key = {
		.destination_port = 80,
		.queue = 0,
		.protocol = 1,
		.direction = 0
	};
	struct value_t temp_value = {
		.total_bytes_recieved = 0xFFFFFFFF,
		.total_packets_recieved = 0xFFFFFFFF
	};

	bpf_map_update_elem(&throughput_map, &temp_key, &temp_value, BPF_ANY);
	
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
