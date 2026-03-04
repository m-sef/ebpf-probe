//#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/udp.h>
//#include <linux/icmp.h>
//#include <linux/in.h>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum direction_t { SOURCE, DESTINATION };

struct key_t {
	union {
		struct {
			__u32 ipv4_source_address;
			__u16 source_port;
		} source;
		struct {
			__u32 ipv4_destination_address;
			__u16 destination_port;
		} destination;
	} un;
	__u16 queue;
	__u8 protocol;
	__u8 direction;
};

struct value_t {
	__u64 total_packets_recieved;
	__u64 total_bytes_recieved;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
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
	//if (ethernet_header->h_proto != ETH_P_IP)
	//	return XDP_PASS;

	struct iphdr* ipv4_header = data + sizeof(*ethernet_header);
	if ((void*)ipv4_header + sizeof(*ipv4_header) > data_end)
		return XDP_PASS;

	if (ipv4_header->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	struct icmphdr* icmp_header = (void*)ipv4_header + sizeof(*ipv4_header);
	if ((void*)icmp_header + sizeof(*icmp_header) > data_end)
		return XDP_PASS;

	int payload_size = bpf_ntohs(ipv4_header->tot_len) - sizeof(*ipv4_header) - sizeof(*icmp_header);

	struct key_t temp_key = {0};
	struct value_t temp_value = {0};

	bpf_map_update_elem(&throughput_map, &temp_key, &temp_value, BPF_ANY);
	
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
