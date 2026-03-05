#include "vmlinux.h"
#include "shared.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

	struct key_t key = {
		.rx_queue_index = context->rx_queue_index,
		.source_ipv4_address = bpf_ntohs(ipv4_header->saddr),
		.destination_ipv4_address = bpf_ntohs(ipv4_header->daddr),
		.source_port = 0,
		.destination_port = 0,
		.protocol = ipv4_header->protocol
	};

	/* Handle UDP packets */
	if (ipv4_header->protocol == IPPROTO_UDP)
	{
		struct udphdr* udp_header = (void*)ipv4_header + sizeof(*ipv4_header);
		if ((void*)udp_header + sizeof(*udp_header) > data_end)
			return XDP_PASS;
		
		key.source_port = bpf_ntohs(udp_header->source);
		key.destination_port = bpf_ntohs(udp_header->dest);
	}

	/* Handle TCP packets */
	if (ipv4_header->protocol == IPPROTO_TCP)
	{
		struct tcphdr* tcp_header = (void*)ipv4_header + sizeof(*ipv4_header);
		if ((void*)tcp_header + sizeof(*tcp_header) > data_end)
			return XDP_PASS;

		key.source_port = bpf_ntohs(tcp_header->source);
		key.destination_port = bpf_ntohs(tcp_header->dest);
	}

	struct value_t* value = bpf_map_lookup_elem(&throughput_map, &key);
	if (value)
	{
		value->total_packets_recieved++;
		value->total_bytes_recieved += data_end - data;
	}
	else
	{
		struct value_t new_value = {
			.total_packets_recieved = 1,
			.total_bytes_recieved = data_end - data
		};

		bpf_map_update_elem(&throughput_map, &key, &new_value, BPF_ANY);
	}
	
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
