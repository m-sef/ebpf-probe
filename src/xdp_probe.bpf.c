/**
 * @file xdp_probe.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief eBPF program which uses the XDP hook to gather basic information about received packets
 * 
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct counters {
	__u64 total_packets_received;
	__u64 total_rx_bytes_received;
};

struct packet_information {
	__u64 time; /* Time, in nanoseconds, when the packet was received */
	__u64 size; /* The size of the entire packet, in bytes, including all headers */
	__u32 rx_queue_index; /* The index of the NIC queue where the packet was received*/
	__u32 source_address;
	__u32 destination_address;
	__u16 source_port;
	__u16 destination_port;
	__u8 protocol;
};

volatile bool record_individual_packet_information; /* Write packet information of received packets to packet_information_buffer */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} counters_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} packet_information_buffer_size SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1 << 10);
	__type(key, __u32);
	__type(value, struct packet_information);
} packet_information_buffer SEC(".maps");

static inline void
increment_global_counters(
		__u64 packets,
		__u64 rx_bytes)
{
	__u32 key = 0;
	struct counters* ptr = bpf_map_lookup_elem(&counters_map, &key);
	if (ptr)
	{
		ptr->total_packets_received  += packets;
		ptr->total_rx_bytes_received += rx_bytes;
	}
}

SEC("xdp")
int xdp_probe(struct xdp_md* context)
{
	void* data     = (void*)(long)context->data;
	void* data_end = (void*)(long)context->data_end;

	increment_global_counters(1, data_end - data);

	if (!record_individual_packet_information)
		return XDP_PASS;

	struct ethhdr* ethernet_header = data;
	if ((void*)ethernet_header + sizeof(*ethernet_header) > data_end)
		return XDP_PASS;

	if (ethernet_header->h_proto != bpf_ntohs(0x0800))
		return XDP_PASS;

	struct iphdr* ip_header = data + sizeof(*ethernet_header);
	if ((void*)ip_header + sizeof(*ip_header) > data_end)
		return XDP_PASS;
	
	__u32 key = 0;
	__u32* size = bpf_map_lookup_elem(&packet_information_buffer_size, &key);
	if (!size)
		return XDP_PASS; /* If you get here, something has gone catastrophically wrong... */
	
	struct packet_information* record = bpf_map_lookup_elem(&packet_information_buffer, size);
	if (!record)
		return XDP_PASS;

	record->time                = bpf_ktime_get_ns();
	record->size                = data_end - data;
	record->rx_queue_index      = context->rx_queue_index;
	record->source_address      = ip_header->saddr;
	record->destination_address = ip_header->daddr;
	record->source_port         = 0;
	record->destination_port    = 0;
	record->protocol            = ip_header->protocol;

	if (ip_header->protocol == IPPROTO_UDP)
	{
		struct udphdr* udp_header = (void*)ip_header + sizeof(*ip_header);
		if ((void*)udp_header + sizeof(*udp_header) > data_end)
			return XDP_PASS;
		
		record->source_port = bpf_ntohs(udp_header->source);
		record->destination_port = bpf_ntohs(udp_header->dest);
	}
	else if (ip_header->protocol == IPPROTO_TCP)
	{
		struct tcphdr* tcp_header = (void*)ip_header + sizeof(*ip_header);
		if ((void*)tcp_header + sizeof(*tcp_header) > data_end)
			return XDP_PASS;

		record->source_port = bpf_ntohs(tcp_header->source);
		record->destination_port = bpf_ntohs(tcp_header->dest);
	}
	
	(*size)++;

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
