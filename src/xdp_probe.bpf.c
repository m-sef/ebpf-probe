#include "vmlinux.h"
#include "shared_definitions.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packet_info_ring_buffer SEC(".maps");

__u64 total_packets_received  = 0;
__u64 total_rx_bytes_received = 0;

SEC("xdp")
int xdp_probe(struct xdp_md* context)
{
	void* data     = (void*)(long)context->data;
	void* data_end = (void*)(long)context->data_end;

	struct ethhdr* ethernet_header = data;
	if ((void*)ethernet_header + sizeof(*ethernet_header) > data_end)
		return XDP_PASS;

	if (ethernet_header->h_proto != bpf_ntohs(0x0800))
		return XDP_PASS;

	struct iphdr* ipv4_header = data + sizeof(*ethernet_header);
	if ((void*)ipv4_header + sizeof(*ipv4_header) > data_end)
		return XDP_PASS;

	total_packets_received++;
	total_rx_bytes_received += data_end - data;

	struct packet_info* record = bpf_ringbuf_reserve(&packet_info_ring_buffer, sizeof(*record), 0);
	if (!record)
		return XDP_PASS;

	record->time = bpf_ktime_get_ns();
	record->size = data_end - data;
	record->rx_queue_index = context->rx_queue_index;
	record->source_ipv4_address = ipv4_header->saddr;
	record->destination_ipv4_address = ipv4_header->daddr;
	record->source_port = 0;
	record->destination_port = 0;
	record->protocol = ipv4_header->protocol;

	if (ipv4_header->protocol == IPPROTO_UDP)
	{
		struct udphdr* udp_header = (void*)ipv4_header + sizeof(*ipv4_header);
		if ((void*)udp_header + sizeof(*udp_header) > data_end)
			return XDP_PASS;
		
		record->source_port = bpf_ntohs(udp_header->source);
		record->destination_port = bpf_ntohs(udp_header->dest);
	}
	else if (ipv4_header->protocol == IPPROTO_TCP)
	{
		struct tcphdr* tcp_header = (void*)ipv4_header + sizeof(*ipv4_header);
		if ((void*)tcp_header + sizeof(*tcp_header) > data_end)
			return XDP_PASS;

		record->source_port = bpf_ntohs(tcp_header->source);
		record->destination_port = bpf_ntohs(tcp_header->dest);
	}
	
	bpf_ringbuf_submit(record, 0);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
