#include "vmlinux.h"
#include "shared.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packet_info_ring_buffer SEC(".maps");

SEC("xdp")
int xdp_probe(struct xdp_md* context)
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

	struct packet_info packet_info = {
		.time = bpf_ktime_get_ns(),
		.size = data_end - data,
		.rx_queue_index = context->rx_queue_index,
		.source_ipv4_address = ipv4_header->saddr,
		.destination_ipv4_address = ipv4_header->daddr,
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
		
		packet_info.source_port = bpf_ntohs(udp_header->source);
		packet_info.destination_port = bpf_ntohs(udp_header->dest);
	}

	/* Handle TCP packets */
	if (ipv4_header->protocol == IPPROTO_TCP)
	{
		struct tcphdr* tcp_header = (void*)ipv4_header + sizeof(*ipv4_header);
		if ((void*)tcp_header + sizeof(*tcp_header) > data_end)
			return XDP_PASS;

		packet_info.source_port = bpf_ntohs(tcp_header->source);
		packet_info.destination_port = bpf_ntohs(tcp_header->dest);
	}

	struct packet_info* record = bpf_ringbuf_reserve(&packet_info_ring_buffer, sizeof(*record), 0);
	if (!record)
		return XDP_PASS;

	*record = packet_info;
	bpf_ringbuf_submit(record, 0);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
