#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
//#include <linux/icmp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "icmp.h"

char LICENSE[] SEC("license") = "GPL";

__u64 packets_recieved = 0;
__u64 bytes_recieved = 0;

SEC("xdp")
int xdp_prog(struct xdp_md* context)
{
	void* data     = (void*)(long)context->data;
	void* data_end = (void*)(long)context->data_end;

	struct ethhdr* ethernet_header = data;
	if ((void*)ethernet_header + sizeof(*ethernet_header) > data_end)
		return XDP_PASS;

	struct iphdr* ip_header = data + sizeof(*ethernet_header);
	if ((void*)ip_header + sizeof(*ip_header) > data_end)
		return XDP_PASS;

	if (ip_header->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	struct icmphdr* icmp_header = (void*)ip_header + sizeof(*ip_header);
	if ((void*)icmp_header + sizeof(*icmp_header) > data_end)
		return XDP_PASS;

	int payload_size = bpf_ntohs(ip_header->tot_len) - sizeof(*ip_header) - sizeof(*icmp_header);
	
	packets_recieved += 1;
	bytes_recieved += payload_size;
	
	return XDP_PASS;
}
