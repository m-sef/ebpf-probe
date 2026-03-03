#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
//#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Some sick and twisted linux developer has if.h, which is included by icmp.h,
// include sys/socket.h (Which isn't usable here)
//
// The workaround i've found is to rip this struct from icmp.h
struct icmphdr {
	__u8		type;
	__u8		code;
	__sum16	checksum;
	union {
		struct {
			__be16	id;
			__be16	sequence;
		} echo;
		__be32	gateway;
		struct {
			__be16	__unused;
			__be16	mtu;
		} frag;
		__u8	reserved[4];
  } un;
};

char LICENSE[] SEC("license") = "GPL";

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

	void* payload = (void*)icmp_header + sizeof(icmp_header);
	int payload_size = data_end - payload;
	bytes_recieved += payload_size;
	
	return XDP_PASS;
}
