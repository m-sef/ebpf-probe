#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

__u64 bytes_recieved = 0;

SEC("xdp")
int xdp_prog(struct xdp_md* context)
{
	int packet_size = context->data_end - context->data;
	bytes_recieved += packet_size;

	return XDP_PASS;
}
