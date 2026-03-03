#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md* context)
{
	int packet_size = context->data_end - context->data;

	bpf_printk("Packet Size: %d", packet_size);

	return XDP_PASS;
}
