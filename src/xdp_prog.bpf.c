#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
static int xdp_prog(struct xdp_md* context)
{
    bpf_trace_printk("Packet Size: %d", context->data_end - context->data);

    return XDP_PASS;
}
