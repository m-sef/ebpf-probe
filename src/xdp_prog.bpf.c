#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char* LICENSE SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md* context)
{
    return XDP_PASS;
}
