#include <uapi/linux/bpf.h>

BPF_HASH(packet_counter, u64);
BPF_HASH(byte_counter, u64);

int xdp_prog(struct xdp_md *ctx)
{
    u32 packet_size = ctx->data_end - ctx->data;
    //bpf_trace_printk("packet size:%d\n", packet_size);

    packet_counter.increment(1);
    byte_counter.increment(packet_size);

    return XDP_PASS;
}

