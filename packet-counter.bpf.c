#include <uapi/linux/bpf.h>

BPF_ARRAY(packets, u64, 1);
BPF_ARRAY(bytes, u64, 1);

int xdp_prog(struct xdp_md *ctx)
{
    u32 packet_size = ctx->data_end - ctx->data;

    u32 key = 0;

    u64* pkt = packets.lookup(&key);
    if (pkt)
    {
        (*pkt)++;
    }

    u64* byt = bytes.lookup(&key);
    if (byt)
    {
        (*byt) += packet_size;
    }

    return XDP_PASS;
}

