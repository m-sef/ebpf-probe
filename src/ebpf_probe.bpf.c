/**
 * @file ebpf_probe.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief eBPF program which uses the XDP hook to gather basic information about received packets
 * 
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <kernel_definitions.h>

volatile bool record_individual_packet_information; /* Write packet information of received packets to packet_information_buffer */
volatile size_t num_cpus;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, fd_t);
} perf_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} packet_information_buffer_size SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1 << 10);
    __type(key, __u32);
    __type(value, struct packet_information);
} packet_information_buffer SEC(".maps");

static inline void
increment_global_counters(
        __u64 packets,
        __u64 rx_bytes)
{
    __u32 key = 0;
    struct counters* ptr = bpf_map_lookup_elem(&counters_map, &key);
    if (ptr)
    {
        ptr->total_packets_received  += packets;
        ptr->total_rx_bytes_received += rx_bytes;
    }
}

static inline void
reset_global_counters()
{
    __u32 key = 0;
    struct counters* ptr = bpf_map_lookup_elem(&counters_map, &key);
    if (ptr)
        __builtin_memset(ptr, 0, sizeof(*ptr));
}

SEC("xdp")
int xdp_probe(struct xdp_md* context)
{
    void* data     = (void*)(long)context->data;
    void* data_end = (void*)(long)context->data_end;

    increment_global_counters(1, data_end - data);

    if (!record_individual_packet_information)
        return XDP_PASS;

    struct ethhdr* ethernet_header = data;
    if ((void*)ethernet_header + sizeof(*ethernet_header) > data_end)
        return XDP_PASS;

    if (ethernet_header->h_proto != bpf_ntohs(0x0800))
        return XDP_PASS;

    struct iphdr* ip_header = data + sizeof(*ethernet_header);
    if ((void*)ip_header + sizeof(*ip_header) > data_end)
        return XDP_PASS;
    
    __u32 key = 0;
    __u32* size = bpf_map_lookup_elem(&packet_information_buffer_size, &key);
    if (!size)
        return XDP_PASS; /* If you get here, something has gone catastrophically wrong... */
    
    struct packet_information* record = bpf_map_lookup_elem(&packet_information_buffer, size);
    if (!record)
        return XDP_PASS;

    record->time                = bpf_ktime_get_ns();
    record->size                = data_end - data;
    record->rx_queue_index      = context->rx_queue_index;
    record->source_address      = ip_header->saddr;
    record->destination_address = ip_header->daddr;
    record->source_port         = 0;
    record->destination_port    = 0;
    record->protocol            = ip_header->protocol;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = (void*)ip_header + sizeof(*ip_header);
        if ((void*)udp_header + sizeof(*udp_header) > data_end)
            return XDP_PASS;
        
        record->source_port = bpf_ntohs(udp_header->source);
        record->destination_port = bpf_ntohs(udp_header->dest);
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp_header = (void*)ip_header + sizeof(*ip_header);
        if ((void*)tcp_header + sizeof(*tcp_header) > data_end)
            return XDP_PASS;

        record->source_port = bpf_ntohs(tcp_header->source);
        record->destination_port = bpf_ntohs(tcp_header->dest);
    }
    
    (*size)++;

    return XDP_PASS;
}

static inline __u64 
read_perf_event_counter(
        size_t perf_event_type,
        size_t cpu_idx)
{
    __u32 key = cpu_idx * NUM_EVENT_TYPES + perf_event_type;
    struct bpf_perf_event_value value = {};

    if (bpf_perf_event_read_value(&perf_event_map, key, &value, sizeof(value)) < 0)
        return 0;

    return value.counter;
}

SEC("perf_event")
/**
 * @brief Attached to Software CPU Clock perf event, triggers every 1Hz
 * 
 */
int perf_event_handler(struct bpf_perf_event_data* ctx)
{
    __u32 cpu_idx = bpf_get_smp_processor_id();

    bpf_printk("[%d] Total Instructions: %ld\n", 
        cpu_idx, read_perf_event_counter(INSTRUCTIONS, cpu_idx));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
