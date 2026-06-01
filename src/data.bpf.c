/**
 * @file data.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf_definitions.h>
#include <bpf_shared_maps.h>

static inline void
increment_core_stats_rx_counters(
        __u64 rx_packets,
        __u64 rx_bytes)
{
    __u32 key = 0;
    struct core_map_entry* ptr = bpf_map_lookup_elem(&core_stats_map, &key);
    if (ptr)
    {
        ptr->rx_packets += rx_packets;
        ptr->rx_bytes   += rx_bytes;
    }
}

static inline void
increment_core_stats_tx_counters(
        __u64 tx_packets,
        __u64 tx_bytes)
{
    __u32 key = 0;
    struct core_map_entry* ptr = bpf_map_lookup_elem(&core_stats_map, &key);
    if (ptr)
    {
        ptr->tx_packets += tx_packets;
        ptr->tx_bytes   += tx_bytes;
    }
}

SEC("xdp")
int xdp_ingress(struct xdp_md* context)
{
    void* data     = (void*)(long)context->data;
    void* data_end = (void*)(long)context->data_end;

    increment_core_stats_rx_counters(1, data_end - data);

    return XDP_PASS;
}

SEC("tcx/egress")
int tcx_egress(struct __sk_buff* context)
{
    void* data     = (void *)(__u64)context->data;
    void* data_end = (void *)(__u64)context->data_end;

    increment_core_stats_tx_counters(1, data_end - data);

    return TCX_PASS;
}

static inline error_t
read_perf_event_counter(
        size_t perf_event_type,
        size_t cpu_idx,
        struct bpf_perf_event_value* value)
{
    __u32 key = (cpu_idx * NUM_EVENT_TYPES) + perf_event_type;

    if (bpf_perf_event_read_value(&perf_event_map, key, value, sizeof(*value)) < 0)
        return 1;

    return 0;
}

static inline error_t
read_rapl_domain_counter(
        size_t rapl_domain_idx)
{
    __u32 key = rapl_domain_idx;
    struct bpf_perf_event_value* value = bpf_map_lookup_elem(&rapl_stats_map, &key);

    if (!value)
        return 1;
    
    if (bpf_perf_event_read_value(&rapl_event_map, key, value, sizeof(*value)) < 0)
        return 1;

    return 0;
}

SEC("perf_event")
int timer(struct bpf_perf_event_data* ctx)
{
    __u32 cpu_idx = bpf_get_smp_processor_id();
    __u32 key = 0;
    struct core_map_entry* core_map_entry_ptr = bpf_map_lookup_elem(&core_stats_map, &key);
    if (!core_map_entry_ptr)
        return 1;
    
    read_perf_event_counter(INSTRUCTIONS,   cpu_idx, &core_map_entry_ptr->instructions);
    read_perf_event_counter(CPU_CYCLES,     cpu_idx, &core_map_entry_ptr->cpu_cycles);
    read_perf_event_counter(REF_CPU_CYCLES, cpu_idx, &core_map_entry_ptr->ref_cpu_cycles);
    read_perf_event_counter(CACHE_MISSES,   cpu_idx, &core_map_entry_ptr->cache_misses);

    /* RAPL events are opened on CPU 0. bpf_perf_event_read_value uses
     * perf_event_read_local, so reads from any other CPU return 0 and
     * would overwrite the correct value in the shared stats map. */
    if (cpu_idx != 0)
        return 0;
    
    read_rapl_domain_counter(RAPL_PKG);
    read_rapl_domain_counter(RAPL_CORE);
    read_rapl_domain_counter(RAPL_UNCORE);
    read_rapl_domain_counter(RAPL_DRAM);
    read_rapl_domain_counter(RAPL_PSYS);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
