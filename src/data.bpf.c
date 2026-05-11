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
increment_core_stats_network_counters(
        __u64 packets,
        __u64 rx_bytes)
{
    __u32 key = 0;
    struct core_stats* ptr = bpf_map_lookup_elem(&core_stats_map, &key);
    if (ptr)
    {
        ptr->total_packets_received  += packets;
        ptr->total_rx_bytes_received += rx_bytes;
    }
}

SEC("xdp")
int xdp_probe(struct xdp_md* context)
{
    void* data     = (void*)(long)context->data;
    void* data_end = (void*)(long)context->data_end;

    increment_core_stats_network_counters(1, data_end - data);

    return XDP_PASS;
}

static inline __u64 
read_perf_event_counter(
        size_t perf_event_type,
        size_t cpu_idx)
{
    __u32 key = (cpu_idx * NUM_EVENT_TYPES) + perf_event_type;
    struct bpf_perf_event_value value = {};

    if (bpf_perf_event_read_value(&perf_event_map, key, &value, sizeof(value)) < 0)
        return 0;

    return value.counter;
}

static inline __u64
read_rapl_domain_event_counter(
        size_t rapl_domain_idx)
{
    __u32 key = rapl_domain_idx;
    struct bpf_perf_event_value value = {};

    if (bpf_perf_event_read_value(&rapl_event_map, key, &value, sizeof(value)) < 0)
        return 0;

    return value.counter;
}

SEC("perf_event")
/**
 * @brief Attached to Software CPU Clock perf event, triggers every 1Hz
 * 
 */
int timer(struct bpf_perf_event_data* ctx)
{
    __u32 cpu_idx = bpf_get_smp_processor_id();
    __u32 key = 0;
    struct core_stats* core_stats_ptr = bpf_map_lookup_elem(&core_stats_map, &key);
    if (!core_stats_ptr)
        return 1;
    
    core_stats_ptr->instructions   = read_perf_event_counter(INSTRUCTIONS,   cpu_idx);
    core_stats_ptr->cpu_cycles     = read_perf_event_counter(CPU_CYCLES,     cpu_idx);
    core_stats_ptr->ref_cpu_cycles = read_perf_event_counter(REF_CPU_CYCLES, cpu_idx);
    core_stats_ptr->cache_misses   = read_perf_event_counter(CACHE_MISSES,   cpu_idx);

    /* RAPL events are opened on CPU 0. bpf_perf_event_read_value uses
     * perf_event_read_local, so reads from any other CPU return 0 and
     * would overwrite the correct value in the shared stats map. */
    if (cpu_idx != 0)
        return 0;
    
    key = RAPL_PKG;
    struct domain_stats* pkg_domain_stats_ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!pkg_domain_stats_ptr)
        return 1;
    pkg_domain_stats_ptr->value = read_rapl_domain_event_counter(RAPL_PKG);

    key = RAPL_CORE;
    struct domain_stats* core_domain_stats_ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!core_domain_stats_ptr)
        return 1;
    core_domain_stats_ptr->value = read_rapl_domain_event_counter(RAPL_CORE);

    key = RAPL_UNCORE;
    struct domain_stats* uncore_domain_stats_ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!uncore_domain_stats_ptr)
        return 1;
    uncore_domain_stats_ptr->value = read_rapl_domain_event_counter(RAPL_UNCORE);

    key = RAPL_DRAM;
    struct domain_stats* dram_domain_stats_ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!dram_domain_stats_ptr)
        return 1;
    dram_domain_stats_ptr->value = read_rapl_domain_event_counter(RAPL_DRAM);

    key = RAPL_PSYS;
    struct domain_stats* psys_domain_stats_ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!psys_domain_stats_ptr)
        return 1;
    psys_domain_stats_ptr->value = read_rapl_domain_event_counter(RAPL_PSYS);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
