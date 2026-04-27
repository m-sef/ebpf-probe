/**
 * @file ebpf_probe_iter.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <bpf_definitions.h>
#include <bpf_shared_maps.h>

volatile const __u32 target_cpu_idx; /* This bpf object instance handles this core */

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

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (!context->key)
        return 0;
    
    __u32 key = 0;
    struct counters* counters = bpf_map_lookup_percpu_elem(
        &counters_map, &key, target_cpu_idx);
    
    if (!counters)
        return 0;
    
    BPF_SEQ_PRINTF(seq, "%llu,%llu,%ld,%ld,%ld,%ld\n", 
        counters->total_packets_received,
        counters->total_rx_bytes_received,
        read_perf_event_counter(INSTRUCTIONS, target_cpu_idx),
        read_perf_event_counter(CPU_CYCLES, target_cpu_idx),
        read_perf_event_counter(REF_CPU_CYCLES, target_cpu_idx),
        read_perf_event_counter(CACHE_MISSES, target_cpu_idx));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";