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

#define DEBUG_MSG \
"%ld: {\n" \
"    total_packets_received: %llu\n" \
"    total_rx_bytes_received: %llu\n" \
"    instructions: %ld\n" \
"    cpu_cycles: %ld\n" \
"    ref_cpu_cycles: %ld\n" \
"    cache_misses: %ld\n" \
"}\n"

volatile const __u32 target_cpu_idx; /* This bpf object instance handles this core */

static inline void
flush()
{
    
}

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (!context->key)
        return 0;
    
    __u32 key = 0;
    struct core_entry* ptr = bpf_map_lookup_percpu_elem(&core_map, &key, target_cpu_idx);
    if (!ptr)
        return 0;
    
    BPF_SEQ_PRINTF(seq, DEBUG_MSG,
        target_cpu_idx,
        ptr->total_packets_received,
        ptr->total_rx_bytes_received,
        ptr->instructions,
        ptr->cpu_cycles,
        ptr->ref_cpu_cycles,
        ptr->cache_misses);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";