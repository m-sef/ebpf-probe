/**
 * @file core_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <bpf_definitions.h>
#include <bpf_shared_maps.h>

volatile const __u32 cpu;

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (!context->key)
        return 0;
    
    __u32 key = 0;
    struct core_map_entry* ptr = bpf_map_lookup_percpu_elem(&core_stats_map, &key, cpu);
    if (!ptr)
        return 0;

    BPF_SEQ_PRINTF(seq, "#core,event,counter,enabled,running\n");
    BPF_SEQ_PRINTF(seq, "%ld,rx_packets,%llu,N/A,N/A\n", cpu, ptr->rx_packets);
    BPF_SEQ_PRINTF(seq, "%ld,rx_bytes,%llu,N/A,N/A\n",   cpu, ptr->rx_bytes);
    BPF_SEQ_PRINTF(seq, "%ld,tx_packets,%llu,N/A,N/A\n", cpu, ptr->tx_packets);
    BPF_SEQ_PRINTF(seq, "%ld,tx_bytes,%llu,N/A,N/A\n",   cpu, ptr->tx_bytes);

    BPF_SEQ_PRINTF(seq, "%ld,instructions,%ld,%ld,%ld\n", cpu,
        ptr->instructions.counter, ptr->instructions.enabled, ptr->instructions.running);
    BPF_SEQ_PRINTF(seq, "%ld,cpu_cycles,%ld,%ld,%ld\n", cpu,
        ptr->cpu_cycles.counter, ptr->cpu_cycles.enabled, ptr->cpu_cycles.running);
    BPF_SEQ_PRINTF(seq, "%ld,ref_cpu_cycles,%ld,%ld,%ld\n", cpu,
        ptr->ref_cpu_cycles.counter, ptr->ref_cpu_cycles.enabled, ptr->ref_cpu_cycles.running);
    BPF_SEQ_PRINTF(seq, "%ld,cache_misses,%ld,%ld,%ld\n", cpu,
        ptr->cache_misses.counter, ptr->cache_misses.enabled, ptr->cache_misses.running);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";