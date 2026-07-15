/**
 * @file core_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include "generated/vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "bpf/definitions.h"
#include "bpf/shared_maps.h"

#define PRINTF(message, ...) BPF_SEQ_PRINTF(seq, message, ##__VA_ARGS__)

volatile const __u32 cpu;

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (context->key == NULL)
        return 0;
    
    __u32 key = 0;
    struct core_map_entry* ptr = bpf_map_lookup_percpu_elem(&core_stats_map, &key, cpu);
    if (ptr == NULL)
        return 0;
    
    __u64 timestamp_ns = last_sample_timestamp_ns;

    //PRINTF("#timestamp_ns,core,event,counter,enabled,running\n");
    PRINTF("%llu,%ld,rx_packets,%llu,N/A,N/A\n", timestamp_ns, cpu, ptr->interface.rx_packets);
    PRINTF("%llu,%ld,rx_bytes,%llu,N/A,N/A\n",   timestamp_ns, cpu, ptr->interface.rx_bytes);
    PRINTF("%llu,%ld,tx_packets,%llu,N/A,N/A\n", timestamp_ns, cpu, ptr->interface.tx_packets);
    PRINTF("%llu,%ld,tx_bytes,%llu,N/A,N/A\n",   timestamp_ns, cpu, ptr->interface.tx_bytes);
    PRINTF("%llu,%ld,instructions,%ld,%ld,%ld\n", timestamp_ns, cpu,
        ptr->instructions.counter, ptr->instructions.enabled, ptr->instructions.running);
    PRINTF("%llu,%ld,cpu_cycles,%ld,%ld,%ld\n", timestamp_ns, cpu,
        ptr->cpu_cycles.counter, ptr->cpu_cycles.enabled, ptr->cpu_cycles.running);
    PRINTF("%llu,%ld,ref_cpu_cycles,%ld,%ld,%ld\n", timestamp_ns, cpu,
        ptr->ref_cpu_cycles.counter, ptr->ref_cpu_cycles.enabled, ptr->ref_cpu_cycles.running);
    PRINTF("%llu,%ld,cache_misses,%ld,%ld,%ld\n", timestamp_ns, cpu,
        ptr->cache_misses.counter, ptr->cache_misses.enabled, ptr->cache_misses.running);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";