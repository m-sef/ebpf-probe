/**
 * @file interface_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include "generated/vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "bpf/definitions.h"
#include "bpf/shared_maps.h"

#define PRINTF(message, ...) BPF_SEQ_PRINTF(seq, message, ##__VA_ARGS__)

volatile const unsigned int cpu;
volatile const unsigned int ifindex;

SEC("iter/bpf_map_elem")
int dump_interface_stats(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (context->key == NULL)
        return 0;
    
    if (*((unsigned int*)context->key) != cpu)
        return 0;
    
    struct interface_stats* ptr = bpf_map_lookup_percpu_elem(&interface_stats_map, &ifindex, cpu);
    if (ptr == NULL)
        return 0;
    
    PRINTF("#rx_packets,rx_bytes,tx_packets,tx_bytes\n");
    PRINTF("%ld,%ld,%ld,%ld\n", ptr->rx_packets, ptr->rx_bytes, ptr->tx_packets, ptr->tx_bytes);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";