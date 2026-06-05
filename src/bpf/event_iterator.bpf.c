/**
 * @file event_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include "generated/vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "bpf/definitions.h"
#include "bpf/shared_maps.h"

#define PRINTF(message, ...) BPF_SEQ_PRINTF(seq, message, ##__VA_ARGS__)

const volatile unsigned int cpu;
const volatile unsigned int event;

SEC("iter/bpf_map_elem")
int dump_perf_stats(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (context->key == NULL)
        return 0;
    
    if (*((unsigned int*)context->key) != cpu)
        return 0;
    
    PRINTF("#event,counter,enabled,running\n");
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";