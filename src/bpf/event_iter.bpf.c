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

volatile const unsigned int cpu;
volatile const unsigned int event;
volatile const char event_name[256];

SEC("iter/bpf_map_elem")
int dump_event_stats(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    void* key_ptr = context->key;
    if (key_ptr == NULL)
        return 0;

    if (*((unsigned int*)key_ptr) != event)
        return 0;

    struct bpf_perf_event_value* ptr = bpf_map_lookup_percpu_elem(&perf_event_stats_map, &event, cpu);
    if (ptr == NULL)
        return 0;

    // Output CSV Columns
    // cpu, event, counter, enabled, running
    PRINTF("%ld,%s,%ld,%ld,%ld\n", cpu, event_name, ptr->counter, ptr->enabled, ptr->running);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";