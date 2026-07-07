/**
 * @file rapl_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include "generated/vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "bpf/definitions.h"
#include "bpf/shared_maps.h"

#define PRINTF(message, ...) BPF_SEQ_PRINTF(seq, message, ##__VA_ARGS__)

volatile const char rapl_domain_name[32];
volatile const char scale[32];
volatile const char unit[32];
volatile const __u32 domain;

static const char rapl_domain_names[][8] = {
	[RAPL_PKG]    = "pkg",
	[RAPL_CORE]   = "cores",
	[RAPL_UNCORE] = "uncore",
	[RAPL_DRAM]   = "ram",
	[RAPL_PSYS]   = "psys",
};

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (context->key == NULL)
        return 0;
    
    if (*((__u32*)context->key) != domain)
        return 0;
    
    __u32 key = domain;
    struct bpf_perf_event_value* ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!ptr)
        return 0;
    
    __u64 timestamp_ns = bpf_ktime_get_ns();
    
    //PRINTF("#timestamp_ns,domain,counter,unit,scale\n");
    PRINTF("%llu,%s,%llu,%s,%s\n", timestamp_ns, rapl_domain_name, ptr->counter, unit, scale);
    
    return 0;
}

char _license[] SEC("license") = "GPL";