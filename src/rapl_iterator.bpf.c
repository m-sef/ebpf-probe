/**
 * @file rapl_iterator.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <bpf_definitions.h>
#include <bpf_shared_maps.h>

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

char _license[] SEC("license") = "GPL";

SEC("iter/bpf_map_elem")
int dump_counters(struct bpf_iter__bpf_map_elem* context)
{
    struct seq_file* seq = context->meta->seq;

    if (!context->key)
        return 0;
    
    if (*((__u32*)context->key) != domain)
        return 0;
    
    __u32 key = domain;
    struct bpf_perf_event_value* ptr = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!ptr)
        return 0;
    
    BPF_SEQ_PRINTF(seq, "#domain,counter,unit,scale\n");
    BPF_SEQ_PRINTF(seq, "%s,%llu,%s,%s\n", rapl_domain_name, ptr->counter, unit, scale);
    
    return 0;
}