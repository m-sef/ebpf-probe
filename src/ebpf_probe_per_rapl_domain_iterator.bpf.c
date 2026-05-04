/**
 * @file ebpf_probe_rapl_iter.bpf.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <bpf_definitions.h>
#include <bpf_shared_maps.h>

#define VERBOSE_OUTPUT \
"# RAPL Domain\n" \
"%s:\n" \
"    value: %llu\n" \
"    scale: %s\n" \
"    unit: %s\n"

#define DEFAULT_OUTPUT "%llu\n"

volatile const bool verbose;
volatile const char scale[32];
volatile const char unit[32];
volatile const __u32 target_rapl_domain_idx;

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
    
    if (*((__u32*)context->key) != target_rapl_domain_idx)
        return 0;
    
    __u32 key = target_rapl_domain_idx;
    struct domain_stats* ptr = bpf_map_lookup_elem(&per_rapl_domain_stats_map, &key);
    if (!ptr)
        return 0;
    
    if (verbose)
    {
        BPF_SEQ_PRINTF(seq, VERBOSE_OUTPUT,
            rapl_domain_names[target_rapl_domain_idx],
            ptr->value,
            "2.3283064365386962890625e-10",
            "Joules");
    }
    else
    {
        BPF_SEQ_PRINTF(seq, DEFAULT_OUTPUT,
            ptr->value);
    }
    
    return 0;
}