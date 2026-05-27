/**
 * @file bpf_definitions.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef BPF_DEFINITIONS_H
#define BPF_DEFINITIONS_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#include <linux/bpf.h>
#endif

struct core_map_entry {
    __u64 total_packets_received;
    __u64 total_rx_bytes_received;
    struct bpf_perf_event_value instructions;
    struct bpf_perf_event_value cpu_cycles;
    struct bpf_perf_event_value ref_cpu_cycles;
    struct bpf_perf_event_value cache_misses;
};

typedef int fd_t;
typedef int error_t;

enum perf_event_map_ids {
    CPU_CYCLES          = 0,
	INSTRUCTIONS        = 1,
    CACHE_REFERENCES    = 2,
    CACHE_MISSES        = 3,
    BRANCH_INSTRUCTIONS = 4,
    BRANCH_MISSES       = 5,
    BUS_CYCLES          = 6,
	REF_CPU_CYCLES      = 7,
	NUM_EVENT_TYPES,
};

enum rapl_domains {
    RAPL_PKG    = 0,
    RAPL_CORE   = 1,
    RAPL_UNCORE = 2,
    RAPL_DRAM   = 3,
    RAPL_PSYS   = 4,
    RAPL_DOMAINS_MAX,
};

#endif
