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
#endif

typedef struct core_stats {
    __u64 timestamp_ns; /* Currently unused, may be removed */
    __u64 total_packets_received;
    __u64 total_rx_bytes_received;
    __u64 instructions;
    __u64 cpu_cycles;
    __u64 ref_cpu_cycles;
    __u64 cache_misses;
    __u64 rapl_counter; /* energy-pkg - Raw counter, needs to be multiplied with appropiate domain scale in post-processing */
} core_stats_t;

typedef struct domain_stats {
    __u64 value;
} domain_stats_t;

typedef int fd_t;

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
