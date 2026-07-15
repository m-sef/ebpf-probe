/**
 * @file bpf_definitions.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief Important BPF-related definitions which are safe to include in both BPF and normal userspace programs
 * 
 */
#ifndef BPF_DEFINITIONS_H
#define BPF_DEFINITIONS_H

#ifdef __BPF__
#include "generated/vmlinux.h"
#else
#include <linux/types.h>
#include <linux/bpf.h>
#endif

struct interface_stats {
    __u64 rx_packets; /* Total received packets */
    __u64 rx_bytes;   /* Total received bytes */
    __u64 tx_packets; /* Total transmitted packets */
    __u64 tx_bytes;   /* Total transmitted bytes */
};

struct core_map_entry {
    struct interface_stats interface;
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

volatile __u64 last_sample_timestamp_ns;

#endif
