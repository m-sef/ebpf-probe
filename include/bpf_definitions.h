/**
 * @file kernel_definitions.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef BPF_DEFINITIONS_H
#define BPF_DEFINITIONS_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#ifdef UNUSED
struct packet_information {
    __u64 time; /* Time, in nanoseconds, when the packet was received */
    __u64 size; /* The size of the entire packet, in bytes, including all headers */
    __u32 rx_queue_index; /* The index of the NIC queue where the packet was received*/
    __u32 source_address;
    __u32 destination_address;
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
};
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

struct rapl_domain {
    __u64 scale;
    fd_t  fd;
};

enum rapl_domains {
    RAPL_PKG    = 0,
    RAPL_CORE   = 1,
    RAPL_UNCORE = 2,
    RAPL_DRAM   = 3,
    RAPL_PSYS   = 4,
    RAPL_DOMAINS_MAX
};

#endif
