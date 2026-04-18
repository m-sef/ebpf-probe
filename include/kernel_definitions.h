/**
 * @file shared.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef SHARED_DEFINITIONS_H
#define SHARED_DEFINITIONS_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

struct counters {
	__u64 total_packets_received;
	__u64 total_rx_bytes_received;
};

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

typedef int fd_t;

enum perf_event_map_ids {
	INSTRUCTIONS,
	CPU_CYCLES,
	REF_CPU_CYCLES,
	NUM_EVENT_TYPES,
};

#endif
