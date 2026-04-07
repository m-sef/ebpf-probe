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
	__u64 time;
	__u64 size;
	__u32 rx_queue_index;
	__u32 source_ipv4_address;
	__u32 destination_ipv4_address;
	__u16 source_port;
	__u16 destination_port;
	__u8 protocol;
};

#endif
