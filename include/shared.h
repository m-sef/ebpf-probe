#ifndef SHARED_H
#define SHARED_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

typedef struct packet_info {
	__u64 time;
	__u64 size;
	__u32 rx_queue_index;
	__u32 source_ipv4_address;
	__u32 destination_ipv4_address;
	__u16 source_port;
	__u16 destination_port;
	__u8 protocol;
} packet_info_t;

#endif
