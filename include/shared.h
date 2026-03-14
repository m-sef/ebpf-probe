#ifndef SHARED_H
#define SHARED_H

struct packet_info_t {
	__u64 size;
	__u32 rx_queue_index;
	__u32 source_ipv4_address;
	__u32 destination_ipv4_address;
	__u16 source_port;
	__u16 destination_port;
	__u8 protocol;
};

#endif
