#ifndef SHARED_H
#define SHARED_H

struct key_t {
	__u32 rx_queue_index;
	__u32 source_ipv4_address;
	__u32 destination_ipv4_address;
	__u16 source_port;
	__u16 destination_port;
	__u8 protocol;
};

struct value_t {
	__u64 total_packets_recieved;
	__u64 total_bytes_recieved;
};

#endif
