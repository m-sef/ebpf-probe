#ifndef SHARED_H
#define SHARED_H

struct key_t {
	union {
		__u16 source_port;
		__u16 destination_port;
	};
	__u16 queue;
	__u8 protocol;
	__u8 direction;
};

struct value_t {
	__u64 total_packets_recieved;
	__u64 total_bytes_recieved;
};

#endif
