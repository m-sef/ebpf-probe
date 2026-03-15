#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>

typedef struct packet_info_t {
	uint64_t size;
	uint32_t rx_queue_index;
	uint32_t source_ipv4_address;
	uint32_t destination_ipv4_address;
	uint16_t source_port;
	uint16_t destination_port;
	uint8_t protocol;
} packet_info_t;

#endif
