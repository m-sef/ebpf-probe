/**
 * @file main.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "xdp_probe.h"

static volatile sig_atomic_t running = true;

static void handle_signal_interrupt(const int sig)
{
	running = false;
}

static void ipv4_address_to_string(
		char* buffer,
		const size_t buffer_size,
		const uint32_t ipv4_address,
		const uint16_t port)
{
	snprintf(buffer, buffer_size, "%u.%u.%u.%u:%u",
		(ipv4_address)       & 0xFF,
		(ipv4_address >> 8)  & 0xFF,
		(ipv4_address >> 16) & 0xFF,
		(ipv4_address >> 24) & 0xFF,
		port);
}

static int handle_record(
		void* context,
		void* data,
		size_t size)
{
	packet_info_t* info = data;

	char source_ipv4_address_as_string[22];
	ipv4_address_to_string(
		source_ipv4_address_as_string, 22,
		info->source_ipv4_address, info->source_port);

	char destination_ipv4_address_as_string[22];
	ipv4_address_to_string(
		destination_ipv4_address_as_string, 22,
		info->destination_ipv4_address, info->destination_port);

	printf("%llu,%s,%s,%u,%u,%llu\n",
		info->time,
		source_ipv4_address_as_string,
		destination_ipv4_address_as_string,
		info->rx_queue_index,
		info->protocol,
		info->size);

	return 0;
}

int main(int argc, char** argv)
{
	signal(SIGINT, handle_signal_interrupt);

	xdp_probe__init();
	xdp_probe__attach("enp0s31f6");
	xdp_probe__init_buffer(handle_record, NULL);

	puts("time,source_socket,destination_socket,rx_queue_index,protocol,size");

	while (running)
	{
		size_t available_buffer_size = xdp_probe__available_buffer_size();

		if (available_buffer_size >= (1 << 10))
		{
			/* printf("%lu available buffer size, flushing...\n",
				available_buffer_size); */
			xdp_probe__flush_buffer();
		}
		else
		{
			/* printf("%lu available buffer size, will flush at %u\n",
				available_buffer_size, (1 << 10)); */
			// Sleep for 1 seconds
			usleep(1000000);
		}
	}

	xdp_probe__flush_buffer();

	xdp_probe__destroy_buffer();
	xdp_probe__destroy();

	return EXIT_SUCCESS;
}
