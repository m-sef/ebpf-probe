#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface_name, "interface", "Interface name")

#include "easyargs.h"
#include "ebpf_probe.h"

static void ipv4_address_to_string(
	char* buffer,
	const size_t buffer_size,
	const uint32_t ipv4_address)
{
	snprintf(buffer, buffer_size, "%u.%u.%u.%u",
		  (ipv4_address)       & 0xFF,
		  (ipv4_address >> 8)  & 0xFF,
		  (ipv4_address >> 16) & 0xFF,
		  (ipv4_address >> 24) & 0xFF);
}

static int handle_record(void* context, void* data, size_t size)
{
	struct packet_info_t* info = data;
	char source_ipv4_address_as_string[16];
	char destination_ipv4_address_as_string[16];
	ipv4_address_to_string(source_ipv4_address_as_string, 16, info->source_ipv4_address);
	ipv4_address_to_string(destination_ipv4_address_as_string, 16, info->destination_ipv4_address);

	printf("%15s:%-5u->%15s:%-5u rx_queue_index: %-9u protocol: %-3u size: %llu\n",
		source_ipv4_address_as_string,
		info->source_port,
		destination_ipv4_address_as_string,
		info->destination_port,
		info->rx_queue_index,
		info->protocol,
		info->size);

	return 0;
}

int main(int argc, char** argv)
{
	args_t args = make_default_args();
	if (!parse_args(argc, argv, &args))
	{
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	struct ebpf_probe* ebpf_probe = ebpf_probe__init(args.interface_name, handle_record, NULL);
	if (!ebpf_probe)
		return EXIT_FAILURE;

	while (1)
		ebpf_probe__flush_buffer(ebpf_probe);

	ebpf_probe__destroy(ebpf_probe);

	return EXIT_SUCCESS;
}
