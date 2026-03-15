#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface_name, "interface", "Interface name")

#include "easyargs.h"
#include "ebpf_probe.h"

static int handle_record(void* context, void* data, size_t size)
{
	struct packet_info_t* info = data;

    printf("%3u.%03u.%03u.%03u:%-5u->%3u.%03u.%03u.%03u:%-5u rx_queue_index: %-9u protocol: %-3u size: %lu\n",
        (info->source_ipv4_address)            & 0xFF,
        (info->source_ipv4_address >> 8)       & 0xFF,
        (info->source_ipv4_address >> 16)      & 0xFF,
        (info->source_ipv4_address >> 24)      & 0xFF,
        info->source_port,
        (info->destination_ipv4_address)       & 0xFF,
        (info->destination_ipv4_address >> 8)  & 0xFF,
        (info->destination_ipv4_address >> 16) & 0xFF,
        (info->destination_ipv4_address >> 24) & 0xFF,
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
		ebpf_probe__flush_packet_info_ring_buffer(ebpf_probe);

	ebpf_probe__destroy(ebpf_probe);

	return EXIT_SUCCESS;
}
