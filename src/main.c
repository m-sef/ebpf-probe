#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface_name, "interface", "Interface name")

#include "easyargs.h"
#include "ebpf_probe.h"

int main(int argc, char** argv)
{
	args_t args = make_default_args();
	if (!parse_args(argc, argv, &args))
	{
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	struct ebpf_probe* ebpf_probe = ebpf_probe__init(args.interface_name);

	while (1)
		ebpf_probe__flush_packet_info_ring_buffer(ebpf_probe);

	ebpf_probe__destroy(ebpf_probe);

	return EXIT_SUCCESS;
}
