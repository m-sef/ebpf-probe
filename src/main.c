#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_prog.skel.h"

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface_name, "interface", "Interface name")

#define OPTIONAL_ARGS \
	OPTIONAL_STRING_ARG(protocols, "HTTP,HTTPS", "-p", "protocol", "Protocols to capture") \
	OPTIONAL_STRING_ARG(destination_ports, "80,443", "-d", "destination", "Destination ports to capture") \
	OPTIONAL_STRING_ARG(source_ports, "", "-s", "source", "Source ports to capture") \
	OPTIONAL_STRING_ARG(queues, "", "-q", "queue", "NIC queues to capture")

#define BOOLEAN_ARGS \
	BOOLEAN_ARG(verbose, "-v", "Enable verbose output") \
	BOOLEAN_ARG(help, "-h", "Show help")

#include "easyargs.h"
#include "shared.h"

int main(int argc, char** argv)
{
	int error = 0;
	uid_t euid = geteuid();
	args_t args = make_default_args();

	if (!parse_args(argc, argv, &args) || args.help)
	{
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	/* Check if the program is being run as root. */
	if (euid != 0)
	{
		printf("This program must be run as root\n");
		return EXIT_FAILURE;
	}

	/* Check if provided interface exists */
	unsigned int interface_index = if_nametoindex(args.interface_name);
	if (!interface_index)
	{
		printf("Could not find interface \"%s\"\n", args.interface_name);
		return EXIT_FAILURE;
	}

	/* Open BPF application */
	struct xdp_prog_bpf* skeleton = xdp_prog_bpf__open();
	if (!skeleton)
	{
		printf("Failed to open BPF skeleton\n");
		return EXIT_FAILURE;
	}

	/* Load and verify BPF programs */
	error = xdp_prog_bpf__load(skeleton);
	if (error)
	{
		printf("Failed to load and verify BPF skeleton\n");
		return EXIT_FAILURE;
	}

	/* Attach BPF program to specified interface */
	skeleton->links.xdp_prog = bpf_program__attach_xdp(skeleton->progs.xdp_prog, interface_index);
	if (!skeleton->links.xdp_prog)
	{
		printf("Failed to attach XDP program");
		return EXIT_FAILURE;
	}

	struct bpf_map* map = bpf_object__find_map_by_name(skeleton->obj, "throughput_map");
	struct key_t key;
	struct key_t next_key;
	
	while (true)
	{
		time_t now = time(NULL);
		struct tm* time_info = localtime(&now);
		char timestamp_buffer[20];

		strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d_%H-%M-%S", time_info);

		error = bpf_map__get_next_key(map, NULL, &key, sizeof(key));
		while(!error)
		{
			struct value_t value;

			bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0);

			printf(
				"%s,%d,%d,%d,%d,%lld,%lld\n",
				timestamp_buffer,
				key.destination_port,
				key.queue,
				key.protocol,
				key.direction,
				value.total_packets_recieved,
				value.total_bytes_recieved);

			error = bpf_map__get_next_key(map, &key, &next_key, sizeof(key));
			key = next_key;
		}

		sleep(1);
	}

	xdp_prog_bpf__destroy(skeleton);
	return EXIT_SUCCESS;
}
