#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface_name, "interface", "Interface name")

#define BOOLEAN_ARGS \
	BOOLEAN_ARG(verbose, "-v", "Enable verbose output") \
	BOOLEAN_ARG(help, "-h", "Show help")

#include "easyargs.h"

int main(int argc, char** argv)
{
	args_t args = make_default_args();

	if (!parse_args(argc, argv, &args) || args.help)
	{
		print_help(argv[0]);

		return EXIT_FAILURE;
	}

	unsigned int interface_index = if_nametoindex(args.interface_name);
	if (!interface_index)
	{
		printf("Could not find interface \"%s\"\n", args.interface_name);
		return EXIT_FAILURE;
	}

	printf("Interface Index: %d\n", interface_index);

	return EXIT_SUCCESS;
}
