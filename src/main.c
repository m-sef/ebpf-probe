#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "ebpf_probe.h"

int main(int argc, char** argv)
{
	struct xdp_prog_bpf* skeleton = ebpf_probe_init("lo");
	if (!skeleton)
		return EXIT_FAILURE;

	ebpf_probe_destroy(skeleton);

	return EXIT_SUCCESS;
}
