#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "ebpf_probe.h"

int main(int argc, char** argv)
{
	struct ebpf_probe* ebpf_probe = ebpf_probe_init("lo");

	while (1)
		ebpf_probe_read_from_packet_info_ring_buffer(ebpf_probe);

	ebpf_probe_destroy(ebpf_probe);

	return EXIT_SUCCESS;
}
