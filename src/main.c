#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "ebpf_probe.h"

static int handle_record(void* context, void* data, size_t size)
{
    struct packet_info_t* info = data;

    printf("src: %u.%u.%u.%u:%u -> dst: %u.%u.%u.%u:%u (proto: %u)\n",
        (info->source_ipv4_address) & 0xFF,
        (info->source_ipv4_address >> 8)  & 0xFF,
        (info->source_ipv4_address >> 16) & 0xFF,
        (info->source_ipv4_address >> 24) & 0xFF,
        info->source_port,
        (info->destination_ipv4_address) & 0xFF,
        (info->destination_ipv4_address >> 8)  & 0xFF,
        (info->destination_ipv4_address >> 16) & 0xFF,
        (info->destination_ipv4_address >> 24) & 0xFF,
        info->destination_port,
        info->protocol);

    return 0;
}

int main(int argc, char** argv)
{
	struct xdp_prog_bpf* skeleton = ebpf_probe_init("lo");
	if (!skeleton)
		return EXIT_FAILURE;

	struct ring_buffer* ring_buffer = ring_buffer__new(
		bpf_map__fd(skeleton->maps.ring_buffer),
		handle_record, NULL, NULL);

	while (true)
        ring_buffer__poll(ring_buffer, 100);

	ring_buffer__free(ring_buffer);
	ebpf_probe_destroy(skeleton);

	return EXIT_SUCCESS;
}
