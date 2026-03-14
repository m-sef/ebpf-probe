#include "ebpf_probe.h"

struct xdp_prog_bpf* ebpf_probe_init(
	const char* interface_name)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "Program must be run as root\n");
		return NULL;
	}
	
	unsigned int interface_index = if_nametoindex(interface_name);
	if (!interface_index)
	{
		fprintf(stderr, "Could not find interface \"%s\"\n", interface_name);
		return NULL;
	}
	
	struct xdp_prog_bpf* skeleton = xdp_prog_bpf__open();
	if (!skeleton)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return NULL;
	}

	int error = xdp_prog_bpf__load(skeleton);
	if (error)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		xdp_prog_bpf__destroy(skeleton);
		return NULL;
	}

	skeleton->links.xdp_prog = bpf_program__attach_xdp(skeleton->progs.xdp_prog, interface_index);
	if (!skeleton->links.xdp_prog)
	{
		fprintf(stderr, "Failed to attach XDP program\n");
		xdp_prog_bpf__destroy(skeleton);
		return NULL;
	}

	return skeleton;
}

void ebpf_probe_destroy(
	struct xdp_prog_bpf* skeleton)
{
	xdp_prog_bpf__destroy(skeleton);
}
