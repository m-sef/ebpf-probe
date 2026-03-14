#ifndef EBPF_PROBE_H
#define EBPF_PROBE_H

#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_prog.skel.h"
#include "shared.h"

struct xdp_prog_bpf* ebpf_probe_init(const char* interface_name);
void ebpf_probe_destroy(struct xdp_prog_bpf* skeleton);

#endif
