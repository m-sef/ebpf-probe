/**
 * @file ebpf_probe.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf_probe.skel.h"
#include "ebpf_probe.hpp"
#include "kernel_definitions.h"

#define ROOT_PRIVILEGES 0

static struct ebpf_probe_bpf* bpf;

error_t
ebpf_probe::init()
{
    assert(bpf == nullptr);

    if (getuid() != ROOT_PRIVILEGES)
    {
        fprintf(stderr, "Program must be run with root privileges\n");
        return EXIT_FAILURE;
    }

    bpf = ebpf_probe_bpf::open_and_load();

    if (bpf == nullptr)
    {
        fprintf(stderr, "Failed to open and load BPF object\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

error_t
ebpf_probe::attach_xdp(
        const std::string& interface_name)
{
    assert(bpf != nullptr);

    unsigned int interface_index = if_nametoindex(interface_name.c_str());
    if (!interface_index)
    {
        fprintf(stderr, "Could not find interface \"%s\"\n", interface_name.c_str());
        return EXIT_FAILURE;
    }

    bpf->links.xdp_probe = bpf_program__attach_xdp(bpf->progs.xdp_probe, interface_index);
    if (!bpf->links.xdp_probe)
    {
        perror("Failed to attach BPF program to XDP hook");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

error_t
ebpf_probe::destroy()
{
    assert(bpf != nullptr);

    ebpf_probe_bpf::destroy(bpf);

    return EXIT_SUCCESS;
}

size_t
ebpf_probe::get_total_packets_received()
{
    size_t cpu_count = libbpf_num_possible_cpus();
    __u32 key = 0;
    __u64 sum = 0;
    struct counters counters[cpu_count];
    int ret;
    int fd = bpf_map__fd(bpf->maps.counters_map);

    ret = bpf_map_lookup_elem(fd, &key, &counters);
    assert(ret >= 0);

    for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
    {
        sum += counters[cpu_idx].total_packets_received;
    }

    return sum;
}

size_t ebpf_probe::get_total_rx_bytes_received()
{
    size_t cpu_count = libbpf_num_possible_cpus();
    __u32 key = 0;
    __u64 sum = 0;
    struct counters counters[cpu_count];
    int ret;
    int fd = bpf_map__fd(bpf->maps.counters_map);

    ret = bpf_map_lookup_elem(fd, &key, &counters);
    assert(ret >= 0);

    for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
    {
        sum += counters[cpu_idx].total_rx_bytes_received;
    }

    return sum;
}
