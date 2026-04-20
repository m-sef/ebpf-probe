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
#include "definitions.hpp"
#include "kernel_definitions.h"

#define ROOT_PRIVILEGES 0

static struct ebpf_probe_bpf* bpf;
static size_t num_cpus = 0;

static struct perf_event_attr perf_events[] = {
    [CPU_CYCLES]          = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CPU_CYCLES},
    [INSTRUCTIONS]        = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_INSTRUCTIONS},
    [CACHE_REFERENCES]    = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CACHE_REFERENCES},
    [CACHE_MISSES]        = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CACHE_MISSES},
    [BRANCH_INSTRUCTIONS] = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    [BRANCH_MISSES]       = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_MISSES},
    [BUS_CYCLES]          = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BUS_CYCLES},
    [REF_CPU_CYCLES]      = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_REF_CPU_CYCLES},
};

static const char* perf_event_names[] = {
    [CPU_CYCLES]          = "cpu-cycles",
    [INSTRUCTIONS]        = "instructions",
    [CACHE_REFERENCES]    = "cache-references",
    [CACHE_MISSES]        = "cache-misses",
    [BRANCH_INSTRUCTIONS] = "branch-instructions",
    [BRANCH_MISSES]       = "branch-misses",
    [BUS_CYCLES]          = "bus-cycles",
    [REF_CPU_CYCLES]      = "ref-cycles",
};

static inline error_t
init_perf_event_handler()
{
    assert(bpf != nullptr);
    assert(num_cpus != 0);

    /* Attaches the Software CPU Clock perf event to the bpf program 'perf_event_handler' */
    for (size_t cpu_idx = 0; cpu_idx < num_cpus; cpu_idx++)
    {
        struct perf_event_attr timer = {};
        timer.type        = PERF_TYPE_SOFTWARE;
        timer.config      = PERF_COUNT_SW_CPU_CLOCK;
        timer.sample_freq = 1;
        timer.freq        = 1;
        
        fd_t timer_fd = syscall(SYS_perf_event_open, &timer, -1, cpu_idx, -1, 0);
        if (timer_fd < 0)
        {
            perror("Failed to get file descriptor for PERF_COUNT_SW_CPU_CLOCK");
            return EXIT_FAILURE;
        }
        
        struct bpf_link* link = bpf_program__attach_perf_event(
            bpf->progs.perf_event_handler, timer_fd);
        if (!link)
        {
            perror("Failed to attach BPF program to perf hook");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static inline error_t
init_perf_event_map()
{
    assert(bpf != nullptr);
    assert(num_cpus != 0);

    fd_t perf_event_map_fd = bpf_map__fd(bpf->maps.perf_event_map);

    /* Add the file descriptors for each perf_event to the BPF program's perf_event_map */
    for (size_t perf_event_idx = 0; perf_event_idx < NUM_EVENT_TYPES; perf_event_idx++)
    {
        for (size_t cpu_idx = 0; cpu_idx < num_cpus; cpu_idx++)
        {

            fd_t perf_event_fd = syscall(
                SYS_perf_event_open, &perf_events[perf_event_idx], -1, cpu_idx, -1, 0);
            if (perf_event_fd < 0)
            {
                fprintf(stderr, "Failed to get file descriptor for perf event '%s' on core %ld\n", 
                    perf_event_names[perf_event_idx], cpu_idx);
                perror("");
                continue;
            }
            
            __u32 key = cpu_idx * NUM_EVENT_TYPES + perf_event_idx;
            bpf_map_update_elem(perf_event_map_fd, &key, &perf_event_fd, BPF_ANY);
        }
    }

    return EXIT_SUCCESS;
}

error_t
ebpf_probe::init()
{
    assert(bpf == nullptr);
    error_t err;

    num_cpus = libbpf_num_possible_cpus();

    if (getuid() != ROOT_PRIVILEGES)
    {
        fprintf(stderr, "Program must be run with root privileges\n");
        return EXIT_FAILURE;
    }

    bpf = ebpf_probe_bpf::open();
    if (bpf == nullptr)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    bpf_map__set_max_entries(bpf->maps.perf_event_map, num_cpus * NUM_EVENT_TYPES);

    if (ebpf_probe_bpf::load(bpf) != 0)
    {
        fprintf(stderr, "Failed to load BPF object\n");
        return EXIT_FAILURE;
    }

    err = init_perf_event_handler();
    if (err != EXIT_SUCCESS)
        return err;
    
    err = init_perf_event_map();
    if (err != EXIT_SUCCESS)
        return err;

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
