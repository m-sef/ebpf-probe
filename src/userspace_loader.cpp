/**
 * @file userspace_loader.cpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf_probe_data.skel.h"
#include "ebpf_probe_per_core_iterator.skel.h"
#include "ebpf_probe_per_rapl_domain_iterator.skel.h"
#include "userspace_loader.hpp"
#include "definitions.hpp"
#include "bpf_definitions.h"

#define ROOT_PRIVILEGES 0

#define FOREACH_CORE(i, n) for (size_t i = 0; i < n; i++)
#define FOREACH_PERF_EVENT(i, n) for (size_t i = 0; i < n; i++)
#define FOREACH_RAPL_DOMAIN(i, n) for (size_t i = 0; i < n; i++)

/*static struct perf_event_attr perf_events[] = {
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
}; */

static const char* rapl_domain_names[] = {
	[RAPL_PKG]    = "pkg",
	[RAPL_CORE]   = "cores",
	[RAPL_UNCORE] = "uncore",
	[RAPL_DRAM]   = "ram",
	[RAPL_PSYS]   = "psys",
};

UserspaceLoader::UserspaceLoader(
        const struct options& options)
{
    _options   = options;
    _cpu_count = libbpf_num_possible_cpus();

    if (getuid() != ROOT_PRIVILEGES)
    {
        ERROR("Program must be run with root privileges\n");
        exit(EXIT_FAILURE);
    }

    _data_bpf = ebpf_probe_data_bpf::open();
    if (_data_bpf == nullptr)
    {
        ERROR("Failed to open BPF object\n");
        exit(EXIT_FAILURE);
    }

    bpf_map__set_max_entries(_data_bpf->maps.perf_event_map, _cpu_count * NUM_EVENT_TYPES);

    if (ebpf_probe_data_bpf::load(_data_bpf) != 0)
    {
        ERROR("Failed to load BPF object\n");
        exit(EXIT_FAILURE);
    }

    _attach_xdp(_options.interface_name);
    _attach_timer(_options.sample_frequency);

    _create_sys_directories();
    _create_core_files();
    _create_rapl_files();

    _init_perf_event_map();
    _init_rapl_map();

    _init_per_core_iterators();
    _init_per_rapl_domain_iterators();
}

UserspaceLoader::~UserspaceLoader()
{
    ebpf_probe_data_bpf::destroy(_data_bpf);

    _remove_core_files();
    _remove_rapl_files();
    _remove_sys_directories();
}

void UserspaceLoader::_create_sys_directories()
{
    mkdir("/sys/fs/bpf/ebpf_probe", 0x700);
    mkdir("/sys/fs/bpf/ebpf_probe/core", 0x700);
    mkdir("/sys/fs/bpf/ebpf_probe/rapl", 0x700);
}

void UserspaceLoader::_create_core_files()
{

}

void UserspaceLoader::_create_rapl_files()
{

}

void UserspaceLoader::_remove_sys_directories()
{
    rmdir("/sys/fs/bpf/ebpf_probe/core");
    rmdir("/sys/fs/bpf/ebpf_probe/rapl");
    rmdir("/sys/fs/bpf/ebpf_probe");
}

void UserspaceLoader::_remove_core_files()
{
    FOREACH_CORE(cpu_idx, _cpu_count)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/core/%ld", cpu_idx);
        unlink(file_path);
    }
}

void UserspaceLoader::_remove_rapl_files()
{
    FOREACH_RAPL_DOMAIN(domain_idx, RAPL_DOMAINS_MAX)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/rapl/%s", rapl_domain_names[domain_idx]);
        unlink(file_path);
    }
}

void UserspaceLoader::_attach_xdp(const std::string& interface_name)
{
    unsigned int interface_index = if_nametoindex(interface_name.c_str());
    if (!interface_index)
    {
        ERROR("Could not find interface \"%s\"\n", interface_name.c_str());
        exit(EXIT_FAILURE);
    }

    _data_bpf->links.xdp_probe = bpf_program__attach_xdp(_data_bpf->progs.xdp_probe, interface_index);
    if (!_data_bpf->links.xdp_probe)
    {
        ERROR("Failed to attach BPF program to XDP hook\n");
        exit(EXIT_FAILURE);
    }
}

void UserspaceLoader::_attach_timer(int sample_frequency)
{
    /* Attaches the Software CPU Clock perf event to the bpf program 'perf_event_handler' */
    FOREACH_CORE(cpu_idx, _cpu_count)
    {
        struct perf_event_attr timer = {};
        timer.type        = PERF_TYPE_SOFTWARE;
        timer.config      = PERF_COUNT_SW_CPU_CLOCK;
        timer.sample_freq = sample_frequency;
        timer.freq        = sample_frequency;
        
        fd_t timer_fd = syscall(SYS_perf_event_open, &timer, -1, cpu_idx, -1, 0);
        if (timer_fd < 0)
        {
            ERROR("Failed to get file descriptor for PERF_COUNT_SW_CPU_CLOCK\n");
            exit(EXIT_FAILURE);
        }
        
        struct bpf_link* link = bpf_program__attach_perf_event(
            _data_bpf->progs.timer, timer_fd);
        if (!link)
        {
            ERROR("Failed to attach BPF program to perf hook\n");
            exit(EXIT_FAILURE);
        }

        close(timer_fd);
    }
}

void UserspaceLoader::_init_perf_event_map()
{

}

void UserspaceLoader::_init_rapl_map()
{

}

void UserspaceLoader::_init_per_core_iterators()
{

}

void UserspaceLoader::_init_per_rapl_domain_iterators()
{

}