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

static struct ebpf_probe_data_bpf*  bpf;
static struct ebpf_probe_per_core_iterator_bpf** per_core_iterator_bpfs; 
static struct ebpf_probe_per_rapl_domain_iterator_bpf** per_rapl_domain_iterator_bpfs;
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

static const char* rapl_domain_names[] = {
	[RAPL_PKG]    = "pkg",
	[RAPL_CORE]   = "cores",
	[RAPL_UNCORE] = "uncore",
	[RAPL_DRAM]   = "ram",
	[RAPL_PSYS]   = "psys",
};

static inline int
read_rapl_type()
{
	FILE* file;
	int type = -1;

	file = fopen("/sys/bus/event_source/devices/power/type", "r");
	if (!file)
		return -1;
	
	if (fscanf(file, "%d", &type) != 1)
	{
		fclose(file);
		return -1;
	}

	fclose(file);
	return type;
}

static inline int
read_rapl_config(
        const char* domain)
{
	char path[256];
	FILE* file;
	int config = -1;
	char buffer[64];

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/power/events/energy-%s", domain);
	file = fopen(path, "r");
	if (!file)
		return -1;

	// Parse "event=0xXX" format (hexadecimal)
	if (fgets(buffer, sizeof(buffer), file))
	{
		if (sscanf(buffer, "event=%i", &config) != 1)
		{
			// Try parsing as hex if decimal fails
			sscanf(buffer, "event=0x%x", &config);
		}
	}

	fclose(file);
	return config;
}

static inline error_t
ebpf_probe__init_rapl_map()
{
    assert(bpf != nullptr);
    assert(num_cpus != 0);

    fd_t rapl_map_fd = bpf_map__fd(bpf->maps.rapl_map);

    for (size_t rapl_domain_idx = 0; rapl_domain_idx < RAPL_DOMAINS_MAX; rapl_domain_idx++)
    {
        struct perf_event_attr rapl_event = {};
        rapl_event.type = read_rapl_type();
        rapl_event.size = sizeof(struct perf_event_attr);
        rapl_event.config = read_rapl_config(rapl_domain_names[rapl_domain_idx]);

        fd_t rapl_event_fd = syscall(
            __NR_perf_event_open, &rapl_event, -1, 0, -1, 0);
        if (rapl_event_fd < 0)
        {
            fprintf(stderr, "Failed to get file descriptor for rapl domain '%s', likely not available on this system\n",
                rapl_domain_names[rapl_domain_idx]);
            continue;
        }

        __u32 key = rapl_domain_idx;
        bpf_map_update_elem(rapl_map_fd, &key, &rapl_event_fd, BPF_ANY);
    }

    return EXIT_SUCCESS;
}

static inline error_t
ebpf_probe__init_perf_event_map()
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
                continue;
            }
            
            __u32 key = (cpu_idx * NUM_EVENT_TYPES) + perf_event_idx;
            bpf_map_update_elem(perf_event_map_fd, &key, &perf_event_fd, BPF_ANY);
        }
    }

    return EXIT_SUCCESS;
}

/**
 * @brief Attach the 'perf_event_handler' program to the perf software CPU clock
 * 
 * @return error_t 
 */
static inline error_t
ebpf_probe__init_perf_event_handler()
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

        close(timer_fd);
    }

    return EXIT_SUCCESS;
}

static inline void
ebpf_probe__create_directories()
{
    mkdir("/sys/fs/bpf/ebpf_probe", 0x700);
    mkdir("/sys/fs/bpf/ebpf_probe/core", 0x700);
    mkdir("/sys/fs/bpf/ebpf_probe/rapl", 0x700);
}

static inline void
ebpf_probe__remove_directories()
{
    rmdir("/sys/fs/bpf/ebpf_probe/core");
    rmdir("/sys/fs/bpf/ebpf_probe/rapl");
    rmdir("/sys/fs/bpf/ebpf_probe");
}

static inline void
ebpf_probe__remove_core_files()
{
    for (size_t cpu_idx = 0; cpu_idx < num_cpus; cpu_idx++)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/core/%ld", cpu_idx);
        unlink(file_path);
    }
}


static inline void
ebpf_probe__remove_rapl_files()
{
    for (size_t domain_idx = 0; domain_idx < RAPL_DOMAINS_MAX; domain_idx++)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/rapl/%s", rapl_domain_names[domain_idx]);
        unlink(file_path);
    }
}

static inline error_t
ebpf_probe__init_per_core_iterators()
{
    assert(bpf != nullptr);
    assert(num_cpus != 0);

    per_core_iterator_bpfs = (ebpf_probe_per_core_iterator_bpf**)malloc(num_cpus * sizeof(ebpf_probe_per_core_iterator_bpf*));

    for (size_t cpu_idx = 0; cpu_idx < num_cpus; cpu_idx++)
    {
        per_core_iterator_bpfs[cpu_idx] = ebpf_probe_per_core_iterator_bpf::open();
        struct ebpf_probe_per_core_iterator_bpf* iterator_bpf = per_core_iterator_bpfs[cpu_idx];

        if (iterator_bpf == nullptr)
        {
            fprintf(stderr, "Failed to open iterator BPF object for core %ld\n", cpu_idx);
            perror("");
            return EXIT_FAILURE;
        }

        bpf_map__reuse_fd(iterator_bpf->maps.perf_event_map,     bpf_map__fd(bpf->maps.perf_event_map));
        bpf_map__reuse_fd(iterator_bpf->maps.rapl_map,           bpf_map__fd(bpf->maps.rapl_map));
        bpf_map__reuse_fd(iterator_bpf->maps.per_core_stats_map, bpf_map__fd(bpf->maps.per_core_stats_map));

        iterator_bpf->rodata->target_cpu_idx = (uint32_t)cpu_idx;

        if (ebpf_probe_per_core_iterator_bpf::load(iterator_bpf) != 0)
        {
            fprintf(stderr, "Failed to load iterator BPF object for core %ld\n", cpu_idx);
            perror("");
            return EXIT_FAILURE;
        }

        union bpf_iter_link_info linfo = {};
        linfo.map.map_fd = (uint32_t)bpf_map__fd(bpf->maps.per_core_stats_map);

        LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
            .link_info     = &linfo,
            .link_info_len = sizeof(linfo),
        );

        struct bpf_link* link = bpf_program__attach_iter(
            iterator_bpf->progs.dump_counters, &attach_opts);
        if (link == nullptr)
        {
            fprintf(stderr, "Failed to attach iterator for core %ld\n", cpu_idx);
            perror("");
            return EXIT_FAILURE;
        }

        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/core/%ld", cpu_idx);

        if (bpf_link__pin(link, file_path) != 0)
        {
            fprintf(stderr, "Failed to pin iterator link for core %ld\n", cpu_idx);
            perror("");
            bpf_link__destroy(link);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static inline error_t
ebpf_probe__init_per_rapl_domain_iterators()
{
    assert(bpf != nullptr);

    per_rapl_domain_iterator_bpfs = (ebpf_probe_per_rapl_domain_iterator_bpf**)malloc(RAPL_DOMAINS_MAX * sizeof(ebpf_probe_per_rapl_domain_iterator_bpf*));

    for (size_t domain_idx = 0; domain_idx < RAPL_DOMAINS_MAX; domain_idx++)
    {
        per_rapl_domain_iterator_bpfs[domain_idx] = ebpf_probe_per_rapl_domain_iterator_bpf::open();
        struct ebpf_probe_per_rapl_domain_iterator_bpf* iterator_bpf = per_rapl_domain_iterator_bpfs[domain_idx];

        if (iterator_bpf == nullptr)
        {
            fprintf(stderr, "Failed to open iterator BPF object for domain %ld\n", domain_idx);
            perror("");
            return EXIT_FAILURE;
        }

        bpf_map__reuse_fd(iterator_bpf->maps.per_rapl_domain_stats_map, bpf_map__fd(bpf->maps.per_rapl_domain_stats_map));

        iterator_bpf->rodata->target_rapl_domain_idx = (uint32_t)domain_idx;

        if (ebpf_probe_per_rapl_domain_iterator_bpf::load(iterator_bpf) != 0)
        {
            fprintf(stderr, "Failed to load iterator BPF object for domain %ld\n", domain_idx);
            perror("");
            return EXIT_FAILURE;
        }

        union bpf_iter_link_info linfo = {};
        linfo.map.map_fd = (uint32_t)bpf_map__fd(bpf->maps.per_rapl_domain_stats_map);

        LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
            .link_info     = &linfo,
            .link_info_len = sizeof(linfo),
        );

        struct bpf_link* link = bpf_program__attach_iter(
            iterator_bpf->progs.dump_counters, &attach_opts);
        if (link == nullptr)
        {
            fprintf(stderr, "Failed to attach iterator for domain %ld\n", domain_idx);
            perror("");
            return EXIT_FAILURE;
        }

        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/rapl/%s", rapl_domain_names[domain_idx]);

        if (bpf_link__pin(link, file_path) != 0)
        {
            fprintf(stderr, "Failed to pin iterator link for domain %ld\n", domain_idx);
            perror("");
            bpf_link__destroy(link);
            return EXIT_FAILURE;
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

    bpf = ebpf_probe_data_bpf::open();
    if (bpf == nullptr)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    bpf_map__set_max_entries(bpf->maps.perf_event_map, num_cpus * NUM_EVENT_TYPES);

    if (ebpf_probe_data_bpf::load(bpf) != 0)
    {
        fprintf(stderr, "Failed to load BPF object\n");
        return EXIT_FAILURE;
    }

    ebpf_probe__create_directories();

    err = ebpf_probe__init_perf_event_handler();
    if (err != EXIT_SUCCESS)
        return err;
    
    err = ebpf_probe__init_perf_event_map();
    if (err != EXIT_SUCCESS)
        return err;
    
    err = ebpf_probe__init_rapl_map();
    if (err != EXIT_SUCCESS)
        return err;
    
    err = ebpf_probe__init_per_core_iterators();
    if (err != EXIT_SUCCESS)
        return err;
    
    err = ebpf_probe__init_per_rapl_domain_iterators();
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

    ebpf_probe_data_bpf::destroy(bpf);

    ebpf_probe__remove_core_files();
    ebpf_probe__remove_rapl_files();
    ebpf_probe__remove_directories();

    return EXIT_SUCCESS;
}
