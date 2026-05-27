/**
 * @file userspace_loader.cpp
 * @author Seth Moore (slmoore@hamilton.edu)
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

#include "data.skel.h"
#include "core_iterator.skel.h"
#include "rapl_iterator.skel.h"
#include "rapl_helpers.hpp"
#include "definitions.hpp"
#include "bpf_definitions.h"
#include "userspace_loader.hpp"

#define ROOT_PRIVILEGES 0

#define FOREACH_CPU(i) for (size_t i = 0; i < _cpu_count; i++)
#define FOREACH_PERF_EVENT(i) for (size_t i = 0; i < NUM_EVENT_TYPES; i++)
#define FOREACH_RAPL_DOMAIN(i) for (size_t i = 0; i < RAPL_DOMAINS_MAX; i++)

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

UserspaceLoader::UserspaceLoader(
        const struct options& options)
    : _options(options)
    , _cpu_count(libbpf_num_possible_cpus())
{

}

UserspaceLoader::~UserspaceLoader()
{
    for (bpf_link* link : _timer_links)
        bpf_link__destroy(link);

    for (bpf_link* link : _core_iterator_links)
        bpf_link__destroy(link);
    
    for (bpf_link* link : _rapl_iterator_links)
        bpf_link__destroy(link);

    data_bpf::destroy(_data_bpf);
    
    for (core_iterator_bpf* skeleton : _core_iterator_bpfs)
        core_iterator_bpf::destroy(skeleton);
    
    for (rapl_iterator_bpf* skeleton : _rapl_iterator_bpfs)
        rapl_iterator_bpf::destroy(skeleton);

    _remove_core_files();
    _remove_rapl_files();
    _remove_sys_directories();
}

void UserspaceLoader::init()
{
    if (getuid() != ROOT_PRIVILEGES)
    {
        ERROR("Program must be run with root privileges\n");
        exit(EXIT_FAILURE);
    }

    _data_bpf = data_bpf::open();
    if (_data_bpf == nullptr)
    {
        ERROR("Failed to open BPF object\n");
        exit(EXIT_FAILURE);
    }

    bpf_map__set_max_entries(_data_bpf->maps.perf_event_map, _cpu_count * NUM_EVENT_TYPES);

    if (data_bpf::load(_data_bpf) != 0)
    {
        ERROR("Failed to load BPF object\n");
        exit(EXIT_FAILURE);
    }

    _create_sys_directories();

    _init_perf_event_map();
    _init_rapl_event_map();

    _init_core_iterators();
    _init_rapl_iterators();

    _attach_xdp(_options.interface_name);
    _attach_timer(_options.sample_frequency);

    INFO("ebpf-probe started successfully\n");
}

static inline void
make_directory(
        const std::string& directory_path, 
        mode_t mode)
{
    if (mkdir(directory_path.c_str(), mode) == -1)
    {
        switch (errno)
        {
        case EEXIST:
            WARNING("Failed to make directory %s, already exists.\n", directory_path.c_str());
            break;
        
        case EACCES:
            ERROR("Failed to make directory %s, permission denied.\n", directory_path.c_str());
            exit(EXIT_FAILURE);
        
        case ENOENT:
            ERROR("Failed to make directory %s, parent directory does not exist.\n", directory_path.c_str());
            exit(EXIT_FAILURE);
        
        default:
            perror("mkdir failed");
            exit(EXIT_FAILURE);
        }
    }
}

void UserspaceLoader::_create_sys_directories()
{
    make_directory("/sys/fs/bpf/ebpf_probe",      0x700);
    make_directory("/sys/fs/bpf/ebpf_probe/core", 0x700);
    make_directory("/sys/fs/bpf/ebpf_probe/rapl", 0x700);
}

void UserspaceLoader::_remove_sys_directories()
{
    rmdir("/sys/fs/bpf/ebpf_probe/core");
    rmdir("/sys/fs/bpf/ebpf_probe/rapl");
    rmdir("/sys/fs/bpf/ebpf_probe");
}

void UserspaceLoader::_remove_core_files()
{
    FOREACH_CPU(cpu_idx)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/core/%ld", cpu_idx);
        unlink(file_path);
    }
}

void UserspaceLoader::_remove_rapl_files()
{
    FOREACH_RAPL_DOMAIN(domain_idx)
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

static inline long
perf_event_open(
    struct perf_event_attr* hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);

    return ret;
}

void UserspaceLoader::_attach_timer(int sample_frequency)
{
    /* Attaches the Software CPU Clock perf event to the bpf program 'perf_event_handler' */
    FOREACH_CPU(cpu_idx)
    {
        struct perf_event_attr timer = {};
        timer.type        = PERF_TYPE_SOFTWARE;
        timer.config      = PERF_COUNT_SW_CPU_CLOCK;
        timer.sample_freq = sample_frequency;
        timer.freq        = 1;
        
        fd_t timer_fd = perf_event_open(&timer, -1, cpu_idx, -1, 0);
        if (timer_fd < 0)
        {
            if (errno == ENODEV)
            {
                WARNING("CPU %ld is offline, skipping timer attachment\n", cpu_idx);
                continue;
            }

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

        _timer_links.push_back(link);
        close(timer_fd);
    }
}

void UserspaceLoader::_init_perf_event_map()
{
    fd_t perf_event_map_fd = bpf_map__fd(_data_bpf->maps.perf_event_map);

    /* Add the file descriptors for each perf_event to the BPF program's perf_event_map */
    FOREACH_PERF_EVENT(perf_event_idx)
    {
        FOREACH_CPU(cpu_idx)
        {
            fd_t perf_event_fd = perf_event_open(&perf_events[perf_event_idx], -1, cpu_idx, -1, 0);
            if (perf_event_fd < 0)
            {
                WARNING("Failed to get file descriptor for perf event '%s' on core %ld, likely not available on this system\n",
                    perf_event_names[perf_event_idx], cpu_idx);
                continue;
            }
            
            __u32 key = (cpu_idx * NUM_EVENT_TYPES) + perf_event_idx;
            bpf_map_update_elem(perf_event_map_fd, &key, &perf_event_fd, BPF_ANY);

            close(perf_event_fd);
        }
    }
}

void UserspaceLoader::_init_rapl_event_map()
{
    fd_t rapl_map_fd = bpf_map__fd(_data_bpf->maps.rapl_event_map);

    int rapl_type = read_rapl_type();
    if (rapl_type < 0)
    {
        ERROR("RAPL is not available on this system\n");
        exit(EXIT_FAILURE);
    }

    FOREACH_RAPL_DOMAIN(domain_idx)
    {
        int rapl_config = read_rapl_config(rapl_domain_names[domain_idx]);
        if (rapl_config < 0)
        {
            WARNING("RAPL domain '%s' not found on this system\n",
                rapl_domain_names[domain_idx]);
            continue;
        }

        struct perf_event_attr rapl_event = {};
        rapl_event.type   = rapl_type;
        rapl_event.size   = sizeof(struct perf_event_attr);
        rapl_event.config = rapl_config;

        fd_t rapl_event_fd = perf_event_open(&rapl_event, -1, 0, -1, 0);
        if (rapl_event_fd < 0)
        {
            WARNING("Failed to get file descriptor for RAPL domain '%s'\n",
                rapl_domain_names[domain_idx]);
            continue;
        }

        __u32 key = domain_idx;
        bpf_map_update_elem(rapl_map_fd, &key, &rapl_event_fd, BPF_ANY);

        close(rapl_event_fd);
    }
}

void UserspaceLoader::_init_core_iterators()
{
    _core_iterator_bpfs = std::vector<struct core_iterator_bpf*>(_cpu_count);

    FOREACH_CPU(cpu_idx)
    {
        _core_iterator_bpfs[cpu_idx] = core_iterator_bpf::open();
        struct core_iterator_bpf* iterator_bpf = _core_iterator_bpfs[cpu_idx];

        if (iterator_bpf == nullptr)
        {
            ERROR("Failed to open iterator BPF object for core %ld\n", cpu_idx);
            exit(EXIT_FAILURE);
        }

        bpf_map__reuse_fd(iterator_bpf->maps.core_stats_map, bpf_map__fd(_data_bpf->maps.core_stats_map));

        iterator_bpf->rodata->target_cpu_idx = (uint32_t)cpu_idx;
        iterator_bpf->rodata->verbose        = _options.verbose;

        if (core_iterator_bpf::load(iterator_bpf) != 0)
        {
            ERROR("Failed to load iterator BPF object for core %ld\n", cpu_idx);
            exit(EXIT_FAILURE);
        }

        union bpf_iter_link_info linfo = {};
        linfo.map.map_fd = (uint32_t)bpf_map__fd(_data_bpf->maps.core_stats_map);

        LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
            .link_info     = &linfo,
            .link_info_len = sizeof(linfo),
        );

        struct bpf_link* link = bpf_program__attach_iter(
            iterator_bpf->progs.dump_counters, &attach_opts);
        if (link == nullptr)
        {
            ERROR("Failed to attach iterator for core %ld\n", cpu_idx);
            exit(EXIT_FAILURE);
        }

        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/core/%ld", cpu_idx);

        if (bpf_link__pin(link, file_path) != 0)
        {
            ERROR("Failed to pin iterator link for core %ld\n", cpu_idx);
            bpf_link__destroy(link);
            exit(EXIT_FAILURE);
        }

        _core_iterator_links.push_back(link);
    }
}

void UserspaceLoader::_init_rapl_iterators()
{
    _rapl_iterator_bpfs = std::vector<struct rapl_iterator_bpf*>(RAPL_DOMAINS_MAX);

    FOREACH_RAPL_DOMAIN(domain_idx)
    {
        _rapl_iterator_bpfs[domain_idx] = rapl_iterator_bpf::open();
        struct rapl_iterator_bpf* iterator_bpf = _rapl_iterator_bpfs[domain_idx];

        if (iterator_bpf == nullptr)
        {
            ERROR("Failed to open iterator BPF object for domain %ld\n", domain_idx);
            exit(EXIT_FAILURE);
        }

        bpf_map__reuse_fd(iterator_bpf->maps.rapl_stats_map, bpf_map__fd(_data_bpf->maps.rapl_stats_map));

        iterator_bpf->rodata->target_rapl_domain_idx = (uint32_t)domain_idx;
        iterator_bpf->rodata->verbose                = _options.verbose;

        if (rapl_iterator_bpf::load(iterator_bpf) != 0)
        {
            ERROR("Failed to load iterator BPF object for domain %ld\n", domain_idx);
            exit(EXIT_FAILURE);
        }

        union bpf_iter_link_info linfo = {};
        linfo.map.map_fd = (uint32_t)bpf_map__fd(_data_bpf->maps.rapl_stats_map);

        LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
            .link_info     = &linfo,
            .link_info_len = sizeof(linfo),
        );

        struct bpf_link* link = bpf_program__attach_iter(
            iterator_bpf->progs.dump_counters, &attach_opts);
        if (link == nullptr)
        {
            ERROR("Failed to attach iterator for domain %ld\n", domain_idx);
            exit(EXIT_FAILURE);
        }

        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/rapl/%s", rapl_domain_names[domain_idx]);

        if (bpf_link__pin(link, file_path) != 0)
        {
            ERROR("Failed to pin iterator link for domain %ld\n", domain_idx);
            bpf_link__destroy(link);
            exit(EXIT_FAILURE);
        }

        _rapl_iterator_links.push_back(link);
    }
}