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
#include "definitions.hpp"
#include "bpf_definitions.h"
#include "userspace_loader.hpp"

#define ROOT_PRIVILEGES 0

#define FOREACH_CPU(i) for (size_t i = 0; i < _cpu_count; i++)
#define FOREACH_RAPL_DOMAIN(i) for (size_t i = 0; i < RAPL_DOMAINS_MAX; i++)

UserspaceLoader::UserspaceLoader(
        const struct options& options)
    : _options(options)
    , _cpu_count(libbpf_num_possible_cpus())
    , _data(_options, _cpu_count)
{
    _core_iterators.reserve(_cpu_count);
    FOREACH_CPU(cpu)
        _core_iterators.emplace_back(_options, cpu);
    
    _rapl_iterators.reserve(RAPL_DOMAINS_MAX);
    FOREACH_RAPL_DOMAIN(domain)
        _rapl_iterators.emplace_back(_options, domain);
}

UserspaceLoader::~UserspaceLoader()
{
    _remove_sys_directories();
}

void UserspaceLoader::init()
{
    if (getuid() != ROOT_PRIVILEGES)
        ERROR("Program must be run with root privileges");
    
    _create_sys_directories();

    _data.init();

    FOREACH_CPU(cpu)
        _core_iterators[cpu].init();
    
    FOREACH_RAPL_DOMAIN(domain)
        _rapl_iterators[domain].init();

    /* _data_bpf = data_bpf::open();
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

    FOREACH_CPU(cpu_idx)
        _init_core(cpu_idx);

    _init_rapl_event_map();
    _init_rapl_iterators();

    _attach_xdp(_options.interface_name);
    _attach_tcx(_options.interface_name);
    _attach_timer(_options.sample_frequency);

    */

    INFO("eBPF Probe is now running");
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
            WARNING("Failed to make directory {}, already exists.", directory_path);
            break;
        
        case EACCES:
            ERROR("Failed to make directory {}, permission denied.", directory_path);
            exit(EXIT_FAILURE);
        
        case ENOENT:
            ERROR("Failed to make directory {}, parent directory does not exist.", directory_path);
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

/*
void UserspaceLoader::_remove_rapl_files()
{
    FOREACH_RAPL_DOMAIN(domain_idx)
    {
        char file_path[64];
        snprintf(file_path, sizeof(file_path), "/sys/fs/bpf/ebpf_probe/rapl/%s", rapl_domain_names[domain_idx]);
        unlink(file_path);
    }
}
*/

/*
bool UserspaceLoader::_is_core_online(size_t cpu_idx)
{
    char path[64];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/online", cpu_idx);
    FILE* file = fopen(path, "r");
    if (!file)
    {
        // All CPUs, with the exception of cpu 0, have an 'online' file
        return true;
    }
    
    int value = 0;
    if (fscanf(file, "%d", &value) != 1)
    {
        fclose(file);
        return false;
    }

    fclose(file);
    return (value == 1);
}
*/

/*
void UserspaceLoader::_init_core(size_t cpu_idx)
{
    // If a core is offline, warn the user and move on
    if (!_is_core_online(cpu_idx))
    {
        WARNINGV(_options, "CPU %ld is offline\n", cpu_idx);
        return;
    }

    // Populate the BPF map which stores perf file descriptors
    _init_perf_event_map_for_core(cpu_idx);

    // Create files under the /sys/fs/bpf/ebpf_probe/core directory and attach Their associated iterators
    _init_iterator_for_core(cpu_idx);
}
*/

void UserspaceLoader::_init_iterator_for_core(size_t cpu_idx)
{
    _core_iterator_bpfs = std::vector<struct core_iterator_bpf*>(_cpu_count);
    _core_iterator_bpfs[cpu_idx] = core_iterator_bpf::open();

    struct core_iterator_bpf* iterator_bpf = _core_iterator_bpfs[cpu_idx];

    if (iterator_bpf == nullptr)
    {
        ERROR("Failed to open iterator BPF object for core %ld\n", cpu_idx);
        exit(EXIT_FAILURE);
    }

    //bpf_map__reuse_fd(iterator_bpf->maps.core_stats_map, bpf_map__fd(_data_bpf->maps.core_stats_map));

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

    INFOV(_options, "Successfully initialized iterator for core %ld\n", cpu_idx);
}

/*
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

        //bpf_map__reuse_fd(iterator_bpf->maps.rapl_stats_map, bpf_map__fd(_data_bpf->maps.rapl_stats_map));

        iterator_bpf->rodata->target_rapl_domain_idx = (uint32_t)domain_idx;
        iterator_bpf->rodata->verbose                = _options.verbose;
        strncpy(iterator_bpf->rodata->rapl_domain_name, rapl_domain_names[domain_idx], sizeof(iterator_bpf->rodata->rapl_domain_name) - 1);
        read_rapl_unit(rapl_domain_names[domain_idx], iterator_bpf->rodata->unit, sizeof(iterator_bpf->rodata->unit));
        read_rapl_scale(rapl_domain_names[domain_idx], iterator_bpf->rodata->scale, sizeof(iterator_bpf->rodata->scale));

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
*/