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

#define FOREACH_CPU(cpu) for (unsigned int cpu = 0; cpu < _cpu_count; cpu++)
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

void
UserspaceLoader::init()
{
    if (getuid() != ROOT_PRIVILEGES)
        ERROR("Program must be run with root privileges");
    
    _create_sys_directories();

    _data.init();

    FOREACH_CPU(cpu)
        if (_is_core_online(cpu))
            _core_iterators[cpu].init();
    
    FOREACH_RAPL_DOMAIN(domain)
        _rapl_iterators[domain].init();

    INFO("eBPF Probe is now running. Data can be found under /sys/fs/bpf/ebpf_probe. CTRL+C to stop");
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

void
UserspaceLoader::_create_sys_directories()
{
    make_directory("/sys/fs/bpf/ebpf_probe",      0x700);
    make_directory("/sys/fs/bpf/ebpf_probe/core", 0x700);
    make_directory("/sys/fs/bpf/ebpf_probe/rapl", 0x700);
}

void
UserspaceLoader::_remove_sys_directories()
{
    rmdir("/sys/fs/bpf/ebpf_probe/core");
    rmdir("/sys/fs/bpf/ebpf_probe/rapl");
    rmdir("/sys/fs/bpf/ebpf_probe");
}

bool
UserspaceLoader::_is_core_online(
        unsigned int cpu)
{
    char path[64];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
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