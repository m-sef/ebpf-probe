/**
 * @file userspace_loader.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef PROBE_H
#define PROBE_H

#include <string>
#include <vector>
#include <memory>

#include "ebpf_probe_data.skel.h"
#include "ebpf_probe_per_core_iterator.skel.h"
#include "ebpf_probe_per_rapl_domain_iterator.skel.h"
#include "definitions.hpp"

class UserspaceLoader
{
protected:
public:
    UserspaceLoader(const struct options& options);
    ~UserspaceLoader();
private:
    void _create_sys_directories();
    void _create_core_files();
    void _create_rapl_files();

    void _remove_sys_directories();
    void _remove_core_files();
    void _remove_rapl_files();

    void _attach_xdp(const std::string& interface_name);
    void _attach_timer(int sample_frequency);

    void _init_perf_event_map();
    void _init_rapl_map();

    void _init_per_core_iterators();
    void _init_per_rapl_domain_iterators();

    struct options _options;
    __u32 _cpu_count;

    struct ebpf_probe_data_bpf*                      _data_bpf;
    //struct ebpf_probe_per_core_iterator_bpf**        _per_core_iterator_bpfs; 
    //struct ebpf_probe_per_rapl_domain_iterator_bpf** _per_rapl_domain_iterator_bpfs;
};

#endif
