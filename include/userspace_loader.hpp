/**
 * @file userspace_loader.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef USERSPACE_LOADER_H
#define USERSPACE_LOADER_H

#include <string>
#include <vector>
#include <memory>

#include "data.skel.h"
#include "core_iterator.skel.h"
#include "rapl_iterator.skel.h"
#include "definitions.hpp"

class UserspaceLoader
{
public:
    UserspaceLoader(const struct options& options);
    ~UserspaceLoader();

    void init();

    UserspaceLoader(const UserspaceLoader& other) = delete;
    UserspaceLoader& operator=(const UserspaceLoader& other) = delete;
    UserspaceLoader(UserspaceLoader&& other) = delete;
    UserspaceLoader& operator=(UserspaceLoader&& other) = delete;
private:
    void _create_sys_directories();
    void _remove_sys_directories();
    void _remove_core_files();
    void _remove_rapl_files();

    void _attach_xdp(const std::string& interface_name);
    void _attach_tcx(const std::string& interface_name);
    void _attach_timer(int sample_frequency);

    bool _is_core_online(size_t cpu_idx);
    void _init_core(size_t cpu_idx);
    void _init_perf_event_map_for_core(size_t cpu_idx);
    void _init_iterator_for_core(size_t cpu_idx);

    void _init_rapl_event_map();
    void _init_rapl_iterators();

    const struct options _options;
    const __u32 _cpu_count;

    struct data_bpf* _data_bpf;
    std::vector<struct core_iterator_bpf*> _core_iterator_bpfs;
    std::vector<struct rapl_iterator_bpf*> _rapl_iterator_bpfs;

    std::vector<bpf_link*> _timer_links;
    std::vector<bpf_link*> _core_iterator_links;
    std::vector<bpf_link*> _rapl_iterator_links;
};

#endif
