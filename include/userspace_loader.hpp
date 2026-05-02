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
#include "ebpf_probe_iter.skel.h"
#include "definitions.hpp"

namespace ebpf_probe
{
    error_t init();
    error_t destroy();

    error_t attach_xdp(const std::string& interface_name);

    error_t set_verbose(bool verbose);

    size_t get_total_packets_received();
    size_t get_total_rx_bytes_received();
}

class UserspaceLoader {
protected:
    UserspaceLoader();
public:
    UserspaceLoader(UserspaceLoader& other) = delete;
    void operator=(const UserspaceLoader& other) = delete;

    void attach_xdp(const std::string& interface_name);
private:
    void _share_map_file_descriptors();
    void _init_iterators();
    void _link_iterators();

    void _init_bpf_data_rapl_map();
    void _init_bpf_data_perf_event_map();
    void _init_bpf_data_perf_event_handler();

    void _create_directories();
    void _create_core_files();

    void _remove_directories();
    void _remove_core_files();

    const uint32_t _cpu_count;
    std::unique_ptr<struct ebpf_probe_data_bpf, decltype(&ebpf_probe_data_bpf::destroy)> _data_bpf;
    std::vector<std::unique_ptr<struct ebpf_probe_iter_bpf, decltype(&ebpf_probe_iter_bpf::destroy)>> _iter_bpf;
    std::vector<std::unique_ptr<struct bpf_link*, decltype(&bpf_link__destroy)>> _perf_timer_links;
};

//UserspaceLoader userspace_loader;

#endif
