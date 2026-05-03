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

namespace ebpf_probe
{
    error_t init(const struct options& opt);
    error_t destroy();

    error_t attach_xdp(const std::string& interface_name);

    size_t get_total_packets_received();
    size_t get_total_rx_bytes_received();
}

#endif
