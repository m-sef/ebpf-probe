/**
 * @file userspace_loader.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef PROBE_H
#define PROBE_H

#include <unistd.h>
#include <errno.h>
#include <string>

#include "definitions.hpp"

namespace ebpf_probe
{
    error_t init();
    error_t destroy();

    error_t attach_xdp(const std::string& interface_name);

    size_t get_total_packets_received();
    size_t get_total_rx_bytes_received();
}

#endif
