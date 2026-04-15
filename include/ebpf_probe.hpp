/**
 * @file ebpf_probe.h
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

    //void init_buffer(buffer_callback_t callback, void* context);
    //void flush_buffer();
    //void destroy_buffer();

    //size_t available_buffer_size();
    //size_t buffer_size();

    size_t get_total_packets_received();
    size_t get_total_rx_bytes_received();
}

#endif
