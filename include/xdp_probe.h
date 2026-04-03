/**
 * @file xdp_probe.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef PROBE_H
#define PROBE_H

#include <unistd.h>

#include "shared.h"

typedef int (*buffer_callback_t)(void* context, void* data, size_t size);

void xdp_probe__init();

void xdp_probe__destroy();

void xdp_probe__attach(
	const char* interface_name);

void xdp_probe__init_buffer(
		buffer_callback_t callback,
		void* context);

void xdp_probe__flush_buffer();

void xdp_probe__destroy_buffer();

size_t xdp_probe__available_buffer_size();

size_t xdp_probe__buffer_size();

size_t xdp_probe__get_total_packets_received();

size_t xdp_probe__get_total_rx_bytes_received();

#endif
