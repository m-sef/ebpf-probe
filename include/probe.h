#ifndef PROBE_H
#define PROBE_H

#include <unistd.h>

#include "shared.h"

typedef struct probe probe_t;
typedef struct probe_config probe_config_t;
typedef int (*buffer_callback_t)(void* context, void* data, size_t size);

probe_t* probe__init();

void probe__destroy(
		probe_t* probe);

void probe__attach_xdp(
		probe_t* probe,
		const char* interface_name);

void probe__init_buffer(
		probe_t* probe,
		buffer_callback_t callback,
		void* context);

void probe__flush_buffer(
		probe_t* probe);

void probe__destroy_buffer(
		probe_t* probe);

size_t probe__available_buffer_size(
		probe_t* probe);

size_t probe__buffer_size(
		probe_t* probe);

void probe__init_perf_event(
		probe_t* probe);

uint64_t probe__read_perf_event(
		probe_t* probe);

#endif
