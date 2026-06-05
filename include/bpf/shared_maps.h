/**
 * @file bpf_shared_maps.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef BPF_SHARED_MAPS_H
#define BPF_SHARED_MAPS_H

#include <bpf/bpf_helpers.h>

#include "bpf/definitions.h"

/* Stores file descriptors for perf events */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, NUM_EVENT_TYPES);
    __type(key, __u32);
    __type(value, fd_t);
} perf_event_map SEC(".maps");

/* Stores file descriptors for RAPL counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, fd_t);
} rapl_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 20);
    __type(key, unsigned int);
    __type(value, struct interface_stats);
} interface_stats_map SEC(".maps");

/* Updated by 'timer' bpf program */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct core_map_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} core_stats_map SEC(".maps");

struct {
    __uint(type,  BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, unsigned int);
    __type(value, struct bpf_perf_event_value);
} perf_event_stats_map SEC(".maps");

/* Updated by 'timer' bpf program, only updated on core 0 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, struct bpf_perf_event_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rapl_stats_map SEC(".maps");


#endif