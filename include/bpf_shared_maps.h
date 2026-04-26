/**
 * @file bpf_shared_maps.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef BPF_SHARED_MAPS_H
#define BPF_SHARED_MAPS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <bpf_definitions.h>

/* Networking metrics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} packet_information_buffer_size SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1 << 10);
    __type(key, __u32);
    __type(value, struct packet_information);
} packet_information_buffer SEC(".maps");

/* Perf events */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1); /* Set at run time to num_cpus * NUM_EVENT_TYPES */
    __type(key, __u32);
    __type(value, fd_t);
} perf_event_map SEC(".maps");

/* RAPL */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5); /* Only storing file descriptors relating to 5 RAPL domains */
    __type(key, __u32);
    __type(value, fd_t);
} rapl_map SEC(".maps");

/* Core */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct core_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} core_map SEC(".maps");


#endif