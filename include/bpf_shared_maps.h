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

/* Perf events */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1); /* Set at run time to num_cpus * NUM_EVENT_TYPES */
    __type(key, __u32);
    __type(value, fd_t);
} perf_event_map SEC(".maps");

/* RAPL */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 5); /* Only storing file descriptors relating to 5 RAPL domains */
    __type(key, __u32);
    __type(value, fd_t);
} rapl_map SEC(".maps");

/* Core */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct core_stats);
} per_core_stats_map SEC(".maps");

/* Domain */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, struct domain_stats);
} per_rapl_domain_stats_map SEC(".maps");


#endif