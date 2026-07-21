#include "generated/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define UNSPECIFIED_MAX_ENTRIES 0 /* Map is a variable-length array; expected to be resized at runtime */

struct interface_value {
    __u64 rx_packets; /* Total received packets */
    __u64 rx_bytes;   /* Total received bytes */
    __u64 tx_packets; /* Total transmitted packets */
    __u64 tx_bytes;   /* Total transmitted bytes */
};

struct timer {
    struct bpf_timer timer;
};

typedef int fd_t;

/* List of perf events to be updated by eBPF Probe, supplied via the CLI */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, size_t);
} perf_events_cli;

/* Stores file descriptors for perf events.
   Indexed by 'event' */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, fd_t);
} perf_event_fds SEC(".maps");

/* List of RAPL domains to be updated by eBPF Probe, supplied via the CLI */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, size_t);
} rapl_events_cli;

/* Stores file descriptors for RAPL counters.
   Indexed by RAPL domain */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 5);
    __type(key, size_t);
    __type(value, fd_t);
} rapl_event_fds SEC(".maps");

/* Per-CPU timers for sample_cpus_callback. 
   Each one should be pinned to a physical CPU */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, size_t);
    __type(value, struct timer);
} sample_cpus_timers SEC(".maps");

/* Timer for sample_rapl_callback. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, size_t);
    __type(value, struct timer);
} sample_rapl_timer SEC(".maps");

/* Map of per-interface counters across all CPUs.
   Indexed by ifindex */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, struct interface_value);
} interface_values SEC(".maps");

/* Map of per-event counters across all CPUs.
   Indexed by 'event' */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, struct bpf_perf_event_value);
} perf_values SEC(".maps");

/* Map of per-domain RAPL counters.
   Indexed by RAPL domain */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNSPECIFIED_MAX_ENTRIES);
    __type(key, size_t);
    __type(value, struct bpf_perf_event_value);
} rapl_values SEC(".maps");

static __always_inline void
increment_interface_rx_values(
        size_t ifindex,
        __u64 rx_packets,
        __u64 rx_bytes)
{
    struct interface_value* value_ptr = bpf_map_lookup_elem(&interface_values, &ifindex);
    if (value_ptr == NULL)
        return;
    
    value_ptr->rx_packets += rx_packets;
    value_ptr->rx_bytes   += rx_bytes;
}

static __always_inline void
increment_interface_tx_values(
        size_t ifindex,
        __u64 tx_packets,
        __u64 tx_bytes)
{
    struct interface_value* value_ptr = bpf_map_lookup_elem(&interface_values, &ifindex);
    if (value_ptr == NULL)
        return;
    
    value_ptr->tx_packets += tx_packets;
    value_ptr->tx_bytes   += tx_bytes;
}

SEC("xdp")
int xdp_ingress(struct xdp_md* context)
{
    void* data     = (void*)context->data;
    void* data_end = (void*)context->data_end;

    increment_interface_rx_values(context->ingress_ifindex, 1, data_end - data);

    return XDP_PASS;
}

SEC("tcx/egress")
int tcx_egress(struct __sk_buff* context)
{
    void* data     = (void*)context->data;
    void* data_end = (void*)context->data_end;

    increment_interface_tx_values(context->ifindex, 1, data_end - data);

    return TCX_PASS;
}

static __always_inline void
update_perf_event_values(
        size_t event)
{
    size_t key = bpf_get_smp_processor_id();
    bpf_perf_event_read_value(&perf_events_fd, &key, )
}

static int
sample_cpus_callback(
        void*   map,
        size_t* key,
        struct bpf_timer* timer)
{
    return 0;
}

static __always_inline void
update_rapl_event_values()
{

}

static int
sample_rapl_callback(
        void*   map,
        size_t* key,
        struct bpf_timer* timer)
{
    return 0;
}

SEC("syscall")
int probe_cpus_init(void* context)
{
    return 0;
}

SEC("syscall")
int probe_rapl_init(void* context)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";