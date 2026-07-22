#include "data_bpf.hpp"

#include <unordered_set>

#include <linux/perf_event.h>
#include <net/if.h>

#include "perf_event_open.h"
#include "perf_event_helpers.hpp"
#include "rapl_helpers.hpp"

#define FOREACH_CPU(i) for (size_t i = 0; i < _cpu_count; i++)
#define FOREACH_RAPL_DOMAIN(i) for (size_t i = 0; i < RAPL_DOMAINS_MAX; i++)

DataBPF::DataBPF(
        unsigned int cpu_count)
    : _cpu_count(cpu_count)
    , _bpf(nullptr, &data_bpf__destroy)
{

}

void
DataBPF::init()
{
    _bpf.reset(data_bpf__open());
    if (_bpf == nullptr)
        ERROR("Failed to open BPF object");
    
    bpf_map__set_max_entries(_bpf->maps.perf_event_map, _cpu_count * NUM_EVENT_TYPES);

    if (data_bpf::load(_bpf.get()) != 0)
        ERROR("Failed to load BPF object");
    
    for (const std::string& interface_name : options.interface)
    {
        _attach_xdp(interface_name);
        _attach_tcx(interface_name);
    }

    FOREACH_CPU(cpu_idx)
    {
        _populate_perf_event_map_for_cpu(cpu_idx);
        _attach_timer_for_cpu(options.frequency, cpu_idx);
    }

    _populate_rapl_event_map();

    INFOV("Initialized DataBPF object");
}

const std::unique_ptr<struct data_bpf, decltype(&data_bpf__destroy)>& DataBPF::bpf() const
{
    return _bpf;
}

void
DataBPF::_populate_perf_event_map() const
{
    FOREACH_CPU(cpu)
        _populate_perf_event_map_for_cpu(cpu);
}

void
DataBPF::_populate_perf_event_map_for_cpu(unsigned int cpu) const
{
    fd_t perf_event_map_fd = bpf_map__fd(_bpf->maps.perf_event_map);

    std::unordered_set<enum perf_events> active_perf_events = {
        INSTRUCTIONS, CPU_CYCLES, REF_CPU_CYCLES, CACHE_MISSES
    }; 

    FOREACH_PERF_EVENT(perf_event)
    {
        if (!active_perf_events.contains(static_cast<enum perf_events>(perf_event)))
            continue;
        
        /* Attempt to open file descriptor for perf event, if it is not available
           then warn the user. If it is available, add it to the BPF perf event map */
        fd_t perf_event_fd = perf_event_open(&perf_events[perf_event], -1, cpu, -1, 0);
        if (perf_event_fd < 0)
        {
            WARNINGV("Failed to get file descriptor for perf event {} for CPU {}", perf_event_names[perf_event], cpu);
            continue;
        }

        __u32 key = (cpu * NUM_EVENT_TYPES) + perf_event;
        bpf_map_update_elem(perf_event_map_fd, &key, &perf_event_fd, BPF_ANY);

        close(perf_event_fd);
    }

    INFOV("Populated perf_event_map for CPU {}", cpu);
}

void
DataBPF::_populate_rapl_event_map() const
{
    fd_t rapl_map_fd = bpf_map__fd(_bpf->maps.rapl_event_map);

    int rapl_type = read_rapl_type();
    if (rapl_type < 0)
    {
        ERROR("RAPL is not available on this system\n");
        exit(EXIT_FAILURE);
    }

    FOREACH_RAPL_DOMAIN(domain)
    {
        int rapl_config = read_rapl_config(rapl_domain_names[domain]);
        if (rapl_config < 0)
        {
            WARNING("RAPL domain '{}' not found on this system", rapl_domain_names[domain]);
            continue;
        }

        struct perf_event_attr rapl_event = {};
        rapl_event.type   = rapl_type;
        rapl_event.size   = sizeof(struct perf_event_attr);
        rapl_event.config = rapl_config;

        fd_t rapl_event_fd = perf_event_open(&rapl_event, -1, 0, -1, 0);
        if (rapl_event_fd < 0)
        {
            WARNING("Failed to get file descriptor for RAPL domain '{}'", rapl_domain_names[domain]);
            continue;
        }

        __u32 key = domain;
        bpf_map_update_elem(rapl_map_fd, &key, &rapl_event_fd, BPF_ANY);

        close(rapl_event_fd);

        INFOV("Populated rapl_event_map for domain '{}'", rapl_domain_names[domain]);
    }
}

void 
DataBPF::_attach_xdp(
        const std::string& interface_name) const
{
    unsigned int interface_index = if_nametoindex(interface_name.c_str());
    if (!interface_index)
        ERROR("Could not find interface \"{}\"", interface_name);

    _bpf->links.xdp_ingress = bpf_program__attach_xdp(_bpf->progs.xdp_ingress, interface_index);
    if (!_bpf->links.xdp_ingress)
        ERROR("Failed to attach BPF program to XDP hook");
}

void
DataBPF::_attach_tcx(
        const std::string& interface_name) const
{
    int interface_index = if_nametoindex(interface_name.c_str());
    if (!interface_index)
        ERROR("Could not find interface \"{}\"", interface_name);

    _bpf->links.tcx_egress = bpf_program__attach_tcx(_bpf->progs.tcx_egress, interface_index, NULL);
    if (!_bpf->links.tcx_egress)
        ERROR("Failed to attach BPF program to TCX hook");
}

void
DataBPF::_attach_timer(
        unsigned int sample_frequency)
{
    FOREACH_CPU(cpu)
        _attach_timer_for_cpu(sample_frequency, cpu);
}

void
DataBPF::_attach_timer_for_cpu(
        unsigned int sample_frequency,
        unsigned int cpu)
{
    struct perf_event_attr timer = {};
    timer.type        = PERF_TYPE_SOFTWARE;
    timer.config      = PERF_COUNT_SW_CPU_CLOCK;
    timer.sample_freq = sample_frequency;
    timer.freq        = 1;
        
    fd_t timer_fd = perf_event_open(&timer, -1, cpu, -1, 0);
    if (timer_fd < 0)
    {
        if (errno == ENODEV)
        {
            WARNING("CPU {} is offline, skipping timer attachment", cpu);
            return;
        }

        ERROR("Failed to get file descriptor for PERF_COUNT_SW_CPU_CLOCK");
    }
        
    std::unique_ptr<struct bpf_link, decltype(&bpf_link__destroy)> link(
        bpf_program__attach_perf_event(_bpf->progs.timer, timer_fd),
        &bpf_link__destroy);
    if (link == nullptr)
        ERROR("Failed to attach BPF program to perf hook");

    _timer_links.push_back(std::move(link));
    close(timer_fd);
}