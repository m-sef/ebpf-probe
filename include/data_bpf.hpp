/**
 * @file data_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef DATA_BPF_H
#define DATA_BPF_H

#include <string>
#include <vector>
#include <memory>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "generated/data.skel.h"
#include "definitions.hpp"

class DataBPF
{
public:
    DataBPF(unsigned int cpu_count);

    void init();

    /* TODO: Replace with actual get fd functions */
    const std::unique_ptr<struct data_bpf, decltype(&data_bpf__destroy)>& bpf() const;
private:
    void _populate_perf_event_map() const;
    void _populate_perf_event_map_for_cpu(unsigned int cpu) const;
    void _populate_rapl_event_map() const;
    void _attach_xdp(const std::string& interface_name) const;
    void _attach_tcx(const std::string& interface_name) const;
    void _attach_timer(unsigned int sample_frequency);
    void _attach_timer_for_cpu(unsigned int sample_frequency, unsigned int cpu);

    const unsigned int _cpu_count;
    
    std::unique_ptr<struct data_bpf, decltype(&data_bpf__destroy)> _bpf;
    std::vector<std::unique_ptr<struct bpf_link, decltype(&bpf_link__destroy)>> _timer_links;
};

#endif