/**
 * @file data_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef DATA_BPF_H
#define DATA_BPF_H

#include <string>
#include <memory>

#include "data.skel.h"
#include "definitions.hpp"

class DataBPF
{
public:
    DataBPF(const options_t& options);
private:
    void _init();
    void _attach_xdp(const std::string& interface_name) const;
    void _attach_tcx(const std::string& interface_name) const;
    void _attach_timer(unsigned int sample_frequency) const;

    const options_t& _options;
    
    std::unique_ptr<data_bpf, decltype(&data_bpf__destroy)> _bpf;
};

#endif