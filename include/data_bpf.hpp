/**
 * @file data_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef DATA_BPF_H
#define DATA_BPF_H

#include <memory>

#include "data.skel.h"
#include "definitions.hpp"

class DataBPF
{
public:
    DataBPF(const options_t& options);
private:
    std::unique_ptr<data_bpf, decltype(&data_bpf__destroy)> _bpf;
};

#endif