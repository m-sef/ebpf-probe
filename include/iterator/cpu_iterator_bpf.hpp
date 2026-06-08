/**
 * @file core_iterator_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief Handles per-core iterator BPF programs, as well as pinning their corresponding file
 * 
 */
#ifndef CPU_ITERATOR_BPF_H
#define CPU_ITERATOR_BPF_H

#include <string>
#include <memory>

#include "generated/cpu_iterator.skel.h"
#include "data_bpf.hpp"
#include "definitions.hpp"

class CPUIteratorBPF
{
public:
    CPUIteratorBPF(
            const DataBPF& data_bpf,
            unsigned int cpu,
            const std::string& file_path);
    ~CPUIteratorBPF();

    void init();

    CPUIteratorBPF(const CPUIteratorBPF&) = delete;
    CPUIteratorBPF& operator=(const CPUIteratorBPF&) = delete;
    CPUIteratorBPF(CPUIteratorBPF&&) = default;
    CPUIteratorBPF& operator=(CPUIteratorBPF&&) = default;
private:
    const DataBPF&     _data_bpf;
    const unsigned int _cpu;
    const std::string  _pinned_file_path;

    std::unique_ptr<cpu_iterator_bpf, decltype(&cpu_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
};

#endif