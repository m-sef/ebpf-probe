/**
 * @file core_iterator_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief Handles per-core iterator BPF programs, as well as pinning their corresponding file
 * 
 */
#ifndef CORE_ITERATOR_BPF_H
#define CORE_ITERATOR_BPF_H

#include <string>
#include <memory>

#include "generated/core_iterator.skel.h"
#include "data_bpf.hpp"
#include "definitions.hpp"

class CoreIteratorBPF
{
public:
    CoreIteratorBPF(
            const DataBPF& data_bpf,
            unsigned int cpu);
    ~CoreIteratorBPF();

    void init();

    CoreIteratorBPF(const CoreIteratorBPF&) = delete;
    CoreIteratorBPF& operator=(const CoreIteratorBPF&) = delete;
    CoreIteratorBPF(CoreIteratorBPF&&) = default;
    CoreIteratorBPF& operator=(CoreIteratorBPF&&) = default;
private:
    const DataBPF&     _data_bpf;
    const unsigned int _cpu;

    std::unique_ptr<core_iterator_bpf, decltype(&core_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
    std::string _pinned_file_path;
};

#endif