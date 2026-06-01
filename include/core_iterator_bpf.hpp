/**
 * @file core_iterator_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief Handles per-core iterator BPF programs, as well as pinning their corresponding file
 * 
 */
#ifndef CORE_ITERATOR_BPF_H
#define CORE_ITERATOR_BPF_H

#include <memory>

#include "core_iterator.skel.h"
#include "definitions.hpp"

class CoreIteratorBPF
{
public:
    CoreIteratorBPF(const options_t& options, unsigned int cpu);
private:
    std::unique_ptr<core_iterator_bpf, decltype(&core_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
};

#endif