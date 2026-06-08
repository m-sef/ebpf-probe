/**
 * @file rapl_iterator_bpf.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief Handles per-domain iterator BPF programs, as well as pinning their corresponding file
 * 
 */
#ifndef RAPL_ITERATOR_BPF_H
#define RAPL_ITERATOR_BPF_H

#include <string>
#include <memory>

#include "generated/rapl_iterator.skel.h"
#include "data_bpf.hpp"
#include "definitions.hpp"

class RAPLIteratorBPF
{
public:
    RAPLIteratorBPF(
            const DataBPF& data_bpf,
            unsigned int domain);
    ~RAPLIteratorBPF();

    void init();

    RAPLIteratorBPF(const RAPLIteratorBPF&) = delete;
    RAPLIteratorBPF& operator=(const RAPLIteratorBPF&) = delete;
    RAPLIteratorBPF(RAPLIteratorBPF&&) = default;
    RAPLIteratorBPF& operator=(RAPLIteratorBPF&&) = default;
private:
    const DataBPF&     _data_bpf;
    const unsigned int _domain;

    std::unique_ptr<rapl_iterator_bpf, decltype(&rapl_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
    std::string _pinned_file_path;
};

#endif