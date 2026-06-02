/**
 * @file userspace_loader.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef USERSPACE_LOADER_H
#define USERSPACE_LOADER_H

#include <string>
#include <vector>
#include <memory>

#include "data.skel.h"
#include "core_iterator.skel.h"
#include "rapl_iterator.skel.h"
#include "data_bpf.hpp"
#include "core_iterator_bpf.hpp"
#include "rapl_iterator_bpf.hpp"
#include "definitions.hpp"

class UserspaceLoader
{
public:
    UserspaceLoader(const struct options& options);
    ~UserspaceLoader();

    UserspaceLoader(const UserspaceLoader& other) = delete;
    UserspaceLoader& operator=(const UserspaceLoader& other) = delete;
    UserspaceLoader(UserspaceLoader&& other) = delete;
    UserspaceLoader& operator=(UserspaceLoader&& other) = delete;

    void init();
private:
    void _create_sys_directories();
    void _remove_sys_directories();

    bool _is_core_online(size_t cpu_idx);

    const struct options _options;
    const __u32 _cpu_count;

    DataBPF _data; /* Handles attaching xdp_ingress, tcx_egress, and timer BPF programs. Also populates perf and rapl event maps */
    std::vector<CoreIteratorBPF> _core_iterators; /* Handles per-core iterator BPF programs */
    std::vector<RAPLIteratorBPF> _rapl_iterators; /* Handles per-RAPL domain iterator BPF programs */
};

#endif
