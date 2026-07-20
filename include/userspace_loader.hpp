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

#include "data_bpf.hpp"
#include "iterator/cpu_iterator_bpf.hpp"
#include "iterator/rapl_iterator_bpf.hpp"
#include "iterator/interface_iterator_bpf.hpp"
#include "iterator/event_iterator_bpf.hpp"
#include "definitions.hpp"

class UserspaceLoader
{
public:
    UserspaceLoader();
    ~UserspaceLoader();

    UserspaceLoader(const UserspaceLoader& other) = delete;
    UserspaceLoader& operator=(const UserspaceLoader& other) = delete;
    UserspaceLoader(UserspaceLoader&& other) = delete;
    UserspaceLoader& operator=(UserspaceLoader&& other) = delete;

    void init();
private:
    void _create_sys_directories();
    void _remove_sys_directories();

    bool _is_core_online(unsigned int cpu);

    const unsigned int _cpu_count;

    DataBPF _data;
    std::vector<CPUIteratorBPF>       _core_iterators;
    std::vector<InterfaceIteratorBPF> _interface_iterators;
    std::vector<EventIteratorBPF>     _event_iterators;
    std::vector<RAPLIteratorBPF>      _rapl_iterators;
};

#endif
