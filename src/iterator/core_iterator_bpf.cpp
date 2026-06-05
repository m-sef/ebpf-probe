#include "iterator/core_iterator_bpf.hpp"

#include <format>

CoreIteratorBPF::CoreIteratorBPF(
        unsigned int cpu)
    : _cpu(cpu)
    , _bpf(nullptr, &core_iterator_bpf__destroy)
    , _link(nullptr, &bpf_link__destroy)
{

}

CoreIteratorBPF::~CoreIteratorBPF()
{
    std::remove(_pinned_file_path.c_str());
}

void
CoreIteratorBPF::init()
{
    _bpf.reset(core_iterator_bpf__open());
    if (_bpf == nullptr)
        ERROR("Failed to open iterator BPF object for CPU {}", _cpu);
    
    _bpf->rodata->cpu = (__u32)_cpu;

    if (core_iterator_bpf__load(_bpf.get()) != 0)
        ERROR("Failed to load iterator BPF object for CPU {}", _cpu);
    
    union bpf_iter_link_info linfo = {};
    linfo.map.map_fd = (uint32_t)bpf_map__fd(_bpf->maps.core_stats_map); /* Possible Error, will find out later :) */

    LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
        .link_info     = &linfo,
        .link_info_len = sizeof(linfo),
    );

    _link.reset(bpf_program__attach_iter(_bpf->progs.dump_counters, &attach_opts));
    if (_link == nullptr)
        ERROR("Failed to attach iterator for CPU {}", _cpu);

    _pinned_file_path = std::format("/sys/fs/bpf/ebpf_probe/core/{}", _cpu);
    if (bpf_link__pin(_link.get(), _pinned_file_path.c_str()) != 0)
        ERROR("Failed to pin iterator link for CPU {}", _cpu);

    INFOV("Initialized CoreIteratorBPF object for CPU {}", _cpu);
}