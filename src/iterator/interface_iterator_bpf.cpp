#include "iterator/interface_iterator_bpf.hpp"

#include <format>

#include "definitions.hpp"

InterfaceIteratorBPF::InterfaceIteratorBPF(
        unsigned int cpu,
        unsigned int ifindex,
        const std::string& file_path)
    : _cpu(cpu)
    , _ifindex(ifindex)
    , _pinned_file_path(file_path)
    , _bpf(nullptr, &interface_iterator_bpf__destroy)
    , _link(nullptr, &bpf_link__destroy)
{

}

InterfaceIteratorBPF::~InterfaceIteratorBPF()
{
    std::remove(_pinned_file_path.c_str());
}

void InterfaceIteratorBPF::init()
{
    _bpf.reset(interface_iterator_bpf__open());
    if (_bpf == nullptr)
        ERROR("Failed to open iterator BPF object for CPU {}, interface {}", _cpu, _ifindex);

    _bpf->rodata->cpu     = _cpu;
    _bpf->rodata->ifindex = _ifindex;

    if (interface_iterator_bpf__load(_bpf.get()) != 0)
        ERROR("Failed to load iterator BPF object for CPU {}, interface {}", _cpu, _ifindex);
    
    union bpf_iter_link_info linfo = {};
    linfo.map.map_fd = (uint32_t)bpf_map__fd(_bpf->maps.interface_stats_map); 
    /* I have no idea why this doesn't break the entire program... 
       (rapl_stats_map should be a member of data.bpf.c, not this BPF, no?)
       But I also don't entirely know why it is necessary either. */

    LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
        .link_info     = &linfo,
        .link_info_len = sizeof(linfo),
    );

    _link.reset(bpf_program__attach_iter(_bpf->progs.dump_interface_stats, &attach_opts));
    if (_link == nullptr)
        ERROR("Failed to attach iterator for CPU {}, interface {}", _cpu, _ifindex);
    
    if (bpf_link__pin(_link.get(), _pinned_file_path.c_str()) != 0)
        ERROR("Failed to pin iterator link for CPU {}, interface {}", _cpu, _ifindex);

    INFOV("Initialized InterfaceIteratorBPF object for CPU {}, interface {}", _cpu, _ifindex);
}