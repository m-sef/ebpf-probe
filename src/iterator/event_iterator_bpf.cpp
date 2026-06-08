#include "iterator/event_iterator_bpf.hpp"

#include <format>

#include "definitions.hpp"

EventIteratorBPF::EventIteratorBPF(
        unsigned int cpu, 
        unsigned int event, 
        const std::string& file_path)
    : _cpu(cpu)
    , _event(event)
    , _pinned_file_path(file_path)
    , _bpf(nullptr, &event_iterator_bpf__destroy)
    , _link(nullptr, &bpf_link__destroy)
{

}

EventIteratorBPF::~EventIteratorBPF()
{
    std::remove(_pinned_file_path.c_str());
}

void EventIteratorBPF::init()
{
    _bpf.reset(event_iterator_bpf__open());
    if (_bpf == nullptr)
        ERROR("Failed to open iterator BPF object for CPU {}, event {}", _cpu, _event);

    _bpf->rodata->cpu   = _cpu;
    _bpf->rodata->event = _event;

    if (event_iterator_bpf__load(_bpf.get()) != 0)
        ERROR("Failed to load iterator BPF object for CPU {}, event {}", _cpu, _event);
    
    union bpf_iter_link_info linfo = {};
    linfo.map.map_fd = (uint32_t)bpf_map__fd(_bpf->maps.interface_stats_map); 
    /* I have no idea why this doesn't break the entire program... 
       (rapl_stats_map should be a member of data.bpf.c, not this BPF, no?)
       But I also don't entirely know why it is necessary either. */

    LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
        .link_info     = &linfo,
        .link_info_len = sizeof(linfo),
    );

    _link.reset(bpf_program__attach_iter(_bpf->progs.dump_event_stats, &attach_opts));
    if (_link == nullptr)
        ERROR("Failed to attach iterator for CPU {}, event {}", _cpu, _event);
    
    if (bpf_link__pin(_link.get(), _pinned_file_path.c_str()) != 0)
        ERROR("Failed to pin iterator link for CPU {}, event {}", _cpu, _event);

    INFOV("Initialized EventIteratorBPF object for CPU {}, event {}", _cpu, _event);
}