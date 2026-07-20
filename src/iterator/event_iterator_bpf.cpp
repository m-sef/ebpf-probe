#include "iterator/event_iterator_bpf.hpp"

#include <format>

#include "definitions.hpp"
#include "perf_event_helpers.hpp"

EventIteratorBPF::EventIteratorBPF(
        const DataBPF& data_bpf,
        unsigned int cpu, 
        const std::string& event_name, 
        const std::string& file_path)
    : _data_bpf(data_bpf)
    , _cpu(cpu)
    , _event_name(event_name)
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
        ERROR("Failed to open iterator BPF object for CPU {}, event '{}'", _cpu, _event_name);

    _bpf->rodata->cpu   = _cpu;
    _bpf->rodata->event = perf_event_name_to_event_id[_event_name];
    strncpy(_bpf->rodata->event_name, _event_name.c_str(), sizeof(_bpf->rodata->event_name) - 1);

    bpf_map__reuse_fd(
            _bpf->maps.perf_event_stats_map,
            bpf_map__fd(_data_bpf.bpf()->maps.perf_event_stats_map));

    if (event_iterator_bpf__load(_bpf.get()) != 0)
        ERROR("Failed to load iterator BPF object for CPU {}, event '{}'", _cpu, _event_name);
    
    union bpf_iter_link_info linfo = {};
    linfo.map.map_fd = (uint32_t)bpf_map__fd(_bpf->maps.perf_event_stats_map);

    LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
        .link_info     = &linfo,
        .link_info_len = sizeof(linfo),
    );

    _link.reset(bpf_program__attach_iter(_bpf->progs.dump_event_stats, &attach_opts));
    if (_link == nullptr)
        ERROR("Failed to attach iterator for CPU {}, event '{}'", _cpu, _event_name);
    
    if (bpf_link__pin(_link.get(), _pinned_file_path.c_str()) != 0)
        ERROR("Failed to pin iterator link for CPU {}, event '{}'", _cpu, _event_name);

    INFOV("Initialized EventIteratorBPF object for CPU {}, event '{}'", _cpu, _event_name);
}