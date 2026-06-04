#include "rapl_iterator_bpf.hpp"

#include <format>

#include "rapl_helpers.hpp"

RAPLIteratorBPF::RAPLIteratorBPF(
        unsigned int domain)
    : _domain(domain)
    , _bpf(nullptr, &rapl_iterator_bpf__destroy)
    , _link(nullptr, &bpf_link__destroy)
{

}

RAPLIteratorBPF::~RAPLIteratorBPF()
{
    std::remove(_pinned_file_path.c_str());
}

void RAPLIteratorBPF::init()
{
    _bpf.reset(rapl_iterator_bpf__open());
    if (_bpf == nullptr)
        ERROR("Failed to open iterator BPF object for domain {}", _domain);
    
    _bpf->rodata->domain = (__u32)_domain;
    strncpy(_bpf->rodata->rapl_domain_name, rapl_domain_names[_domain], sizeof(_bpf->rodata->rapl_domain_name) - 1);
    read_rapl_unit(rapl_domain_names[_domain], _bpf->rodata->unit, sizeof(_bpf->rodata->unit));
    read_rapl_scale(rapl_domain_names[_domain], _bpf->rodata->scale, sizeof(_bpf->rodata->scale));

    if (rapl_iterator_bpf__load(_bpf.get()) != 0)
        ERROR("Failed to load iterator BPF object for domain {}", _domain);

    union bpf_iter_link_info linfo = {};
    linfo.map.map_fd = (uint32_t)bpf_map__fd(_bpf->maps.rapl_stats_map);

    LIBBPF_OPTS(bpf_iter_attach_opts, attach_opts,
        .link_info     = &linfo,
        .link_info_len = sizeof(linfo),
    );

    _link.reset(bpf_program__attach_iter(_bpf->progs.dump_counters, &attach_opts));
    if (_link == nullptr)
        ERROR("Failed to attach iterator for domain {}", _domain);

    _pinned_file_path = std::format("/sys/fs/bpf/ebpf_probe/rapl/{}", rapl_domain_names[_domain]);
    if (bpf_link__pin(_link.get(), _pinned_file_path.c_str()) != 0)
        ERROR("Failed to pin iterator link for domain {}", _domain);

    INFOV("Initialized RAPLIteratorBPF object for domain '{}'", rapl_domain_names[_domain]);
}