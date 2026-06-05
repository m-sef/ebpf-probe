#include "event_iterator_bpf.hpp"

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

}

void EventIteratorBPF::init()
{

}