#ifndef EVENT_ITERATOR_BPF_H
#define EVENT_ITERATOR_BPF_H

#include <string>
#include <memory>

#include "generated/event_iterator.skel.h"
#include "data_bpf.hpp"

class EventIteratorBPF
{
public:
    EventIteratorBPF(const DataBPF& data_bpf, unsigned int cpu, const std::string& event_name, const std::string& file_path);
    ~EventIteratorBPF();

    void init();

    EventIteratorBPF(const EventIteratorBPF& other) = delete;
    EventIteratorBPF& operator=(const EventIteratorBPF& other) = delete;
    EventIteratorBPF(EventIteratorBPF&& other) = default;
    EventIteratorBPF& operator=(EventIteratorBPF&& other) = default;
private:
    const DataBPF& _data_bpf;
    const unsigned int _cpu;
    const std::string _event_name;
    const std::string _pinned_file_path;

    std::unique_ptr<struct event_iterator_bpf, decltype(&event_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
};

#endif