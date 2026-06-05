#ifndef EVENT_ITERATOR_BPF_H
#define EVENT_ITERATOR_BPF_H

#include <string>
#include <memory>

#include "generated/event_iterator.skel.h"

class EventIteratorBPF
{
public:
    EventIteratorBPF(unsigned int cpu, unsigned int event, const std::string& file_path);
    ~EventIteratorBPF();

    void init();

    EventIteratorBPF(const EventIteratorBPF& other) = delete;
    EventIteratorBPF& operator=(const EventIteratorBPF& other) = delete;
    EventIteratorBPF(EventIteratorBPF&& other) = delete;
    EventIteratorBPF& operator=(EventIteratorBPF&& other) = delete;
private:
    const unsigned int _cpu;
    const unsigned int _event;
    const std::string _pinned_file_path;

    std::unique_ptr<struct event_iterator_bpf, decltype(&event_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
};

#endif