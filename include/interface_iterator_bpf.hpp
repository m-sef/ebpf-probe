#ifndef INTERFACE_ITERATOR_BPF
#define INTERFACE_ITERATOR_BPF

#include <string>
#include <memory>

#include "generated/interface_iterator.skel.h"

class InterfaceIteratorBPF
{
public:
    InterfaceIteratorBPF(unsigned int cpu, unsigned int ifindex, const std::string& file_path);
    ~InterfaceIteratorBPF();

    void init();

    InterfaceIteratorBPF(const InterfaceIteratorBPF&) = delete;
    InterfaceIteratorBPF& operator=(const InterfaceIteratorBPF&) = delete;
    InterfaceIteratorBPF(InterfaceIteratorBPF&&) = default;
    InterfaceIteratorBPF& operator=(InterfaceIteratorBPF&&) = default;
private:
    const unsigned int _cpu;
    const unsigned int _ifindex;
    const std::string _pinned_file_path;

    std::unique_ptr<struct interface_iterator_bpf, decltype(&interface_iterator_bpf__destroy)> _bpf;
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> _link;
};

#endif