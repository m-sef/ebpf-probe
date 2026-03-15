package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../build -lebpf_probe -Wl,-rpath,${SRCDIR}/../build
#cgo CFLAGS: -I${SRCDIR}/../include
#include "../include/ebpf_probe.h"
*/
import "C"

func main() {
	ebpf_probe := C.ebpf_probe__init(C.CString("enp0s31f6"))
	defer C.ebpf_probe__destroy(ebpf_probe)

	for {
		C.ebpf_probe__flush_packet_info_ring_buffer(ebpf_probe)
	}
}
