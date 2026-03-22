package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../build -lebpf_probe -Wl,-rpath,${SRCDIR}/../build
#cgo CFLAGS: -I${SRCDIR}/../include
#include "../include/probe.h"

extern int handleRecord(void* context, void* data, size_t size);
*/
import "C"
import "unsafe"
import "fmt"

//export handleRecord
func handleRecord(context unsafe.Pointer, data unsafe.Pointer, size C.size_t) C.int {
	info := (*C.packet_info_t)(data)

	fmt.Printf("%3d.%03d.%03d.%03d:%-5d->%3d.%03d.%03d.%03d:%-5d rx_queue_index: %-9d protocol: %-3d size: %d\n",
        (info.source_ipv4_address)            & 0xFF,
        (info.source_ipv4_address >> 8)       & 0xFF,
        (info.source_ipv4_address >> 16)      & 0xFF,
        (info.source_ipv4_address >> 24)      & 0xFF,
        info.source_port,
        (info.destination_ipv4_address)       & 0xFF,
        (info.destination_ipv4_address >> 8)  & 0xFF,
        (info.destination_ipv4_address >> 16) & 0xFF,
        (info.destination_ipv4_address >> 24) & 0xFF,
        info.destination_port,
		info.rx_queue_index,
        info.protocol,
		info.size);

    return 0
}

func main() {
	probe := C.probe__init()

	C.probe__attach_xdp(probe, C.CString("lo"))
	C.probe__attach_xdp(probe, C.CString("enp0s31f6"))

	C.probe__init_buffer(probe, C.buffer_callback_t(C.handleRecord), nil)

	for {
		C.probe__flush_buffer(probe)
	}

	C.probe__destroy_buffer(probe)
	C.probe__destroy(probe)
}
