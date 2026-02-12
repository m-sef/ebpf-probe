#!/user/bin/env python3
import time
from bcc import BPF
from pathlib import Path

def main() -> None:
    interface = 'enp0s31f6'
    src = Path('packet-counter.bpf.c').read_text()
    bpf = BPF(text=src)
    function = bpf.load_func("xdp_prog", BPF.XDP)

    bpf.attach_xdp(interface, function, 0)

    packet_counter = bpf["packet_counter"]
    byte_counter = bpf["byte_counter"]

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        pass

    bpf.remove_xdp(interface, 0)

if __name__ == '__main__':
    main()

#3179959 le ticket number
