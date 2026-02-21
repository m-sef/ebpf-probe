#!/usr/bin/env python3
import sys
import socket
import logging
from logging import Logger
from datetime import datetime
import time
from bcc import BPF
import ctypes
from pathlib import Path

def init_logger(
        name : str,
        file_path : str,
        level=logging.INFO,
        date_format : str = "%Y-%m-%d %H:%M:%S") -> Logger:
    """Function for creating new Logger objects
    https://stackoverflow.com/questions/11232230/logging-to-two-files-with-different-settings"""

    formatter = logging.Formatter(
        '%(asctime)s,%(message)s',
        datefmt=date_format)

    handler = logging.FileHandler(file_path)        
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

def main() -> None:
    interface = sys.argv[1]
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    hostname = socket.gethostname().split('.')[0]

    logger = init_logger(
        "rx",
        f"{hostname}-{interface}-{timestamp}.log")

    src = Path('packet-counter.bpf.c').read_text()
    bpf = BPF(text=src)
    function = bpf.load_func("xdp_prog", BPF.XDP)

    bpf.attach_xdp(interface, function, 0)

    print("packets,bytes")

    previous_packet_count = 0
    previous_byte_count = 0

    try:
        while True:
            time.sleep(1)

            current_packet_count = bpf['packets'][0].value
            current_byte_count = bpf['bytes'][0].value

            print(
                current_packet_count - previous_packet_count,
                current_byte_count - previous_byte_count,
                sep=',');

            logger.info(
                f"{current_packet_count - previous_packet_count},"
                f"{current_byte_count - previous_byte_count}")

            previous_packet_count = current_packet_count
            previous_byte_count = current_byte_count
    except KeyboardInterrupt:
        pass

    bpf.remove_xdp(interface, 0)

if __name__ == '__main__':
    main()
