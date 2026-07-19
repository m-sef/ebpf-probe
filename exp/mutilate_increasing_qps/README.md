# ebpf-probe/exp/mutilate_increasing_qps

Observing the measurements made by eBPF Probe as compared to the intlogger.

## Notes

| Node | IP | OS | Node Type | Description
| :- | :- | :- | :- | :- |
| master | 10.10.1.4 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Leader |
| worker0 | 10.10.1.1 | Ubuntu 24.04 | CloudLab c220g2 | Memcached Server|
| worker1 | 10.10.1.2 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Agent 1 |
| worker2 | 10.10.1.3 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Agent 2 |

__Hyperthreading and Turbo Boost is disabled on all nodes__

__irqbalance is intentionally disabled on the node running Memcached__

__CPU Governer is set "performance" on all nodes__

### master
```bash
# Load key, value pairs on Memcached server
taskset -c 0 mutilate -vv --binary -s 10.10.1.1:11211 --loadonly -K fb_key -V fb_value

# Run mutilate workload
taskset -c 0 mutilate --binary -s 10.10.1.1:11211 --noload --agent={10.10.1.2,10.10.1.3} --threads=1 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0.25 --depth=128 --measure_connections=32 --qps=100000 --time=30
```

### worker0
```bash
# Run bare-metal Memcached
memcached -t 20 -m 32G -c 8192 -b 8192 -p 11211 -u nobody -B binary

# Run eBPF Probe on the node's main interface and set sample frequency to every millisecond (1000 times a second)
sudo ./build/ebpf_probe --interface=${WORKER0_IF} --frequency=1000
```

### worker1 & worker2
```bash
# Run mutilate workload generator as agent
mutilate --agentmode --threads=16
```