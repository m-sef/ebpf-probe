# ebpf-probe/exp/memcached

## Notes

| Node | IP | OS | Node Type | Description
| :- | :- | :- | :- | :- |
| master | 10.10.1.4 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Leader |
| worker0 | 10.10.1.1 | Ubuntu 24.04 | CloudLab c220g2 | Memcached Server|
| worker1 | 10.10.1.2 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Agent 1 |
| worker2 | 10.10.1.3 | Ubuntu 24.04 | CloudLab c220g2 | Mutilate Agent 2 |

__Hyperthreading and Turbo Boost is disabled on all nodes, irqbalance is untouched__

__CPU Governer is set "performance" on all nodes__

## master
```bash
# Pull mutilate workload generator docker image
sudo docker pull ghcr.io/m-sef/mutilate:latest

# 'Sleep infinity' so that this container can be used later using 'docker exec'
sudo docker run --detach --network host ghcr.io/m-sef/mutilate:latest sleep infinity

# Load key, value pairs on Memcached server
sudo docker exec ${CONTAINER_NAME} taskset -c 0 mutilate -vv --binary -s 10.10.1.1:11211 --loadonly -K fb_key -V fb_value

# Run mutilate workload
sudo docker exec ${CONTAINER_NAME} taskset -c 0 mutilate --binary -s 10.10.1.1:11211 --noload --agent={10.10.1.2,10.10.1.3} --threads=1 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0.25 --depth=128 --measure_connections=32 --qps=100000 --time=30
```

## worker0
```bash
# Pull and run memcached docker image
sudo docker pull memcached:1.6-alpine
sudo docker run --detach --network host memcached:1.6-alpine -t 20 -m 32G -c 8192 -b 8192 -p 11211 -u nobody -B binary

# Run eBPF Probe on the node's main interface and set sample frequency to 6000 times a second
sudo ./build/ebpf_probe --interface=enp6s0f0 --frequency=6000
```

## worker1 & worker2
```bash
# Pull mutilate workload generator docker image
sudo docker pull ghcr.io/m-sef/mutilate:latest

# Run mutilate workload generator as agent
sudo docker run --detach --network host ghcr.io/m-sef/mutilate:latest mutilate --agentmode --threads=16
```
