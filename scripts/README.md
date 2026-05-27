# ebpf-probe/scripts

## cat_all_cores.sh

```
cat /sys/fs/bpf/ebpf_probe/core/* | column -t -s,
```

## validate_with_perf.sh

### Usage:

```
./validate_with_perf.sh [DURATION]
```

### Results:

On CloudLab c220g1, with stress-ng running, turboboost disabled, hyperthreads disabled, and all CPUs set to 'performance' mode:
```
slmoore@node0:~/ebpf-probe$ sudo perf stat -a -e instructions,cache-misses,ref-cycles,power/energy-pkg/,power/energy-ram/ -x, stress-ng --cpu 0 --cpu-method int64
slmoore@node0:~/ebpf-probe$ sudo ./build/ebpf_probe --interface=lo --frequency=1000
slmoore@node0:~/ebpf-probe$ sudo ./scripts/validate_with_perf 60

=== eBPF probe vs perf stat (60s window, system-wide) ===

Event                    eBPF (normalized)               perf stat      mux%       ratio
-----                    -----------------               ---------      ----       -----
instructions                 6097439260474           6097558844181     37.3%      1.0000
cpu-cycles                   2283845878195           2284200455580     34.4%      0.9998
ref-cycles                   2283623278570           2284348806906     29.7%      0.9997
cache-misses                       3012804                 2954057     40.2%      1.0199

Event                                 eBPF               perf stat       ratio
-----                                 ----               ---------       -----
energy-pkg (J)                   2382.4553                       4    595.6138

rx_bytes          0 bytes

--- raw perf stat output ---

 Performance counter stats for 'system wide':

 6,097,558,844,181        instructions                     #    2.67  insn per cycle              (37.50%)
 2,284,200,455,580        cpu-cycles                                                              (37.50%)
 2,284,348,806,906        ref-cycles                                                              (33.75%)
         2,954,057        cache-misses                                                            (36.67%)
          4,715.18 Joules power/energy-pkg/                                                     

      60.001875379 seconds time elapsed
```

On my personal laptop:

```
m-sef@m-sef-Surface-Laptop-4:~/ebpf-probe$ sudo ./build/ebpf_probe --interface=lo --frequency=1000
m-sef@m-sef-Surface-Laptop-4:~/ebpf-probe$ sudo ./scripts/validate_with_perf 60

=== eBPF probe vs perf stat (60s window, system-wide) ===

Event                    eBPF (normalized)               perf stat      mux%       ratio
-----                    -----------------               ---------      ----       -----
instructions                   89032955412             87719681241     52.1%      1.0150
cpu-cycles                     67376495242             66241894865     43.8%      1.0171
ref-cycles                    105133748432            103291943159     35.4%      1.0178
cache-misses                     347163519               344520456     66.7%      1.0077

Event                                 eBPF               perf stat       ratio
-----                                 ----               ---------       -----
energy-pkg (J)                    274.9099                  274.42      1.0018

rx_bytes          1976 bytes

--- raw perf stat output ---

 Performance counter stats for 'system wide':

    87,719,681,241        instructions                     #    1.32  insn per cycle              (83.33%)
    66,241,894,865        cpu-cycles                                                              (83.33%)
   103,291,943,159        ref-cycles                                                              (64.58%)
       344,520,456        cache-misses                                                            (72.92%)
            274.42 Joules power/energy-pkg/                                                     

      60.005470289 seconds time elapsed
```