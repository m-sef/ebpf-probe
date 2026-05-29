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

__OUTDATED as of May 29th, 2026__

On CloudLab c220g1, with stress-ng running, turboboost disabled, hyperthreads disabled, and all CPUs set to 'performance' mode:
```
slmoore@node0:~/ebpf-probe$ stress-ng --cpu 0 --cpu-method int64
slmoore@node0:~/ebpf-probe$ sudo ./build/ebpf_probe --interface=lo --frequency=1000
slmoore@node0:~/ebpf-probe$ sudo ./scripts/validate_with_perf 60

=== eBPF probe vs perf stat (60s window, system-wide) ===

Event                    eBPF (normalized)               perf stat      mux%       ratio
-----                    -----------------               ---------      ----       -----
instructions                 6099617338099           6099520385130     49.2%      1.0000
cpu-cycles                   2283775473391           2283714063461     42.3%      1.0000
ref-cycles                   2283615929549           2283945309530     41.6%      0.9999
cache-misses                       2779970                 2596513     50.3%      1.0707

Event                                 eBPF               perf stat       ratio
-----                                 ----               ---------       -----
energy-pkg (J)                   2361.9441                       4    590.4860

rx_bytes          528 bytes

--- raw perf stat output ---

 Performance counter stats for 'system wide':

 6,099,520,385,130        instructions                     #    2.67  insn per cycle              (47.40%)
 2,283,714,063,461        cpu-cycles                                                              (44.27%)
 2,283,945,309,530        ref-cycles                                                              (48.96%)
         2,596,513        cache-misses                                                            (50.00%)
          4,695.51 Joules power/energy-pkg/                                                     

      60.004140167 seconds time elapsed
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