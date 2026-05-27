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

```
ebpf_probe$ sudo ./build/ebpf_probe --interface=lo --frequency=1000
ebpf_probe$ sudo ./scripts/validate_with_perf 60

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