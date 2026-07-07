# ebpf-probe/scripts

## gather_cpu_metrics.sh

Gathers CPU metrics and logs them under `/tmp/ebpf-probe/cpu.log`

### Usage

```bash
gather_cpu_metrics DURATION

# Example - Gather for 10 seconds
./gather_cpu_metrics 10
```

## gether_rapl_metrics.sh

Gathers RAPL metrics and logs them under `/tmp/ebpf-probe/rapl.log`

### Usage

```bash
gather_rapl_metrics DURATION

# Example - Gather for 10 seconds
./gather_rapl_metrics 10
```

## install_dependencies.sh

```bash
sudo apt-get update -y
sudo apt-get install -y libbpf-dev cmake clang
```