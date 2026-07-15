# ebpf-probe/scripts

## gather_cpu_metrics.sh

Gathers CPU metrics and logs them under `/tmp/ebpf_probe/summary.log`

### Usage

```bash
gather_cpu_metrics DURATION FREQUENCY

# Example - Gather for 10 seconds, sampling 20 times per second
./gather_cpu_metrics 10 20

# Read log file
cat /tmp/ebpf_probe/summary.log
```

## gether_rapl_metrics.sh

Gathers RAPL metrics and logs them under `/tmp/ebpf_probe/rapl.log`

### Usage

```bash
gather_rapl_metrics DURATION FREQUENCY

# Example - Gather for 10 seconds, sampling 20 times per second
./gather_rapl_metrics 10 20

# Read log file
cat /tmp/ebpf_probe/rapl.log
```

## install_dependencies.sh

```bash
sudo apt-get update -y
sudo apt-get install -y libbpf-dev cmake clang
```