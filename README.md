# ebpf-probe

A low-overhead eBPF-based monitoring program designed to collect and expose low-level system metrics (e.g. received and transmitted bytes/packets, total instructions processed per CPU, etc.) under the Linux sys psuedo filesystem.

## Requirements

- Root privileges
- `clang`, `cmake`, `libbpf-dev`, `bpftool`

## Setup

```bash
# Dependencies
sudo apt-get update -y
sudo apt-get install -y libbpf-dev cmake clang

# Build
mkdir build
cd build
cmake ..
make
```

## Usage

```
ebpf_probe [OPTIONS]
```

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-h` | `--help` | Show help |
| `-i INTERFACE` | `--interface` | Listen for network traffic on this interface/interfaces (required) |
| `-f FREQUENCY` | `--frequency` | Sample at this frequency per second for each CPU (default: 1) |
| `-v` | `--verbose` | Verbose output (default: false) |

### Example

```bash
# Monitor the Loopback ('lo') and Ethernet ('eth0') interfaces with verbose output
sudo ./ebpf_probe --interface=lo eth0 --verbose
```

## Reading CPU Metrics

Once attached, per-CPU metrics are available at `/sys/fs/bpf/ebpf_probe/cpu<cpu>/summary`:

```bash
# Single CPU
cat /sys/fs/bpf/ebpf_probe/cpu0/summary

# All CPUs
cat /sys/fs/bpf/ebpf_probe/cpu*/summary
```

Each entry contains received and transmitted packet/byte counts alongside hardware counters (cycles, instructions, cache misses).

## Reading Interface Metrics
per-CPU interface metrics are available at `/sys/fs/bpf/ebpf_probe/cpu<cpu>/<interface>`

```bash
# Loopback interface on CPU 0
cat /sys/fs/bpf/ebpf_probe/cpu0/lo

# Loopback interface on all CPUs
cat /sys/fs/bpf/ebpf_probe/cpu*/lo
```

## Reading RAPL Metrics

RAPL metrics are available at `/sys/fs/bpf/ebpf_probe/rapl/<domain_name>`:

```bash
# pkg domain
cat /sys/fs/bpf/ebpf_probe/rapl/pkg

# All domains
cat /sys/fs/bpf/ebpf_probe/rapl/*
```

## License

See [LICENSE](LICENSE).
