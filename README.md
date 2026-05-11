# ebpf-probe

An XDP-based packet counter with per-CPU hardware performance counter and energy (RAPL) collection. Metrics are written to pinned BPF iterator files under `/sys/fs/bpf/ebpf_probe/` and can be read with standard shell tools.

## Requirements

- Root privileges
- `clang`, `cmake`, `libbpf-dev`, `bpftool`

## Setup

```bash
# Install dependencies (run once)
sudo ./scripts/install_dependencies.sh

# Build
mkdir build
cd build
cmake ..
make
```

## Usage

```
sudo ./build/ebpf_probe -i INTERFACE [-f FREQUENCY] [-hv]
```

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-h` | `--help` | Show help |
| `-i INTERFACE` | `--interface` | Network interface to attach to (e.g. `eth0`, `ens3`) |
| `-f FREQUENCY` | `--frequency` | Sampling frequency for perf/RAPL events in Hz (default: 1) |
| `-v` | `--verbose` | Verbose output when reading pinned files |

## Reading Core Metrics

Once attached, per-CPU metrics are available at `/sys/fs/bpf/ebpf_probe/core/<cpu_id>`:

```bash
# Single CPU
cat /sys/fs/bpf/ebpf_probe/core/0

# All CPUs
cat /sys/fs/bpf/ebpf_probe/core/*
```

Each entry contains packet/byte counts alongside hardware counters (cycles, instructions, cache misses) and RAPL energy readings for that core.

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
