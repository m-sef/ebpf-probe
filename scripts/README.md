# ebpf-probe/scripts

## cat_all_cpus.sh

```bash
cat /sys/fs/bpf/ebpf_probe/cpu*/summary | column -t -s,
```

## cat_all_domains.sh

```bash
cat /sys/fs/bpf/ebpf_probe/rapl/* | column -t -s,
```

## install_dependencies.sh

```bash
sudo apt-get update -y
sudo apt-get install -y libbpf-dev cmake clang
```

## log_cores.py

OUTDATED
* TODO - Rewrite this script to properly handle new sys file directory