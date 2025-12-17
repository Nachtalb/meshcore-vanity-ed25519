#!/bin/bash

# CPU name
cpu=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^[ \t]*//;s/[ \t]*$//')

# Physical cores (Cores per socket * Sockets)
cores=$(lscpu | awk '/^Core\(s\) per socket:/ {cores=$NF} /^Socket\(s\):/ {sockets=$NF} END {print cores * sockets}')

# CPU threads (logical processors)
threads=$(nproc --all)

# RAM in GiB (rounded down)
ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
ram_gib=$((ram_kb / 1048576))
[ "$ram_gib" -lt 10 ] && ram="${ram_gib}GiB" || ram="${ram_gib}GiB"

# OS name
os=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 || echo "Linux")

# Rust version
if rustc --version >/dev/null 2>&1; then
    rustver=$(rustc --version | cut -d' ' -f2)
else
    rustver="not installed"
fi

echo "$cpu, $cores cores, $threads CPU threads, $ram RAM, $os, rustc $rustver"
