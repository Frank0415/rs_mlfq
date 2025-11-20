#!/bin/bash

# Build script for SCX Lottery Scheduler
# Based on the build process from the markdown guides

set -euo pipefail  # Exit on any error and propagate unset variables

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "Building SCX Lottery Scheduler..."

# Variables
BPF_C_FILE="scx_lottery.bpf.c"
BPF_O_FILE="scx_lottery.bpf.o"
SKELETON_FILE="scx_lottery.bpf.skel.h"
USER_C_FILE="scx_lottery.c"
OUTPUT_BINARY="scx_lottery"

# Check if required tools are available
command -v clang >/dev/null 2>&1 || { echo "Error: clang is required but not installed."; exit 1; }
command -v bpftool >/dev/null 2>&1 || { echo "Error: bpftool is required but not installed."; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "Error: gcc is required but not installed."; exit 1; }

# Detect architecture for __TARGET_ARCH_*
ARCH=$(uname -m)
case "$ARCH" in
	x86_64)
		TARGET_ARCH="x86"
		;;
	aarch64)
		TARGET_ARCH="arm64"
		;;
	*)
		echo "Error: Unsupported architecture $ARCH for __TARGET_ARCH_* define."
		exit 1
		;;
esac

# Step 1: Compile BPF program
echo "Step 1: Compiling BPF program..."
clang -g -O2 -target bpf -D__TARGET_ARCH_${TARGET_ARCH} -c "$BPF_C_FILE" -o "$BPF_O_FILE"

# Step 2: Generate skeleton
echo "Step 2: Generating skeleton..."
bpftool gen skeleton "$BPF_O_FILE" > "$SKELETON_FILE"